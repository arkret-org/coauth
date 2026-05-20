// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 (2026-05-20, spec a77b995) — `/api/v1/policy/check`
//! handler.
//!
//! Wire-breaking: replaces the pre-round-4 dry-run-only policy surface
//! exposed under `/api/admin/v1/policy-checks/dry-run`. The round-4
//! endpoint is the production policy-decision API: principal servers,
//! events submitters, and federation peers MUST consume this surface
//! to obtain a signed `PolicyCheckResponse` they can attach to their
//! own audit transcript.
//!
//! ## Request / response shapes
//!
//! Driven entirely by the SDK types
//! ([`contrix_core::model::round4::PolicyCheckRequest`] and
//! [`contrix_core::model::round4::PolicyCheckResponse`]) so the wire
//! never drifts. The full transcript binding is:
//!
//! - **request side**: `(realm_id, actor, action, request_canonical_hash,
//!   source.{service_did, service_type}, source_ip_hash,
//!   signed_transport)`
//! - **response side**: `decision` + `bound_to{realm_id, actor, action,
//!   request_canonical_hash, policy_server_id}` + the three frontier
//!   hashes (`auth_state_hash`, `policy_frontier_hash`,
//!   `membership_frontier_hash`) + detached `signature{kid, sig}` over
//!   the canonical transcript.
//!
//! ## TODOs
//!
//! - `TODO(round4-policy-check-signing-transcript)`: full RFC 8785
//!   canonical-JSON transcript signing over the
//!   `(bound_to, decision, *_hash)` tuple. The wire shape is correct
//!   end-to-end; the inner sig today is a stub digest that downstream
//!   verifiers MUST treat as untrusted until this lands.
//! - `TODO(round4-policy-check-frontier-source)`: the three frontier
//!   hashes are sourced from a placeholder. Once soland exposes the
//!   `cx.events.frontier` federation-peer response with
//!   `frontier_root`, coauth MUST plumb that through here.

use chrono::Utc;
use coauth_config::ContrixConfig;
use coauth_data::UrlBuilder;
use coauth_keystore::Keystore;
use contrix_core::{
    AuthzDecision, Did, Hash, PolicyCheckBoundTo, PolicyCheckRequest, PolicyCheckResponse,
    PolicyCheckSignature,
};
use salvo::prelude::*;
use sha2::Digest as _;

use crate::handlers::{
    common::DepotExt,
    contrix::{self, ContrixRouteError},
};

/// `POST /api/v1/policy/check`
///
/// Round 4 `cx.policy.check` endpoint. Consumes
/// [`PolicyCheckRequest`], emits a signed [`PolicyCheckResponse`].
#[handler]
pub async fn post_policy_check(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PolicyCheckResponse>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;

    let body: PolicyCheckRequest = req
        .parse_json()
        .await
        .map_err(|e| ContrixRouteError::BadRequest(format!("invalid policy-check body: {e}")))?;

    // Reject obviously malformed requests early. The SDK newtype
    // validators already enforced the `^did:[a-z0-9]+:[^\s]+$` regex on
    // `actor` and `source.service_did` during deserialise, and the
    // `RealmId` newtype on `realm_id` — so any further validation here
    // is shape-only.
    if body.action.trim().is_empty() {
        return Err(ContrixRouteError::BadRequest("action is required".into()));
    }
    if body.request_id.trim().is_empty() {
        return Err(ContrixRouteError::BadRequest(
            "request_id is required".into(),
        ));
    }

    let response =
        build_policy_check_response(&body, &url_builder, &contrix_config, &key_store)?;
    Ok(Json(response))
}

/// Build the full [`PolicyCheckResponse`] bound to the request
/// transcript. Pulled out so unit tests can exercise the binding
/// without spinning up the full salvo Depot.
pub(crate) fn build_policy_check_response(
    request: &PolicyCheckRequest,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
) -> Result<PolicyCheckResponse, ContrixRouteError> {
    // Policy server identity: coauth's own service DID (signs the
    // response with its preferred signing key).
    let policy_server_did = contrix::service_did_for(url_builder, contrix_config);
    let policy_server_id = Did::new(policy_server_did.clone()).map_err(|e| {
        ContrixRouteError::Internal(Box::new(std::io::Error::other(format!(
            "policy server DID failed SDK validation: {e}"
        ))))
    })?;

    // Real policy decision computation is plumbed elsewhere; this
    // round-4 wire-shape handler defers the actual evaluation to the
    // policy crate (which currently returns `Allow` for any
    // syntactically-valid request — the in-tree Cedar evaluator is
    // gated behind a feature flag).
    //
    // TODO(round4-policy-check-evaluator): hook the `coauth_policy`
    // factory here instead of returning Allow unconditionally.
    let decision = AuthzDecision::Allow;

    let bound_to = PolicyCheckBoundTo {
        realm_id: request.realm_id.clone(),
        actor: request.actor.clone(),
        action: request.action.clone(),
        request_canonical_hash: request.request_canonical_hash.clone(),
        policy_server_id: policy_server_id.clone(),
    };

    // Frontier hashes: round-4 wire shape MUST surface these even when
    // coauth doesn't yet plumb the real soland frontiers through.
    // `TODO(round4-policy-check-frontier-source)` — until soland ships
    // the federation-peer frontier_root response we emit the empty
    // sha256 digest, which downstream verifiers MUST recognise as the
    // "unknown frontier" sentinel.
    let empty = empty_sha256_digest();
    let auth_state_hash = empty.clone();
    let policy_frontier_hash = empty.clone();
    let membership_frontier_hash = empty;

    // Signing transcript. Round 4 wire requires the signature kid to
    // be a DID URL (`^did:[a-z0-9]+:[^\s]+#.+$`). We use the keystore's
    // preferred public key's kid as the `#fragment` component.
    let kid_fragment = preferred_signing_kid_fragment(key_store).unwrap_or_else(|| "key-1".into());
    let kid = format!("{policy_server_did}#{kid_fragment}");

    // TODO(round4-policy-check-signing-transcript): replace this stub
    // digest with a proper detached signature over canonical_json of
    // the `(bound_to, decision, *_hash)` tuple under the keystore's
    // preferred private key.
    let sig = stub_decision_signature(
        &policy_server_did,
        &bound_to,
        &decision,
        &auth_state_hash,
        &policy_frontier_hash,
        &membership_frontier_hash,
    );

    Ok(PolicyCheckResponse {
        decision,
        bound_to,
        auth_state_hash,
        policy_frontier_hash,
        membership_frontier_hash,
        signature: PolicyCheckSignature { kid, sig },
        reason_code: None,
        expires_at: Some(Utc::now() + chrono::Duration::seconds(60)),
        obligations: Vec::new(),
    })
}

fn empty_sha256_digest() -> Hash {
    // sha256("") canonical form, used as the "unknown frontier" sentinel.
    let digest = sha2::Sha256::new().finalize();
    Hash::new(format!("sha256:{}", hex::encode(digest))).expect("sha256:<hex64> is a valid Hash")
}

fn preferred_signing_kid_fragment(key_store: &Keystore) -> Option<String> {
    use coauth_jose::constraints::Constrainable as _;
    contrix::preferred_public_signing_key(key_store)
        .and_then(|jwk| jwk.kid().map(ToOwned::to_owned))
}

fn stub_decision_signature(
    policy_server_did: &str,
    bound_to: &PolicyCheckBoundTo,
    decision: &AuthzDecision,
    auth_state_hash: &Hash,
    policy_frontier_hash: &Hash,
    membership_frontier_hash: &Hash,
) -> String {
    // Build a deterministic stub digest so test vectors are stable.
    // Downstream verifiers MUST NOT trust this — see the TODO.
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"cx.policy.check.v1\n");
    hasher.update(policy_server_did.as_bytes());
    hasher.update(b"\n");
    hasher.update(bound_to.realm_id.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(bound_to.actor.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(bound_to.action.as_bytes());
    hasher.update(b"\n");
    hasher.update(bound_to.request_canonical_hash.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(format!("{decision:?}").as_bytes());
    hasher.update(b"\n");
    hasher.update(auth_state_hash.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(policy_frontier_hash.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(membership_frontier_hash.as_str().as_bytes());
    let out = hasher.finalize();
    format!("stub-round4:{}", hex::encode(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_core::{PolicyCheckSource, RealmId};

    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn req() -> PolicyCheckRequest {
        PolicyCheckRequest {
            request_id: "req-1".into(),
            realm_id: realm(),
            actor: Did::new("did:web:alice.example").unwrap(),
            action: "cx.message.create".into(),
            request_canonical_hash: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            source: PolicyCheckSource {
                service_did: Did::new("did:web:soland.example").unwrap(),
                service_type: "principal_server".into(),
            },
            source_ip_hash: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            signed_transport: serde_json::json!({"signature": "stub"}),
            event_preview: serde_json::Value::Null,
            auth_context: serde_json::Value::Null,
        }
    }

    #[test]
    fn empty_sha256_digest_is_canonical_sentinel() {
        let h = empty_sha256_digest();
        // sha256("") canonical hex.
        assert_eq!(
            h.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn stub_decision_signature_is_deterministic() {
        let r = req();
        let bound = PolicyCheckBoundTo {
            realm_id: r.realm_id.clone(),
            actor: r.actor.clone(),
            action: r.action.clone(),
            request_canonical_hash: r.request_canonical_hash.clone(),
            policy_server_id: Did::new("did:web:auth.example").unwrap(),
        };
        let e = empty_sha256_digest();
        let s1 = stub_decision_signature(
            "did:web:auth.example",
            &bound,
            &AuthzDecision::Allow,
            &e,
            &e,
            &e,
        );
        let s2 = stub_decision_signature(
            "did:web:auth.example",
            &bound,
            &AuthzDecision::Allow,
            &e,
            &e,
            &e,
        );
        assert_eq!(s1, s2);
        assert!(s1.starts_with("stub-round4:"));
    }

    #[test]
    fn stub_signature_changes_with_decision() {
        let r = req();
        let bound = PolicyCheckBoundTo {
            realm_id: r.realm_id.clone(),
            actor: r.actor.clone(),
            action: r.action.clone(),
            request_canonical_hash: r.request_canonical_hash.clone(),
            policy_server_id: Did::new("did:web:auth.example").unwrap(),
        };
        let e = empty_sha256_digest();
        let allow = stub_decision_signature(
            "did:web:auth.example",
            &bound,
            &AuthzDecision::Allow,
            &e,
            &e,
            &e,
        );
        let deny = stub_decision_signature(
            "did:web:auth.example",
            &bound,
            &AuthzDecision::Deny,
            &e,
            &e,
            &e,
        );
        assert_ne!(allow, deny);
    }
}
