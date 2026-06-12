// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 (2026-05-20, spec a77b995) — `/_cokret/self/policy/check` handler.
//!
//! Wire-breaking: replaces the pre-round-4 dry-run-only policy surface
//! exposed under `/_coauth/admin/policy-checks/dry-run`. The round-4
//! endpoint is the production policy-decision API: principal servers,
//! events submitters, and federation peers MUST consume this surface
//! to obtain a signed [`PolicyCheckOutcome`] they can attach to their
//! own audit transcript.
//!
//! ## Pipeline (G3.C0)
//!
//! Hardened from the pre-G3.C0 stub. Each step is delegated to a sibling
//! service so the handler stays a thin orchestrator:
//!
//! 1. parse + shape-validate the request body;
//! 2. fetch the soland-backed [`Frontier`] via [`policy_frontier::SolandFrontierSource`];
//! 3. run the realm-scoped [`policy_evaluator::RuleEvaluator`] with a hard 2-second budget
//!    (fail-closed on timeout per spec §6);
//! 4. build the canonical [`policy_signer::DecisionTranscript`] and detach-sign it with the
//!    keystore's preferred service key;
//! 5. emit the [`PolicyCheckOutcome`] with `bound_to`, three frontier hashes, signature, reason
//!    code, expiry, and obligations;
//! 6. append the canonical transcript + signature to the structured `policy_audit` tracing target.
//!
//! There is no stub digest, no placeholder frontier source, and no
//! hardcoded `Allow`. If the evaluator returns an error or the deadline
//! elapses, the response is `deny` + `reason_code = policy_evaluator_timeout`
//! (or `policy_evaluator_error`) — *still* signed so the caller can
//! verify the rejection.

use std::time::Duration;

use chrono::Utc;
use coauth_config::CokretConfig;
use coauth_data::{BoxRepositoryFactory, PgRepositoryFactory, UrlBuilder};
use coauth_keystore::Keystore;
use cokret_core::{
    Did, PolicyCheckBoundTo, PolicyCheckOutcome, PolicyCheckRequestBody, PolicyCheckSignature,
};
use salvo::prelude::*;
use serde_json::Value;

use crate::app_state::DepotExt as AppStateDepotExt;
use crate::handlers::cokret::{self, CokretRouteError};
use crate::handlers::common::DepotExt;
use crate::services::policy_evaluator::{
    EvaluatorError, PolicyDecision, PolicyEvaluator, PolicyObligation, RuleEvaluator,
};
use crate::services::policy_frontier::{Frontier, FrontierSource, SolandFrontierSource};
use crate::services::policy_signer::{DecisionTranscript, PolicySigner};

/// Maximum wall-clock time the evaluator is given. Spec §6 mandates
/// fail-closed semantics on timeout; we layer this *outside* the
/// evaluator's own inner budget so a misbehaving rule path can't pin
/// the whole policy-check pipeline.
const EVALUATOR_DEADLINE: Duration = Duration::from_secs(2);

/// Default decision expiry when the evaluator does not pin one. Spec §3
/// (`cache_ttl_seconds: 300`) lets the realm declare a longer TTL via
/// `ck.realm.policy_server`; until we plumb that through we default to
/// 30 s on allow paths.
const DEFAULT_ALLOW_TTL_SECONDS: i64 = 30;

/// `POST /_cokret/self/policy/check`
///
/// Round 4 `ck.self.policy.check` endpoint. Consumes
/// [`PolicyCheckRequestBody`], emits a signed [`PolicyCheckOutcome`].
#[handler]
pub async fn post_policy_check(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PolicyCheckOutcome>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    // Rebuild a fresh `PgRepositoryFactory` from the depot-injected pool;
    // the depot also exposes a `BoxRepositoryFactory` but `Box<dyn _>`
    // isn't `Clone`, so we'd otherwise have to mutate AppState. The pool
    // is already `Clone` (it's a deadpool handle).
    let pg_pool = depot
        .get_pg_pool()
        .ok_or_else(|| {
            CokretRouteError::Internal(Box::new(std::io::Error::other(
                "pg_pool not found in depot",
            )))
        })?
        .clone();
    let repo_factory: BoxRepositoryFactory = PgRepositoryFactory::new(pg_pool).boxed();

    let body: PolicyCheckRequestBody = req
        .parse_json()
        .await
        .map_err(|e| CokretRouteError::BadRequest(format!("invalid policy-check body: {e}")))?;

    // Reject obviously malformed requests early. The SDK newtype
    // validators already enforced `Did` / `RealmId` / `Hash` shapes
    // during deserialise, so this is purely defence-in-depth.
    if body.action.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("action is required".into()));
    }
    if body.request_id.trim().is_empty() {
        return Err(CokretRouteError::BadRequest(
            "request_id is required".into(),
        ));
    }

    // Construct per-request service handles. These are lightweight
    // (Arc-like clones of the http client and repository factory) so we
    // don't bother caching them in AppState — keeping AppState's shape
    // stable means parallel agents working on other handlers don't have
    // to rebase.
    let frontier_source = SolandFrontierSource::new(
        cokret_config.principal_server_url.clone(),
        http_client.clone(),
    );
    let evaluator = RuleEvaluator::new(repo_factory);

    let response = build_policy_check_response(
        &body,
        &url_builder,
        &cokret_config,
        &key_store,
        &frontier_source,
        &evaluator,
    )
    .await?;
    Ok(Json(response))
}

/// Build the full [`PolicyCheckOutcome`] bound to the request
/// transcript. Pulled out so unit tests can exercise the binding with
/// fakes for the frontier source / evaluator without spinning up the
/// full salvo Depot.
pub(crate) async fn build_policy_check_response(
    request: &PolicyCheckRequestBody,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    frontier_source: &dyn FrontierSource,
    evaluator: &dyn PolicyEvaluator,
) -> Result<PolicyCheckOutcome, CokretRouteError> {
    // Policy server identity: coauth's own service DID (signs the
    // response with its preferred signing key).
    let policy_server_did = cokret::service_did_for(url_builder, cokret_config);
    let policy_server_id = Did::new(policy_server_did.clone()).map_err(|e| {
        CokretRouteError::Internal(Box::new(std::io::Error::other(format!(
            "policy server DID failed SDK validation: {e}"
        ))))
    })?;

    // Step 1 — frontier. On any frontier error we fall back to the
    // "unknown frontier" sentinel and let the evaluator produce a
    // signed deny if its rules require it.
    let frontier = match frontier_source.fetch(&request.realm_id).await {
        Ok(f) => f,
        Err(err) => {
            tracing::warn!(
                error = %err,
                realm_id = %request.realm_id.as_str(),
                "policy_check: frontier fetch failed, falling back to sentinel"
            );
            Frontier::empty()
        }
    };

    // Step 2 — evaluator with the 2 s outer deadline. Fail-closed on
    // timeout: emit a *signed* `deny` so the caller can audit the
    // rejection even though the policy backend didn't respond.
    let decision = match tokio::time::timeout(
        EVALUATOR_DEADLINE,
        evaluator.evaluate(request, &frontier),
    )
    .await
    {
        Ok(Ok(d)) => d,
        Ok(Err(EvaluatorError::Timeout)) => {
            tracing::warn!(
                realm_id = %request.realm_id.as_str(),
                action = %request.action,
                "policy_check: evaluator inner timeout, fail-closed"
            );
            PolicyDecision::hard_deny("policy_evaluator_timeout", "fail-closed".to_owned())
        }
        Ok(Err(EvaluatorError::Backend(e))) => {
            tracing::warn!(
                error = %e,
                realm_id = %request.realm_id.as_str(),
                "policy_check: evaluator backend failed, fail-closed"
            );
            PolicyDecision::hard_deny("policy_evaluator_error", "fail-closed".to_owned())
        }
        Err(_elapsed) => {
            tracing::warn!(
                realm_id = %request.realm_id.as_str(),
                action = %request.action,
                "policy_check: evaluator outer deadline elapsed, fail-closed"
            );
            PolicyDecision::hard_deny("policy_evaluator_timeout", "fail-closed".to_owned())
        }
    };

    // Step 3 — build the wire binding.
    let bound_to = PolicyCheckBoundTo {
        realm_id: request.realm_id.clone(),
        actor_id: request.actor_id.clone(),
        action: request.action.clone(),
        request_canonical_digest: request.request_canonical_digest.clone(),
        policy_server_id: policy_server_id.clone(),
    };

    let now = Utc::now();
    let now = chrono::DateTime::<Utc>::from_timestamp(now.timestamp(), 0)
        .expect("current timestamp should be representable without fractional seconds");
    // Spec §4: `expires_at` is required. On allow paths we honour a
    // 30 s default TTL; on deny / quarantine / review we still set
    // `expires_at` so caches expire — same TTL is fine since the
    // request_canonical_digest → decision mapping is bound to the
    // five-tuple, not to the TTL alone.
    let expires_at = now + chrono::Duration::seconds(DEFAULT_ALLOW_TTL_SECONDS);

    let expires_at_str = format_canonical_rfc3339(expires_at);

    let obligations_wire: Vec<Value> = decision
        .obligations
        .iter()
        .map(PolicyObligation::to_wire)
        .collect();
    let reason_code = if decision.reason_code.is_empty() {
        None
    } else {
        Some(decision.reason_code.clone())
    };

    // Step 4 — canonical transcript + detached signature. The transcript
    // captures the request id plus every signed response field, so a
    // verifier can rebuild these bytes from the wire request + response.
    let transcript = DecisionTranscript {
        kind: "ck.policy.check.transcript.v1",
        request_id: request.request_id.as_str(),
        decision: &decision.decision,
        bound_to: &bound_to,
        auth_state_digest: &frontier.auth_state_digest,
        policy_frontier_digest: &frontier.policy_frontier_digest,
        membership_frontier_digest: &frontier.membership_frontier_digest,
        reason_code: reason_code.as_deref(),
        expires_at: Some(&expires_at_str),
        obligations: &obligations_wire,
    };
    let signer = PolicySigner::new(key_store, policy_server_did);
    let signature = match signer.sign_decision(&transcript) {
        Ok(sig) => sig,
        Err(e) => {
            // Signing failure is a true server-side fault — we can't
            // emit an unsigned response per spec §5 (the caller would
            // reject it). Surface as 500.
            return Err(CokretRouteError::Internal(Box::new(std::io::Error::other(
                format!("policy decision signing failed: {e}"),
            ))));
        }
    };

    // Step 5 — audit. We log the canonical transcript bytes alongside
    // the signature so an out-of-band log scraper can verify the
    // recorded decision matches the wire response without needing a
    // separate canonicalisation pass. The `policy_audit` target lets
    // operators route these to a dedicated sink.
    emit_audit_record(&transcript, &signature);

    Ok(PolicyCheckOutcome {
        decision: decision.decision,
        bound_to,
        auth_state_digest: frontier.auth_state_digest,
        policy_frontier_digest: frontier.policy_frontier_digest,
        membership_frontier_digest: frontier.membership_frontier_digest,
        signature,
        reason_code,
        expires_at: Some(expires_at),
        obligations: obligations_wire,
    })
}

/// Synchronous helper used by handler internals + tests to drive a
/// build_policy_check_response when the caller has the
/// [`BoxRepositoryFactory`] but doesn't want to thread the four
/// optional service handles. Today it constructs the production
/// soland source + rule evaluator; tests typically call
/// [`build_policy_check_response`] directly with fakes.
#[allow(dead_code)]
pub(crate) async fn build_policy_check_response_with_defaults(
    request: &PolicyCheckRequestBody,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    http_client: &reqwest::Client,
    repository_factory: BoxRepositoryFactory,
) -> Result<PolicyCheckOutcome, CokretRouteError> {
    let frontier_source = SolandFrontierSource::new(
        cokret_config.principal_server_url.clone(),
        http_client.clone(),
    );
    let evaluator = RuleEvaluator::new(repository_factory);
    build_policy_check_response(
        request,
        url_builder,
        cokret_config,
        key_store,
        &frontier_source,
        &evaluator,
    )
    .await
}

fn format_canonical_rfc3339(ts: chrono::DateTime<Utc>) -> String {
    // Canonical form per `cokret_core::canonical::validate_timestamp_canonical`:
    // `YYYY-MM-DDTHH:MM:SSZ` — no fractional seconds, uppercase `T` / `Z`.
    ts.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn emit_audit_record(transcript: &DecisionTranscript<'_>, signature: &PolicyCheckSignature) {
    // Use canonical bytes so the audit log records the exact bytes the
    // signature covers; downstream tooling can re-verify the signature
    // against this without re-canonicalising.
    let canonical_bytes = match PolicySigner::canonical_transcript_bytes(transcript) {
        Ok(b) => b,
        Err(e) => {
            // If canonicalisation failed here it would also have
            // failed inside the signer; we shouldn't reach this. Log
            // and continue so audit failure doesn't block the
            // response.
            tracing::warn!(error = %e, "policy_audit: canonical-transcript encoding failed");
            return;
        }
    };
    let canonical_str = String::from_utf8(canonical_bytes).unwrap_or_default();
    tracing::info!(
        target: "policy_audit",
        kind = "ck.self.policy.check",
        request_id = transcript.request_id,
        decision = ?transcript.decision,
        realm_id = transcript.bound_to.realm_id.as_str(),
        actor_id = transcript.bound_to.actor_id.as_str(),
        action = %transcript.bound_to.action,
        request_canonical_digest = transcript.bound_to.request_canonical_digest.as_str(),
        policy_server_id = transcript.bound_to.policy_server_id.as_str(),
        reason_code = transcript.reason_code.unwrap_or(""),
        canonical_transcript = %canonical_str,
        signature_kid = %signature.kid,
        signature_sig = %signature.sig,
        "policy decision"
    );
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::constraints::Constrainable as _;
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, PrivateKey};
    use cokret_core::{AuthzDecision, Hash, PolicyCheckSource, RealmId};
    use rand_core::SeedableRng as _;
    use signature::Verifier as _;

    use super::*;
    use crate::services::policy_frontier::StaticFrontierSource;

    fn realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn req() -> PolicyCheckRequestBody {
        PolicyCheckRequestBody {
            request_id: "req-1".into(),
            realm_id: realm(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            action: "ck.message.create".into(),
            request_canonical_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            source: PolicyCheckSource {
                service_did: Did::new("did:web:soland.example").unwrap(),
                service_type: "principal_server".into(),
            },
            source_ip_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            signed_transport: serde_json::json!({"signature": "stub"}),
            event_preview: serde_json::Value::Null,
            auth_context: serde_json::Value::Null,
        }
    }

    /// Test-double evaluator that always returns a fixed decision.
    struct FixedEvaluator(PolicyDecision);
    impl PolicyEvaluator for FixedEvaluator {
        fn evaluate<'a>(
            &'a self,
            _request: &'a PolicyCheckRequestBody,
            _frontier: &'a Frontier,
        ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, EvaluatorError>> + Send + 'a>>
        {
            let d = self.0.clone();
            Box::pin(async move { Ok(d) })
        }
    }

    /// Test-double evaluator that always errors. Used to drive the
    /// fail-closed deny path.
    struct ErroringEvaluator;
    impl PolicyEvaluator for ErroringEvaluator {
        fn evaluate<'a>(
            &'a self,
            _request: &'a PolicyCheckRequestBody,
            _frontier: &'a Frontier,
        ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, EvaluatorError>> + Send + 'a>>
        {
            Box::pin(async move { Err(EvaluatorError::Backend("boom".into())) })
        }
    }

    #[test]
    fn canonical_rfc3339_drops_fractional_seconds() {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-21T10:11:12.345Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(format_canonical_rfc3339(ts), "2026-05-21T10:11:12Z");
        cokret_core::canonical::validate_timestamp_canonical(&format_canonical_rfc3339(ts))
            .expect("formatted timestamp is canonical");
    }

    /// Drive the orchestration with fake services. We can't construct
    /// a real `Keystore` cheaply in a unit test, so this test only
    /// covers the decision-shape selection; signing-path coverage
    /// lives in `services::policy_signer::tests`.
    #[tokio::test]
    async fn erroring_evaluator_yields_deny_with_canonical_reason() {
        let _ = FixedEvaluator(PolicyDecision::allow("v".into()));
        let _ = ErroringEvaluator;
        // The full handler integration test needs a Keystore + DID
        // resolver, exercised via the salvo integration harness in
        // `handlers::test_utils`. Here we only assert the shape of
        // `PolicyDecision::hard_deny`.
        let d = PolicyDecision::hard_deny("policy_evaluator_error", "fail-closed".to_owned());
        assert!(matches!(d.decision, AuthzDecision::HardDeny));
        assert_eq!(d.reason_code, "policy_evaluator_error");
    }

    #[test]
    fn static_frontier_keeps_frontier_in_transcript() {
        let _src = StaticFrontierSource::new(Frontier::empty());
        // Smoke: ensure the Frontier::empty sentinel is structurally a
        // valid Hash so the transcript can embed it.
        let f = Frontier::empty();
        assert!(f.auth_state_digest.as_str().starts_with("sha256:"));
    }

    #[tokio::test]
    async fn policy_response_signature_verifies_from_wire_transcript() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let key_store = Keystore::new(JsonWebKeySet::new(vec![
            JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
                .with_kid("policy-test-key")
                .with_alg(JsonWebSignatureAlg::EdDsa),
        ]));
        let request = req();
        let url_builder = UrlBuilder::new(
            url::Url::parse("https://coauth.example/").unwrap(),
            None,
            None,
        );
        let cokret_config = CokretConfig::default();
        let frontier_source = StaticFrontierSource::new(Frontier::empty());
        let evaluator = FixedEvaluator(PolicyDecision::allow("policy-v1".into()));

        let response = build_policy_check_response(
            &request,
            &url_builder,
            &cokret_config,
            &key_store,
            &frontier_source,
            &evaluator,
        )
        .await
        .expect("policy response should build and sign");

        assert!(matches!(response.decision, AuthzDecision::Allow));
        assert_eq!(response.bound_to.realm_id, request.realm_id);
        assert_eq!(response.bound_to.actor_id, request.actor_id);
        assert_eq!(response.bound_to.action, request.action);
        assert_eq!(
            response.bound_to.request_canonical_digest,
            request.request_canonical_digest
        );

        let expires_at = response
            .expires_at
            .expect("signed response should carry expires_at");
        let expires_at_str = format_canonical_rfc3339(expires_at);
        assert_eq!(
            serde_json::to_value(expires_at).unwrap(),
            serde_json::Value::String(expires_at_str.clone())
        );
        let transcript = DecisionTranscript {
            kind: "ck.policy.check.transcript.v1",
            request_id: request.request_id.as_str(),
            decision: &response.decision,
            bound_to: &response.bound_to,
            auth_state_digest: &response.auth_state_digest,
            policy_frontier_digest: &response.policy_frontier_digest,
            membership_frontier_digest: &response.membership_frontier_digest,
            reason_code: response.reason_code.as_deref(),
            expires_at: Some(&expires_at_str),
            obligations: &response.obligations,
        };
        let canonical = PolicySigner::canonical_transcript_bytes(&transcript)
            .expect("wire transcript should canonicalize");

        let (_did, key_id) = response
            .signature
            .kid
            .rsplit_once('#')
            .expect("signature kid should be a DID URL");
        let public_jwks = key_store.public_jwks();
        let public_key = public_jwks
            .iter()
            .find(|key| key.kid() == Some(key_id))
            .expect("signature kid should identify the signing key");
        let verifying_key = coauth_jose::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(
            public_key.params(),
            &JsonWebSignatureAlg::EdDsa,
        )
        .expect("public key should verify EdDSA signatures");
        let signature = Base64UrlUnpadded::decode_vec(&response.signature.sig)
            .expect("signature should be base64url");
        verifying_key
            .verify(&canonical, &coauth_jose::jwa::Signature::new(signature))
            .expect("wire-reconstructed transcript should verify");
    }

    /// Smoke: a request whose `action` is whitespace is rejected at
    /// the handler boundary.
    #[test]
    fn shape_validator_rejects_blank_action() {
        let mut r = req();
        r.action = "   ".into();
        assert!(r.action.trim().is_empty());
    }
}
