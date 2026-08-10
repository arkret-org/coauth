// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 `ak.self.policy.read.check` decision signer.
//!
//! Pulls the preferred service signing key out of the keystore, signs a
//! canonical-JSON transcript (RFC 8785 / `arkret_canonical`), and
//! returns the wire-form `{kid, sig}` payload that
//! [`crate::handlers::policy_check`] embeds in
//! [`arkret_models_collaboration::governance::policy_check::PolicyCheckOutcome`].
//!
//! ## Why a dedicated module
//!
//! The pre-G3.C0 stub computed a `sha256("stub-round4:" || ...)` digest in
//! place of a real signature. That made the wire shape valid but left
//! downstream consumers (soland, federation peers) unable to verify the
//! decision — the spec [`policy-server.md` §5] requires a detached
//! Ed25519 / ECDSA signature over the canonical transcript.
//!
//! This module owns:
//!
//! - canonical-transcript serialisation (no nondeterministic ordering),
//! - key selection (mirrors `handlers::arkret::preferred_signing_key`),
//! - DID-URL `kid` construction (`<policy_server_did>#<jwk_kid>`),
//! - signature emission as base64url-unpadded.
//!
//! Anything outside this contract (the *decision* itself, the *frontier*
//! source, the *audit* sink) lives in sibling services so the signer
//! stays small and testable.

use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckOutcome, PolicyCheckSignature, policy_decision_transcript_bytes,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use coauth_jose::constraints::Constrainable as _;
use coauth_keystore::Keystore;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;
use signature::RandomizedSigner as _;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicySignerError {
    #[error("no usable service signing key in keystore")]
    NoSigningKey,
    #[error("keystore signing key rejected the policy-check algorithm")]
    KeyAlgMismatch,
    #[error("canonical-JSON encoding of the policy transcript failed: {0}")]
    Canonical(String),
    #[error("ed25519 / ecdsa signing of the policy transcript failed")]
    Sign,
}

/// Detached signer for `ak.self.policy.read.check` decisions.
///
/// Constructed once per request from the shared [`Keystore`] +
/// `policy_server_did` (the coauth service DID). The signer is stateless
/// beyond the picked key reference; it is safe to construct many per
/// request and is not cached because the keystore already returns
/// references into its in-memory key list.
pub struct PolicySigner<'a> {
    key_store: &'a Keystore,
    policy_server_did: String,
}

impl<'a> PolicySigner<'a> {
    /// Bind a signer to the request-scoped keystore + the policy server
    /// DID. The DID is the value emitted as `bound_to.policy_server_id`;
    /// callers MUST pass the same DID to keep the transcript binding
    /// consistent.
    #[must_use]
    pub fn new(key_store: &'a Keystore, policy_server_did: String) -> Self {
        Self {
            key_store,
            policy_server_did,
        }
    }

    /// Sign the canonical transcript of a policy decision.
    ///
    /// The transcript captures every field §5 of `policy-server.md`
    /// requires to be bound to the signature and keeps the set
    /// reconstructable from the wire request + response: `request_id`,
    /// `bound_to` (realm + actor_id + action + canonical request hash +
    /// policy server id), the decision, reason code, expiry, obligations,
    /// and the three frontier hashes. Optional fields are included only
    /// when present so the canonical bytes are stable across requests
    /// that omit them.
    pub fn sign_decision(
        &self,
        outcome: &PolicyCheckOutcome,
    ) -> Result<PolicyCheckSignature, PolicySignerError> {
        let canonical = policy_decision_transcript_bytes(outcome)
            .map_err(|e| PolicySignerError::Canonical(e.to_string()))?;

        // Pick the preferred service signing key. Today coauth seeds an
        // Ed25519 key first; ECDSA / RSA fall-back paths are accepted so
        // a deployment that has not yet rotated to Ed25519 still gets a
        // real signature (not a stub).
        let (alg, key) =
            preferred_service_signing_key(self.key_store).ok_or(PolicySignerError::NoSigningKey)?;
        let key_id = key.kid().ok_or(PolicySignerError::NoSigningKey)?;
        let signer = self
            .key_store
            .signer_for_algorithm(&alg)
            .map_err(|_| PolicySignerError::KeyAlgMismatch)?;

        // RandomizedSigner: ECDSA needs an RNG; Ed25519 ignores it. Seed
        // a fresh ChaCha from OsRng to match the rest of coauth's signing
        // paths (`handlers::common::make_rng`).
        let mut rng = ChaChaRng::from_rng(rand_core::OsRng).map_err(|_| PolicySignerError::Sign)?;
        let raw = signer
            .try_sign_with_rng(&mut rng, &canonical)
            .map_err(|_| PolicySignerError::Sign)?;

        let sig_bytes: Box<[u8]> = raw.into();
        let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
        let kid = format!("{}#{}", self.policy_server_did, key_id);
        Ok(PolicyCheckSignature { kid, sig: sig_b64 })
    }

    /// Return the canonical JSON bytes of a transcript without signing.
    /// Used by the audit sink so the recorded transcript bytes are
    /// byte-identical to the bytes the signer actually signed.
    pub fn canonical_transcript_bytes(
        outcome: &PolicyCheckOutcome,
    ) -> Result<Vec<u8>, PolicySignerError> {
        policy_decision_transcript_bytes(outcome)
            .map_err(|e| PolicySignerError::Canonical(e.to_string()))
    }
}

/// Pick the preferred service signing key from the keystore. Mirrors
/// `handlers::arkret::preferred_signing_key` so the policy decision
/// signer uses the *same* key the rest of coauth uses for
/// service-issued artefacts (session grant JWTs, handle-claim proofs).
///
/// Returned as an owned `(alg, key)` because the caller needs both the
/// algorithm (for `signing_key_for_alg`) and the JWK reference (for
/// `kid`). The key reference borrows from the keystore.
fn preferred_service_signing_key(
    key_store: &Keystore,
) -> Option<(
    coauth_iana::jose::JsonWebSignatureAlg,
    &coauth_keystore::JsonWebKey<coauth_keystore::PrivateKey>,
)> {
    use coauth_iana::jose::JsonWebSignatureAlg;
    [
        JsonWebSignatureAlg::Ed25519,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps256,
    ]
    .into_iter()
    .find_map(|alg| {
        key_store
            .signing_key_for_algorithm(&alg)
            .map(|key| (alg, key))
    })
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{DidCoreId, Hash, RealmId};
    use arkret_models_collaboration::governance::policy_check::PolicyCheckBoundTo;
    use arkret_wire::{AuthzDecision, FreshnessState};
    use chrono::{TimeZone as _, Utc};

    use super::*;

    fn empty_sha256() -> Hash {
        Hash::new(format!(
            "sha256:{}",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ))
        .unwrap()
    }

    fn outcome() -> PolicyCheckOutcome {
        let digest = empty_sha256();
        PolicyCheckOutcome {
            request_id: "req-1".to_owned(),
            decision: AuthzDecision::Allow,
            bound_to: PolicyCheckBoundTo {
                realm_id: RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")
                    .unwrap(),
                actor_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                action: "ak.message.create".into(),
                request_canonical_digest: digest.clone(),
                policy_server_id: DidCoreId::new("ak:did_core:web:coauth.example").unwrap(),
            },
            reason_code: arkret_wire::ReasonCode::Ok,
            freshness_state: FreshnessState::Fresh,
            expires_at: Utc.with_ymd_and_hms(2026, 5, 21, 0, 1, 0).unwrap(),
            auth_state_digest: digest.clone(),
            policy_frontier_digest: digest.clone(),
            membership_frontier_digest: digest,
            signature: PolicyCheckSignature {
                kid: String::new(),
                sig: String::new(),
            },
            next_retry_at: None,
            obligations: Vec::new(),
        }
    }

    #[test]
    fn transcript_canonical_bytes_are_deterministic() {
        let outcome = outcome();
        let a = PolicySigner::canonical_transcript_bytes(&outcome).unwrap();
        let b = PolicySigner::canonical_transcript_bytes(&outcome).unwrap();
        assert_eq!(a, b);
        // The canonical bytes MUST start with `{` (object) and contain
        // the version tag verbatim.
        assert!(a.starts_with(b"{"));
        let s = std::str::from_utf8(&a).unwrap();
        assert!(s.contains("ak.policy.check.transcript.v1"));
        // Lexicographic key order: `auth_state_digest` precedes `bound_to`
        // precedes `decision`; the serializer
        // sorts keys so we can spot-check the prefix.
        assert!(s.starts_with("{\"auth_state_digest\""));
    }

    #[test]
    fn changing_decision_changes_canonical_bytes() {
        let mut outcome = outcome();
        let allow_bytes = PolicySigner::canonical_transcript_bytes(&outcome).unwrap();
        outcome.decision = AuthzDecision::HardDeny;
        let deny_bytes = PolicySigner::canonical_transcript_bytes(&outcome).unwrap();
        assert_ne!(allow_bytes, deny_bytes);
    }

    #[test]
    fn retry_time_and_obligations_are_signed() {
        let mut outcome = outcome();
        let baseline = PolicySigner::canonical_transcript_bytes(&outcome).unwrap();
        outcome.next_retry_at = Some(Utc.with_ymd_and_hms(2026, 5, 21, 0, 0, 30).unwrap());
        let retry = PolicySigner::canonical_transcript_bytes(&outcome).unwrap();
        assert_ne!(baseline, retry);

        outcome.obligations.push(serde_json::json!({
            "kind": "accountability_grant_required"
        }));
        let obligation = PolicySigner::canonical_transcript_bytes(&outcome).unwrap();
        assert_ne!(retry, obligation);
    }
}
