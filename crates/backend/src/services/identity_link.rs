// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 (2026-05-20, spec a77b995) — Realm-scoped `identity_link`
//! payload.
//!
//! Wire-breaking: identity-link payloads are now scoped to
//! `(realm_id, trust_domain)`. A link minted in realm A / trust_domain
//! X MUST NOT be replayable in realm B or trust_domain Y. The
//! encrypted payload's canonical signing transcript includes both
//! identifiers so receivers can detect scope mismatch *before*
//! decrypting.
//!
//! The encrypted payload itself remains opaque on the wire — coauth
//! only knows the realm + trust_domain binding, not the plaintext
//! material. End-to-end decryption happens at the claimant device.
//!
//! ## Why both realm_id and trust_domain?
//!
//! - `realm_id` scopes the link to a single Realm policy graph: a link valid for `ak:realm:r1` MUST
//!   NOT enable joining `ak:realm:r2`.
//! - `trust_domain` scopes the link to a deployment: a link minted in `ak:trust_domain:tenant-a`
//!   MUST NOT be replayable into `ak:trust_domain:tenant-b` even when the realm UUID happens to
//!   collide (e.g. dev / staging / prod sharing a fixture realm).
//!
//! See `arkret-spec` round-4 §7fae9ba "Enhance third-party invites +
//! transport bindings" — the same dual-scoping rule applies here.

use chrono::{DateTime, Utc};
use arkret_core::{RealmId, TypedTrustDomainId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Round 4 identity-link envelope. Payload is opaque on the wire
/// (encrypted under the recipient's key), and the *scope* fields
/// `realm_id` + `trust_domain` are the only plaintext bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLinkEnvelope {
    /// Realm the link is valid within. Replays into a different realm
    /// MUST be rejected.
    pub realm_id: RealmId,
    /// Trust domain (deployment scope) the link is valid within.
    /// Replays across trust domains MUST be rejected, even when
    /// `realm_id` happens to collide.
    pub trust_domain: TypedTrustDomainId,
    /// Opaque ciphertext bytes (base64url-encoded on the wire). The
    /// recipient device decrypts with the link's ephemeral key; coauth
    /// never sees the plaintext.
    pub encrypted_payload: String,
    /// Wall-clock expiry; receivers MUST reject after this.
    pub expires_at: DateTime<Utc>,
}

/// Errors raised when validating an inbound `IdentityLinkEnvelope`.
#[derive(Debug, Error)]
pub enum IdentityLinkError {
    #[error("identity_link realm_id mismatch: expected {expected}, got {actual}")]
    RealmMismatch { expected: String, actual: String },
    #[error("identity_link trust_domain mismatch: expected {expected}, got {actual}")]
    TrustDomainMismatch { expected: String, actual: String },
    #[error("identity_link has expired (now={now:?}, expires_at={expires_at:?})")]
    Expired {
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    #[error("identity_link encrypted_payload is empty")]
    EmptyPayload,
}

impl IdentityLinkEnvelope {
    /// Validate the envelope against the receiver's expected realm,
    /// trust domain, and wall-clock. **Returns the validated borrow on
    /// success — callers MUST then hand the `encrypted_payload` to the
    /// device for decryption.** Coauth itself does not decrypt.
    pub fn validate_for_recipient(
        &self,
        expected_realm: &RealmId,
        expected_trust_domain: &TypedTrustDomainId,
        now: DateTime<Utc>,
    ) -> Result<&Self, IdentityLinkError> {
        if self.realm_id != *expected_realm {
            return Err(IdentityLinkError::RealmMismatch {
                expected: expected_realm.as_str().to_owned(),
                actual: self.realm_id.as_str().to_owned(),
            });
        }
        if self.trust_domain != *expected_trust_domain {
            return Err(IdentityLinkError::TrustDomainMismatch {
                expected: expected_trust_domain.as_str().to_owned(),
                actual: self.trust_domain.as_str().to_owned(),
            });
        }
        if self.encrypted_payload.is_empty() {
            return Err(IdentityLinkError::EmptyPayload);
        }
        if now > self.expires_at {
            return Err(IdentityLinkError::Expired {
                now,
                expires_at: self.expires_at,
            });
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn realm(s: &str) -> RealmId {
        RealmId::new(s).unwrap()
    }
    fn td(s: &str) -> TypedTrustDomainId {
        TypedTrustDomainId::new(s).unwrap()
    }
    fn envelope() -> IdentityLinkEnvelope {
        IdentityLinkEnvelope {
            realm_id: realm("ak:realm:01904100-0000-7000-8000-000000000001"),
            trust_domain: td("ak:trust_domain:example.net"),
            encrypted_payload: "ct-bytes".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
        }
    }

    #[test]
    fn accepts_matching_realm_and_trust_domain() {
        let env = envelope();
        let now = Utc::now();
        env.validate_for_recipient(&env.realm_id.clone(), &env.trust_domain.clone(), now)
            .unwrap();
    }

    #[test]
    fn rejects_cross_realm_replay() {
        let env = envelope();
        let other = realm("ak:realm:01904100-0000-7000-8000-000000000002");
        let now = Utc::now();
        let err = env
            .validate_for_recipient(&other, &env.trust_domain.clone(), now)
            .unwrap_err();
        assert!(matches!(err, IdentityLinkError::RealmMismatch { .. }));
    }

    #[test]
    fn rejects_cross_trust_domain_replay() {
        let env = envelope();
        let other = td("ak:trust_domain:other.example");
        let now = Utc::now();
        let err = env
            .validate_for_recipient(&env.realm_id.clone(), &other, now)
            .unwrap_err();
        assert!(matches!(err, IdentityLinkError::TrustDomainMismatch { .. }));
    }

    #[test]
    fn rejects_expired_envelope() {
        let mut env = envelope();
        env.expires_at = Utc::now() - Duration::seconds(1);
        let err = env
            .validate_for_recipient(&env.realm_id.clone(), &env.trust_domain.clone(), Utc::now())
            .unwrap_err();
        assert!(matches!(err, IdentityLinkError::Expired { .. }));
    }

    #[test]
    fn rejects_empty_payload() {
        let mut env = envelope();
        env.encrypted_payload.clear();
        let err = env
            .validate_for_recipient(&env.realm_id.clone(), &env.trust_domain.clone(), Utc::now())
            .unwrap_err();
        assert!(matches!(err, IdentityLinkError::EmptyPayload));
    }
}
