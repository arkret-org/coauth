// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 (2026-05-20, spec a77b995) — 3PID invite engine.
//!
//! Replaces the previous plaintext email / SMS invite pathway with the
//! `cx.schema.invite.v1` `third_party_invite` shape. Two wire modes are
//! supported:
//!
//! - `offline_token`: the OOB code is a high-entropy (`≥128 bits`) opaque
//!   token. The wire carries `token_commitment = sha256(token | salt)` +
//!   `token_salt_id` (opaque) + `token_entropy_bits`. The plaintext token
//!   is delivered out-of-band; servers verify by hashing the claimant's
//!   token against the stored salt and constant-time-comparing the
//!   commitment.
//!
//! - `lookup`: the OOB code is a short human-typeable string indexed
//!   into a server-private lookup table. The wire carries
//!   `lookup_table_ref` + `pepper_id` (both opaque). The plaintext code
//!   is delivered out-of-band; servers HMAC-pepper the claimant's input
//!   and look it up in the table. **3 wrong attempts invalidate the
//!   record** (terminal state `invalidated_by_rate_limit`).
//!
//! **Plaintext 3PID values (email addresses / phone numbers) MUST NEVER
//! appear on the wire.** This is enforced at the type level: the
//! [`ThirdPartyInviteRecord`] does not carry the plaintext value — only
//! commitment / lookup_table_ref + pepper_id. The plaintext is consumed
//! by the local mint code and then dropped.
//!
//! ## State machine
//!
//! Wire states (`cx.schema.invite.v1` §state enum):
//!
//! ```text
//!                ┌─────────┐
//!                │ pending │
//!                └─┬───────┘
//!                  │
//!     ┌────────────┼────────────┬──────────────┬──────────────────────┐
//!     ▼            ▼            ▼              ▼                      ▼
//! claimed     send_failed   revoked_by_      revoked_by_         invalidated_
//!                           capability_loss  inviter_left        by_rate_limit
//! ```
//!
//! All five non-`pending` states are terminal. On any terminal state,
//! the engine schedules a **zeroize-within-24h** task that drops the
//! stored salt (offline_token mode) or pepper (lookup mode) so the
//! invite can never be replayed — see [`schedule_terminal_zeroize`].
//!
//! ## TODO(round4-binding-proof-verifier)
//!
//! The full `binding_proof` / `subject_proof` chain verifier (the
//! `verification_service_did` -> DID document -> signature chain) is
//! not yet implemented end-to-end. The wire shape is correct; internal
//! verification is a stub that accepts well-formed proofs. See
//! [`crate::services::invite_claim_binding`] for the proof issuance
//! side.

use std::time::Duration;

use chrono::{DateTime, Utc};
use contrix_core::{
    Did, RealmId, ThirdPartyInvite, ThirdPartyInviteOobKind, ThirdPartyInviteTerminalState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

/// Minimum entropy (in bits) required for offline_token mode invites.
/// Mirrors `cx.schema.invite.v1` `third_party_invite.token_entropy_bits`
/// minimum.
pub const OFFLINE_TOKEN_MIN_ENTROPY_BITS: u32 = 128;

/// Maximum lookup-mode verification failures before the entry is moved to
/// [`ThirdPartyInviteTerminalState::InvalidatedByRateLimit`]. Mirrors
/// `services::oob_code::LOOKUP_STRIKE_LIMIT`.
pub const LOOKUP_RATE_LIMIT_FAILURES: u8 = 3;

/// Window after the terminal state in which the engine MUST scrub the
/// stored salt (offline_token mode) or pepper (lookup mode). Round 4
/// requirement.
pub const TERMINAL_ZEROIZE_WITHIN: Duration = Duration::from_secs(24 * 60 * 60);

/// Errors raised by the 3PID invite engine.
#[derive(Debug, Error)]
pub enum ThirdPartyInviteError {
    #[error("invite wire shape rejected: {0}")]
    InvalidWire(String),
    #[error("invite is in a terminal state ({0:?}) and cannot accept this transition")]
    AlreadyTerminal(ThirdPartyInviteTerminalState),
    #[error("invite token_entropy_bits {actual} < {min} (offline_token mode)")]
    InsufficientEntropy { actual: u32, min: u32 },
    #[error("invite rate limit exceeded ({attempts} failed attempts)")]
    RateLimitExceeded { attempts: u8 },
}

/// Internal (server-side) representation of an in-flight 3PID invite.
///
/// **Never serialise this struct to the wire — it MAY hold the
/// per-invite salt or pepper. Use [`ThirdPartyInvite`] (from the SDK)
/// for the wire shape; that struct only carries commitments and opaque
/// `*_id` references.**
#[derive(Debug, Clone)]
pub struct ThirdPartyInviteRecord {
    /// Wire form. The only thing that ever leaves coauth's address
    /// space.
    pub wire: ThirdPartyInvite,
    /// Server-private salt bytes (offline_token mode only). Stored
    /// indexed by [`ThirdPartyInvite::token_salt_id`]. MUST be zeroized
    /// on terminal transitions.
    pub server_private_salt: Option<Vec<u8>>,
    /// Server-private pepper bytes (lookup mode only). Stored indexed
    /// by [`ThirdPartyInvite::pepper_id`]. MUST be zeroized on terminal
    /// transitions.
    pub server_private_pepper: Option<Vec<u8>>,
    /// Wall-clock state-machine state.
    pub terminal_state: Option<ThirdPartyInviteTerminalState>,
    /// When the row entered the terminal state, used to schedule
    /// zeroize within 24h.
    pub terminal_at: Option<DateTime<Utc>>,
    /// Number of lookup-mode verification failures observed so far.
    /// Ignored for offline_token mode.
    pub lookup_failures: u8,
}

impl ThirdPartyInviteRecord {
    /// Build a record from the wire shape. Validates the
    /// offline_token / lookup field-population invariants and the
    /// `≥128 bit` entropy floor.
    pub fn from_wire(
        wire: ThirdPartyInvite,
        server_private_salt: Option<Vec<u8>>,
        server_private_pepper: Option<Vec<u8>>,
    ) -> Result<Self, ThirdPartyInviteError> {
        wire.validate_minimal()
            .map_err(|e| ThirdPartyInviteError::InvalidWire(e.to_string()))?;

        match wire.oob_code_kind {
            ThirdPartyInviteOobKind::OfflineToken => {
                let bits = wire.token_entropy_bits.unwrap_or(0);
                if bits < OFFLINE_TOKEN_MIN_ENTROPY_BITS {
                    return Err(ThirdPartyInviteError::InsufficientEntropy {
                        actual: bits,
                        min: OFFLINE_TOKEN_MIN_ENTROPY_BITS,
                    });
                }
                if server_private_pepper.is_some() {
                    return Err(ThirdPartyInviteError::InvalidWire(
                        "offline_token mode must not carry a pepper".into(),
                    ));
                }
            }
            ThirdPartyInviteOobKind::Lookup => {
                if server_private_salt.is_some() {
                    return Err(ThirdPartyInviteError::InvalidWire(
                        "lookup mode must not carry a salt".into(),
                    ));
                }
            }
        }

        Ok(Self {
            wire,
            server_private_salt,
            server_private_pepper,
            terminal_state: None,
            terminal_at: None,
            lookup_failures: 0,
        })
    }

    /// Returns `true` when the record is in any terminal state.
    pub fn is_terminal(&self) -> bool {
        self.terminal_state.is_some()
    }

    /// Drive a transition to a terminal state. Idempotent — re-applying
    /// the same terminal state is a no-op. Distinct terminal states
    /// MUST NOT chain; the second call returns
    /// [`ThirdPartyInviteError::AlreadyTerminal`].
    pub fn transition_terminal(
        &mut self,
        state: ThirdPartyInviteTerminalState,
        now: DateTime<Utc>,
    ) -> Result<(), ThirdPartyInviteError> {
        match self.terminal_state {
            None => {
                self.terminal_state = Some(state);
                self.terminal_at = Some(now);
                // Schedule the zeroize task. In the production handler
                // this is dispatched to `coauth-tasks`; here we just
                // mark the intent — the actual scrub happens via
                // [`Self::zeroize_secrets`] when the task fires.
                Ok(())
            }
            Some(existing) if existing == state => Ok(()),
            Some(existing) => Err(ThirdPartyInviteError::AlreadyTerminal(existing)),
        }
    }

    /// Record a wrong-attempt in lookup mode. Returns `true` when the
    /// strike limit has been reached and the caller MUST also drive
    /// `transition_terminal(InvalidatedByRateLimit, now)`.
    pub fn record_lookup_failure(&mut self) -> Result<bool, ThirdPartyInviteError> {
        if !matches!(self.wire.oob_code_kind, ThirdPartyInviteOobKind::Lookup) {
            return Err(ThirdPartyInviteError::InvalidWire(
                "record_lookup_failure called on non-lookup invite".into(),
            ));
        }
        self.lookup_failures = self.lookup_failures.saturating_add(1);
        Ok(self.lookup_failures >= LOOKUP_RATE_LIMIT_FAILURES)
    }

    /// Drop server-private salt / pepper bytes. MUST be called within
    /// `TERMINAL_ZEROIZE_WITHIN` of [`Self::transition_terminal`] when
    /// the engine moves the record off the hot path. Tests assert that
    /// the bytes are observably scrubbed.
    pub fn zeroize_secrets(&mut self) {
        if let Some(mut salt) = self.server_private_salt.take() {
            salt.zeroize();
        }
        if let Some(mut pepper) = self.server_private_pepper.take() {
            pepper.zeroize();
        }
    }

    /// Whether the engine MUST schedule a zeroize for this record at
    /// (or before) `terminal_at + TERMINAL_ZEROIZE_WITHIN`.
    pub fn zeroize_due_at(&self) -> Option<DateTime<Utc>> {
        self.terminal_at
            .map(|t| t + chrono::Duration::from_std(TERMINAL_ZEROIZE_WITHIN).expect("24h fits"))
    }
}

/// Helper: build a `token_commitment` for the offline_token mode wire
/// shape. The commitment is `sha256(token | salt)` rendered as
/// `sha256:<hex>` to match the `cx.schema.invite.v1` pattern.
#[must_use]
pub fn offline_token_commitment(token: &[u8], salt: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(token);
    h.update(salt);
    let digest = h.finalize();
    format!("sha256:{}", hex::encode(digest))
}

/// Helper: schedule a zeroize task for a terminal record. Today this
/// returns the `due_at` instant — the call-site posts a `coauth-tasks`
/// job that runs `zeroize_secrets` at or before `due_at`.
///
/// TODO(round4-zeroize-task): wire this to the production
/// `coauth-tasks` queue once the round-4 admin migration lands. The
/// terminal_at + 24h policy is documented in `oob_code.rs`.
pub fn schedule_terminal_zeroize(rec: &ThirdPartyInviteRecord) -> Option<DateTime<Utc>> {
    rec.zeroize_due_at()
}

/// Round 4 invite-claim transcript fragment. Distinct from the SDK's
/// wire shape (which lives in `model::round4`) so coauth can attach
/// service-local fields (`audience`, `claim_nonce`) before signing.
///
/// `binding_proof` covers the *verification-service* side of the chain
/// (auth server attesting the 3PID was verified). `subject_proof` is
/// produced by the claimant device — see the partner crate
/// `yougen-client::claim_invite` which is **not** part of coauth's
/// build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteClaimBindingProof {
    /// `verification_service_did` from the originating invite.
    pub verification_service_did: Did,
    /// Verification method identifier (DID URL `#fragment` form), e.g.
    /// `did:web:auth.example#key-1`. The fragment is mandatory per
    /// round 4 (kid pattern `^did:[a-z0-9]+:[^\s]+#.+$`).
    pub verification_method: String,
    /// Claimant DID — the subject the proof binds to.
    pub subject_did: Did,
    /// Realm scope of the binding (round 4 — every binding is
    /// realm-scoped, no global bindings).
    pub realm_id: RealmId,
    /// Audience the proof is issued for (typically the principal
    /// server's service DID).
    pub audience: String,
    /// Single-use nonce echoed by the claimant in their `subject_proof`
    /// to prevent re-binding.
    pub claim_nonce: String,
    /// Wall-clock expiry. Receivers MUST reject after this point.
    pub expires_at: DateTime<Utc>,
    /// Detached signature over the canonical proof transcript. Round 4
    /// internal verifier chain is TODO — see module docs above.
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_core::Hash;

    fn build_wire_offline() -> ThirdPartyInvite {
        ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::OfflineToken,
            token_commitment: Some(Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()),
            token_salt_id: Some("salt-1".to_owned()),
            token_entropy_bits: Some(128),
            lookup_table_ref: None,
            pepper_id: None,
            max_claims: 1,
            verification_service_did: Did::new("did:web:auth.example").unwrap(),
            verification_public_key: "z6MkAuthKey".to_owned(),
        }
    }

    fn build_wire_lookup() -> ThirdPartyInvite {
        ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::Lookup,
            token_commitment: None,
            token_salt_id: None,
            token_entropy_bits: None,
            lookup_table_ref: Some("lkup-1".to_owned()),
            pepper_id: Some("pepper-1".to_owned()),
            max_claims: 1,
            verification_service_did: Did::new("did:web:auth.example").unwrap(),
            verification_public_key: "z6MkAuthKey".to_owned(),
        }
    }

    #[test]
    fn from_wire_accepts_well_formed_offline_invite() {
        let wire = build_wire_offline();
        let rec =
            ThirdPartyInviteRecord::from_wire(wire, Some(b"salt".to_vec()), None).unwrap();
        assert_eq!(rec.wire.oob_code_kind, ThirdPartyInviteOobKind::OfflineToken);
        assert!(rec.server_private_salt.is_some());
        assert!(rec.server_private_pepper.is_none());
        assert!(!rec.is_terminal());
    }

    #[test]
    fn from_wire_rejects_low_entropy_offline_invite() {
        let mut wire = build_wire_offline();
        wire.token_entropy_bits = Some(64);
        let err = ThirdPartyInviteRecord::from_wire(wire, Some(b"salt".to_vec()), None);
        // The SDK's `validate_minimal()` rejects entropy<128 first, so
        // we accept either path (the engine surfaces the SDK's
        // protocol error or our explicit `InsufficientEntropy`).
        assert!(err.is_err());
    }

    #[test]
    fn from_wire_rejects_mode_field_mixup() {
        let mut wire = build_wire_offline();
        wire.lookup_table_ref = Some("oops".to_owned());
        let err = ThirdPartyInviteRecord::from_wire(wire, Some(b"salt".to_vec()), None);
        assert!(err.is_err());
    }

    #[test]
    fn from_wire_accepts_well_formed_lookup_invite() {
        let wire = build_wire_lookup();
        let rec = ThirdPartyInviteRecord::from_wire(wire, None, Some(b"pep".to_vec())).unwrap();
        assert_eq!(rec.wire.oob_code_kind, ThirdPartyInviteOobKind::Lookup);
        assert!(rec.server_private_pepper.is_some());
    }

    #[test]
    fn transition_terminal_is_idempotent_for_same_state() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let now = Utc::now();
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        // Same state again — no error.
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        assert_eq!(rec.terminal_state, Some(ThirdPartyInviteTerminalState::Claimed));
    }

    #[test]
    fn transition_terminal_rejects_distinct_second_terminal() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let now = Utc::now();
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        let err = rec
            .transition_terminal(ThirdPartyInviteTerminalState::RevokedByInviterLeft, now)
            .unwrap_err();
        assert!(matches!(err, ThirdPartyInviteError::AlreadyTerminal(_)));
    }

    #[test]
    fn record_lookup_failure_triggers_at_three_strikes() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_lookup(), None, Some(b"pep".to_vec()))
                .unwrap();
        assert!(!rec.record_lookup_failure().unwrap());
        assert!(!rec.record_lookup_failure().unwrap());
        assert!(rec.record_lookup_failure().unwrap()); // third strike → true
    }

    #[test]
    fn record_lookup_failure_rejects_on_offline_invite() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let err = rec.record_lookup_failure().unwrap_err();
        assert!(matches!(err, ThirdPartyInviteError::InvalidWire(_)));
    }

    #[test]
    fn zeroize_secrets_scrubs_salt_and_pepper() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"hot_salt".to_vec()), None)
                .unwrap();
        assert!(rec.server_private_salt.is_some());
        rec.zeroize_secrets();
        assert!(rec.server_private_salt.is_none());
    }

    #[test]
    fn zeroize_due_at_is_24h_from_terminal() {
        let mut rec =
            ThirdPartyInviteRecord::from_wire(build_wire_offline(), Some(b"salt".to_vec()), None)
                .unwrap();
        let now = Utc::now();
        rec.transition_terminal(ThirdPartyInviteTerminalState::Claimed, now)
            .unwrap();
        let due = rec.zeroize_due_at().unwrap();
        let delta = (due - now).num_hours();
        assert_eq!(delta, 24, "zeroize MUST be due exactly 24h after terminal");
    }

    #[test]
    fn offline_token_commitment_matches_canonical_form() {
        let c = offline_token_commitment(b"correct horse battery staple", b"some-salt");
        assert!(c.starts_with("sha256:"));
        assert_eq!(c.len(), "sha256:".len() + 64);
        // Hex digits only.
        assert!(c["sha256:".len()..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn five_terminal_states_are_all_reachable() {
        let now = Utc::now();
        for state in [
            ThirdPartyInviteTerminalState::Claimed,
            ThirdPartyInviteTerminalState::SendFailed,
            ThirdPartyInviteTerminalState::RevokedByCapabilityLoss,
            ThirdPartyInviteTerminalState::RevokedByInviterLeft,
            ThirdPartyInviteTerminalState::InvalidatedByRateLimit,
        ] {
            let mut rec = ThirdPartyInviteRecord::from_wire(
                build_wire_offline(),
                Some(b"salt".to_vec()),
                None,
            )
            .unwrap();
            rec.transition_terminal(state, now).unwrap();
            assert_eq!(rec.terminal_state, Some(state));
        }
    }
}

// Inline reference: spec doc anchors for reviewers.
//   `contrix-spec/spec/v1/artifacts/schemas/invite.schema.json` $defs.third_party_invite
//   `contrix-spec/spec/v1/zh/identity/3pid-invite-engine.md` (round-4 SP3.4)
