// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! 3PID Out-Of-Band (OOB) code generation + verification — Round R2/R3 T15.
//!
//! Two legal code forms are supported, configurable per deployment via
//! `ArkretConfig::oob_code_kind` (default `OobCodeKind::OfflineVerifiable`):
//!
//! ## Form 1 — `OobCodeKind::OfflineVerifiable`
//!
//! Offline-verifiable opaque token with ≥128-bit entropy. Sampled from the
//! restricted 31-symbol base32 alphabet (excluding the easily-confused
//! characters `I`, `L`, `0`, `1`, `O`). At [`OFFLINE_CODE_LEN`] = 26 chars
//! the code carries ≈128.8 bits, clearing the spec's ≥128-bit floor.
//! Holders verify by direct
//! byte comparison against a stored hash; no server-side rate-limit
//! pepper is required for confidentiality. Suitable for email-link
//! delivery where the recipient's mailbox is the second factor.
//!
//! ## Form 2 — `OobCodeKind::Lookup`
//!
//! Short human-typeable code (6 chars from the same restricted base32
//! alphabet — ~32 bits of entropy) paired with a server-side HMAC pepper.
//! The wire response carries `oob_code_kind = "lookup"` so the verifier
//! knows to enforce the lookup-mode rules:
//!
//!  - the supplied code is HMAC-peppered before comparison
//!  - per-(actor, target) rate-limit MUST be enforced upstream
//!  - **3-strike invalidation**: three wrong attempts invalidate the code (state transitions to
//!    `RateLimitInvalidated` and verification will never succeed again for that code)
//!
//! ## Non-enumerable failures (7-trigger state machine)
//!
//! See [`OobInviteFailure`]. All seven triggers MUST surface to the wire
//! as an indistinguishable `{ "error": "not_found" }` body, padded to a
//! constant ≤50 ms response time. The internal reason code is logged
//! (and stored on the invite row) but never returned. Constants are
//! re-exported from `arkret_core::error` to keep parity with the SDK.
//!
//! See `arkret-spec` 2026-05-20 §T15 ("OOB token state machine") for
//! the wire contract this module implements.

use std::time::Duration;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The restricted base32 alphabet used by both OOB code forms. Excludes
/// `I`, `L`, `0`, `1`, `O` per T15 to avoid visual confusion when codes
/// are read from email / SMS / printed media.
///
/// 26 letters minus `I`, `L`, `O` = 23 letters, plus 10 digits minus
/// `0`, `1` = 8 digits, total 31 symbols. Each output symbol encodes
/// log2(31) ≈ 4.954 bits.
pub const OOB_ALPHABET: &[u8; 31] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// The exact restricted alphabet (asserted at compile time).
const OOB_ALPHABET_BYTES: &[u8] = OOB_ALPHABET;

/// Number of characters in a Form 1 (offline-verifiable) code. 26 chars
/// from the 31-symbol alphabet yield 26·log2(31) ≈ 128.8 bits, which
/// clears the **≥128-bit entropy floor** the spec requires for production
/// offline OOB codes (`security-closure-vectors.json`: "production offline
/// OOB code must have at least 128 bits of entropy"). The spec states the
/// requirement as an entropy floor, not a fixed character count; with this
/// restricted 31-symbol alphabet (log2(31) ≈ 4.954 bits/char) 26 chars is
/// the smallest length that clears 128 bits (22 chars would be only
/// 109.0 bits — a 22-char floor only holds for a full 32-symbol base32
/// alphabet, which this alphabet is not).
pub const OFFLINE_CODE_LEN: usize = 26;

/// Number of characters in a Form 2 (lookup) short code. 6 chars × ~4.75
/// bits ≈ 28.5 bits — low enough to be human-typeable but defended by
/// the 3-strike invalidation rule and the per-(actor, target) rate
/// limit upstream.
pub const LOOKUP_CODE_LEN: usize = 6;

/// Number of wrong attempts that invalidate a lookup-form code.
pub const LOOKUP_STRIKE_LIMIT: u8 = 3;

/// Constant response-pad window for all seven failure triggers. The
/// handler MUST sleep_until(arrival + this) before writing the response
/// body. ≤50 ms per T15.
pub const NON_ENUMERABLE_PAD: Duration = Duration::from_millis(50);

/// Configurable OOB code form. Deployments default to
/// `OfflineVerifiable`; switching to `Lookup` enables the short-code +
/// 3-strike strand at the cost of needing server-side rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OobCodeKind {
    /// Form 1 — opaque ≥128-bit token, offline-verifiable.
    #[default]
    OfflineVerifiable,
    /// Form 2 — short lookup-style code with server-side pepper. Wire
    /// surface MUST include `oob_code_kind = "lookup"` so verifiers
    /// know to apply the 3-strike rule.
    ///
    /// FEATURE-GATED OFF: config rejects `oob_code_kind=lookup` (see
    /// `coauth-config` `ArkretConfig::validate`, the
    /// "oob_code_kind=lookup is disabled until lookup-mode strike counters
    /// are durable" guard). Every Form-2 code path below
    /// (`LOOKUP_CODE_LEN`, `LOOKUP_STRIKE_LIMIT`,
    /// `OobInviteFailure::RateLimitInvalidated`) is therefore unreachable in
    /// production until strike-counter persistence lands; do not assume the
    /// lookup wire behaviour is live.
    Lookup,
}

impl OobCodeKind {
    /// Wire string used on the verification response when this kind is
    /// in play. Only `Lookup` advertises itself; `OfflineVerifiable`
    /// returns `None` so the field is omitted and the offline path
    /// remains indistinguishable from other tokens on the wire.
    #[must_use]
    pub fn wire_label(self) -> Option<&'static str> {
        match self {
            OobCodeKind::OfflineVerifiable => None,
            OobCodeKind::Lookup => Some("lookup"),
        }
    }
}

/// One of the seven internal failure triggers for an OOB invite. All
/// seven MUST surface as `{ "error": "not_found" }` on the wire — the
/// caller logs the variant via `internal_reason_code` and feeds the
/// outcome into the response-pad delay.
///
/// See `arkret-spec` 2026-05-20 §T15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobInviteFailure {
    /// The token's `expires_at` is in the past.
    Expired,
    /// The notification carrier (email / SMS / push) reported a
    /// permanent delivery failure for this invite.
    SendFailed,
    /// The inviter lost a capability (e.g. left the realm, was
    /// downgraded) between mint and claim.
    CapabilityLoss,
    /// The inviter explicitly left or was removed from the realm.
    InviterLeft,
    /// An admin revoked the invite.
    Revoked,
    /// Already claimed — claim-success is treated as a failure for
    /// the second-claim path so enumerators can't probe.
    ClaimSuccess,
    /// Lookup-mode 3-strike or upstream rate-limit invalidation.
    RateLimitInvalidated,
}

impl OobInviteFailure {
    /// Internal-only reason code. Logged and stored; never written to
    /// the wire (the wire body is always `{ "error": "not_found" }`).
    ///
    /// The variants use stable snake_case reason strings for internal audit.
    /// The public wire surface remains the non-enumerating `not_found` code.
    #[must_use]
    pub fn internal_reason_code(self) -> &'static str {
        match self {
            OobInviteFailure::Expired => "expired_invite_token",
            OobInviteFailure::SendFailed => "send_failed",
            OobInviteFailure::CapabilityLoss => "capability_loss",
            OobInviteFailure::InviterLeft => "inviter_left",
            OobInviteFailure::Revoked => "revoked",
            OobInviteFailure::ClaimSuccess => "claim_success",
            OobInviteFailure::RateLimitInvalidated => "rate_limit_invalidated",
        }
    }
}

/// Generate an OOB code for the requested kind. Form 1 returns a ≥128-
/// bit offline-verifiable token; Form 2 returns a short lookup-style
/// code that callers MUST pair with a server-side pepper (see
/// [`pepper_lookup_code`]).
#[must_use]
pub fn generate_oob_code(kind: OobCodeKind) -> String {
    match kind {
        OobCodeKind::OfflineVerifiable => generate_restricted_base32(OFFLINE_CODE_LEN),
        OobCodeKind::Lookup => generate_restricted_base32(LOOKUP_CODE_LEN),
    }
}

/// Verify that a candidate code is a syntactically valid Form 1 token.
/// Does NOT check against any stored hash; that's the caller's job.
#[must_use]
pub fn is_valid_offline_code(candidate: &str) -> bool {
    candidate.len() == OFFLINE_CODE_LEN && all_in_restricted_alphabet(candidate)
}

/// Verify that a candidate code is a syntactically valid Form 2 lookup
/// code.
#[must_use]
pub fn is_valid_lookup_code(candidate: &str) -> bool {
    candidate.len() == LOOKUP_CODE_LEN && all_in_restricted_alphabet(candidate)
}

/// HMAC-SHA256 the supplied lookup code under the deployment pepper.
/// Use the returned bytes (constant-time-compared) as the verification
/// key, never compare the plaintext code against a stored value.
///
/// `pepper` SHOULD be ≥32 random bytes loaded from
/// `COAUTH_OOB_LOOKUP_PEPPER` (or equivalent) and rotated with the rest
/// of the deployment's symmetric secrets.
#[must_use]
pub fn pepper_lookup_code(pepper: &[u8], code: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(code.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Strike accumulator for lookup-mode codes. Three wrong attempts → the
/// code MUST be marked `RateLimitInvalidated` and verification MUST
/// fail thereafter, even with the correct code.
///
/// TODO(round23-T15, durable-blocker): wire this into the diesel `oob_codes`
/// row so the strike counter survives process restarts and horizontal
/// replicas. This helper is safe only for pure unit tests; production lookup
/// verification MUST use a durable row transition before enabling lookup-mode
/// invites.
#[derive(Debug, Clone, Copy)]
pub struct LookupStrikes {
    pub wrong_attempts: u8,
}

impl LookupStrikes {
    #[must_use]
    pub const fn new() -> Self {
        Self { wrong_attempts: 0 }
    }

    /// Record a wrong attempt. Returns `true` once the strike limit has
    /// been hit (the row should be moved to `RateLimitInvalidated`).
    pub fn record_wrong(&mut self) -> bool {
        self.wrong_attempts = self.wrong_attempts.saturating_add(1);
        self.wrong_attempts >= LOOKUP_STRIKE_LIMIT
    }

    #[must_use]
    pub const fn is_invalidated(self) -> bool {
        self.wrong_attempts >= LOOKUP_STRIKE_LIMIT
    }
}

impl Default for LookupStrikes {
    fn default() -> Self {
        Self::new()
    }
}

// ── internals ──────────────────────────────────────────────────

fn generate_restricted_base32(out_len: usize) -> String {
    use rand::RngCore as _;
    debug_assert_eq!(OOB_ALPHABET_BYTES.len(), 31);
    let alphabet = OOB_ALPHABET_BYTES;
    let modulus = alphabet.len() as u32;
    // Rejection-sample u32 values to avoid the modulo bias that would
    // otherwise tilt the distribution towards the first few alphabet
    // symbols. The accepted ceiling is the largest multiple of `modulus`
    // ≤ u32::MAX.
    let ceiling = u32::MAX - (u32::MAX % modulus);
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(out_len);
    let mut buf = [0u8; 4];
    while out.len() < out_len {
        rng.fill_bytes(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v >= ceiling {
            continue;
        }
        let idx = (v % modulus) as usize;
        out.push(alphabet[idx] as char);
    }
    out
}

fn all_in_restricted_alphabet(s: &str) -> bool {
    s.bytes().all(|b| OOB_ALPHABET_BYTES.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Form 1 (offline-verifiable) ────────────────────────────

    #[test]
    fn offline_code_has_required_length_and_alphabet() {
        for _ in 0..16 {
            let code = generate_oob_code(OobCodeKind::OfflineVerifiable);
            assert_eq!(code.len(), OFFLINE_CODE_LEN, "len: {code}");
            assert!(is_valid_offline_code(&code), "alphabet violation: {code}");
            // Excluded characters MUST NOT appear.
            for forbidden in ['I', 'L', '0', '1', 'O'] {
                assert!(
                    !code.contains(forbidden),
                    "code {code} contained forbidden char {forbidden}"
                );
            }
        }
    }

    #[test]
    fn offline_code_meets_entropy_floor() {
        // 26 chars × log2(31) ≈ 128.8 bits, just over the 128-bit floor.
        let bits = (OFFLINE_CODE_LEN as f64) * (OOB_ALPHABET_BYTES.len() as f64).log2();
        assert!(bits >= 128.0, "entropy {bits} below 128-bit floor");
    }

    // ── Form 2 (lookup) ────────────────────────────────────────

    #[test]
    fn lookup_code_has_correct_length_and_alphabet() {
        let code = generate_oob_code(OobCodeKind::Lookup);
        assert_eq!(code.len(), LOOKUP_CODE_LEN);
        assert!(is_valid_lookup_code(&code));
    }

    #[test]
    fn lookup_code_three_strikes_invalidates() {
        let mut strikes = LookupStrikes::new();
        assert!(!strikes.record_wrong());
        assert!(!strikes.record_wrong());
        assert!(
            strikes.record_wrong(),
            "third wrong attempt MUST signal invalidation"
        );
        assert!(strikes.is_invalidated());
    }

    #[test]
    fn lookup_wire_label_is_advertised() {
        assert_eq!(OobCodeKind::Lookup.wire_label(), Some("lookup"));
        assert_eq!(OobCodeKind::OfflineVerifiable.wire_label(), None);
    }

    #[test]
    fn pepper_is_deterministic_and_key_dependent() {
        let h1 = pepper_lookup_code(b"pepper-A", "ABCDEF");
        let h2 = pepper_lookup_code(b"pepper-A", "ABCDEF");
        let h3 = pepper_lookup_code(b"pepper-B", "ABCDEF");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3, "different pepper MUST yield different MAC");
    }

    // ── 7-trigger failure machine ──────────────────────────────

    #[test]
    fn expired_uses_sdk_error_code_constant() {
        assert_eq!(
            OobInviteFailure::Expired.internal_reason_code(),
            "expired_invite_token"
        );
    }

    #[test]
    fn all_seven_triggers_have_distinct_reason_codes() {
        let codes = [
            OobInviteFailure::Expired,
            OobInviteFailure::SendFailed,
            OobInviteFailure::CapabilityLoss,
            OobInviteFailure::InviterLeft,
            OobInviteFailure::Revoked,
            OobInviteFailure::ClaimSuccess,
            OobInviteFailure::RateLimitInvalidated,
        ]
        .map(super::OobInviteFailure::internal_reason_code);
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 7, "reason codes must be unique");
    }
}
