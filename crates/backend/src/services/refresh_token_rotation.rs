// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Refresh-token rotation policy enforcement.
//!
//! ## Policy
//!
//! `coauth` enforces strict rotation on every successful refresh-token
//! exchange, following the OAuth 2.1 / FAPI 2.0 baseline:
//!
//! 1. **Rotate on every refresh.** A successful `POST /token` with
//!    `grant_type=refresh_token` MUST invalidate the presented refresh
//!    token and mint a new one. The old token can never be redeemed
//!    again, even within its TTL.
//! 2. **Revoke the entire chain on reuse.** If a refresh token that
//!    has already been rotated (i.e. already has a `successor`) is
//!    presented again, `coauth` treats it as a leak indicator and
//!    revokes the whole rotation chain — past, present, and future —
//!    along with any access tokens that descend from it.
//! 3. **Revoke chain on device lock / logout.** Locking a device or
//!    explicit logout calls [`revoke_chain_for_device`] / the session
//!    grant revoke path to ensure no refresh token from that device
//!    can continue to mint access tokens.
//! 4. **Rotation window.** The maximum lifetime of any single refresh
//!    token in a chain is 24 hours by default
//!    ([`DEFAULT_ROTATION_WINDOW`]). After the window the token MUST
//!    NOT be exchanged even if it hasn't been rotated yet.
//! 5. **Idle window.** Independent of the absolute rotation window,
//!    a refresh token that has not been used for `idle_window` (12h
//!    default) is treated as abandoned and rejected.
//!
//! This module is intentionally a *policy* layer — it does not own
//! the token table. It exposes pure decision functions
//! ([`evaluate_refresh`]) and orchestration helpers
//! ([`revoke_chain`], [`revoke_chain_for_device`]) that callers in
//! `handlers::oauth::token` and `handlers::admin::*` invoke inside
//! their own transactions.
//!
//! TODO(P5-impl): wire the storage side once the
//! `oauth_refresh_token.chain_root_id` / `superseded_by` columns land
//! in `coauth-data`. Today the data layer carries a flat
//! `revoked_at` flag without explicit rotation chains, so chain
//! revocation falls back to "revoke this token only" with the chain
//! semantics enforced at the session-grant level.

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

/// Default absolute rotation window. After this much wall-clock time
/// has elapsed since the chain root was minted, no token in the chain
/// may be exchanged.
pub const DEFAULT_ROTATION_WINDOW: Duration = Duration::hours(24);

/// Default idle window. A token unused for longer than this is
/// treated as abandoned.
pub const DEFAULT_IDLE_WINDOW: Duration = Duration::hours(12);

/// Outcome of evaluating a presented refresh token against the
/// rotation policy. Callers translate this into an OAuth error
/// response or a successful rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationDecision {
    /// Token is valid and may be exchanged. The caller MUST mint a
    /// successor and mark the presented token as `superseded_by` it.
    Accept,
    /// Token has already been rotated (its `superseded_by` column is
    /// set). This is a leak indicator — caller MUST revoke the chain.
    ReuseDetected,
    /// Token was explicitly revoked (device logout, admin action,
    /// chain compromise). Caller returns `invalid_grant`.
    Revoked,
    /// Token is outside the absolute rotation window.
    RotationWindowExpired,
    /// Token was not used for longer than the idle window.
    IdleExpired,
}

/// Per-token state required by [`evaluate_refresh`]. This is
/// intentionally a value type so callers can construct it from
/// whatever storage shape they happen to have today.
#[derive(Debug, Clone)]
pub struct RefreshTokenState {
    /// When the *root* of the rotation chain was minted. Used for
    /// the absolute rotation window.
    pub chain_minted_at: DateTime<Utc>,
    /// When this specific token was last touched. Used for the idle
    /// window.
    pub last_seen_at: DateTime<Utc>,
    /// `true` if the token already has a successor (already rotated).
    pub already_rotated: bool,
    /// `true` if the token (or chain) has been explicitly revoked.
    pub revoked: bool,
}

/// Policy configuration. Defaults to
/// `RotationPolicy { rotation_window: 24h, idle_window: 12h }`.
#[derive(Debug, Clone, Copy)]
pub struct RotationPolicy {
    pub rotation_window: Duration,
    pub idle_window: Duration,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            rotation_window: DEFAULT_ROTATION_WINDOW,
            idle_window: DEFAULT_IDLE_WINDOW,
        }
    }
}

/// Pure decision function. No I/O; the caller passes in the relevant
/// row state plus the current wall-clock instant.
#[must_use]
pub fn evaluate_refresh(
    state: &RefreshTokenState,
    now: DateTime<Utc>,
    policy: RotationPolicy,
) -> RotationDecision {
    if state.revoked {
        return RotationDecision::Revoked;
    }
    if state.already_rotated {
        // Re-presentation of an already-rotated token: treat as a
        // leak indicator. Caller MUST revoke the chain.
        return RotationDecision::ReuseDetected;
    }
    if now.signed_duration_since(state.chain_minted_at) > policy.rotation_window {
        return RotationDecision::RotationWindowExpired;
    }
    if now.signed_duration_since(state.last_seen_at) > policy.idle_window {
        return RotationDecision::IdleExpired;
    }
    RotationDecision::Accept
}

#[derive(Debug, Error)]
pub enum RotationError {
    #[error("refresh token presented after rotation; chain revoked")]
    ReuseDetected,
    #[error("refresh token revoked")]
    Revoked,
    #[error("refresh token outside rotation window")]
    RotationWindowExpired,
    #[error("refresh token idle window exceeded")]
    IdleExpired,
}

impl RotationDecision {
    /// Convert to an error for the OAuth handler. `Accept` returns
    /// `Ok(())`.
    pub fn into_result(self) -> Result<(), RotationError> {
        match self {
            Self::Accept => Ok(()),
            Self::ReuseDetected => Err(RotationError::ReuseDetected),
            Self::Revoked => Err(RotationError::Revoked),
            Self::RotationWindowExpired => Err(RotationError::RotationWindowExpired),
            Self::IdleExpired => Err(RotationError::IdleExpired),
        }
    }
}

/// Marker function for the chain-revocation path. Today this is a
/// no-op pending the storage-side `chain_root_id` column; the
/// session-grant level revoke owns the actual data mutation. The
/// stub is here so handlers can call the policy module with a stable
/// signature and the impl can land without further handler churn.
///
/// TODO(P5-impl): walk `oauth_refresh_token WHERE chain_root_id = ?`
/// and bulk-update `revoked_at`. Today the cascading revoke is
/// performed at the `oauth_session_grant` level via
/// [`super::device_revoke::cascade_revoke_session_grants`].
pub fn revoke_chain(_chain_root_id: &str) {
    // Stub: see TODO above.
}

/// Convenience wrapper: revoke every rotation chain owned by a
/// device. Delegates to the session-grant cascade today.
///
/// TODO(P5-impl): once `oauth_refresh_token.device_id` is denormalised
/// on the chain root, this becomes a single bulk update.
pub fn revoke_chain_for_device(_device_id: &str) {
    // Stub: see TODO above.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid")
    }

    fn fresh(minted_at: DateTime<Utc>, last_seen_at: DateTime<Utc>) -> RefreshTokenState {
        RefreshTokenState {
            chain_minted_at: minted_at,
            last_seen_at,
            already_rotated: false,
            revoked: false,
        }
    }

    #[test]
    fn accepts_fresh_token_within_windows() {
        let now = at(1_000_000);
        let state = fresh(now - Duration::minutes(5), now - Duration::seconds(30));
        assert_eq!(
            evaluate_refresh(&state, now, RotationPolicy::default()),
            RotationDecision::Accept
        );
    }

    #[test]
    fn detects_reuse_after_rotation() {
        let now = at(1_000_000);
        let mut state = fresh(now - Duration::minutes(5), now - Duration::seconds(30));
        state.already_rotated = true;
        assert_eq!(
            evaluate_refresh(&state, now, RotationPolicy::default()),
            RotationDecision::ReuseDetected
        );
    }

    #[test]
    fn rejects_revoked_token() {
        let now = at(1_000_000);
        let mut state = fresh(now - Duration::minutes(5), now - Duration::seconds(30));
        state.revoked = true;
        assert_eq!(
            evaluate_refresh(&state, now, RotationPolicy::default()),
            RotationDecision::Revoked
        );
    }

    #[test]
    fn rejects_token_outside_rotation_window() {
        let now = at(1_000_000);
        let state = fresh(now - Duration::hours(25), now - Duration::seconds(30));
        assert_eq!(
            evaluate_refresh(&state, now, RotationPolicy::default()),
            RotationDecision::RotationWindowExpired
        );
    }

    #[test]
    fn rejects_idle_token() {
        let now = at(1_000_000);
        let state = fresh(now - Duration::hours(1), now - Duration::hours(13));
        assert_eq!(
            evaluate_refresh(&state, now, RotationPolicy::default()),
            RotationDecision::IdleExpired
        );
    }

    #[test]
    fn revoked_beats_rotated() {
        // Both flags set: revoked is the stronger signal because it
        // means we've already decided to kill the chain.
        let now = at(1_000_000);
        let mut state = fresh(now - Duration::minutes(5), now - Duration::seconds(30));
        state.revoked = true;
        state.already_rotated = true;
        assert_eq!(
            evaluate_refresh(&state, now, RotationPolicy::default()),
            RotationDecision::Revoked
        );
    }

    #[test]
    fn decision_into_result_maps_correctly() {
        assert!(RotationDecision::Accept.into_result().is_ok());
        assert!(matches!(
            RotationDecision::ReuseDetected.into_result(),
            Err(RotationError::ReuseDetected)
        ));
        assert!(matches!(
            RotationDecision::Revoked.into_result(),
            Err(RotationError::Revoked)
        ));
    }
}
