// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! 7-trigger non-enumerable failure-state machine for OOB invites.
//!
//! Round R2/R3 T15. All seven failure triggers (expired, send_failed,
//! capability_loss, inviter_left, revoked, claim_success,
//! rate_limit_invalidated) surface as a byte-identical wire response
//! padded to ≤50 ms so the timing channel can't be used to enumerate
//! invite IDs.
//!
//! ## Wire response
//!
//! ```json
//! { "error": "not_found" }
//! ```
//!
//! …with HTTP status `404 Not Found`. The internal reason code is
//! logged at INFO and persisted to the audit row, but never written to
//! the response body. This mirrors the recommendation in
//! `consent-model.md` §11 ("anti-enumeration responses MUST be byte-
//! identical across causes").
//!
//! ## Constant-time padding
//!
//! [`pad_to_non_enumerable`] sleeps until `arrival + NON_ENUMERABLE_PAD`
//! before returning. Callers MUST capture the request arrival timestamp
//! at the top of the handler (before any DB I/O) and pass it in, so the
//! padding window covers the *entire* failure path — not just whatever
//! ran after the failure was detected.

use std::time::Instant;

use serde::Serialize;

use crate::services::oob_code::{NON_ENUMERABLE_PAD, OobInviteFailure};

/// The exact JSON body coauth emits for every non-enumerable failure.
/// Serialised as a unit struct so callers can `Json(NotFoundBody)`
/// without re-allocating.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct NotFoundBody {
    pub error: &'static str,
}

impl NotFoundBody {
    /// The single allowed value — `{"error": "not_found"}`. Re-used
    /// across all seven failure paths to keep the response byte-stable.
    pub const NOT_FOUND: Self = Self { error: "not_found" };
}

/// Public outcome of [`finalise_oob_failure`] — the (status, body) pair
/// the caller should write, after [`pad_to_non_enumerable`] returns.
///
/// We keep `status` and `body` as ready-to-serialise values rather than
/// salvo types so the helper is reusable from non-handler code (admin
/// CLI tools, test fixtures).
#[derive(Debug, Clone, Copy)]
pub struct NonEnumerableOutcome {
    pub status: u16,
    pub body: NotFoundBody,
}

impl NonEnumerableOutcome {
    /// Canonical not-found response. All seven failure causes resolve
    /// to exactly this value on the wire.
    pub const NOT_FOUND: Self = Self {
        status: 404,
        body: NotFoundBody::NOT_FOUND,
    };
}

/// Audit-side record: what actually happened, so the operator can
/// trace the failure even though the wire response is opaque. This
/// MUST be logged + persisted but MUST NOT be returned to the client.
#[derive(Debug, Clone, Copy)]
pub struct NonEnumerableAudit {
    pub trigger: OobInviteFailure,
    pub internal_reason_code: &'static str,
}

/// Build the audit + response pair for a known failure trigger. The
/// caller logs (and persists) `audit`, sleeps via
/// [`pad_to_non_enumerable`], then writes `response`.
#[must_use]
pub fn finalise_oob_failure(
    trigger: OobInviteFailure,
) -> (NonEnumerableAudit, NonEnumerableOutcome) {
    (
        NonEnumerableAudit {
            trigger,
            internal_reason_code: trigger.internal_reason_code(),
        },
        NonEnumerableOutcome::NOT_FOUND,
    )
}

/// Sleep until `arrival + NON_ENUMERABLE_PAD`. If the handler took
/// longer than the pad window the function returns immediately (and
/// the caller MAY emit a `slow_path` metric — see
/// `TODO(oob-slow-path-telemetry)` below). Always-async to keep the timing window
/// uniform across runtimes.
///
/// TODO(oob-slow-path-telemetry): emit a
/// `coauth_oob_failure_slow_path_total` counter when the elapsed > pad
/// window. This is observability-only: the fail-closed wire behavior is
/// already uniform (`404`) and the padding still executes for fast paths.
/// The metric is deferred because metrics fan-out is owned by `telemetry.rs`.
pub async fn pad_to_non_enumerable(arrival: Instant) {
    let elapsed = arrival.elapsed();
    if let Some(remaining) = NON_ENUMERABLE_PAD.checked_sub(elapsed) {
        tokio::time::sleep(remaining).await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn all_seven_triggers_collapse_to_one_wire_body() {
        let triggers = [
            OobInviteFailure::Expired,
            OobInviteFailure::SendFailed,
            OobInviteFailure::CapabilityLoss,
            OobInviteFailure::InviterLeft,
            OobInviteFailure::Revoked,
            OobInviteFailure::ClaimSuccess,
            OobInviteFailure::RateLimitInvalidated,
        ];
        let mut seen = Vec::new();
        for t in triggers {
            let (_audit, resp) = finalise_oob_failure(t);
            assert_eq!(resp.status, 404);
            seen.push(serde_json::to_vec(&resp.body).unwrap());
        }
        let first = &seen[0];
        for body in &seen[1..] {
            assert_eq!(first, body, "wire body MUST be byte-identical");
        }
        assert_eq!(first.as_slice(), br#"{"error":"not_found"}"#);
    }

    #[test]
    fn audit_carries_distinct_reason_per_trigger() {
        let (a_exp, _) = finalise_oob_failure(OobInviteFailure::Expired);
        let (a_rev, _) = finalise_oob_failure(OobInviteFailure::Revoked);
        assert_eq!(a_exp.internal_reason_code, "expired_invite_token");
        assert_eq!(a_rev.internal_reason_code, "revoked");
        assert_ne!(a_exp.internal_reason_code, a_rev.internal_reason_code);
    }

    #[tokio::test]
    async fn pad_extends_short_path_to_window() {
        let start = Instant::now();
        // Simulate a 5 ms failure path.
        tokio::time::sleep(Duration::from_millis(5)).await;
        pad_to_non_enumerable(start).await;
        let elapsed = start.elapsed();
        // Pad target is 50 ms — allow a few ms slop for the test
        // runtime scheduler.
        assert!(
            elapsed >= NON_ENUMERABLE_PAD,
            "elapsed {elapsed:?} < pad {NON_ENUMERABLE_PAD:?}"
        );
    }

    #[tokio::test]
    async fn pad_does_not_oversleep_when_already_past_window() {
        // Pretend the handler took longer than the pad — we should
        // return promptly without an extra delay.
        let arrival = Instant::now()
            .checked_sub(Duration::from_millis(80))
            .unwrap();
        let before = Instant::now();
        pad_to_non_enumerable(arrival).await;
        let extra = before.elapsed();
        assert!(
            extra < Duration::from_millis(10),
            "pad_to_non_enumerable should be a no-op when already past window (took {extra:?})"
        );
    }
}
