//! SEC-04 — receiver-side independent enforcement of the inception-key 24h
//! online window (`spec/v1/zh/identity/key-management.md` §5.0.1 step 5).
//!
//! The protocol requires the receiver / Auth Server to anchor on the
//! verifiable inception bootstrap timestamp (`did:webvh` entry-0 `versionTime`
//! / equivalent continuity proof) and to compute the inception key age against
//! its **own local clock** — never silently trusting a longer
//! `inception_key_max_online_window` self-reported by the issuing deployment.
//! When the age exceeds the 24h hard cap, the receiver MUST reject any
//! `ck.session.grant` / `ck.device.authorize` / long-lived capability /
//! ordinary DID update signed by that inception key, with reason code
//! [`cokret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`].
//!
//! This module is the thin, hermetic enforcement primitive: it wraps the SDK
//! age check ([`cokret_core::inception_key_age_exceeded`]) and adds the
//! **fail-closed** discipline for missing / unparseable anchors. The 24h cap is
//! a protocol hard limit sourced from the SDK constant — it is intentionally
//! *not* configurable.
//!
//! ## Mount-point status (honest boundary — see SEC-04 report)
//!
//! coauth does **not** currently issue any `ck.session.grant` /
//! `ck.device.authorize` that is *signed by a client-presented inception key*:
//! session grants are signed by coauth's own deployment service key
//! (`preferred_signing_key`) over an already-authenticated browser session, and
//! `ck.device.authorize` is not issued by coauth at all. Consequently there is
//! today no issuance path where "the signing key is provably the inception
//! key" can be decided, and the persisted principal-DID row keeps only the
//! webvh `versionId` (`key_log_head`) + DB `created_at`, not the verifiable
//! entry-0 `versionTime` anchor. Bolting this gate onto the existing
//! service-key-signed session-grant path would be a *wrongly-triggering or
//! always-off* gate, which the SEC-04 task explicitly forbids.
//!
//! Therefore this helper is wired as a **ready, tested enforcement primitive**
//! to be called from a genuine inception-key-signed issuance path once coauth
//! grows one (verifying the signing `verification_method` against the entry-0
//! controller key and carrying the entry-0 `versionTime` as the anchor). The
//! correct conservative behaviour (fail closed on a missing / unparseable
//! anchor) is encoded here so the mount-point wiring is a one-liner and cannot
//! accidentally fail open.

use chrono::{DateTime, Utc};
use cokret_core::inception_key_age_exceeded;

/// Receiver-side decision: may an inception key whose bootstrap anchor is
/// `bootstrap_ts` still sign at `now`?
///
/// Returns `Ok(())` only when the inception key is within the 24h hard cap.
/// Returns [`InceptionKeyWindowError::Exceeded`] when the age exceeds the cap —
/// the caller MUST reject the issuance and surface
/// [`cokret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`].
///
/// A `bootstrap_ts` in the future (anchor clock ahead of the receiver) is not
/// treated as exceeded here, matching the SDK contract; that anomaly is a
/// separate bootstrap-evidence concern, not an age-cap violation.
pub fn enforce_inception_key_window(
    bootstrap_ts: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), InceptionKeyWindowError> {
    if inception_key_age_exceeded(bootstrap_ts, now) {
        return Err(InceptionKeyWindowError::Exceeded);
    }
    Ok(())
}

/// Like [`enforce_inception_key_window`] but takes the raw RFC3339
/// `versionTime` string straight off the inception bootstrap evidence
/// (`did:webvh` entry-0). A missing (`None`) or unparseable anchor is treated
/// as **window-exceeded (fail closed)** per the SDK's conservative-reject
/// convention — the receiver MUST NOT admit an inception-key issuance whose
/// age it cannot verify, and MUST NOT substitute `now` to "pass" the check.
pub fn enforce_inception_key_window_rfc3339(
    version_time: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), InceptionKeyWindowError> {
    let Some(raw) = version_time
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        // Missing anchor → fail closed.
        return Err(InceptionKeyWindowError::Exceeded);
    };
    let Ok(parsed) = DateTime::parse_from_rfc3339(raw) else {
        // Unparseable anchor → fail closed.
        return Err(InceptionKeyWindowError::Exceeded);
    };
    enforce_inception_key_window(parsed.with_timezone(&Utc), now)
}

/// Failure of the receiver-side inception-key window check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InceptionKeyWindowError {
    /// The inception key is past its 24h online window (or its bootstrap
    /// anchor was missing / unparseable, which fails closed). Maps to wire
    /// reason code
    /// [`cokret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`].
    #[error("inception key online window (24h hard cap) exceeded")]
    Exceeded,
}

impl InceptionKeyWindowError {
    /// Stable wire reason code, sourced from the SDK registry so coauth and the
    /// protocol never drift.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        cokret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn age_under_24h_is_allowed() {
        let bootstrap = ts("2026-06-04T00:00:00Z");
        let now = ts("2026-06-04T23:00:00Z"); // 23h
        assert!(enforce_inception_key_window(bootstrap, now).is_ok());
    }

    #[test]
    fn age_over_24h_is_rejected_even_with_longer_self_reported_window() {
        // The deployment may *self-report* a longer window, but the receiver
        // enforces the 24h hard cap regardless: 25h MUST reject.
        let bootstrap = ts("2026-06-04T00:00:00Z");
        let now = ts("2026-06-05T01:00:00Z"); // 25h
        assert_eq!(
            enforce_inception_key_window(bootstrap, now),
            Err(InceptionKeyWindowError::Exceeded)
        );
    }

    #[test]
    fn exactly_24h_boundary_is_allowed() {
        // `inception_key_age_exceeded` uses strict `>`, so exactly 24h is not
        // yet "exceeded".
        let bootstrap = ts("2026-06-04T00:00:00Z");
        let now = ts("2026-06-05T00:00:00Z"); // exactly 24h
        assert!(enforce_inception_key_window(bootstrap, now).is_ok());
    }

    #[test]
    fn missing_anchor_fails_closed() {
        let now = ts("2026-06-04T12:00:00Z");
        assert_eq!(
            enforce_inception_key_window_rfc3339(None, now),
            Err(InceptionKeyWindowError::Exceeded)
        );
        assert_eq!(
            enforce_inception_key_window_rfc3339(Some("   "), now),
            Err(InceptionKeyWindowError::Exceeded)
        );
    }

    #[test]
    fn unparseable_anchor_fails_closed() {
        let now = ts("2026-06-04T12:00:00Z");
        assert_eq!(
            enforce_inception_key_window_rfc3339(Some("not-a-timestamp"), now),
            Err(InceptionKeyWindowError::Exceeded)
        );
    }

    #[test]
    fn rfc3339_anchor_under_window_allowed() {
        let now = ts("2026-06-04T10:00:00Z");
        assert!(enforce_inception_key_window_rfc3339(Some("2026-06-04T00:00:00Z"), now).is_ok());
    }

    #[test]
    fn reason_code_matches_sdk_registry() {
        assert_eq!(
            InceptionKeyWindowError::Exceeded.reason_code(),
            "inception_key_window_exceeded"
        );
    }
}
