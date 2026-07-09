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
//! [`arkret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`].
//!
//! This module is the thin, hermetic enforcement primitive: it wraps the SDK
//! age check ([`arkret_core::inception_key_age_exceeded`]) and adds the
//! **fail-closed** discipline for missing / unparseable anchors. The 24h cap is
//! a protocol hard limit sourced from the SDK constant — it is intentionally
//! *not* configurable.
//!
//! ## Mount-point status
//!
//! coauth's current production session grants are still signed by the
//! deployment service key, and managed-DID device enrollment is
//! `service_attested` by the persistent enrollment authority. Those paths are
//! inert unless the request / signed grant explicitly carries an inception
//! bootstrap anchor or selects an inception-key proof branch. When that happens,
//! the session-grant and device-enroll handlers call this primitive before
//! issuing or minting downstream material, preserving the same fail-closed
//! reason code on every mount point.

use chrono::{DateTime, Utc};
use arkret_core::inception_key_age_exceeded;
use serde_json::Value;

const INCEPTION_KEY_VERSION_TIME: &str = "inception_key_version_time";
const INCEPTION_KEY_VERSION_TIME_CAMEL: &str = "inceptionKeyVersionTime";
const VERSION_TIME: &str = "version_time";
const VERSION_TIME_CAMEL: &str = "versionTime";

/// Receiver-side decision: may an inception key whose bootstrap anchor is
/// `bootstrap_ts` still sign at `now`?
///
/// Returns `Ok(())` only when the inception key is within the 24h hard cap.
/// Returns [`InceptionKeyWindowError::Exceeded`] when the age exceeds the cap —
/// the caller MUST reject the issuance and surface
/// [`arkret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`].
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

/// Extract a client-presented inception-key entry-0 `versionTime` from a
/// session-grant request body. The SDK request model has not grown a
/// first-class field yet, so coauth reads the raw JSON overlay while still
/// deserializing the rest of the body through the SDK type.
pub fn session_grant_request_anchor(raw_body: &Value) -> Option<&str> {
    raw_body
        .pointer("/proof")
        .and_then(version_time_field)
        .or_else(|| version_time_field(raw_body))
}

/// Extract the same anchor from account device-enroll request overlays.
pub fn device_authorize_request_anchor(raw_body: &Value) -> Option<&str> {
    version_time_field(raw_body)
}

/// Extract an anchor carried forward inside a signed session grant's
/// `scope_details` overlay.
pub fn scope_details_anchor(scope_details: &Value) -> Option<&str> {
    version_time_field(scope_details)
}

fn version_time_field(value: &Value) -> Option<&str> {
    value
        .get(INCEPTION_KEY_VERSION_TIME)
        .or_else(|| value.get(INCEPTION_KEY_VERSION_TIME_CAMEL))
        .or_else(|| value.get(VERSION_TIME))
        .or_else(|| value.get(VERSION_TIME_CAMEL))
        .and_then(Value::as_str)
}

/// Failure of the receiver-side inception-key window check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InceptionKeyWindowError {
    /// The inception key is past its 24h online window (or its bootstrap
    /// anchor was missing / unparseable, which fails closed). Maps to wire
    /// reason code
    /// [`arkret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`].
    #[error("inception key online window (24h hard cap) exceeded")]
    Exceeded,
}

impl InceptionKeyWindowError {
    /// Stable wire reason code, sourced from the SDK registry so coauth and the
    /// protocol never drift.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        arkret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED
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
