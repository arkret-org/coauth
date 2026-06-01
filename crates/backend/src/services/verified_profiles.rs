//! G4.T3 — coauth-side loader for cotest's `verified-profiles.json`
//! artifact.
//!
//! Mirror of `soland/src/verified_profiles.rs`. The wire schema (`version`,
//! `generated_at`, `run_id`, `verified[]`) is identical across both
//! services; the only thing that differs is the `service_role` filter:
//! - soland filters to `principal_server`
//! - coauth filters to [`COAUTH_SERVICE_ROLE`] (`auth_server`)
//!
//! The env var [`VERIFIED_PROFILES_ARTIFACT_ENV`]
//! (`COAUTH_VERIFIED_PROFILES_ARTIFACT`) is the feature flag — there is no
//! Cargo cfg for this surface. When the env var is unset OR the file is
//! missing OR malformed, the loader returns an empty Vec and the wire
//! `verified_profiles[]` slot stays `[]` (dev-mode invariant per
//! service-surface.md §3.0).
//!
//! Cross-check: the consumer (currently
//! `handlers::contrix::service_describe_response`) MUST additionally drop
//! any loaded entry whose `profile_id` is absent from coauth's local
//! `claimed_profiles[]` set. The check is intentionally external — this
//! module just parses + role-filters and leaves the claim invariant to the
//! describe builder where the truth source for `claimed_profiles` lives.

use camino::Utf8Path;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::Arc;

/// Env var coauth reads at startup to locate the cotest
/// `verified-profiles.json` artifact. Empty / unset disables the loader.
pub const VERIFIED_PROFILES_ARTIFACT_ENV: &str = "COAUTH_VERIFIED_PROFILES_ARTIFACT";

/// coauth's role string. Mirrors `service_roles[]` in
/// `handlers::contrix::service_describe_response` and the canonical role
/// names in
/// `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json#/profile_role_map`.
pub const COAUTH_SERVICE_ROLE: &str = "auth_server";

#[derive(Debug, Deserialize)]
struct VerifiedProfilesArtifact {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    generated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    verified: Vec<RawVerifiedEntry>,
}

#[derive(Debug, Deserialize)]
struct RawVerifiedEntry {
    profile_id: String,
    #[serde(default)]
    service_role: Option<String>,
    #[serde(default)]
    test_count: Option<u64>,
    #[serde(default)]
    spec_file: Option<String>,
    #[serde(default)]
    artifact_digest: Option<String>,
    #[serde(default)]
    artifact_ref: Option<String>,
    #[serde(default)]
    cotest_issuer_did: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

/// In-memory representation of a loaded verified-profile entry, consumed
/// by `handlers::contrix::service_describe_response`. The handler converts
/// each entry into the wire-shaped `VerifiedProfileDescriptor` on the way
/// out (different struct because contrix.rs uses `&'static str` for the
/// `claim_kind` discriminant — coauth's describe builder pre-dates the SDK
/// switch).
#[derive(Debug, Clone)]
pub struct VerifiedProfileDescriptor {
    pub profile_id: String,
    pub service_role: String,
    pub cotest_run_id: String,
    pub artifact_digest: String,
    pub artifact_ref: String,
    pub cotest_issuer_did: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub test_count: u64,
    pub spec_file: Option<String>,
}

/// Read the artifact pointed to by [`VERIFIED_PROFILES_ARTIFACT_ENV`] (if
/// any) and return entries whose `service_role` matches
/// [`COAUTH_SERVICE_ROLE`]. The function never panics and never returns
/// `Err`; on any failure path it logs and returns an empty Vec.
pub fn load_from_env() -> Arc<Vec<VerifiedProfileDescriptor>> {
    let path = match std::env::var(VERIFIED_PROFILES_ARTIFACT_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            tracing::debug!(
                target: "verified_profiles",
                env_var = VERIFIED_PROFILES_ARTIFACT_ENV,
                "verified-profiles artifact env var unset; verified_profiles=[] (dev-mode invariant)"
            );
            return Arc::new(Vec::new());
        }
    };
    Arc::new(load_from_path(&path))
}

/// Split-out body of [`load_from_env`] for tests and for callers that
/// already have the artifact path resolved.
pub fn load_from_path(path: impl AsRef<Utf8Path>) -> Vec<VerifiedProfileDescriptor> {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path,
                %error,
                "verified-profiles artifact path is set but file is unreadable; verified_profiles=[]"
            );
            return Vec::new();
        }
    };
    let parsed: VerifiedProfilesArtifact = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path,
                %error,
                "verified-profiles artifact failed to parse as JSON; verified_profiles=[]"
            );
            return Vec::new();
        }
    };

    let run_id = parsed.run_id.unwrap_or_default();
    let generated_at = parsed.generated_at.unwrap_or_else(Utc::now);
    let total_input = parsed.verified.len();
    let mut out = Vec::with_capacity(total_input);
    for entry in parsed.verified {
        let role = match entry.service_role.as_deref() {
            Some(r) => r,
            None => {
                tracing::warn!(
                    target: "verified_profiles",
                    profile_id = %entry.profile_id,
                    "dropping verified-profile entry: missing service_role"
                );
                continue;
            }
        };
        if role != COAUTH_SERVICE_ROLE {
            continue;
        }
        let Some(artifact_digest) = valid_artifact_digest(entry.artifact_digest, &entry.profile_id)
        else {
            continue;
        };
        let Some(artifact_ref) =
            required_non_empty(entry.artifact_ref, "artifact_ref", &entry.profile_id)
        else {
            continue;
        };
        let Some(cotest_issuer_did) = required_non_empty(
            entry.cotest_issuer_did,
            "cotest_issuer_did",
            &entry.profile_id,
        ) else {
            continue;
        };
        if !cotest_issuer_did.starts_with("did:") {
            tracing::warn!(
                target: "verified_profiles",
                profile_id = %entry.profile_id,
                cotest_issuer_did = %cotest_issuer_did,
                "dropping verified-profile entry: cotest_issuer_did must be a DID"
            );
            continue;
        }
        let Some(signature) = required_non_empty(entry.signature, "signature", &entry.profile_id)
        else {
            continue;
        };
        out.push(VerifiedProfileDescriptor {
            profile_id: entry.profile_id,
            service_role: role.to_owned(),
            cotest_run_id: run_id.clone(),
            artifact_digest,
            artifact_ref,
            cotest_issuer_did,
            signature,
            timestamp: generated_at,
            expires_at: entry.expires_at,
            test_count: entry.test_count.unwrap_or(0),
            spec_file: entry.spec_file,
        });
    }

    tracing::info!(
        target: "verified_profiles",
        path = %path,
        version = parsed.version.as_deref().unwrap_or(""),
        run_id = %run_id,
        loaded = out.len(),
        total_in_artifact = total_input,
        service_role = COAUTH_SERVICE_ROLE,
        "loaded verified-profile entries from artifact"
    );
    out
}

fn valid_artifact_digest(value: Option<String>, profile_id: &str) -> Option<String> {
    let hash = required_non_empty(value, "artifact_digest", profile_id)?;
    if hash.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }) {
        return Some(hash);
    }
    tracing::warn!(
        target: "verified_profiles",
        profile_id = %profile_id,
        "dropping verified-profile entry: artifact_digest must match sha256:<64 lowercase hex>"
    );
    None
}

fn required_non_empty(value: Option<String>, field: &str, profile_id: &str) -> Option<String> {
    match value {
        Some(value) if !value.trim().is_empty() => Some(value),
        _ => {
            tracing::warn!(
                target: "verified_profiles",
                profile_id = %profile_id,
                field = %field,
                "dropping verified-profile entry: missing required field"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn malformed_json_yields_empty() {
        let dir = tempfile_dir();
        let path = dir.join("verified-profiles.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let v = load_from_path(&path);
        assert!(v.is_empty());
    }

    #[test]
    fn missing_file_yields_empty() {
        let v = load_from_path("Z:/definitely/nonexistent/verified-profiles.json");
        assert!(v.is_empty());
    }

    #[test]
    fn filters_to_auth_server_role() {
        let dir = tempfile_dir();
        let path = dir.join("verified-profiles.json");
        let mut f = std::fs::File::create(&path).unwrap();
        let payload = r#"{
            "version": "1",
            "generated_at": "2026-05-20T00:00:00Z",
            "run_id": "test-run",
            "verified": [
                {
                    "profile_id": "cx.profile.principal_server.v1",
                    "service_role": "principal_server",
                    "test_count": 3,
                    "spec_file": "cotest/e2e/tests/conformance/profile-gates.spec.ts",
                    "artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "artifact_ref": "file:///tmp/verified-profiles.json",
                    "cotest_issuer_did": "did:web:cotest.example",
                    "signature": "eddsa-jcs-b64url:test-principal-signature"
                },
                {
                    "profile_id": "cx.profile.auth_server.v1",
                    "service_role": "auth_server",
                    "test_count": 1,
                    "spec_file": "cotest/e2e/tests/sync/service-surface-contract.spec.ts",
                    "artifact_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "artifact_ref": "file:///tmp/verified-profiles.json",
                    "cotest_issuer_did": "did:web:cotest.example",
                    "signature": "eddsa-jcs-b64url:test-auth-signature",
                    "expires_at": "2026-06-20T00:00:00Z"
                }
            ]
        }"#;
        f.write_all(payload.as_bytes()).unwrap();
        let v = load_from_path(&path);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].profile_id, "cx.profile.auth_server.v1");
        assert_eq!(v[0].service_role, "auth_server");
        assert_eq!(v[0].cotest_run_id, "test-run");
        assert_eq!(
            v[0].artifact_digest,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(v[0].artifact_ref, "file:///tmp/verified-profiles.json");
        assert_eq!(v[0].cotest_issuer_did, "did:web:cotest.example");
        assert_eq!(v[0].signature, "eddsa-jcs-b64url:test-auth-signature");
        assert_eq!(
            v[0].expires_at.unwrap().to_rfc3339(),
            "2026-06-20T00:00:00+00:00"
        );
    }

    fn tempfile_dir() -> camino::Utf8PathBuf {
        let temp = camino::Utf8PathBuf::from_path_buf(std::env::temp_dir())
            .expect("system temp dir is not valid UTF-8");
        let p = temp.join(format!("coauth-verified-profiles-{}", uniq()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn uniq() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
