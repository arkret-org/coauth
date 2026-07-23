//! Coauth I/O adapter for cotest's `verified-profiles.json` artifact.

use std::sync::Arc;

use arkret_models_discovery::{VerifiedProfileArtifactEntry, parse_verified_profiles_artifact};
use camino::Utf8Path;

pub const VERIFIED_PROFILES_ARTIFACT_ENV: &str = "COAUTH_VERIFIED_PROFILES_ARTIFACT";
pub const COAUTH_SERVICE_ROLE: &str = "auth_server";

pub type VerifiedProfileDescriptor = VerifiedProfileArtifactEntry;

pub fn load_from_env() -> Arc<Vec<VerifiedProfileDescriptor>> {
    let path = match coauth_config::runtime_var(VERIFIED_PROFILES_ARTIFACT_ENV) {
        Ok(value) if !value.is_empty() => value,
        _ => {
            tracing::debug!(
                target: "verified_profiles",
                env_var = VERIFIED_PROFILES_ARTIFACT_ENV,
                "verified-profiles artifact env var unset; verified_profiles=[]"
            );
            return Arc::new(Vec::new());
        }
    };
    Arc::new(load_from_path(path))
}

pub fn load_from_path(path: impl AsRef<Utf8Path>) -> Vec<VerifiedProfileDescriptor> {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path,
                %error,
                "verified-profiles artifact is unreadable; verified_profiles=[]"
            );
            return Vec::new();
        }
    };
    let report = match parse_verified_profiles_artifact(&bytes, COAUTH_SERVICE_ROLE) {
        Ok(report) => report,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path,
                %error,
                "verified-profiles artifact is malformed; verified_profiles=[]"
            );
            return Vec::new();
        }
    };
    for dropped in &report.dropped {
        tracing::warn!(
            target: "verified_profiles",
            profile_id = %dropped.profile_id,
            reason = dropped.reason,
            "dropping invalid verified-profile entry"
        );
    }
    tracing::info!(
        target: "verified_profiles",
        path = %path,
        version = report.version.as_deref().unwrap_or(""),
        run_id = report.run_id.as_deref().unwrap_or(""),
        loaded = report.entries.len(),
        total_in_artifact = report.total_entries,
        service_role = COAUTH_SERVICE_ROLE,
        "loaded verified-profile entries from artifact"
    );
    report.entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_json_yields_empty() {
        let path = std::env::temp_dir().join(format!(
            "coauth-verified-profiles-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, b"{ not json").unwrap();
        let path = camino::Utf8PathBuf::from_path_buf(path).unwrap();
        assert!(load_from_path(path).is_empty());
    }

    #[test]
    fn filters_to_auth_server_role() {
        let path = std::env::temp_dir().join(format!(
            "coauth-verified-profiles-role-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            br#"{"verified":[
                {"profile_id":"principal","claim_kind":"conformance_verified","verification_run_id":"run","service_role":"principal_server","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact_ref":"file:///artifact","verifier_did":"did:web:cotest.example","signature":"sig","timestamp":"2026-05-20T00:00:00Z"},
                {"profile_id":"auth","claim_kind":"conformance_verified","verification_run_id":"run","service_role":"auth_server","artifact_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifact_ref":"file:///artifact","verifier_did":"did:web:cotest.example","signature":"sig","timestamp":"2026-05-20T00:00:00Z"}
            ]}"#,
        )
        .unwrap();
        let path = camino::Utf8PathBuf::from_path_buf(path).unwrap();
        let entries = load_from_path(path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].profile_id, "auth");
    }
}
