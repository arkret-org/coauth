//! Admin DTOs for the coauth integration manifest discovery surface.
//!
//! Mirrors the wire shape emitted by:
//!
//! - `GET /api/v1/integration/describe` — `IntegrationManifestResponse` from
//!   `coauth/crates/backend/src/handlers/account/auth/oidc_bridge.rs`.
//!
//! Round-34 (C34.2): lifted out of the inline
//! `IntegrationManifestResponse` / `IntegrationManifestDependency` /
//! `IntegrationManifestSurface` definitions on the backend and the
//! divergent `CoauthIntegrationManifest` / `CoauthIntegrationDependency` /
//! `CoauthIntegrationSurface` decoder shims in `sodmin/src/api/coauth.rs`.
//!
//! Wire-drift caught: the sodmin shim was **missing the `examples` field
//! entirely** — the backend has been emitting a JSON object that
//! describes the multi-step compose flow (oidc browser bridge →
//! exchange → soland session-grant → push register-device), and the
//! sodmin decoder silently dropped it on the floor every call. The
//! shared shape now decodes it as `serde_json::Value` so the SPA can
//! render it in a future panel iteration without another migration.

use serde::{Deserialize, Serialize};

/// Top-level integration manifest response.
///
/// Field order mirrors `IntegrationManifestResponse` in
/// `coauth/crates/backend/src/handlers/account/auth/oidc_bridge.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct IntegrationManifest {
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub service_kind: String,
    #[serde(default)]
    pub api_base_path: String,
    #[serde(default)]
    pub describe_path: String,
    #[serde(default)]
    pub dependencies: Vec<IntegrationManifestDependency>,
    #[serde(default)]
    pub surfaces: Vec<IntegrationManifestSurface>,
    /// Compose-flow examples (multi-service step graph). The backend
    /// emits this as a free-form JSON object so the SPA can render it
    /// without locking the schema down before the compose contract
    /// stabilizes — but **the field has to be on the wire shape** so it
    /// stops being silently dropped.
    #[serde(default)]
    pub examples: serde_json::Value,
    #[serde(default)]
    pub todos: Vec<String>,
}

/// One declared dependency on another contrix service or external
/// resolver.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct IntegrationManifestDependency {
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub required_contract: String,
    #[serde(default)]
    pub discovery_path: String,
    #[serde(default)]
    pub mode: String,
}

/// One advertised REST surface inside the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct IntegrationManifestSurface {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub stability: String,
    #[serde(default)]
    pub todo: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_default_round_trips_through_serde_json() {
        let m = IntegrationManifest::default();
        let s = serde_json::to_string(&m).unwrap();
        let back: IntegrationManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn manifest_decodes_backend_wire_payload_with_examples() {
        // Mirrors what `oidc_bridge::integration_describe` actually emits
        // — including the multi-step compose-flow `examples` block that
        // the prior sodmin shim was silently dropping on the floor.
        let wire = r#"{
            "contract": "contrix.rest.integration_manifest.v1",
            "version": "2026-05-04-scaffold",
            "service": "coauth",
            "service_kind": "account_authority",
            "api_base_path": "/api/v1",
            "describe_path": "/api/v1/integration/describe",
            "dependencies": [
                {
                    "service": "soland",
                    "purpose": "principal_server_session_exchange",
                    "required_contract": "contrix.rest.principal_bridge.v1",
                    "discovery_path": "/api/v1/auth/bridge/describe",
                    "mode": "remote_service_contract"
                }
            ],
            "surfaces": [
                {
                    "name": "auth_bridge",
                    "method": "GET",
                    "path": "/api/v1/auth/bridge/describe",
                    "contract": "contrix.rest.auth_bridge.v1",
                    "stability": "scaffold",
                    "todo": "TODO: keep aligned"
                }
            ],
            "examples": {
                "compose_flow": {
                    "step_1": {"service": "coauth", "path": "/api/v1/auth/oidc/browser-bridge/session", "method": "POST"},
                    "step_2": {"service": "coauth", "path": "/api/v1/auth/oidc/exchange", "method": "POST"}
                }
            },
            "todos": ["TODO: persist things"]
        }"#;
        let m: IntegrationManifest = serde_json::from_str(wire).unwrap();
        assert_eq!(m.service, "coauth");
        assert_eq!(m.service_kind, "account_authority");
        assert_eq!(m.dependencies.len(), 1);
        assert_eq!(m.dependencies[0].service, "soland");
        assert_eq!(m.surfaces.len(), 1);
        assert_eq!(m.surfaces[0].name, "auth_bridge");
        // The previously-dropped `examples` field — now visible.
        assert!(m.examples.is_object());
        assert!(m.examples.get("compose_flow").is_some());
        assert_eq!(m.todos.len(), 1);
    }

    #[test]
    fn dependency_round_trip() {
        let d = IntegrationManifestDependency {
            service: "soland".into(),
            purpose: "session-exchange".into(),
            required_contract: "contrix.rest.principal_bridge.v1".into(),
            discovery_path: "/api/v1/auth/bridge/describe".into(),
            mode: "remote_service_contract".into(),
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: IntegrationManifestDependency = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn surface_round_trip() {
        let s_in = IntegrationManifestSurface {
            name: "admin_bridge".into(),
            method: "GET".into(),
            path: "/api/admin/v1/bridge/describe".into(),
            contract: "contrix.rest.coauth_admin_bridge.v1".into(),
            stability: "scaffold".into(),
            todo: "TODO".into(),
        };
        let s = serde_json::to_string(&s_in).unwrap();
        let back: IntegrationManifestSurface = serde_json::from_str(&s).unwrap();
        assert_eq!(s_in, back);
    }
}
