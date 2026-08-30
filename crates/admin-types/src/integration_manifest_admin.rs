//! Admin DTOs for the coauth integration manifest discovery surface.
//!
//! Mirrors the wire shape emitted by:
//!
//! - `GET /_coauth/gate/account/integration/describe` — `IntegrationManifestResponse` from
//!   `coauth/crates/backend/src/handlers/account/auth/oidc_bridge.rs`.
//!
//! These types contain only stable discovery data consumed by sodmin.
//! Historical rollout metadata, TODO text, and example payloads belong
//! in documentation or OpenAPI rather than the runtime contract.

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
}

/// One declared dependency on another arkret service or external
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
    fn manifest_decodes_backend_wire_payload() {
        let wire = r#"{
            "contract": "arkret.rest.integration_manifest.v1",
            "service": "coauth",
            "service_kind": "account_authority",
            "api_base_path": "/_coauth",
            "describe_path": "/_coauth/gate/account/integration/describe",
            "dependencies": [
                {
                    "service": "soland",
                    "purpose": "station_session_exchange",
                    "required_contract": "arkret.rest.principal_bridge.v1",
                    "discovery_path": "/_coauth/gate/account/auth/bridge/describe",
                    "mode": "remote_service_contract"
                }
            ],
            "surfaces": [
                {
                    "name": "auth_bridge",
                    "method": "GET",
                    "path": "/_coauth/gate/account/auth/bridge/describe",
                    "contract": "arkret.rest.auth_bridge.v1"
                }
            ]
        }"#;
        let m: IntegrationManifest = serde_json::from_str(wire).unwrap();
        assert_eq!(m.service, "coauth");
        assert_eq!(m.service_kind, "account_authority");
        assert_eq!(m.dependencies.len(), 1);
        assert_eq!(m.dependencies[0].service, "soland");
        assert_eq!(m.surfaces.len(), 1);
        assert_eq!(m.surfaces[0].name, "auth_bridge");
    }

    #[test]
    fn dependency_round_trip() {
        let d = IntegrationManifestDependency {
            service: "soland".into(),
            purpose: "session-exchange".into(),
            required_contract: "arkret.rest.principal_bridge.v1".into(),
            discovery_path: "/_coauth/gate/account/auth/bridge/describe".into(),
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
            path: "/_coauth/admin/bridge/describe".into(),
            contract: "arkret.rest.coauth_admin_bridge.v1".into(),
        };
        let s = serde_json::to_string(&s_in).unwrap();
        let back: IntegrationManifestSurface = serde_json::from_str(&s).unwrap();
        assert_eq!(s_in, back);
    }
}
