use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

/// Contrix-specific deployment settings layered on top of the generic OIDC
/// and account-management configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContrixConfig {
    /// Principal Server audiences trusted to consume session grants and admin
    /// tokens emitted by coauth.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_servers: Vec<PrincipalServerConfig>,

    /// External DID / identity registry resolver used for Contrix identity
    /// binding workflows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry: Option<IdentityRegistryConfig>,

    /// `starid` registry endpoint used by onboarding / recovery flows to
    /// mint and verify managed `did:webvh` identifiers for principals.
    /// When omitted, principal-DID minting falls back to the local
    /// `did:web` derivation in [`crate::services::did_resolver`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starid: Option<StaridConfig>,

    /// Optional explicit service DID for the coauth deployment.
    ///
    /// When omitted, the backend derives a `did:web` identifier from
    /// `http.public_base`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_did: Option<String>,

    /// Optional issuer DID to embed in Contrix session grants and discovery
    /// documents. Defaults to `service_did`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,

    /// Audience string expected by Contrix admin integrations.
    ///
    /// When omitted, the backend falls back to the local `/api/v1` endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_audience: Option<String>,

    /// Base URL of the principal server (`soland`) used for cross-service
    /// consent-cell queries (Move/Anchor/Lattice model — see consent-model
    /// spec §3-§9). When omitted, the consent gate degrades to a
    /// `consent_unknown` result and the caller decides the policy outcome.
    ///
    /// Override at runtime via `COAUTH_PRINCIPAL_SERVER_URL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_server_url: Option<Url>,

    /// Minimum number of distinct admin DID approvals required to execute a
    /// high-risk risk-action proposal. Defaults to `2`.
    ///
    /// "High-risk" actions today are `disable`, `erase`, and `reset_recovery`;
    /// the action `lock` is treated as low-risk and only needs the proposer's
    /// own approval.
    #[serde(default = "default_high_risk_threshold")]
    pub high_risk_threshold: u32,
}

fn default_high_risk_threshold() -> u32 {
    2
}

impl Default for ContrixConfig {
    fn default() -> Self {
        Self {
            principal_servers: Vec::new(),
            identity_registry: None,
            starid: None,
            service_did: None,
            issuer_did: None,
            admin_audience: None,
            principal_server_url: None,
            high_risk_threshold: default_high_risk_threshold(),
        }
    }
}

impl ContrixConfig {
    /// Returns `true` when the Contrix section carries no explicit overrides.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.principal_servers.is_empty()
            && self.identity_registry.is_none()
            && self.starid.is_none()
            && self.service_did.is_none()
            && self.issuer_did.is_none()
            && self.admin_audience.is_none()
            && self.principal_server_url.is_none()
            && self.high_risk_threshold == default_high_risk_threshold()
    }
}

impl ConfigurationSection for ContrixConfig {
    const PATH: &'static str = "contrix";
}

/// Trusted Principal Server metadata published through Contrix discovery.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalServerConfig {
    /// Human-readable identifier for the consumer, such as `soland-prod`.
    pub name: String,

    /// Audience string used when validating tokens or session grants for this
    /// Principal Server.
    pub audience: String,

    /// Base URL of the Principal Server integration point.
    pub endpoint: Url,

    /// Optional DID advertised for this Principal Server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,

    /// Optional static bearer token accepted when this Principal Server calls
    /// coauth's OAuth 2.0 introspection endpoint. This is intended for
    /// server-to-server resource-server authentication, not for browser
    /// clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_introspection_bearer: Option<String>,

    /// Optional static bearer token accepted when this Principal Server calls
    /// coauth's legacy Contrix session-grant introspection endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_grant_introspection_bearer: Option<String>,

    /// Optional static bearer token coauth should send when writing embedded
    /// `did:webvh` registration records into this Principal Server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_webvh_registration_bearer: Option<String>,
}

/// External identity-registry resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IdentityRegistryConfig {
    /// Resolver flavour used by the deployment.
    #[serde(default)]
    pub kind: IdentityRegistryKind,

    /// Base URL of the resolver, for example a public DID resolver deployment.
    pub resolver: Url,

    /// Whether pairwise or private DID lookups require proof material before
    /// the resolver should be queried.
    #[serde(default)]
    pub proof_required_for_pairwise: bool,
}

/// Supported identity-registry resolver flavours.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRegistryKind {
    /// Resolver backed by public DID methods or delegated DID services.
    #[default]
    PublicDidResolver,
    /// Generic external resolver.
    External,
}

/// `starid` registry endpoint configuration.
///
/// The principal-server (coauth) calls into starid during onboarding and
/// recovery to mint a managed `did:webvh` for the principal and to
/// verify control-proofs on subsequent privileged operations. The
/// adapter implementation lives in
/// [`crate::services::starid_adapter::StaridResolver`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StaridConfig {
    /// Base URL of the starid deployment, for example
    /// `https://starid.example.com`. Path segments are ignored — the
    /// adapter joins `/api/v1/webvh/...` itself.
    pub base_url: Url,

    /// `host` value passed to starid's `POST /api/v1/webvh/dids`. Defaults
    /// to the host of `base_url` when omitted. Override when starid is
    /// fronted by a different public-facing hostname than the URL coauth
    /// reaches it on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_host: Option<String>,

    /// Path prefix for minted principal DIDs (e.g. `accounts`). The
    /// adapter appends the account's stable id, so the final path is
    /// `<path_prefix>/<account_id>`.
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,

    /// Optional bearer token for starid's admin endpoints. When set,
    /// the adapter prefers `POST /admin/api/v1/dids` over the public
    /// `POST /api/v1/webvh/dids` — both produce the same DID but the
    /// admin route bypasses public-rate-limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_token: Option<String>,
}

fn default_path_prefix() -> String {
    "accounts".to_owned()
}
