use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

/// Contrix-specific deployment settings layered on top of the generic OIDC
/// and account-management configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct ContrixConfig {
    /// Principal Server audiences trusted to consume session grants and admin
    /// tokens emitted by coauth.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_servers: Vec<PrincipalServerConfig>,

    /// External DID / identity registry resolver used for Contrix identity
    /// binding workflows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry: Option<IdentityRegistryConfig>,

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
}

impl ContrixConfig {
    /// Returns `true` when the Contrix section carries no explicit overrides.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.principal_servers.is_empty()
            && self.identity_registry.is_none()
            && self.service_did.is_none()
            && self.issuer_did.is_none()
            && self.admin_audience.is_none()
            && self.principal_server_url.is_none()
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
