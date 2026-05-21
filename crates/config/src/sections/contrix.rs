use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

/// Round R2/R3 (2026-05-20) — deployment-scope trust-domain prefix.
///
/// A `trust_domain` value MUST match `cx:trust_domain:<scope>` where
/// `<scope>` is `[a-z0-9._:-]{1,128}`. This mirrors the SDK validator
/// `contrix_core::TypedTrustDomainId` so coauth and the Realm policy
/// engine agree on the exact byte-form. Validate via
/// [`validate_trust_domain`].
const TRUST_DOMAIN_PREFIX: &str = "cx:trust_domain:";
const TRUST_DOMAIN_MAX_SCOPE_LEN: usize = 128;

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

    /// Round R2/R3 (2026-05-20) — deployment trust-domain identifier
    /// injected into Realm policy and the server-describe document.
    ///
    /// Wire form: `cx:trust_domain:<scope>` where `<scope>` matches
    /// `[a-z0-9._:-]{1,128}`. This value enters the canonical transcript
    /// of every `cx.cross_signing.reset` proof; **changing
    /// `trust_domain` invalidates existing cross-signing reset proofs**
    /// — see the README "Trust domain rotation" note.
    ///
    /// When omitted, callers expected to honour cross-deployment replay
    /// protection (`Realm` policy, principal-server describe) MUST be
    /// told the trust domain is unset and fail closed.
    ///
    /// Typically injected into `soland` via its config API on first
    /// boot; see `services::onboarding_starid` for the call site.
    // TODO(round23-T08): once soland exposes a `PATCH /admin/v1/policy/
    //  trust_domain` mutation, propagate changes from coauth's runtime
    //  reload through that channel rather than requiring a soland
    //  restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,

    /// Round R2/R3 (2026-05-20) — selects the OOB code mint form for
    /// 3PID invites. Default `OfflineVerifiable` mints a ≥128-bit
    /// opaque token; `Lookup` mints a short human-typeable code with
    /// server-side pepper + 3-strike invalidation. See
    /// `backend::services::oob_code` for the implementation.
    #[serde(default)]
    pub oob_code_kind: OobCodeKindConfig,

    /// Round 4 — DID of the trusted 3PID verification service whose
    /// `binding_proof` JWTs this coauth deployment will accept on
    /// `POST /api/v1/invites/3pid/verify`. When omitted, the invite
    /// verifier endpoint returns `503 verifier_not_configured` because
    /// it has no trusted `iss` to compare against.
    ///
    /// Override at runtime via `COAUTH_VERIFICATION_SERVICE_DID`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_service_did: Option<String>,
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
            trust_domain: None,
            oob_code_kind: OobCodeKindConfig::default(),
            verification_service_did: None,
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
            && self.trust_domain.is_none()
            && matches!(self.oob_code_kind, OobCodeKindConfig::OfflineVerifiable)
            && self.verification_service_did.is_none()
    }

    /// Validate the configured `trust_domain` (if any) against the SDK
    /// `cx:trust_domain:<scope>` wire format. Returns the borrowed
    /// scope half on success so call-sites can build the
    /// `TypedTrustDomainId` directly. Mirrors
    /// `contrix_core::TypedTrustDomainId::new`'s acceptance rules so
    /// the two never drift.
    ///
    /// # Errors
    ///
    /// Returns a static string when:
    /// - the value lacks the `cx:trust_domain:` prefix
    /// - the scope is empty or > 128 bytes
    /// - the first character is not `[a-z0-9]`
    /// - any byte is outside `[a-z0-9._:-]`
    pub fn validate_trust_domain<'a>(value: &'a str) -> Result<&'a str, &'static str> {
        let scope = value
            .strip_prefix(TRUST_DOMAIN_PREFIX)
            .ok_or("trust_domain MUST start with `cx:trust_domain:`")?;
        if scope.is_empty() {
            return Err("trust_domain scope MUST NOT be empty");
        }
        if scope.len() > TRUST_DOMAIN_MAX_SCOPE_LEN {
            return Err("trust_domain scope MUST be ≤128 bytes");
        }
        let bytes = scope.as_bytes();
        if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9') {
            return Err("trust_domain scope MUST start with [a-z0-9]");
        }
        let ok = scope.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b':'
            )
        });
        if !ok {
            return Err("trust_domain scope contains characters outside [a-z0-9._:-]");
        }
        Ok(scope)
    }
}

/// Round R2/R3 — wire-config mirror of
/// `backend::services::oob_code::OobCodeKind`. Lives in `config` so
/// schema export can reach it without pulling the backend crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum OobCodeKindConfig {
    /// Form 1 — offline-verifiable, ≥128-bit token.
    #[default]
    OfflineVerifiable,
    /// Form 2 — short lookup-style code; requires a server-side pepper
    /// and 3-strike invalidation.
    Lookup,
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
    /// coauth's OAuth introspection endpoint. This is intended for
    /// server-to-server resource-server authentication, not for browser
    /// clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_introspection_bearer: Option<String>,

    /// Optional static bearer token accepted when this Principal Server calls
    /// coauth's session-grant introspection endpoint
    /// (`/api/v1/contrix/session-grants/introspect`). Mirrors
    /// `oauth_introspection_bearer` for the session-grant exchange path:
    /// avoids requiring a DB-backed PAT/OAuth-session for the
    /// server-to-server hop, which is awkward in dev when the coauth DB
    /// is reset frequently.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_domain_accepts_well_formed_scope() {
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:example.net").is_ok());
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:soland-prod.eu").is_ok());
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:tenant_a.shard_1").is_ok());
    }

    #[test]
    fn trust_domain_rejects_uppercase_and_empty() {
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:Example").is_err());
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:").is_err());
        assert!(ContrixConfig::validate_trust_domain("example.net").is_err());
    }

    #[test]
    fn trust_domain_rejects_overlong_scope() {
        let too_long = format!("cx:trust_domain:{}", "a".repeat(129));
        assert!(ContrixConfig::validate_trust_domain(&too_long).is_err());
        let just_right = format!("cx:trust_domain:{}", "a".repeat(128));
        assert!(ContrixConfig::validate_trust_domain(&just_right).is_ok());
    }

    #[test]
    fn trust_domain_rejects_disallowed_chars() {
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:bad space").is_err());
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:bad/slash").is_err());
        // Scope MUST start with [a-z0-9], not a separator.
        assert!(ContrixConfig::validate_trust_domain("cx:trust_domain:.dotleader").is_err());
    }
}
