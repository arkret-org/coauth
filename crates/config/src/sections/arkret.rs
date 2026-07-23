use std::sync::{Arc, RwLock};

use arkret_identifiers::Did;
use arkret_identity::service_identity::{
    LocalServiceIdentity, ServiceIdentityDiagnostic, ServiceIdentityKeyRef, ServiceIdentityState,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_wire::ServiceType;
use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::ConfigurationSection;

/// Round R2/R3 (2026-05-20) — deployment-scope trust-domain prefix.
///
/// A `trust_domain` value MUST match `ak:trust_domain:<scope>` where
/// `<scope>` is `[a-z0-9._:-]{1,128}`. This mirrors the SDK validator
/// `arkret_identifiers::TypedTrustDomainId` so coauth and the Realm policy
/// engine agree on the exact byte-form. Validate via
/// [`validate_trust_domain`].
const TRUST_DOMAIN_PREFIX: &str = "ak:trust_domain:";
// 8 hours. The session grant is the refresh credential for a device session;
// the access bearers minted from it are short-lived (capped server-side), so a
// multi-hour grant gives a normal working-session length WITHOUT long-lived
// bearers. Stays within the spec ceiling (`conformance-profiles.md`
// §ak.profile.auth_server.v1: minutes-to-hours, not multi-day) and the
// configurable [min, max] = [60s, 24h] range below.
const SESSION_GRANT_TTL_MICROS: i64 = 8 * 60 * 60 * 1_000_000;
const SESSION_GRANT_TTL_MIN_SECONDS: i64 = 60;
const SESSION_GRANT_TTL_MAX_SECONDS: i64 = 86_400;
fn default_session_grant_ttl() -> Duration {
    Duration::microseconds(SESSION_GRANT_TTL_MICROS)
}

fn session_grant_ttl_is_default(ttl: &Duration) -> bool {
    *ttl == default_session_grant_ttl()
}

/// Deployment profile used to constrain Arkret identity and trust choices.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentProfileConfig {
    /// Single-user node profile that may opt into local `did:web` principals.
    PersonalNode,
    /// Small team deployment with managed principal issuance.
    SmallTeam,
    /// Default organization deployment profile.
    #[default]
    Organization,
    /// Organization profile for stricter operational controls.
    HighSecurityOrganization,
    /// Sovereign deployment profile for isolated trust domains.
    SovereignDeployment,
}

impl DeploymentProfileConfig {
    /// Return true when the value matches the serialized default.
    #[must_use]
    pub const fn is_default(value: &Self) -> bool {
        matches!(value, Self::Organization)
    }
}

/// Principal DID method selected for coauth-managed principals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PrincipalMethodConfig {
    /// Use `did:webvh` principal DIDs.
    #[serde(rename = "did:webvh")]
    #[default]
    DidWebvh,
    /// Use `did:web` principal DIDs.
    #[serde(rename = "did:web")]
    DidWeb,
}

impl PrincipalMethodConfig {
    /// Return the canonical DID method string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DidWebvh => "did:webvh",
            Self::DidWeb => "did:web",
        }
    }

    /// Return true when the value matches the serialized default.
    #[must_use]
    pub const fn is_default(value: &Self) -> bool {
        matches!(value, Self::DidWebvh)
    }
}

/// Shared runtime lifecycle state for the deployment service identity.
///
/// This handle is skipped by serde and schema generation because the DID is
/// resolved from a trusted Provider and never belongs in configuration.
#[derive(Clone)]
pub struct RuntimeServiceIdentity(Arc<RwLock<ServiceIdentityState>>);

impl std::fmt::Debug for RuntimeServiceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("RuntimeServiceIdentity")
            .field(&self.state())
            .finish()
    }
}

impl Default for RuntimeServiceIdentity {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(ServiceIdentityState::Faulted {
            diagnostic: ServiceIdentityDiagnostic::ProviderNotConfigured,
            next_action: "configure one trusted service-registration Provider endpoint and bearer"
                .to_owned(),
        })))
    }
}

impl RuntimeServiceIdentity {
    /// Returns a snapshot of the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> ServiceIdentityState {
        self.0
            .read()
            .expect("service identity lock poisoned")
            .clone()
    }

    /// Replaces the current state after validating its invariants.
    pub fn store(&self, state: ServiceIdentityState) {
        state.validate().expect("valid service identity state");
        *self.0.write().expect("service identity lock poisoned") = state;
    }

    /// Returns the resolved service DID when the state carries an identity.
    #[must_use]
    pub fn service_id(&self) -> Option<Did> {
        self.state()
            .identity()
            .map(|identity| identity.service_id.clone())
    }

    /// Returns whether normal request handling may proceed.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state().is_ready()
    }

    #[doc(hidden)]
    #[must_use]
    pub fn fixture(service_id: &str) -> Self {
        let signing_key_ref =
            ServiceIdentityKeyRef::new("fixture:coauth:signing").expect("fixture key ref");
        let handle = Self::default();
        handle.store(ServiceIdentityState::Ready {
            identity: LocalServiceIdentity {
                service_id: Did::new(service_id.to_owned()).expect("fixture service DID"),
                registration_key: ServiceRegistrationKey::new(
                    ServiceType::AuthServer,
                    CanonicalServiceUrl::canonicalize("https://auth.test/")
                        .expect("fixture public base"),
                )
                .expect("fixture registration key"),
                provider: None,
                signing_key_refs: vec![signing_key_ref.clone()],
                active_signing_key_ref: signing_key_ref,
                control_key_ref: ServiceIdentityKeyRef::new("fixture:coauth:control")
                    .expect("fixture control key ref"),
                version_id: "fixture-v1".to_owned(),
                last_verified_at: chrono::DateTime::UNIX_EPOCH,
            },
        });
        handle
    }
}

/// Arkret-specific deployment settings layered on top of the generic OIDC
/// and account-management configuration.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArkretConfig {
    /// Principal Server audiences trusted to consume session grants and admin
    /// tokens emitted by coauth.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_servers: Vec<PrincipalServerConfig>,

    /// Trusted services that provide the standard service-registration role
    /// without also acting as a Principal Server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_services: Vec<IdentityServiceConfig>,

    /// Provider name used only to disambiguate multiple registration-capable
    /// entries. A single candidate is selected automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_provider: Option<String>,

    /// Deployment profile that gates principal DID method choices.
    ///
    /// `did:web` is only valid for principal DIDs when this is
    /// `personal_node` and `principal_method` is explicitly `did:web`.
    /// Other built-in profiles use `did:webvh` for coauth-managed
    /// principal issuance.
    #[serde(default, skip_serializing_if = "DeploymentProfileConfig::is_default")]
    pub deployment_profile: DeploymentProfileConfig,

    /// Principal DID method selected by this deployment.
    ///
    /// Defaults to `did:webvh`; setting `did:web` is accepted only for
    /// `deployment_profile=personal_node`.
    #[serde(default, skip_serializing_if = "PrincipalMethodConfig::is_default")]
    pub principal_method: PrincipalMethodConfig,

    /// External DID / identity registry resolver used for Arkret identity
    /// binding workflows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry: Option<IdentityRegistryConfig>,

    /// Runtime-only Provider resolution result. Never serialized.
    #[serde(skip)]
    #[schemars(skip)]
    pub runtime_service_identity: RuntimeServiceIdentity,

    /// Lifetime of Arkret session grants, in seconds.
    ///
    /// These are the DPoP-bound JWT grants returned by the REST auth bridge
    /// login/exchange paths and rotated through
    /// `/_arkret/gate/account/session-grants/refresh`. Default: 28800 (8h) —
    /// access bearers minted from a grant are short-lived (capped Principal-Server
    /// side), so a multi-hour grant gives a normal working session without
    /// long-lived bearers, within the spec ceiling (minutes-to-hours).
    #[schemars(with = "u64", range(min = 60, max = 86400))]
    #[serde(
        default = "default_session_grant_ttl",
        skip_serializing_if = "session_grant_ttl_is_default"
    )]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub session_grant_ttl: Duration,

    /// Audience string expected by Arkret admin integrations.
    ///
    /// When omitted, the backend falls back to the local `/_arkret` endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_audience: Option<String>,

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
    /// Wire form: `ak:trust_domain:<scope>` where `<scope>` matches
    /// `[a-z0-9._:-]{1,128}`. This value enters the canonical transcript
    /// of every `ak.cross_signing.reset` proof; **changing
    /// `trust_domain` invalidates existing cross-signing reset proofs**
    /// — see the README "Trust domain rotation" note.
    ///
    /// When omitted, callers expected to honour cross-deployment replay
    /// protection (`Realm` policy, principal-server describe) MUST be
    /// told the trust domain is unset and fail closed.
    ///
    /// Typically provisioned consistently across the deployment.
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

    /// Fail-closed gate for the temporary password-login bridge that returns a
    /// Arkret principal-server session grant directly from
    /// `POST /_coauth/gate/account/auth/login`.
    ///
    /// Defaults to `false`: production callers must use the OIDC/passkey bridge
    /// and proof-bound grant exchange. When enabled for development, the login
    /// handler still requires a valid DPoP proof before minting the grant.
    #[serde(default, skip_serializing_if = "is_false")]
    pub password_login_session_grants_enabled: bool,

    /// Deployment-scoped organization id accepted by the Admin API.
    ///
    /// coauth does not yet model true multi-tenant ownership on every entity.
    /// Setting this makes admin requests supply the same
    /// `x-coauth-org-id` value and rejects all other orgs, so a deployment can
    /// fail closed instead of pretending cross-tenant admin isolation exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_org_id: Option<String>,

    /// Require signed admin-audit writes to succeed before committing
    /// security-sensitive admin mutations. Defaults to `false` so existing
    /// deployments tolerate missing service signing keys during rollout; set
    /// to `true` in production once JWKS publication and key rotation are
    /// operational.
    #[serde(default, skip_serializing_if = "is_false")]
    pub audit_signature_fail_closed: bool,
}

fn default_high_risk_threshold() -> u32 {
    2
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Default for ArkretConfig {
    fn default() -> Self {
        Self {
            principal_servers: Vec::new(),
            identity_services: Vec::new(),
            identity_provider: None,
            deployment_profile: DeploymentProfileConfig::default(),
            principal_method: PrincipalMethodConfig::default(),
            identity_registry: None,
            runtime_service_identity: RuntimeServiceIdentity::default(),
            session_grant_ttl: default_session_grant_ttl(),
            admin_audience: None,
            high_risk_threshold: default_high_risk_threshold(),
            trust_domain: None,
            oob_code_kind: OobCodeKindConfig::default(),
            password_login_session_grants_enabled: false,
            admin_org_id: None,
            audit_signature_fail_closed: false,
        }
    }
}

impl ArkretConfig {
    /// Returns `true` when the Arkret section carries no explicit overrides.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.principal_servers.is_empty()
            && self.identity_services.is_empty()
            && self.identity_provider.is_none()
            && DeploymentProfileConfig::is_default(&self.deployment_profile)
            && PrincipalMethodConfig::is_default(&self.principal_method)
            && self.identity_registry.is_none()
            && session_grant_ttl_is_default(&self.session_grant_ttl)
            && self.admin_audience.is_none()
            && self.high_risk_threshold == default_high_risk_threshold()
            && self.trust_domain.is_none()
            && matches!(self.oob_code_kind, OobCodeKindConfig::OfflineVerifiable)
            && !self.password_login_session_grants_enabled
            && self.admin_org_id.is_none()
            && !self.audit_signature_fail_closed
    }

    /// Set of host names this deployment trusts as outbound
    /// principal-server / identity-resolver targets.
    ///
    /// Built from every configured `principal_servers[].endpoint` and the
    /// `identity_registry.resolver`.
    /// Hosts are lower-cased so comparison is
    /// case-insensitive. Used by outbound relays (e.g. the consent-gated
    /// invite relay) to reject caller-supplied URLs that do not resolve to a
    /// configured trust anchor (deny-by-default for the federation hop).
    #[must_use]
    pub fn trusted_outbound_hosts(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |url: &Url| {
            if let Some(host) = url.host_str() {
                let host = host.to_ascii_lowercase();
                if !host.is_empty() && !out.iter().any(|existing| existing == &host) {
                    out.push(host);
                }
            }
        };
        for server in &self.principal_servers {
            push(&server.endpoint);
        }
        for service in &self.identity_services {
            push(&service.endpoint);
        }
        if let Some(registry) = self.identity_registry.as_ref() {
            push(&registry.resolver);
        }
        out
    }

    /// Returns `true` when `url`'s host matches a configured trust anchor
    /// (see [`Self::trusted_outbound_hosts`]). A `url` with no host is never
    /// trusted.
    #[must_use]
    pub fn is_trusted_outbound_target(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        self.trusted_outbound_hosts()
            .iter()
            .any(|trusted| trusted == &host)
    }

    /// Primary Principal Server endpoint for call sites that operate on a
    /// single server. The endpoint is topology configuration only; its
    /// service DID is always resolved at runtime.
    #[must_use]
    pub fn primary_principal_server_url(&self) -> Option<&Url> {
        self.principal_servers
            .first()
            .map(|server| &server.endpoint)
    }

    /// Returns whether this deployment explicitly opts into `did:web` as a
    /// principal method. Both fields must match the spec's personal-node
    /// exception; an omitted `principal_method` still means `did:webvh`.
    #[must_use]
    pub const fn did_web_principal_allowed(&self) -> bool {
        matches!(
            self.deployment_profile,
            DeploymentProfileConfig::PersonalNode
        ) && matches!(self.principal_method, PrincipalMethodConfig::DidWeb)
    }

    /// Validate the configured `trust_domain` (if any) against the SDK
    /// `ak:trust_domain:<scope>` wire format. Returns the borrowed
    /// scope half on success so call-sites can build the
    /// `TypedTrustDomainId` directly. Delegates the acceptance check to
    /// the SDK validator `arkret_identifiers::is_trust_domain` so the
    /// config side and the SDK never drift; the prefix strip below only
    /// recovers the `<scope>` slice for the success return.
    ///
    /// # Errors
    ///
    /// Returns a static string when the value is not a well-formed
    /// `ak:trust_domain:<scope>` (missing prefix, empty/oversized scope,
    /// bad leading byte, or any byte outside `[a-z0-9._:-]`).
    pub fn validate_trust_domain(value: &str) -> Result<&str, &'static str> {
        if !arkret_identifiers::is_trust_domain(value) {
            return Err(
                "trust_domain MUST be `ak:trust_domain:<scope>` with scope `[a-z0-9][a-z0-9._:-]{0,127}`",
            );
        }
        // `is_trust_domain` already guaranteed the prefix is present.
        value
            .strip_prefix(TRUST_DOMAIN_PREFIX)
            .ok_or("trust_domain MUST start with `ak:trust_domain:`")
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

impl ConfigurationSection for ArkretConfig {
    const PATH: &'static str = "arkret";

    fn validate(
        &self,
        _figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let min_ttl = Duration::try_seconds(SESSION_GRANT_TTL_MIN_SECONDS).unwrap();
        let max_ttl = Duration::try_seconds(SESSION_GRANT_TTL_MAX_SECONDS).unwrap();
        if self.session_grant_ttl < min_ttl || self.session_grant_ttl > max_ttl {
            return Err(std::io::Error::other(
                "arkret.session_grant_ttl must be between 60 and 86400 seconds",
            )
            .into());
        }

        if matches!(self.principal_method, PrincipalMethodConfig::DidWeb)
            && !matches!(
                self.deployment_profile,
                DeploymentProfileConfig::PersonalNode
            )
        {
            return Err(std::io::Error::other(
                "arkret.principal_method=did:web requires arkret.deployment_profile=personal_node",
            )
            .into());
        }

        if let Some(trust_domain) = self.trust_domain.as_deref() {
            Self::validate_trust_domain(trust_domain).map_err(std::io::Error::other)?;
        }

        if matches!(self.oob_code_kind, OobCodeKindConfig::Lookup) {
            return Err(std::io::Error::other(
                "arkret.oob_code_kind=lookup is disabled until lookup-mode strike counters are durable",
            )
            .into());
        }

        if let Some(org_id) = self.admin_org_id.as_deref()
            && org_id.trim().is_empty()
        {
            return Err(std::io::Error::other("arkret.admin_org_id must not be empty").into());
        }

        let mut provider_names = std::collections::BTreeSet::new();
        for server in &self.principal_servers {
            if server.name.trim().is_empty() {
                return Err(std::io::Error::other(
                    "arkret.principal_servers[].name must not be empty",
                )
                .into());
            }
            if server
                .embedded_webvh_registration_bearer
                .as_deref()
                .is_some_and(|bearer| bearer.trim().is_empty())
            {
                return Err(std::io::Error::other(
                    "arkret.principal_servers[].embedded_webvh_registration_bearer must not be empty",
                )
                .into());
            }
            if server.embedded_webvh_registration_bearer.is_some()
                && !provider_names.insert(server.name.as_str())
            {
                return Err(std::io::Error::other(
                    "service-registration Provider names must be unique",
                )
                .into());
            }
        }
        for service in &self.identity_services {
            if service.name.trim().is_empty() || service.registration_bearer.trim().is_empty() {
                return Err(std::io::Error::other(
                    "arkret.identity_services[] requires non-empty name and registration_bearer",
                )
                .into());
            }
            if !provider_names.insert(service.name.as_str()) {
                return Err(std::io::Error::other(
                    "service-registration Provider names must be unique",
                )
                .into());
            }
        }
        if let Some(selected) = self.identity_provider.as_deref()
            && (selected.trim().is_empty() || !provider_names.contains(selected))
        {
            return Err(std::io::Error::other(
                "arkret.identity_provider must name a configured registration-capable service entry",
            )
            .into());
        }

        // Fail closed: `password_login_session_grants_enabled` activates the
        // P0 password-bootstrap scaffold (auth.rs), which mints a
        // principal-server session grant directly from a password login,
        // bypassing the canonical OIDC `authorize -> token` ceremony, PKCE
        // binding and the PoP strand. It is a development-only bring-up
        // path that MUST be replaced before production. Require an explicit
        // dev-only environment escape hatch so a mis-configured production
        // deployment refuses to start instead of silently trusting these
        // grants. Mirrors `account.registration_email_delivery_bypass_allowed`.
        if self.password_login_session_grants_enabled
            && crate::runtime_var_os(PASSWORD_BOOTSTRAP_ESCAPE_HATCH).is_none()
        {
            return Err(std::io::Error::other(format!(
                "arkret.password_login_session_grants_enabled is enabled but the dev-only escape \
                 hatch {PASSWORD_BOOTSTRAP_ESCAPE_HATCH} is not set; this password-bootstrap \
                 scaffold is for dev/test only and must never run in production"
            ))
            .into());
        }

        Ok(())
    }
}

/// Dev-only escape hatch gating the P0 password-bootstrap session-grant
/// scaffold. Production deployments must never set
/// `arkret.password_login_session_grants_enabled=true`; requiring this
/// environment variable makes a mis-configured production process fail
/// closed at startup.
const PASSWORD_BOOTSTRAP_ESCAPE_HATCH: &str = "COAUTH_ALLOW_INSECURE_PASSWORD_BOOTSTRAP";

/// Trusted Principal Server metadata published through Arkret discovery.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrincipalServerConfig {
    /// Human-readable identifier for the consumer, such as `soland-prod`.
    pub name: String,

    /// Base URL of the Principal Server integration point.
    pub endpoint: Url,

    /// Optional static bearer for the Account Authority / Principal Server
    /// trust edge. The Principal Server presents it to coauth introspection and
    /// Auth-side logout; coauth presents the same deployment credential when
    /// reading the standard agent projection for lifecycle authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_grant_introspection_bearer: Option<String>,

    /// Optional static bearer token coauth should send when writing embedded
    /// `did:webvh` registration records into this Principal Server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_webvh_registration_bearer: Option<String>,
}

/// Trusted standalone service-identity Provider metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityServiceConfig {
    /// Operator-facing stable name used for ambiguity resolution.
    pub name: String,

    /// Base URL serving the standard service-registration operations.
    pub endpoint: Url,

    /// Deployment credential authorizing service-registration calls.
    pub registration_bearer: String,
}

/// External identity-registry resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityRegistryConfig {
    /// Base URL of the resolver, for example a public DID resolver deployment.
    pub resolver: Url,

    /// Whether pairwise or private DID lookups require proof material before
    /// the resolver should be queried.
    #[serde(default)]
    pub proof_required_for_pairwise: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_service_config() -> ArkretConfig {
        ArkretConfig::default()
    }

    #[test]
    fn trust_domain_accepts_well_formed_scope() {
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:example.net").is_ok());
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:soland-prod.eu").is_ok());
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:tenant_a.shard_1").is_ok());
    }

    #[test]
    fn trust_domain_rejects_uppercase_and_empty() {
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:Example").is_err());
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:").is_err());
        assert!(ArkretConfig::validate_trust_domain("example.net").is_err());
    }

    #[test]
    fn trust_domain_rejects_overlong_scope() {
        let too_long = format!("ak:trust_domain:{}", "a".repeat(129));
        assert!(ArkretConfig::validate_trust_domain(&too_long).is_err());
        let just_right = format!("ak:trust_domain:{}", "a".repeat(128));
        assert!(ArkretConfig::validate_trust_domain(&just_right).is_ok());
    }

    #[test]
    fn trust_domain_rejects_disallowed_chars() {
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:bad space").is_err());
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:bad/slash").is_err());
        // Scope MUST start with [a-z0-9], not a separator.
        assert!(ArkretConfig::validate_trust_domain("ak:trust_domain:.dotleader").is_err());
    }

    #[test]
    fn lookup_oob_kind_is_fail_closed_until_strikes_are_durable() {
        let config = ArkretConfig {
            oob_code_kind: OobCodeKindConfig::Lookup,
            ..valid_service_config()
        };
        let figment = figment::Figment::new();
        assert!(config.validate(&figment).is_err());
    }

    #[test]
    fn session_grant_ttl_defaults_to_eight_hours() {
        // The session grant is the refresh credential for a device session;
        // access bearers minted from it are short-lived (capped server-side).
        // An 8h default gives a normal working-session length without long-lived
        // bearers, and stays within the spec ceiling (minutes-to-hours, not
        // multi-day) and the [60s, 24h] configurable range.
        assert_eq!(
            ArkretConfig::default().session_grant_ttl,
            Duration::try_hours(8).unwrap()
        );
    }

    #[test]
    fn session_grant_ttl_deserializes_seconds() {
        let config: ArkretConfig =
            serde_json::from_value(serde_json::json!({ "session_grant_ttl": 900 })).unwrap();

        assert_eq!(config.session_grant_ttl, Duration::try_minutes(15).unwrap());
    }

    #[test]
    fn did_web_principal_requires_explicit_personal_node_profile() {
        assert!(!ArkretConfig::default().did_web_principal_allowed());

        let personal_web = ArkretConfig {
            deployment_profile: DeploymentProfileConfig::PersonalNode,
            principal_method: PrincipalMethodConfig::DidWeb,
            ..ArkretConfig::default()
        };
        assert!(personal_web.did_web_principal_allowed());
        assert!(personal_web.validate(&figment::Figment::new()).is_ok());

        let personal_web_unconfigured = ArkretConfig {
            deployment_profile: DeploymentProfileConfig::PersonalNode,
            principal_method: PrincipalMethodConfig::DidWeb,
            ..ArkretConfig::default()
        };
        assert!(
            personal_web_unconfigured
                .validate(&figment::Figment::new())
                .is_ok()
        );

        let personal_default = ArkretConfig {
            deployment_profile: DeploymentProfileConfig::PersonalNode,
            ..ArkretConfig::default()
        };
        assert!(!personal_default.did_web_principal_allowed());

        let organization_web = ArkretConfig {
            principal_method: PrincipalMethodConfig::DidWeb,
            ..ArkretConfig::default()
        };
        assert!(!organization_web.did_web_principal_allowed());
        assert!(organization_web.validate(&figment::Figment::new()).is_err());
    }

    #[test]
    fn service_identity_is_runtime_only() {
        let config = ArkretConfig::default();
        let serialized = serde_json::to_value(&config).unwrap();
        assert!(serialized.get("service_id").is_none());
        assert!(serialized.get("runtime_service_identity").is_none());
    }

    #[test]
    fn stale_service_identity_fields_are_rejected() {
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "service_id": "did:webvh:zold:auth.example:webvh:service"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "principal_servers": [{
                    "name": "principal-a",
                    "endpoint": "https://principal.example/",
                    "audience": "did:webvh:zold:principal.example:webvh:service"
                }]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "principal_servers": [{
                    "name": "principal-a",
                    "endpoint": "https://principal.example/",
                    "did": "did:webvh:zold:principal.example:webvh:service"
                }]
            }))
            .is_err()
        );
    }

    #[test]
    fn principal_server_config_persists_endpoint_without_runtime_identity() {
        let config: ArkretConfig = serde_json::from_value(serde_json::json!({
            "principal_servers": [{
                "name": "principal-a",
                "endpoint": "https://principal.example/"
            }]
        }))
        .unwrap();

        let serialized = serde_json::to_value(&config.principal_servers[0]).unwrap();
        assert_eq!(serialized["name"], "principal-a");
        assert_eq!(serialized["endpoint"], "https://principal.example/");
        assert!(serialized.get("audience").is_none());
        assert!(serialized.get("did").is_none());
    }

    #[test]
    fn standalone_identity_provider_uses_role_shaped_config() {
        let config: ArkretConfig = serde_json::from_value(serde_json::json!({
            "identity_services": [{
                "name": "identity-a",
                "endpoint": "https://identity.example/",
                "registration_bearer": "secret"
            }]
        }))
        .unwrap();
        assert_eq!(config.identity_services[0].name, "identity-a");
        assert!(config.validate(&figment::Figment::new()).is_ok());
    }

    #[test]
    fn session_grant_ttl_rejects_out_of_range_values() {
        let figment = figment::Figment::new();
        let config = ArkretConfig {
            session_grant_ttl: Duration::try_seconds(30).unwrap(),
            ..ArkretConfig::default()
        };
        assert!(config.validate(&figment).is_err());
    }
}
