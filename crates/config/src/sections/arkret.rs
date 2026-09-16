use std::sync::{Arc, RwLock};

use arkret_identifiers::{Did, DidCoreId};
use camino::Utf8PathBuf;
use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::{ClientSecret, ConfigurationSection};

/// Round R2/R3 (2026-05-20) — deployment-scope trust-domain prefix.
///
/// A `trust_domain` value MUST match `ak:trust_domain:<scope>` where
/// `<scope>` is `[a-z0-9._:-]{1,128}`. This mirrors the SDK validator
/// `arkret_identifiers::TrustDomainId` so coauth and the Realm policy
/// engine agree on the exact byte-form. Validate via
/// [`validate_trust_domain`].
const TRUST_DOMAIN_PREFIX: &str = "ak:trust_domain:";
// 8 hours. The session grant is the refresh credential for a device session;
// the access bearers minted from it are short-lived (capped server-side), so a
// multi-hour grant gives a normal working-session length WITHOUT long-lived
// bearers. Stays within the spec ceiling (`conformance-profiles.md`
// Station Account Authority contract: minutes-to-hours, not multi-day) and the
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

/// Identity of the owning Station delegated to this deployment-private
/// Account Authority component after trust preflight.
#[derive(Debug, Clone)]
pub struct DelegatedStationIdentity {
    /// Stable authorization id of the owning Station.
    pub station_id: DidCoreId,
    /// Full verified DID of the owning Station.
    pub did: Did,
}

/// Shared runtime slot populated exclusively by verified Station trust.
#[derive(Clone, Default)]
pub struct RuntimeOwningStationIdentity(Arc<RwLock<Option<DelegatedStationIdentity>>>);

impl std::fmt::Debug for RuntimeOwningStationIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("RuntimeOwningStationIdentity")
            .field(&self.get())
            .finish()
    }
}

impl RuntimeOwningStationIdentity {
    /// Return the currently delegated identity, if trust preflight installed it.
    #[must_use]
    pub fn get(&self) -> Option<DelegatedStationIdentity> {
        self.0
            .read()
            .expect("owning Station identity lock poisoned")
            .clone()
    }

    /// Install identity material after successful owning Station verification.
    pub fn store(&self, station_id: DidCoreId, did: Did) {
        *self
            .0
            .write()
            .expect("owning Station identity lock poisoned") =
            Some(DelegatedStationIdentity { station_id, did });
    }

    /// Install a delegated identity directly, skipping the owning Station
    /// trust preflight that [`store`](Self::store) normally follows.
    ///
    /// Compiled for this crate's own tests and, for other crates' test code,
    /// behind the `test-support` feature they opt into from
    /// `[dev-dependencies]`.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn fixture(did: &str) -> Self {
        let did = Did::new(did.to_owned()).expect("fixture Station DID");
        let station_id =
            arkret_identifiers::project_did_to_core_id(&did).expect("fixture Station core ID");
        let value = Self::default();
        value.store(station_id, did);
        value
    }
}

/// Arkret-specific deployment settings layered on top of the generic OIDC
/// and account-management configuration.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArkretConfig {
    /// Station audiences trusted to consume session grants and admin
    /// tokens emitted by coauth. Every Station that configures an internal
    /// authority bearer must use a credential unique within this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stations: Vec<StationConfig>,

    /// Name of the Station that owns this deployment-private Account
    /// Authority component. A single configured Station is selected
    /// automatically; deployments with multiple Station trust edges must set
    /// this explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owning_station: Option<String>,

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

    /// Runtime-only identity delegated by the verified owning Station.
    #[serde(skip)]
    #[schemars(skip)]
    pub runtime_owning_station_identity: RuntimeOwningStationIdentity,

    /// Lifetime of Arkret session grants, in seconds.
    ///
    /// These are the DPoP-bound JWT grants returned by the REST auth bridge
    /// login/exchange paths and rotated through
    /// `/_arkret/gate/account/session-grants/refresh`. Default: 28800 (8h) —
    /// access bearers minted from a grant are short-lived (capped Station
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
    /// Session-grant audiences are `did_core_id` values (the target service's
    /// stable authorization identity). When omitted, the backend falls back to
    /// this deployment's own runtime service core id.
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
    /// `[a-z0-9._:-]{1,128}`. This value binds peer and recovery
    /// authorization transcripts to the deployment.
    ///
    /// When omitted, callers expected to honour cross-deployment replay
    /// protection (`Realm` policy, station describe) MUST be
    /// told the trust domain is unset and fail closed.
    ///
    /// Typically provisioned consistently across the deployment.
    // TODO(trust-domain-runtime-propagation): once soland exposes a `PATCH /admin/v1/policy/
    //  trust_domain` mutation, propagate changes from coauth's runtime
    //  reload through that channel rather than requiring a soland
    //  restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,

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

    /// Fresh high-risk-action authentication ceiling, in seconds, for the
    /// self-service erasure entry point
    /// `ak.gate.account.command.request_erasure.v1`
    /// (`POST /_arkret/gate/account/erasure-requests`).
    ///
    /// account-lifecycle.md §8.1 makes the Account Authority judge
    /// authentication freshness locally from its own facts (recent login,
    /// WebAuthn, recovery key). This value is that deployment policy: the
    /// caller's most recent local authentication must be at most this many
    /// seconds old. When omitted the deployment has no fresh high-risk
    /// authentication policy, so every erasure request fails closed with
    /// `reauthentication_required` and zero writes.
    #[schemars(with = "Option<u64>", range(min = 1, max = 86400))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<i64>>")]
    pub erasure_request_max_auth_age: Option<Duration>,
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
            stations: Vec::new(),
            owning_station: None,
            deployment_profile: DeploymentProfileConfig::default(),
            principal_method: PrincipalMethodConfig::default(),
            identity_registry: None,
            runtime_owning_station_identity: RuntimeOwningStationIdentity::default(),
            session_grant_ttl: default_session_grant_ttl(),
            admin_audience: None,
            high_risk_threshold: default_high_risk_threshold(),
            trust_domain: None,
            admin_org_id: None,
            audit_signature_fail_closed: false,
            erasure_request_max_auth_age: None,
        }
    }
}

impl ArkretConfig {
    /// Resolve every Station shared-secret file exactly once during process
    /// startup, then reject empty or duplicate resolved credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when a configured file cannot be read, contains no
    /// non-whitespace bytes, or resolves to the same credential as another
    /// Station edge.
    pub async fn resolve_internal_authority_shared_secrets(&mut self) -> anyhow::Result<()> {
        let mut secrets = std::collections::BTreeSet::new();
        for station in &mut self.stations {
            station.resolve_internal_authority_shared_secret().await?;
            if let Some(secret) = station.internal_authority_shared_secret()
                && !secrets.insert(secret.to_owned())
            {
                anyhow::bail!(
                    "arkret.stations[].internal_authority_shared_secret values must be unique across Stations"
                );
            }
        }
        Ok(())
    }

    /// Returns `true` when the Arkret section carries no explicit overrides.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.stations.is_empty()
            && self.owning_station.is_none()
            && DeploymentProfileConfig::is_default(&self.deployment_profile)
            && PrincipalMethodConfig::is_default(&self.principal_method)
            && self.identity_registry.is_none()
            && session_grant_ttl_is_default(&self.session_grant_ttl)
            && self.admin_audience.is_none()
            && self.high_risk_threshold == default_high_risk_threshold()
            && self.trust_domain.is_none()
            && self.admin_org_id.is_none()
            && !self.audit_signature_fail_closed
            && self.erasure_request_max_auth_age.is_none()
    }

    /// Set of host names this deployment trusts as outbound
    /// station / identity-resolver targets.
    ///
    /// Built from every configured `stations[].endpoint` and the
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
        for server in &self.stations {
            push(&server.endpoint);
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

    /// Primary Station endpoint for call sites that operate on a
    /// single server. The endpoint is topology configuration only; its
    /// service DID is always resolved at runtime.
    #[must_use]
    pub fn primary_station_url(&self) -> Option<&Url> {
        self.stations.first().map(|server| &server.endpoint)
    }

    /// Station whose verified identity is delegated to this private Account
    /// Authority component.
    #[must_use]
    pub fn owning_station(&self) -> Option<&StationConfig> {
        match self.owning_station.as_deref() {
            Some(name) => self.stations.iter().find(|station| station.name == name),
            None => match self.stations.as_slice() {
                [station] => Some(station),
                _ => None,
            },
        }
    }

    /// Validate the configured `trust_domain` (if any) against the SDK
    /// `ak:trust_domain:<scope>` wire format. Returns the borrowed
    /// scope half on success so call-sites can build the
    /// `TrustDomainId` directly. Delegates the acceptance check to
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

        if let Some(org_id) = self.admin_org_id.as_deref()
            && org_id.trim().is_empty()
        {
            return Err(std::io::Error::other("arkret.admin_org_id must not be empty").into());
        }

        let mut station_names = std::collections::BTreeSet::new();
        let mut internal_authority_shared_secrets = std::collections::BTreeSet::new();
        for server in &self.stations {
            if server.name.trim().is_empty() {
                return Err(
                    std::io::Error::other("arkret.stations[].name must not be empty").into(),
                );
            }
            if matches!(
                server.internal_authority_shared_secret,
                Some(ClientSecret::Value(ref secret)) if secret.trim().is_empty()
            ) {
                return Err(std::io::Error::other(
                    "arkret.stations[].internal_authority_shared_secret must not be empty",
                )
                .into());
            }
            if server
                .embedded_webvh_registration_bearer
                .as_deref()
                .is_some_and(|bearer| bearer.trim().is_empty())
            {
                return Err(std::io::Error::other(
                    "arkret.stations[].embedded_webvh_registration_bearer must not be empty",
                )
                .into());
            }
            if let Some(trust_domain) = server.trust_domain.as_deref() {
                Self::validate_trust_domain(trust_domain).map_err(|error| {
                    std::io::Error::other(format!("arkret.stations[].trust_domain: {error}"))
                })?;
            }
            if server.internal_authority_shared_secret.is_some() {
                if server.trust_domain.is_none() {
                    return Err(std::io::Error::other(
                        "arkret.stations[].internal_authority_shared_secret requires an explicit Station trust_domain",
                    )
                    .into());
                }
                if self.trust_domain.is_none() {
                    return Err(std::io::Error::other(
                        "arkret.stations[].internal_authority_shared_secret requires an explicit arkret.trust_domain",
                    )
                    .into());
                }
                if let Some(ClientSecret::Value(secret)) =
                    server.internal_authority_shared_secret.as_ref()
                    && !internal_authority_shared_secrets.insert(secret.trim())
                {
                    return Err(std::io::Error::other(
                            "arkret.stations[].internal_authority_shared_secret values must be unique across Stations",
                        )
                        .into());
                }
            }
            if !station_names.insert(server.name.as_str()) {
                return Err(std::io::Error::other("Station names must be unique").into());
            }
        }
        if self.stations.len() > 1 && self.owning_station.is_none() {
            return Err(std::io::Error::other(
                "arkret.owning_station is required when multiple Stations are configured",
            )
            .into());
        }
        if let Some(selected) = self.owning_station.as_deref()
            && (selected.trim().is_empty() || !station_names.contains(selected))
        {
            return Err(std::io::Error::other(
                "arkret.owning_station must name a configured Station",
            )
            .into());
        }

        Ok(())
    }
}

/// Serialization helper for a Station's inline/file internal-authority
/// shared secret.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct InternalAuthoritySharedSecretRaw {
    /// Inline per-edge secret. Mutually exclusive with the file source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    internal_authority_shared_secret: Option<String>,
    /// UTF-8 secret file read once during process startup. Mutually exclusive
    /// with the inline source.
    #[schemars(with = "Option<String>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    internal_authority_shared_secret_file: Option<Utf8PathBuf>,
}

impl TryFrom<InternalAuthoritySharedSecretRaw> for Option<ClientSecret> {
    type Error = anyhow::Error;

    fn try_from(raw: InternalAuthoritySharedSecretRaw) -> Result<Self, Self::Error> {
        match (
            raw.internal_authority_shared_secret,
            raw.internal_authority_shared_secret_file,
        ) {
            (None, None) => Ok(None),
            (Some(value), None) => Ok(Some(ClientSecret::Value(value))),
            (None, Some(path)) => Ok(Some(ClientSecret::File(path))),
            (Some(_), Some(_)) => anyhow::bail!(
                "Cannot specify both `internal_authority_shared_secret` and `internal_authority_shared_secret_file`"
            ),
        }
    }
}

impl From<Option<ClientSecret>> for InternalAuthoritySharedSecretRaw {
    fn from(secret: Option<ClientSecret>) -> Self {
        match secret {
            None => Self {
                internal_authority_shared_secret: None,
                internal_authority_shared_secret_file: None,
            },
            Some(ClientSecret::Value(value)) => Self {
                internal_authority_shared_secret: Some(value),
                internal_authority_shared_secret_file: None,
            },
            Some(ClientSecret::File(path)) => Self {
                internal_authority_shared_secret: None,
                internal_authority_shared_secret_file: Some(path),
            },
        }
    }
}

/// Trusted Station metadata published through Arkret discovery.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StationConfig {
    /// Human-readable identifier for the consumer, such as `soland-prod`.
    pub name: String,

    /// Base URL of the Station integration point.
    pub endpoint: Url,

    /// Optional shared per-edge secret for only the registered
    /// deployment-internal
    /// Account Authority / Station operations: session-grant introspection,
    /// Auth-side logout, controller grant gating, and device-revocation
    /// gating. Standard Agent resource and command operations use RFC 9421
    /// service signatures instead. It is presented as an HTTP Bearer token,
    /// defines the internal authority peer, and must be unique across Station
    /// entries.
    #[schemars(with = "InternalAuthoritySharedSecretRaw")]
    #[serde_as(as = "serde_with::TryFromInto<InternalAuthoritySharedSecretRaw>")]
    #[serde(flatten)]
    pub internal_authority_shared_secret: Option<ClientSecret>,

    /// Optional static bearer token coauth should send when writing embedded
    /// `did:webvh` registration records into this Station.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_webvh_registration_bearer: Option<String>,

    /// This Station's trust domain, as a registered deployment fact.
    ///
    /// This is a fact of the Station peer entry, never something derived from
    /// the endpoint URL, hostname or `arkret.trust_domain` (coauth's own
    /// domain). When an internal authority shared secret is present, this
    /// value is mandatory and is never repeated in request headers.
    ///
    /// Wire form: `ak:trust_domain:<scope>`, validated by
    /// [`ArkretConfig::validate_trust_domain`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
}

impl StationConfig {
    /// Return the startup-resolved credential. A file source is deliberately
    /// unavailable until [`Self::resolve_internal_authority_shared_secret`]
    /// has loaded it, preventing request-path file I/O.
    #[must_use]
    pub fn internal_authority_shared_secret(&self) -> Option<&str> {
        match self.internal_authority_shared_secret.as_ref() {
            Some(ClientSecret::Value(value)) => Some(value.as_str()),
            Some(ClientSecret::File(_)) | None => None,
        }
    }

    async fn resolve_internal_authority_shared_secret(&mut self) -> anyhow::Result<()> {
        let Some(source) = self.internal_authority_shared_secret.as_ref() else {
            return Ok(());
        };
        let value = source.value().await.map_err(|error| {
            anyhow::anyhow!(
                "failed to load arkret Station {:?} internal authority shared secret: {error}",
                self.name
            )
        })?;
        let value = value.trim().to_owned();
        anyhow::ensure!(
            !value.is_empty(),
            "arkret Station {:?} internal authority shared secret must not be empty",
            self.name
        );
        self.internal_authority_shared_secret = Some(ClientSecret::Value(value));
        Ok(())
    }

    /// Whether this Station has the complete minimal peer binding used by the
    /// fixed internal authority routes.
    #[must_use]
    pub fn has_internal_authority_peer(&self) -> bool {
        self.trust_domain.is_some()
            && self
                .internal_authority_shared_secret()
                .is_some_and(|secret| !secret.trim().is_empty())
    }
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
        let personal_web = ArkretConfig {
            deployment_profile: DeploymentProfileConfig::PersonalNode,
            principal_method: PrincipalMethodConfig::DidWeb,
            ..ArkretConfig::default()
        };
        assert!(personal_web.validate(&figment::Figment::new()).is_ok());

        let organization_web = ArkretConfig {
            principal_method: PrincipalMethodConfig::DidWeb,
            ..ArkretConfig::default()
        };
        assert!(organization_web.validate(&figment::Figment::new()).is_err());
    }

    #[test]
    fn coauth_has_no_independent_service_identity_configuration() {
        let config = ArkretConfig::default();
        let serialized = serde_json::to_value(&config).unwrap();
        assert!(serialized.get("service_id").is_none());
        assert!(serialized.get("runtime_owning_station_identity").is_none());
        assert!(serialized.get("identity_services").is_none());
        assert!(serialized.get("identity_provider").is_none());
    }

    #[test]
    fn unsupported_arkret_config_fields_are_rejected() {
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "development_auto_enrollment_hosts": ["localhost"]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "password_login_session_grants_enabled": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "service_id": "did:webvh:zold:auth.example:webvh:service"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "stations": [{
                    "name": "principal-a",
                    "endpoint": "https://principal.example/",
                    "audience": "did:webvh:zold:principal.example:webvh:service"
                }]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "stations": [{
                    "name": "principal-a",
                    "endpoint": "https://principal.example/",
                    "did": "did:webvh:zold:principal.example:webvh:service"
                }]
            }))
            .is_err()
        );
    }

    #[test]
    fn station_config_rejects_service_identity_pin() {
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "stations": [{
                    "name": "principal-a",
                    "endpoint": "https://principal.example/",
                    "service_id": "ak:did_core:webvh:QmUz1hyNMdPEzWvu41UVazczohzzXmiWFy8w6xxrboxN3i"
                }]
            }))
            .is_err()
        );

        let config: ArkretConfig = serde_json::from_value(serde_json::json!({
            "stations": [{
                "name": "principal-a",
                "endpoint": "https://principal.example/"
            }]
        }))
        .unwrap();
        assert!(config.validate(&figment::Figment::new()).is_ok());
        let serialized = serde_json::to_value(&config.stations[0]).unwrap();
        assert!(serialized.get("service_id").is_none());
    }

    #[test]
    fn internal_authority_shared_secret_requires_complete_unique_station_binding() {
        let complete = ArkretConfig {
            trust_domain: Some("ak:trust_domain:authority.example".to_owned()),
            stations: vec![StationConfig {
                name: "principal-a".to_owned(),
                endpoint: "https://principal-a.example/".parse().unwrap(),
                internal_authority_shared_secret: Some(ClientSecret::Value(
                    "credential-a".to_owned(),
                )),
                embedded_webvh_registration_bearer: None,
                trust_domain: Some("ak:trust_domain:principal-a.example".to_owned()),
            }],
            ..ArkretConfig::default()
        };
        assert!(complete.validate(&figment::Figment::new()).is_ok());
        assert!(complete.stations[0].has_internal_authority_peer());

        let mut missing_secret = complete.clone();
        missing_secret.stations[0].internal_authority_shared_secret = None;
        assert!(missing_secret.validate(&figment::Figment::new()).is_ok());
        assert!(!missing_secret.stations[0].has_internal_authority_peer());

        let mut missing_station_domain = complete.clone();
        missing_station_domain.stations[0].trust_domain = None;
        assert!(
            missing_station_domain
                .validate(&figment::Figment::new())
                .is_err()
        );

        let mut missing_authority_domain = complete.clone();
        missing_authority_domain.trust_domain = None;
        assert!(
            missing_authority_domain
                .validate(&figment::Figment::new())
                .is_err()
        );

        let mut duplicate_secret = complete;
        let mut second = duplicate_secret.stations[0].clone();
        second.name = "principal-b".to_owned();
        second.endpoint = "https://principal-b.example/".parse().unwrap();
        second.trust_domain = Some("ak:trust_domain:principal-b.example".to_owned());
        duplicate_secret.stations.push(second);
        duplicate_secret.owning_station = Some("principal-a".to_owned());
        assert!(duplicate_secret.validate(&figment::Figment::new()).is_err());
    }

    #[tokio::test]
    async fn internal_authority_shared_secret_file_is_resolved_once() {
        let path = std::env::temp_dir().join(format!(
            "coauth-internal-authority-secret-{}",
            ulid::Ulid::generate()
        ));
        tokio::fs::write(&path, " file-secret\n").await.unwrap();
        let path = Utf8PathBuf::from_path_buf(path).unwrap();
        let mut config: ArkretConfig = serde_json::from_value(serde_json::json!({
            "trust_domain": "ak:trust_domain:authority.example",
            "stations": [{
                "name": "principal-a",
                "endpoint": "https://principal.example/",
                "trust_domain": "ak:trust_domain:principal.example",
                "internal_authority_shared_secret_file": path.clone()
            }]
        }))
        .unwrap();

        assert_eq!(config.stations[0].internal_authority_shared_secret(), None);
        config
            .resolve_internal_authority_shared_secrets()
            .await
            .unwrap();
        assert_eq!(
            config.stations[0].internal_authority_shared_secret(),
            Some("file-secret")
        );
        tokio::fs::remove_file(path).await.unwrap();
        assert_eq!(
            config.stations[0].internal_authority_shared_secret(),
            Some("file-secret")
        );
    }

    #[test]
    fn internal_authority_shared_secret_rejects_inline_and_file_sources_together() {
        assert!(
            serde_json::from_value::<ArkretConfig>(serde_json::json!({
                "trust_domain": "ak:trust_domain:authority.example",
                "stations": [{
                    "name": "principal-a",
                    "endpoint": "https://principal.example/",
                    "trust_domain": "ak:trust_domain:principal.example",
                    "internal_authority_shared_secret": "inline-secret",
                    "internal_authority_shared_secret_file": "secret.txt"
                }]
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn internal_authority_shared_secret_rejects_empty_file() {
        let path = std::env::temp_dir().join(format!(
            "coauth-empty-internal-authority-secret-{}",
            ulid::Ulid::generate()
        ));
        tokio::fs::write(&path, "  \n").await.unwrap();
        let path = Utf8PathBuf::from_path_buf(path).unwrap();
        let mut config: ArkretConfig = serde_json::from_value(serde_json::json!({
            "trust_domain": "ak:trust_domain:authority.example",
            "stations": [{
                "name": "principal-a",
                "endpoint": "https://principal.example/",
                "trust_domain": "ak:trust_domain:principal.example",
                "internal_authority_shared_secret_file": path.clone()
            }]
        }))
        .unwrap();

        assert!(
            config
                .resolve_internal_authority_shared_secrets()
                .await
                .is_err()
        );
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn internal_authority_shared_secret_rejects_duplicate_file_values() {
        let suffix = ulid::Ulid::generate();
        let first_path =
            std::env::temp_dir().join(format!("coauth-internal-authority-secret-a-{suffix}"));
        let second_path =
            std::env::temp_dir().join(format!("coauth-internal-authority-secret-b-{suffix}"));
        tokio::fs::write(&first_path, "duplicate-secret")
            .await
            .unwrap();
        tokio::fs::write(&second_path, "duplicate-secret\n")
            .await
            .unwrap();
        let first_path = Utf8PathBuf::from_path_buf(first_path).unwrap();
        let second_path = Utf8PathBuf::from_path_buf(second_path).unwrap();
        let mut config: ArkretConfig = serde_json::from_value(serde_json::json!({
            "trust_domain": "ak:trust_domain:authority.example",
            "owning_station": "principal-a",
            "stations": [
                {
                    "name": "principal-a",
                    "endpoint": "https://principal-a.example/",
                    "trust_domain": "ak:trust_domain:principal-a.example",
                    "internal_authority_shared_secret_file": first_path.clone()
                },
                {
                    "name": "principal-b",
                    "endpoint": "https://principal-b.example/",
                    "trust_domain": "ak:trust_domain:principal-b.example",
                    "internal_authority_shared_secret_file": second_path.clone()
                }
            ]
        }))
        .unwrap();

        assert!(
            config
                .resolve_internal_authority_shared_secrets()
                .await
                .is_err()
        );
        tokio::fs::remove_file(first_path).await.unwrap();
        tokio::fs::remove_file(second_path).await.unwrap();
    }

    /// The target's trust domain is a registered fact of the Station entry
    /// (`service-http-binding.md` §2.2.3), validated in the same wire form as
    /// this deployment's own and kept separate from it.
    #[test]
    fn station_trust_domain_is_validated_and_independent_of_the_deployment_one() {
        let figment = figment::Figment::new();
        let station = |trust_domain: Option<&str>| StationConfig {
            name: "soland".to_owned(),
            endpoint: "https://soland.example/".parse().unwrap(),
            internal_authority_shared_secret: None,
            embedded_webvh_registration_bearer: None,
            trust_domain: trust_domain.map(ToOwned::to_owned),
        };
        let config = |station: StationConfig| ArkretConfig {
            trust_domain: Some("ak:trust_domain:auth.example".to_owned()),
            stations: vec![station],
            ..ArkretConfig::default()
        };
        // A Station in a different domain from this deployment is the normal
        // split-host case, not a conflict.
        assert!(
            config(station(Some("ak:trust_domain:soland.example")))
                .validate(&figment)
                .is_ok()
        );
        // Absent is allowed at the config layer; the operations that must bind
        // it fail closed instead of guessing.
        assert!(config(station(None)).validate(&figment).is_ok());
        assert!(
            config(station(Some("ak:trust_domain:Soland.Example")))
                .validate(&figment)
                .is_err()
        );
        assert!(
            config(station(Some("soland.example")))
                .validate(&figment)
                .is_err()
        );
    }

    #[test]
    fn multiple_stations_require_explicit_owner() {
        let station = |name: &str| StationConfig {
            name: name.to_owned(),
            endpoint: format!("https://{name}.example/").parse().unwrap(),
            internal_authority_shared_secret: None,
            embedded_webvh_registration_bearer: None,
            trust_domain: None,
        };
        let mut config = ArkretConfig {
            stations: vec![station("one"), station("two")],
            ..ArkretConfig::default()
        };
        assert!(config.validate(&figment::Figment::new()).is_err());
        config.owning_station = Some("two".to_owned());
        assert!(config.validate(&figment::Figment::new()).is_ok());
        assert_eq!(config.owning_station().unwrap().name, "two");
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
