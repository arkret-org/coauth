use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::ConfigurationSection;

/// Round R2/R3 (2026-05-20) — deployment-scope trust-domain prefix.
///
/// A `trust_domain` value MUST match `ck:trust_domain:<scope>` where
/// `<scope>` is `[a-z0-9._:-]{1,128}`. This mirrors the SDK validator
/// `cokret_core::TypedTrustDomainId` so coauth and the Realm policy
/// engine agree on the exact byte-form. Validate via
/// [`validate_trust_domain`].
const TRUST_DOMAIN_PREFIX: &str = "ck:trust_domain:";
const SESSION_GRANT_TTL_MICROS: i64 = 5 * 60 * 1_000_000;
const SESSION_GRANT_TTL_MIN_SECONDS: i64 = 60;
const SESSION_GRANT_TTL_MAX_SECONDS: i64 = 86_400;

fn default_session_grant_ttl() -> Duration {
    Duration::microseconds(SESSION_GRANT_TTL_MICROS)
}

fn session_grant_ttl_is_default(ttl: &Duration) -> bool {
    *ttl == default_session_grant_ttl()
}

/// Cokret-specific deployment settings layered on top of the generic OIDC
/// and account-management configuration.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CokretConfig {
    /// Principal Server audiences trusted to consume session grants and admin
    /// tokens emitted by coauth.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_servers: Vec<PrincipalServerConfig>,

    /// External DID / identity registry resolver used for Cokret identity
    /// binding workflows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry: Option<IdentityRegistryConfig>,

    /// `starid` registry endpoint used by onboarding / recovery strands to
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

    /// Optional issuer DID to embed in Cokret session grants and discovery
    /// documents. Defaults to `service_did`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,

    /// Lifetime of Cokret session grants, in seconds.
    ///
    /// These are the DPoP-bound JWT grants returned by the REST auth bridge
    /// login/exchange paths and refreshed through
    /// `/_coauth/gate/account/session-grants/refresh`. Default: 300 (5 min).
    #[schemars(with = "u64", range(min = 60, max = 86400))]
    #[serde(
        default = "default_session_grant_ttl",
        skip_serializing_if = "session_grant_ttl_is_default"
    )]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub session_grant_ttl: Duration,

    /// Audience string expected by Cokret admin integrations.
    ///
    /// When omitted, the backend falls back to the local `/_cokret` endpoint.
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
    /// Wire form: `ck:trust_domain:<scope>` where `<scope>` matches
    /// `[a-z0-9._:-]{1,128}`. This value enters the canonical transcript
    /// of every `ck.cross_signing.reset` proof; **changing
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

    /// Fail-closed gate for the temporary password-login bridge that returns a
    /// Cokret principal-server session grant directly from
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

    /// Round 4 — DID of the trusted 3PID verification service whose
    /// `binding_proof` JWTs this coauth deployment will accept on
    /// `POST /_coauth/self/invites/3pid/verify`. When omitted, the invite
    /// verifier endpoint returns `503 verifier_not_configured` because
    /// it has no trusted `iss` to compare against.
    ///
    /// Override at runtime via `COAUTH_VERIFICATION_SERVICE_DID`.
    ///
    /// Deprecated single-value form. New deployments use
    /// [`Self::verification_service_dids`]; this field is ignored by the
    /// effective allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_service_did: Option<String>,

    /// SEC-07a — explicit allowlist of trusted 3PID verification-service
    /// DIDs whose `binding_proof` JWTs this coauth deployment will accept
    /// on `POST /_coauth/self/invites/3pid/verify`.
    ///
    /// Per `spec/v1/zh/sync/third-party-invites.md` §2.1 (Allowlist MUST)
    /// the verification service is the trust root of a 3PID invite, so the
    /// acceptable `verification_service_did` MUST be constrained to an
    /// explicit authorization set rather than taken from invite metadata.
    /// Any `binding_proof.verification_service_did` not in this set MUST be
    /// rejected (and MUST NOT be admitted merely because the `subject_proof`
    /// is valid — see §4.3 step 2a).
    ///
    /// The effective set is computed by [`Self::verification_service_allowlist`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_service_dids: Vec<String>,

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

impl Default for CokretConfig {
    fn default() -> Self {
        Self {
            principal_servers: Vec::new(),
            identity_registry: None,
            starid: None,
            service_did: None,
            issuer_did: None,
            session_grant_ttl: default_session_grant_ttl(),
            admin_audience: None,
            principal_server_url: None,
            high_risk_threshold: default_high_risk_threshold(),
            trust_domain: None,
            oob_code_kind: OobCodeKindConfig::default(),
            password_login_session_grants_enabled: false,
            admin_org_id: None,
            verification_service_did: None,
            verification_service_dids: Vec::new(),
            audit_signature_fail_closed: false,
        }
    }
}

impl CokretConfig {
    /// Returns `true` when the Cokret section carries no explicit overrides.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.principal_servers.is_empty()
            && self.identity_registry.is_none()
            && self.starid.is_none()
            && self.service_did.is_none()
            && self.issuer_did.is_none()
            && session_grant_ttl_is_default(&self.session_grant_ttl)
            && self.admin_audience.is_none()
            && self.principal_server_url.is_none()
            && self.high_risk_threshold == default_high_risk_threshold()
            && self.trust_domain.is_none()
            && matches!(self.oob_code_kind, OobCodeKindConfig::OfflineVerifiable)
            && !self.password_login_session_grants_enabled
            && self.admin_org_id.is_none()
            && self.verification_service_did.is_none()
            && self.verification_service_dids.is_empty()
            && !self.audit_signature_fail_closed
    }

    /// SEC-07a — effective allowlist of trusted 3PID verification-service
    /// DIDs from the multi-value [`Self::verification_service_dids`].
    ///
    /// Empty/whitespace-only entries are dropped and duplicates are
    /// collapsed. An empty result means no verifier is configured and the
    /// verify endpoint MUST fail closed
    /// (`503 verifier_not_configured`).
    #[must_use]
    pub fn verification_service_allowlist(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |candidate: &str| {
            let trimmed = candidate.trim();
            if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
                out.push(trimmed.to_owned());
            }
        };
        for did in &self.verification_service_dids {
            push(did);
        }
        out
    }

    /// Validate the configured `trust_domain` (if any) against the SDK
    /// `ck:trust_domain:<scope>` wire format. Returns the borrowed
    /// scope half on success so call-sites can build the
    /// `TypedTrustDomainId` directly. Delegates the acceptance check to
    /// the SDK validator `cokret_identifiers::is_trust_domain` so the
    /// config side and the SDK never drift; the prefix strip below only
    /// recovers the `<scope>` slice for the success return.
    ///
    /// # Errors
    ///
    /// Returns a static string when the value is not a well-formed
    /// `ck:trust_domain:<scope>` (missing prefix, empty/oversized scope,
    /// bad leading byte, or any byte outside `[a-z0-9._:-]`).
    pub fn validate_trust_domain(value: &str) -> Result<&str, &'static str> {
        if !cokret_identifiers::is_trust_domain(value) {
            return Err(
                "trust_domain MUST be `ck:trust_domain:<scope>` with scope `[a-z0-9][a-z0-9._:-]{0,127}`",
            );
        }
        // `is_trust_domain` already guaranteed the prefix is present.
        value
            .strip_prefix(TRUST_DOMAIN_PREFIX)
            .ok_or("trust_domain MUST start with `ck:trust_domain:`")
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

impl ConfigurationSection for CokretConfig {
    const PATH: &'static str = "cokret";

    fn validate(
        &self,
        _figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let min_ttl = Duration::try_seconds(SESSION_GRANT_TTL_MIN_SECONDS).unwrap();
        let max_ttl = Duration::try_seconds(SESSION_GRANT_TTL_MAX_SECONDS).unwrap();
        if self.session_grant_ttl < min_ttl || self.session_grant_ttl > max_ttl {
            return Err(std::io::Error::other(
                "cokret.session_grant_ttl must be between 60 and 86400 seconds",
            )
            .into());
        }

        if let Some(trust_domain) = self.trust_domain.as_deref() {
            Self::validate_trust_domain(trust_domain).map_err(std::io::Error::other)?;
        }

        if matches!(self.oob_code_kind, OobCodeKindConfig::Lookup) {
            return Err(std::io::Error::other(
                "cokret.oob_code_kind=lookup is disabled until lookup-mode strike counters are durable",
            )
            .into());
        }

        if let Some(org_id) = self.admin_org_id.as_deref()
            && org_id.trim().is_empty()
        {
            return Err(std::io::Error::other("cokret.admin_org_id must not be empty").into());
        }

        Ok(())
    }
}

/// Trusted Principal Server metadata published through Cokret discovery.
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
    /// (`/_coauth/gate/account/session-grants/introspect`). Mirrors
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
    /// adapter joins `/_starid/root/webvh/...` itself.
    pub base_url: Url,

    /// `host` value passed to starid's `POST /_starid/root/webvh/dids`.
    /// Defaults to the host of `base_url` when omitted. Override when
    /// starid is fronted by a different public-facing hostname than the URL
    /// coauth reaches it on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_host: Option<String>,

    /// Path prefix for minted principal DIDs (e.g. `accounts`). The
    /// adapter appends the account's stable id, so the final path is
    /// `<path_prefix>/<account_id>`.
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,

    /// Optional bearer token for starid's admin endpoints. When set,
    /// the adapter prefers `POST /_starid/local/admin/dids` over the public
    /// `POST /_starid/root/webvh/dids` — both produce the same DID but the
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
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:example.net").is_ok());
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:soland-prod.eu").is_ok());
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:tenant_a.shard_1").is_ok());
    }

    #[test]
    fn trust_domain_rejects_uppercase_and_empty() {
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:Example").is_err());
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:").is_err());
        assert!(CokretConfig::validate_trust_domain("example.net").is_err());
    }

    #[test]
    fn trust_domain_rejects_overlong_scope() {
        let too_long = format!("ck:trust_domain:{}", "a".repeat(129));
        assert!(CokretConfig::validate_trust_domain(&too_long).is_err());
        let just_right = format!("ck:trust_domain:{}", "a".repeat(128));
        assert!(CokretConfig::validate_trust_domain(&just_right).is_ok());
    }

    #[test]
    fn trust_domain_rejects_disallowed_chars() {
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:bad space").is_err());
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:bad/slash").is_err());
        // Scope MUST start with [a-z0-9], not a separator.
        assert!(CokretConfig::validate_trust_domain("ck:trust_domain:.dotleader").is_err());
    }

    #[test]
    fn lookup_oob_kind_is_fail_closed_until_strikes_are_durable() {
        let config = CokretConfig {
            oob_code_kind: OobCodeKindConfig::Lookup,
            ..CokretConfig::default()
        };
        let figment = figment::Figment::new();
        assert!(config.validate(&figment).is_err());
    }

    #[test]
    fn session_grant_ttl_defaults_to_five_minutes() {
        assert_eq!(
            CokretConfig::default().session_grant_ttl,
            Duration::try_minutes(5).unwrap()
        );
    }

    #[test]
    fn session_grant_ttl_deserializes_seconds() {
        let config: CokretConfig =
            serde_json::from_value(serde_json::json!({ "session_grant_ttl": 900 })).unwrap();

        assert_eq!(config.session_grant_ttl, Duration::try_minutes(15).unwrap());
    }

    #[test]
    fn verification_allowlist_ignores_deprecated_single_value() {
        let config = CokretConfig {
            verification_service_did: Some("did:web:verifier.example".to_owned()),
            ..CokretConfig::default()
        };
        assert!(config.verification_service_allowlist().is_empty());
    }

    #[test]
    fn verification_allowlist_merges_and_dedups() {
        let config = CokretConfig {
            verification_service_did: Some("did:web:a.example".to_owned()),
            verification_service_dids: vec![
                "did:web:a.example".to_owned(),
                "  ".to_owned(), // whitespace dropped
                "did:web:b.example".to_owned(),
            ],
            ..CokretConfig::default()
        };
        assert_eq!(
            config.verification_service_allowlist(),
            vec![
                "did:web:a.example".to_owned(),
                "did:web:b.example".to_owned()
            ]
        );
    }

    #[test]
    fn verification_allowlist_empty_when_unset() {
        assert!(
            CokretConfig::default()
                .verification_service_allowlist()
                .is_empty()
        );
    }

    #[test]
    fn verification_dids_deserializes_list() {
        let config: CokretConfig = serde_json::from_value(serde_json::json!({
            "verification_service_dids": ["did:web:x.example", "did:web:y.example"]
        }))
        .unwrap();
        assert_eq!(
            config.verification_service_allowlist(),
            vec![
                "did:web:x.example".to_owned(),
                "did:web:y.example".to_owned()
            ]
        );
    }

    #[test]
    fn session_grant_ttl_rejects_out_of_range_values() {
        let figment = figment::Figment::new();
        let config = CokretConfig {
            session_grant_ttl: Duration::try_seconds(30).unwrap(),
            ..CokretConfig::default()
        };
        assert!(config.validate(&figment).is_err());
    }
}
