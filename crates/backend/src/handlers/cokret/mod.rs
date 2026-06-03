mod did_document;
mod handle_claim;
mod identity;
mod service_describe;
mod session_grant;

pub use did_document::*;
pub use handle_claim::*;
pub use identity::*;
pub use service_describe::*;
pub use session_grant::*;

#[cfg(test)]
mod tests;

use anyhow::Error as AnyhowError;
use coauth_config::CokretConfig;
use coauth_data::{RepositoryAccess, UrlBuilder, User};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::{constraints::Constrainable, jwk::PublicJsonWebKey, jwt::JwtSignatureError};
use coauth_keystore::{Keystore, WrongAlgorithmError};
use cokret_core::ErrorEnvelope;
use oauth_types::scope::Scope;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::common::{DepotExt, RouteError};

const COKRET_PROTOCOL_VERSION: &str = "1.0";

const COKRET_HTTP_BINDING: &str = "http_json";

pub const CLAIM_PRINCIPAL_DID: &str = "org.cokret.principal_did";

pub const CLAIM_DEVICE_ID: &str = "org.cokret.device_id";

pub const CLAIM_SESSION_ID: &str = "org.cokret.session_id";

pub const PRINCIPAL_SERVER_SESSION_BIND_SCOPE: &str = "urn:cokret:principal-server:session.bind";

#[derive(Debug, Error)]
pub enum SessionGrantError {
    #[error("no signing key is configured for Cokret session grants")]
    NoSigningKey,

    #[error(transparent)]
    JwtSignature(#[from] JwtSignatureError),

    #[error(transparent)]
    WrongAlgorithm(#[from] WrongAlgorithmError),

    #[error(transparent)]
    Serialize(#[from] serde_json::Error),

    /// Canonical-JSON / digest failure surfaced by the shared SDK pipeline
    /// (`cokret_core::canonical`). Carried as the SDK error itself so call
    /// sites keep its structured variants (e.g. `NonCanonicalNumber`)
    /// instead of a flattened string.
    #[error(transparent)]
    Canonical(#[from] cokret_core::Error),

    #[error("failed to encode session private key as PEM: {0}")]
    PemEncode(String),

    /// R3.2 (HC-COAUTH-1/2) — the handle-claim issuance request failed the
    /// `claim_kind` allow-list or subject (holder/principal DID)
    /// validation. Carries the SDK / shared wire reason code.
    #[error(transparent)]
    HandleClaimSubject(#[from] crate::services::handle_subject_validator::HandleClaimSubjectError),

    #[error(transparent)]
    Other(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum CokretRouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("not found")]
    NotFound,

    #[error("{0}")]
    BadRequest(String),

    /// Caller did not present a usable bearer token. Renders as `401`.
    #[error("{0}")]
    Unauthorized(String),

    /// Caller presented a token, but it lacks the scope required for the
    /// requested operation. Renders as `403`.
    #[error("{0}")]
    Forbidden(String),
}

impl From<RouteError> for CokretRouteError {
    fn from(value: RouteError) -> Self {
        match value {
            RouteError::BadRequest(message) => Self::BadRequest(message),
            RouteError::NotFound => Self::NotFound,
            other => Self::Internal(Box::new(other)),
        }
    }
}

impl From<coauth_data::RepositoryError> for CokretRouteError {
    fn from(value: coauth_data::RepositoryError) -> Self {
        Self::Internal(Box::new(value))
    }
}

/// Authorization decision for a session-grant administrative endpoint.
#[derive(Debug, Clone, Copy)]
enum SessionGrantAuthz {
    /// The caller presented an admin scope. Allowed for read and write.
    Admin,
    /// The caller presented the `server_name` `session.bind` scope.
    /// Allowed for read-only paths (list / introspect).
    PrincipalServer,
}

/// Resolve the bearer token on the request and require either an admin
/// scope or the `server_name` session-bind scope. Used by the
/// session-grant admin surface to gate access without going through the
/// heavier admin call-context extractor.
async fn require_session_grant_caller(
    req: &Request,
    depot: &Depot,
) -> Result<SessionGrantAuthz, CokretRouteError> {
    use coauth_data::{RepositoryAccess, TokenType};

    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| CokretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let auth_str = auth_header
        .to_str()
        .map_err(|_| CokretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    let token = auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .ok_or_else(|| CokretRouteError::Unauthorized("invalid authorization header".to_owned()))?;

    // Static bearer fallback: a Principal Server may authenticate with a
    // token configured in `cokret.principal_servers[].
    // session_grant_introspection_bearer`. Mirrors the
    // `oauth_introspection_bearer` fallback on the OAuth introspection
    // endpoint and lets a server-to-server caller skip the DB-backed
    // PAT/OAuth-session lookup. Grants `PrincipalServer` authz only —
    // never `Admin` — so it cannot revoke session grants.
    let cokret_config = depot.cokret_config()?;
    if principal_server_static_session_grant_bearer_matches(&cokret_config, token) {
        return Ok(SessionGrantAuthz::PrincipalServer);
    }

    let token_type = TokenType::check(token)
        .map_err(|_| CokretRouteError::Unauthorized("invalid bearer token".to_owned()))?;

    let mut repo = depot.repo().await?;
    let scope = match token_type {
        TokenType::AccessToken => {
            let access = repo
                .oauth_access_token()
                .find_by_token(token)
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| CokretRouteError::Unauthorized("unknown access token".to_owned()))?;
            let session = repo
                .oauth_session()
                .lookup(access.session_id)
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "access token references missing session",
                    ))
                })?;
            session.scope.clone()
        }
        TokenType::PersonalAccessToken => {
            let access = repo
                .personal_access_token()
                .find_by_token(token)
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| CokretRouteError::Unauthorized("unknown access token".to_owned()))?;
            let session = repo
                .personal_session()
                .lookup(access.session_id)
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "access token references missing session",
                    ))
                })?;
            session.scope.clone()
        }
        _ => {
            return Err(CokretRouteError::Unauthorized(
                "unsupported access token type".to_owned(),
            ));
        }
    };
    repo.cancel().await?;

    if crate::handlers::admin::has_admin_scope(&scope) {
        Ok(SessionGrantAuthz::Admin)
    } else if scope.contains(PRINCIPAL_SERVER_SESSION_BIND_SCOPE) {
        Ok(SessionGrantAuthz::PrincipalServer)
    } else {
        Err(CokretRouteError::Forbidden(
            "missing admin or principal-server scope".to_owned(),
        ))
    }
}

fn principal_server_static_session_grant_bearer_matches(
    cokret_config: &CokretConfig,
    token: &str,
) -> bool {
    !token.trim().is_empty()
        && cokret_config
            .principal_servers
            .iter()
            .filter_map(|server| server.session_grant_introspection_bearer.as_deref())
            .any(|configured| configured == token)
}

impl Scribe for CokretRouteError {
    fn render(self, res: &mut Response) {
        let (status, code, message) = match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error".to_owned(),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_owned()),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_json", message),
            Self::Unauthorized(message) => (StatusCode::UNAUTHORIZED, "unauthorized", message),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message),
        };

        if status == StatusCode::UNAUTHORIZED {
            // RFC 7235 says 401 responses MUST include a WWW-Authenticate
            // challenge so the caller can negotiate.
            res.headers_mut().insert(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static("Bearer realm=\"cokret\", error=\"invalid_token\""),
            );
        }

        res.status_code(status);
        res.render(Json(ErrorEnvelope::new(code, message)));
    }
}

fn map_did_resolve_error(
    error: crate::services::did_resolver::DidResolveError,
) -> CokretRouteError {
    match error {
        crate::services::did_resolver::DidResolveError::NotFound
        | crate::services::did_resolver::DidResolveError::UnsupportedMethod => {
            CokretRouteError::NotFound
        }
        crate::services::did_resolver::DidResolveError::InvalidDid(message) => {
            CokretRouteError::BadRequest(format!("invalid did: {message}"))
        }
        other => CokretRouteError::Internal(Box::new(other)),
    }
}

pub(crate) fn service_did(url_builder: &UrlBuilder) -> String {
    let base = url_builder.http_base();
    let host = match base.port() {
        Some(port) => format!(
            "{}%3A{}",
            base.host_str().unwrap_or("localhost").to_lowercase(),
            port
        ),
        None => base.host_str().unwrap_or("localhost").to_lowercase(),
    };

    let mut segments = vec![host];
    segments.extend(
        base.path_segments()
            .into_iter()
            .flatten()
            .filter(|segment| !segment.is_empty())
            .map(ToOwned::to_owned),
    );

    format!("did:web:{}", segments.join(":"))
}

pub(crate) fn service_did_for(url_builder: &UrlBuilder, cokret_config: &CokretConfig) -> String {
    cokret_config
        .service_did
        .clone()
        .unwrap_or_else(|| service_did(url_builder))
}

pub(crate) fn issuer_did_for(url_builder: &UrlBuilder, cokret_config: &CokretConfig) -> String {
    cokret_config
        .issuer_did
        .clone()
        .unwrap_or_else(|| service_did_for(url_builder, cokret_config))
}

pub(crate) fn user_did(url_builder: &UrlBuilder, user: &User) -> String {
    format!("{}:users:{}", service_did(url_builder), user.id)
}

pub(crate) fn user_did_for(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    user: &User,
) -> String {
    format!(
        "{}:users:{}",
        service_did_for(url_builder, cokret_config),
        user.id
    )
}

/// Legacy display form `local@host` used by some logging / display
/// paths. NOT the canonical handle form — use [`user_handle`]
/// (spec 7157ee8 §3.1) for `alsoKnownAs` / DID Document / claim emission.
pub(crate) fn user_handle_display(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}@{}",
        user.handle,
        url_builder.public_hostname().to_lowercase()
    )
}

/// Canonical Cokret handle for a user per spec 7157ee8 §3.1:
/// `<lowercase-localpart>:<lowercase-domain>`. This is the form that MUST
/// appear in `alsoKnownAs`, on any handle claim `handle` field, and as
/// directory cache key. `acct:<local>@<host>` is interop-only and lives in
/// `handle_aliases[]` on the handle claim.
pub(crate) fn user_handle(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}:{}",
        user.handle.to_lowercase(),
        url_builder.public_hostname().to_lowercase()
    )
}

/// `acct:` interop alias for [`user_handle`]. Use this for
/// `handle_aliases[]` on a `handle-claim.schema.json` payload.
pub(crate) fn user_handle_acct_alias(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "acct:{}@{}",
        user.handle.to_lowercase(),
        url_builder.public_hostname().to_lowercase()
    )
}

/// Stable wire-level error code returned when a caller passes a non-
/// canonical handle string (legacy `cokret://` URI, `acct:` alias, or
/// other malformed input).
///
/// Mirrored by [`coauth_data::user::HANDLE_NOT_CANONICAL_CODE`] — kept in
/// sync so the audit / HTTP layers can refer to the same constant without
/// an extra dependency.
pub const HANDLE_NOT_CANONICAL_CODE: &str = "handle_not_canonical";

/// Reject any inbound `handle` that is not in the canonical
/// `<localpart>:<domain>` shape (spec 7157ee8 §3.1). Returns a
/// [`CokretRouteError::BadRequest`] wrapping the standard error envelope
/// `code = "handle_not_canonical"`.
pub(crate) fn require_canonical_handle(input: &str) -> Result<&str, CokretRouteError> {
    coauth_data::user::validate_canonical_handle(input).map_err(|(_code, message)| {
        // The error envelope sets `code` from the variant; we embed the
        // reason text so callers see why their input was rejected.
        CokretRouteError::BadRequest(format!("{HANDLE_NOT_CANONICAL_CODE}: {message}"))
    })
}

pub(crate) fn required_audience(url_builder: &UrlBuilder) -> String {
    url_builder.absolute_url("/api/v1").to_string()
}

fn trust_domain_for(url_builder: &UrlBuilder, cokret_config: &CokretConfig) -> String {
    cokret_config.trust_domain.clone().unwrap_or_else(|| {
        let scope = derived_trust_domain_scope(url_builder.public_hostname());
        let trust_domain = format!("ck:trust_domain:{scope}");
        debug_assert!(CokretConfig::validate_trust_domain(&trust_domain).is_ok());
        trust_domain
    })
}

fn derived_trust_domain_scope(host: &str) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    let mut scope: String = host
        .to_ascii_lowercase()
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' | ':' => ch,
            _ => '-',
        })
        .collect();
    if scope.is_empty() {
        scope.push_str("host");
    }
    let first = scope.as_bytes()[0];
    if !matches!(first, b'a'..=b'z' | b'0'..=b'9') {
        scope.insert_str(0, "host-");
    }
    if scope.len() > 128 {
        scope.truncate(128);
    }
    scope
}

pub(crate) fn required_audience_for(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
) -> String {
    cokret_config
        .admin_audience
        .clone()
        .unwrap_or_else(|| required_audience(url_builder))
}

pub(crate) fn is_allowed_session_grant_audience(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    audience: &str,
) -> bool {
    let audience = audience.trim();
    if audience.is_empty() {
        return false;
    }

    audience == required_audience_for(url_builder, cokret_config)
        || cokret_config
            .principal_servers
            .iter()
            .any(|server| server.audience == audience)
}

/// Reasons why a caller-supplied principal-server audience could not be
/// honoured. Distinct error variants let the HTTP layer return precise
/// 4xx codes instead of a generic "bad request".
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum SessionGrantTargetError {
    #[error("requested audience is not configured for this coauth service")]
    UnknownAudience,
    #[error(
        "audience resolves to the local admin surface; specify a principal_server audience instead"
    )]
    LocalAudienceNotAllowed,
}

/// Resolve the principal-server target for a password login session grant.
///
/// `requested_audience` is the audience the client proved during the login
/// ceremony (e.g. carried in a request body field or audience-bound state).
/// When supplied, only an exact match against a configured `server_name`
/// is accepted — falling back to "first `server_name` wins" silently
/// would let any caller mint a grant for an audience they never asked for.
///
/// When `requested_audience` is `None` and exactly one principal server is
/// configured, that single server is used. With zero or multiple principal
/// servers and no explicit choice, returns `UnknownAudience` so the caller
/// must disambiguate.
pub(crate) fn password_login_session_grant_target(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    requested_audience: Option<&str>,
) -> Result<SessionGrantTarget, SessionGrantTargetError> {
    if let Some(audience) = requested_audience.map(str::trim).filter(|a| !a.is_empty()) {
        if let Some(server) = cokret_config
            .principal_servers
            .iter()
            .find(|server| server.audience == audience)
        {
            return Ok(SessionGrantTarget {
                audience: server.audience.clone(),
                principal_server_name: Some(server.name.clone()),
                principal_server_endpoint: Some(server.endpoint.to_string()),
            });
        }

        // The local admin audience is allowed for OIDC bridge flows, but
        // not for password login session grants — there is no principal
        // server to bind the grant to.
        if audience == required_audience_for(url_builder, cokret_config) {
            return Err(SessionGrantTargetError::LocalAudienceNotAllowed);
        }

        return Err(SessionGrantTargetError::UnknownAudience);
    }

    match cokret_config.principal_servers.as_slice() {
        [server] => Ok(SessionGrantTarget {
            audience: server.audience.clone(),
            principal_server_name: Some(server.name.clone()),
            principal_server_endpoint: Some(server.endpoint.to_string()),
        }),
        [] => Err(SessionGrantTargetError::UnknownAudience),
        _ => Err(SessionGrantTargetError::UnknownAudience),
    }
}

// T5.3 (Round 22, 2026-05-20) — handle_claim digest convergence.
//
// The previous in-file `write_canonical_json` walker and
// `canonical_json_sha256` helper were a hand-rolled (but spec-equivalent)
// canonical-JSON implementation. They are now a thin shim over
// `cokret_core::canonical::canonical_sha256`, which is the single canonical
// JSON pipeline shared by soland / starid / yougen / floria. This keeps
// the handle-claim payload hash byte-identical to every other Cokret
// service computing `sha256(canonical_json(payload))`.
//
// The SDK encoder is *stricter* than the original (it rejects float
// numbers per `encoding.md` §3.2). Coauth's `HandleClaimDigestInput` is
// composed of strings, DateTime<Utc> (rendered as RFC 3339 strings), and
// an inner struct of strings, so no shape that previously hashed cleanly
// will now reject. The result type is the SDK's own `cokret_core::Error`
// so callers retain its structured variants rather than a re-wrapped
// `serde_json::Error`.
fn canonical_json_sha256(value: &impl Serialize) -> Result<String, cokret_core::Error> {
    cokret_core::canonical::canonical_sha256(value)
}

fn session_grant_claims_hash(
    claims: &SessionGrantPayloadClaims,
) -> Result<String, cokret_core::Error> {
    canonical_json_sha256(claims)
}

#[cfg(test)]
fn session_grant_claims_from_payload(payload: &SessionGrantPayload) -> SessionGrantPayloadClaims {
    SessionGrantPayloadClaims {
        kind: payload.kind.clone(),
        issuer: payload.issuer.clone(),
        subject: payload.subject.clone(),
        service_account_id: payload.service_account_id.clone(),
        session_public_key: payload.session_public_key.clone(),
        audience: payload.audience.clone(),
        scopes: payload.scopes.clone(),
        not_before: payload.not_before,
        expires_at: payload.expires_at,
        revocation_ref: payload.revocation_ref.clone(),
        device_id: payload.device_id.clone(),
        session_id: payload.session_id.clone(),
        browser_session_id: payload.browser_session_id.clone(),
        cnf: payload.cnf.clone(),
    }
}

fn primary_device_id_from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Option<String> {
    tokens.into_iter().find_map(|token| {
        token
            .strip_prefix("urn:cokret:client:device:")
            .map(ToOwned::to_owned)
    })
}

pub(crate) fn primary_device_id(scope: &Scope) -> Option<String> {
    primary_device_id_from_tokens(scope.iter().map(oauth_types::scope::ScopeToken::as_str))
}

fn preferred_signing_key(
    key_store: &Keystore,
) -> Option<(
    JsonWebSignatureAlg,
    &coauth_keystore::JsonWebKey<coauth_keystore::PrivateKey>,
)> {
    [
        JsonWebSignatureAlg::EdDsa,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps256,
    ]
    .into_iter()
    .find_map(|alg| {
        key_store
            .signing_key_for_algorithm(&alg)
            .map(|key| (alg, key))
    })
}

pub(crate) fn preferred_public_signing_key(key_store: &Keystore) -> Option<PublicJsonWebKey> {
    let (alg, key) = preferred_signing_key(key_store)?;
    let public_jwks = key_store.public_jwks();

    public_jwks
        .iter()
        .find(|candidate| candidate.alg() == Some(&alg) && candidate.kid() == key.kid())
        .cloned()
        .or_else(|| {
            public_jwks
                .iter()
                .find(|candidate| candidate.kid() == key.kid())
                .cloned()
        })
}

pub(crate) fn parse_local_user_did_for(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    did: &str,
) -> Option<Ulid> {
    let prefix = format!("{}:users:", service_did_for(url_builder, cokret_config));
    did.strip_prefix(&prefix)?.parse::<Ulid>().ok()
}

pub(crate) fn parse_local_handle(url_builder: &UrlBuilder, handle: &str) -> Option<String> {
    // Spec 7157ee8 §3.1 canonical form: `<localpart>:<domain>`. Also
    // accept the legacy `<localpart>@<domain>` display form for clients
    // that have not yet migrated. `acct:` prefix is stripped first so
    // both `acct:alice@host` and bare `alice@host` round-trip the same.
    let trimmed = handle.trim().trim_start_matches("acct:");
    let host = url_builder.public_hostname().to_lowercase();
    let colon_suffix = format!(":{host}");
    let at_suffix = format!("@{host}");
    trimmed
        .strip_suffix(&colon_suffix)
        .or_else(|| trimmed.strip_suffix(&at_suffix))
        .filter(|h| !h.is_empty())
        .map(ToOwned::to_owned)
}

// ── Test-only DPoP-bound grant seeding ──────────────────────────

/// Body for the cotest debug helper. `dpop_jwk` is the device's public
/// JWK (RFC 7517 shape) — we recompute its thumbprint and bake it in as
/// `cnf.jkt` on the issued grant. `actor_id` is the subject DID the
/// caller wants the grant bound to; we trust it because this endpoint
/// is gated behind `debug_assertions` / a `COAUTH_ENABLE_TEST_ENDPOINTS`
/// env var.
#[derive(Debug, Deserialize)]
pub struct DebugIssueDpopGrantRequest {
    pub actor_id: String,
    pub device_id: String,
    pub dpop_jwk: serde_json::Value,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct DebugIssueDpopGrantResponse {
    pub grant_id: String,
    pub grant_jwt: String,
    pub dpop_jkt: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
}

/// Returns true when test-only endpoints are allowed at runtime. We are
/// permissive when either `cfg!(debug_assertions)` is true (i.e. dev /
/// debug builds) OR the operator sets `COAUTH_ENABLE_TEST_ENDPOINTS=1`.
#[must_use]
pub fn test_endpoints_enabled() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    matches!(
        std::env::var("COAUTH_ENABLE_TEST_ENDPOINTS")
            .ok()
            .as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// `POST /api/v1/test/debug/issue-dpop-grant` — deterministic DPoP-bound
/// session-grant seed used by the cotest e2e harness. Returns a fully
/// signed grant whose `cnf.jkt` matches the thumbprint of the supplied
/// `dpop_jwk`. Gated by [`test_endpoints_enabled`].
#[handler]
pub async fn debug_issue_dpop_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DebugIssueDpopGrantResponse>, CokretRouteError> {
    use coauth_jose::jwk::{PublicJsonWebKey, Thumbprint};

    if !test_endpoints_enabled() {
        return Err(CokretRouteError::NotFound);
    }

    let body: DebugIssueDpopGrantRequest = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;

    if body.actor_id.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("missing actor_id".to_owned()));
    }
    if body.device_id.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("missing device_id".to_owned()));
    }

    let public_jwk: PublicJsonWebKey = serde_json::from_value(body.dpop_jwk.clone())
        .map_err(|error| CokretRouteError::BadRequest(format!("invalid dpop_jwk: {error}")))?;
    let jkt = public_jwk.params().thumbprint_sha256_base64();

    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    let mut repo = depot.repo().await?;

    // We need a browser session for the underlying grant row. Pick the
    // most recent one for the user identified by `actor_id`, or fail
    // closed when none exists. The cotest harness registers the user
    // first, so a session always exists in practice.
    let user_id = parse_local_user_did_for(&url_builder, &cokret_config, &body.actor_id)
        .ok_or_else(|| {
            CokretRouteError::BadRequest("actor_id is not a local Cokret user DID".to_owned())
        })?;
    let user = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| CokretRouteError::NotFound)?;

    let user_agent = Some(format!("coauth-test-harness/device:{}", body.device_id));
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &*clock, &user, user_agent)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    let audience = body
        .audience
        .clone()
        .unwrap_or_else(|| required_audience_for(&url_builder, &cokret_config));
    let scopes = body.scopes.clone().unwrap_or_else(|| {
        vec![
            format!("urn:cokret:client:device:{}", body.device_id),
            PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(),
        ]
    });

    let material = issue_session_grant_for_audience(
        &mut rng,
        &*clock,
        &url_builder,
        &cokret_config,
        &key_store,
        &browser_session,
        audience,
        scopes,
        Some(&body.actor_id),
        Some(jkt.clone()),
    )
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    let persisted =
        persist_session_grant(&mut repo, &mut rng, &*clock, &browser_session, &material)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(DebugIssueDpopGrantResponse {
        grant_id: persisted.id.to_string(),
        grant_jwt: material.grant_jwt,
        dpop_jkt: jkt,
        audience: material.audience,
        scopes: material.scopes,
        expires_at: material.expires_at,
    }))
}
