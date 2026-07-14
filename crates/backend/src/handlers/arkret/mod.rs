mod device_enroll;
mod did_document;
mod handle_claim;
mod identity;
mod service_describe;
mod session_grant;

pub use device_enroll::*;
pub use did_document::*;
pub use handle_claim::*;
pub use identity::*;
pub use service_describe::*;
pub use session_grant::*;

#[cfg(test)]
mod tests;

use anyhow::Error as AnyhowError;
use arkret_core::ErrorEnvelope;
use arkret_core::error::{
    ERROR_CODE_BAD_JSON, ERROR_CODE_CAPABILITY_DENIED, ERROR_CODE_CONFLICT,
    ERROR_CODE_FAILED_PRECONDITION, ERROR_CODE_INTERNAL_ERROR, ERROR_CODE_INVALID_PARAM,
    ERROR_CODE_NOT_FOUND, ERROR_CODE_RATE_LIMITED, ERROR_CODE_SCHEMA_VIOLATION,
    ERROR_CODE_UNAUTHENTICATED, ERROR_CODE_UNSUPPORTED_FEATURE,
};
use coauth_config::ArkretConfig;
use coauth_data::{RepositoryAccess, UrlBuilder, User};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::constraints::Constrainable;
use coauth_jose::jwt::JwtSignatureError;
use coauth_keystore::{Keystore, WrongAlgorithmError};
use coauth_oauth_types::scope::Scope;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::common::{DepotExt, RouteError};
use crate::services::resolved_principal_audiences::{
    self, ResolvedPrincipalAudiences, effective_audience,
};

const ARKRET_PROTOCOL_VERSION: &str = "1.0";

const ARKRET_HTTP_BINDING: &str = "http_json";

pub const CLAIM_PRINCIPAL_DID: &str = "org.arkret.principal_did";

pub const CLAIM_DEVICE_ID: &str = "org.arkret.device_id";

pub const CLAIM_SESSION_ID: &str = "org.arkret.session_id";

pub const PRINCIPAL_SERVER_SESSION_BIND_SCOPE: &str = "urn:arkret:principal-server:session.bind";

#[derive(Debug, Error)]
pub enum SessionGrantError {
    #[error("no signing key is configured for Arkret session grants")]
    NoSigningKey,

    #[error(transparent)]
    JwtSignature(#[from] JwtSignatureError),

    #[error(transparent)]
    WrongAlgorithm(#[from] WrongAlgorithmError),

    #[error(transparent)]
    Serialize(#[from] serde_json::Error),

    /// Canonical-JSON / digest failure surfaced by the shared SDK pipeline
    /// (`arkret_core::canonical`). Carried as the SDK error itself so call
    /// sites keep its structured variants (e.g. `NonCanonicalNumber`)
    /// instead of a flattened string.
    #[error(transparent)]
    Canonical(#[from] arkret_core::Error),

    /// SEC-04 — the inception key that would sign this issuance is past its
    /// 24h online window (or its bootstrap anchor was missing / unparseable,
    /// which fails closed). Carries reason code
    /// [`arkret_core::error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED`]
    /// (`inception_key_window_exceeded`). The receiver enforces this 24h hard
    /// cap independently, regardless of any longer window the issuing
    /// deployment self-reports.
    ///
    /// NOTE (honest boundary): coauth does not currently issue any
    /// `ak.session.grant` signed by a client inception key (grants are signed
    /// by the deployment service key over an authenticated browser session),
    /// so this variant is not produced by the present issuance path. It exists
    /// as the typed rejection surface for a future genuine inception-key-signed
    /// path; the enforcement primitive lives in
    /// [`crate::services::inception_key_window`].
    #[error(transparent)]
    InceptionKeyWindowExceeded(
        #[from] crate::services::inception_key_window::InceptionKeyWindowError,
    ),

    /// R3.2 (HC-COAUTH-1/2) — the handle-claim issuance request failed the
    /// `claim_kind` allow-list or subject (holder/principal DID)
    /// validation. Carries the SDK / shared wire reason code.
    #[error(transparent)]
    HandleClaimSubject(#[from] crate::services::handle_subject_validator::HandleClaimSubjectError),

    #[error(
        "did:web principal requires arkret.deployment_profile=personal_node and arkret.principal_method=did:web"
    )]
    DidWebPrincipalNotExplicit,

    #[error(transparent)]
    Other(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum ArkretRouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("not found")]
    NotFound,

    #[error("{0}")]
    BadRequest(String),

    /// A protocol failure whose registry error code MUST surface as the
    /// envelope's top-level `code` (e.g. `grant_already_consumed`,
    /// `session_logged_out`, `audience_mismatch`, `session_grant_not_found`)
    /// rather than being collapsed into `bad_json`. This lets conformant
    /// clients discriminate the failure structurally (account-lifecycle §4.1,
    /// error-code-registry `codes`) instead of string-matching the message.
    #[error("{message}")]
    Coded {
        status: StatusCode,
        code: &'static str,
        message: String,
    },

    /// Agent runtime must correlate this opaque request with an out-of-band
    /// controller approval flow. It renders as a closed `claim_required`
    /// details object and never as a browser challenge.
    #[error("controller approval required")]
    HumanApprovalRequired(arkret_core::AgentHumanApprovalErrorDetails),

    /// Caller did not present a usable bearer token. Renders as `401`.
    #[error("{0}")]
    Unauthorized(String),

    /// Caller presented a token, but it lacks the scope required for the
    /// requested operation. Renders as `403`.
    #[error("{0}")]
    Forbidden(String),
}

impl ArkretRouteError {
    /// Build a [`ArkretRouteError::Coded`] carrying a registry error code that
    /// will surface as the envelope's top-level `code`.
    pub fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self::Coded {
            status,
            code,
            message: message.into(),
        }
    }
}

impl From<RouteError> for ArkretRouteError {
    fn from(value: RouteError) -> Self {
        match value {
            RouteError::BadRequest(message) => Self::BadRequest(message),
            RouteError::NotFound => Self::NotFound,
            other => Self::Internal(Box::new(other)),
        }
    }
}

impl From<coauth_data::RepositoryError> for ArkretRouteError {
    fn from(value: coauth_data::RepositoryError) -> Self {
        Self::Internal(Box::new(value))
    }
}

impl From<crate::AppError> for ArkretRouteError {
    fn from(value: crate::AppError) -> Self {
        let status = value.status();
        let message = value.message().to_owned();
        if let Some(code) = value.protocol_code() {
            return Self::coded(status, code, message);
        }
        match status {
            StatusCode::BAD_REQUEST => Self::coded(status, ERROR_CODE_INVALID_PARAM, message),
            StatusCode::UNAUTHORIZED => Self::Unauthorized(message),
            StatusCode::FORBIDDEN => Self::Forbidden(message),
            StatusCode::NOT_FOUND => Self::coded(status, ERROR_CODE_NOT_FOUND, message),
            StatusCode::CONFLICT => Self::coded(status, ERROR_CODE_CONFLICT, message),
            StatusCode::GONE | StatusCode::PRECONDITION_FAILED => {
                Self::coded(status, ERROR_CODE_FAILED_PRECONDITION, message)
            }
            StatusCode::UNPROCESSABLE_ENTITY => {
                Self::coded(status, ERROR_CODE_SCHEMA_VIOLATION, message)
            }
            StatusCode::TOO_MANY_REQUESTS => Self::coded(status, ERROR_CODE_RATE_LIMITED, message),
            StatusCode::NOT_IMPLEMENTED => {
                Self::coded(status, ERROR_CODE_UNSUPPORTED_FEATURE, message)
            }
            StatusCode::INTERNAL_SERVER_ERROR => Self::Internal(Box::new(value)),
            _ => Self::coded(status, ERROR_CODE_INTERNAL_ERROR, message),
        }
    }
}

/// Authorization decision for a session-grant administrative endpoint.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SessionGrantAuthz {
    /// The caller presented an admin scope. Allowed for read and write.
    Admin,
    /// The caller presented the `server_name` `session.bind` scope.
    /// Allowed for read-only paths (list / introspect).
    PrincipalServer,
}

/// Resolved session-grant caller: the authorization tier plus, for a
/// Principal Server caller, the set of audiences it is allowed to read.
///
/// `allowed_audiences` is `None` for an admin caller (unrestricted) and
/// `Some(..)` for a Principal Server caller. A Principal Server is only ever
/// authorized for the audience(s) of the principal-server configuration it
/// authenticated as, so it must not be able to enumerate session-grant
/// metadata across other subjects/audiences (SEC-SG-ENUM).
#[derive(Debug, Clone)]
pub(crate) struct SessionGrantCaller {
    pub(crate) authz: SessionGrantAuthz,
    allowed_audiences: Option<Vec<String>>,
}

impl SessionGrantCaller {
    fn admin() -> Self {
        Self {
            authz: SessionGrantAuthz::Admin,
            allowed_audiences: None,
        }
    }

    fn principal_server(allowed_audiences: Vec<String>) -> Self {
        Self {
            authz: SessionGrantAuthz::PrincipalServer,
            allowed_audiences: Some(allowed_audiences),
        }
    }

    /// Resolve the audience a session-grant *read* query must be pinned to,
    /// given the audience the caller requested (if any).
    ///
    /// - An admin caller (`allowed_audiences == None`) is unrestricted: the requested audience is
    ///   honoured as-is and `None` means "all".
    /// - A Principal Server caller MUST stay within its `allowed_audiences` (SEC-SG-ENUM). When it
    ///   requests an audience, that audience must be in the allow-list. When it requests none and
    ///   exactly one audience is configured for it, that single audience is auto-pinned. Otherwise
    ///   the caller must disambiguate, so cross-subject enumeration is refused.
    pub(crate) fn resolve_read_audience(
        &self,
        requested: Option<&str>,
    ) -> Result<Option<String>, ArkretRouteError> {
        let requested = requested.map(str::trim).filter(|a| !a.is_empty());
        match &self.allowed_audiences {
            None => Ok(requested.map(ToOwned::to_owned)),
            Some(allowed) => match requested {
                Some(audience) => {
                    if allowed.iter().any(|candidate| candidate == audience) {
                        Ok(Some(audience.to_owned()))
                    } else {
                        Err(ArkretRouteError::Forbidden(
                            "principal-server caller may only query its own audience".to_owned(),
                        ))
                    }
                }
                None => match allowed.as_slice() {
                    [audience] => Ok(Some(audience.clone())),
                    _ => Err(ArkretRouteError::Forbidden(
                        "principal-server caller must specify an allowed audience".to_owned(),
                    )),
                },
            },
        }
    }
}

/// Resolve the bearer token on the request and require either an admin
/// scope or the `server_name` session-bind scope. Used by the
/// session-grant admin surface to gate access without going through the
/// heavier admin call-context extractor.
///
/// In addition to the scope check, this validates the credential's liveness:
/// expired or revoked access tokens / sessions are rejected with `401`
/// (SEC-SG-EXPIRY / REL-04). The legacy behaviour only inspected
/// `session.scope` and would happily authorize a long-expired or revoked
/// token.
pub(crate) async fn require_session_grant_caller(
    req: &Request,
    depot: &Depot,
) -> Result<SessionGrantCaller, ArkretRouteError> {
    use coauth_data::{RepositoryAccess, TokenType};

    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| ArkretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let auth_str = auth_header
        .to_str()
        .map_err(|_| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    let token = auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .ok_or_else(|| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?;

    // Static bearer fallback: a Principal Server may authenticate with a
    // token configured in `arkret.principal_servers[].
    // session_grant_introspection_bearer`. This lets a server-to-server caller
    // skip the DB-backed PAT/OAuth-session lookup. Grants `PrincipalServer`
    // authz only — never `Admin` — so it cannot revoke session grants. The
    // matching server's audience is the only one this caller may read.
    let arkret_config = depot.arkret_config()?;
    if let Some(audience) =
        principal_server_static_session_grant_bearer_audience(&arkret_config, token)
    {
        return Ok(SessionGrantCaller::principal_server(vec![audience]));
    }

    let now = crate::handlers::make_clock().now();

    let token_type = TokenType::check(token)
        .map_err(|_| ArkretRouteError::Unauthorized("invalid bearer token".to_owned()))?;

    let mut repo = depot.repo().await?;
    let scope = match token_type {
        TokenType::AccessToken => {
            let access = repo
                .oauth_access_token()
                .find_by_token(token)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| ArkretRouteError::Unauthorized("unknown access token".to_owned()))?;
            // SEC-SG-EXPIRY / REL-04: reject revoked or expired access tokens.
            if !access.is_valid(now) {
                repo.cancel().await?;
                return Err(ArkretRouteError::Unauthorized(
                    "access token is expired or revoked".to_owned(),
                ));
            }
            let session = repo
                .oauth_session()
                .lookup(access.session_id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "access token references missing session",
                    ))
                })?;
            // SEC-SG-EXPIRY / REL-04: reject finished (logged-out) sessions.
            if !session.is_valid() {
                repo.cancel().await?;
                return Err(ArkretRouteError::Unauthorized(
                    "session is finished".to_owned(),
                ));
            }
            session.scope.clone()
        }
        TokenType::PersonalAccessToken => {
            let access = repo
                .personal_access_token()
                .find_by_token(token)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| ArkretRouteError::Unauthorized("unknown access token".to_owned()))?;
            // SEC-SG-EXPIRY / REL-04: reject revoked or expired personal tokens.
            if !access.is_valid(now) {
                repo.cancel().await?;
                return Err(ArkretRouteError::Unauthorized(
                    "access token is expired or revoked".to_owned(),
                ));
            }
            let session = repo
                .personal_session()
                .lookup(access.session_id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "access token references missing session",
                    ))
                })?;
            // SEC-SG-EXPIRY / REL-04: reject revoked personal sessions.
            if !session.is_valid() {
                repo.cancel().await?;
                return Err(ArkretRouteError::Unauthorized(
                    "session is revoked".to_owned(),
                ));
            }
            session.scope.clone()
        }
        _ => {
            return Err(ArkretRouteError::Unauthorized(
                "unsupported access token type".to_owned(),
            ));
        }
    };
    repo.cancel().await?;

    if crate::handlers::admin::has_admin_scope(&scope) {
        Ok(SessionGrantCaller::admin())
    } else if scope.contains(PRINCIPAL_SERVER_SESSION_BIND_SCOPE) {
        // A `session.bind`-scoped caller is a Principal Server. The scope does
        // not pin which configured server, so the caller may read any of the
        // configured principal-server audiences (and only those). The list /
        // introspect handlers further require the caller to pin one of these
        // audiences before any subject/device enumeration is allowed.
        let allowed_audiences = arkret_config
            .principal_servers
            .iter()
            .filter_map(|server| effective_audience(server, resolved_principal_audiences::shared()))
            .collect();
        Ok(SessionGrantCaller::principal_server(allowed_audiences))
    } else {
        Err(ArkretRouteError::Forbidden(
            "missing admin or principal-server scope".to_owned(),
        ))
    }
}

pub(crate) fn principal_server_static_session_grant_bearer_matches(
    arkret_config: &ArkretConfig,
    token: &str,
) -> bool {
    principal_server_static_session_grant_bearer_audience(arkret_config, token).is_some()
}

/// Returns the audience of the principal server whose static
/// `session_grant_introspection_bearer` matches `token`, or `None` when no
/// configured static bearer matches. The audience scopes what a static-bearer
/// Principal Server caller is allowed to read (SEC-SG-ENUM).
fn principal_server_static_session_grant_bearer_audience(
    arkret_config: &ArkretConfig,
    token: &str,
) -> Option<String> {
    if token.trim().is_empty() {
        return None;
    }
    arkret_config
        .principal_servers
        .iter()
        .find(|server| {
            server
                .session_grant_introspection_bearer
                .as_deref()
                .is_some_and(|configured| crate::util::constant_time_token_eq(configured, token))
        })
        .and_then(|server| effective_audience(server, resolved_principal_audiences::shared()))
}

impl Scribe for ArkretRouteError {
    fn render(self, res: &mut Response) {
        let (status, envelope) = match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorEnvelope::new(ERROR_CODE_INTERNAL_ERROR, "internal server error"),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorEnvelope::new(ERROR_CODE_NOT_FOUND, "not found"),
            ),
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                ErrorEnvelope::new(ERROR_CODE_BAD_JSON, message),
            ),
            Self::Coded {
                status,
                code,
                message,
            } => (status, ErrorEnvelope::new(code, message)),
            Self::HumanApprovalRequired(details) => (
                StatusCode::FORBIDDEN,
                ErrorEnvelope::claim_required_human_approval(
                    "controller approval required",
                    details,
                ),
            ),
            Self::Unauthorized(message) => (
                StatusCode::UNAUTHORIZED,
                ErrorEnvelope::new(ERROR_CODE_UNAUTHENTICATED, message),
            ),
            Self::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                ErrorEnvelope::new(ERROR_CODE_CAPABILITY_DENIED, message),
            ),
        };

        if status == StatusCode::UNAUTHORIZED {
            // RFC 7235 says 401 responses MUST include a WWW-Authenticate
            // challenge so the caller can negotiate.
            res.headers_mut().insert(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static("Bearer realm=\"arkret\", error=\"invalid_token\""),
            );
        }

        res.status_code(status);
        res.render(Json(envelope));
    }
}

fn map_did_resolve_error(
    error: crate::services::did_resolver::DidResolveError,
) -> ArkretRouteError {
    match error {
        crate::services::did_resolver::DidResolveError::NotFound
        | crate::services::did_resolver::DidResolveError::UnsupportedMethod => {
            ArkretRouteError::NotFound
        }
        crate::services::did_resolver::DidResolveError::InvalidDid(message) => {
            ArkretRouteError::BadRequest(format!("invalid did: {message}"))
        }
        crate::services::did_resolver::DidResolveError::DidWebPrincipalNotExplicit => {
            ArkretRouteError::BadRequest(
                "did:web principal requires deployment_profile=personal_node and principal_method=did:web"
                    .to_owned(),
            )
        }
        other => ArkretRouteError::Internal(Box::new(other)),
    }
}

/// The deployment's configured service DID.
///
/// There is deliberately NO host-derived `did:web` fallback here:
/// `identity-did.md` §3 makes `did:webvh` the default service DID method and
/// any `did:web` downgrade an explicit no-history choice, so an unconfigured
/// `arkret.service_id` fails startup validation instead of silently minting
/// a `did:web` identity (see `ArkretConfig::validate`).
pub(crate) fn service_id_for(arkret_config: &ArkretConfig) -> String {
    arkret_config
        .service_id
        .clone()
        .expect("arkret.service_id is enforced by startup configuration validation")
}

pub(crate) fn issuer_did_for(arkret_config: &ArkretConfig) -> String {
    arkret_config
        .issuer_did
        .clone()
        .unwrap_or_else(|| service_id_for(arkret_config))
}

pub(crate) fn user_did_for(arkret_config: &ArkretConfig, user: &User) -> String {
    format!("{}:users:{}", service_id_for(arkret_config), user.id)
}

#[must_use]
pub(crate) fn is_did_web_principal(did: &str) -> bool {
    did.starts_with("did:web:")
}

pub(crate) fn ensure_principal_did_method_allowed(
    arkret_config: &ArkretConfig,
    did: &str,
) -> Result<(), SessionGrantError> {
    if is_did_web_principal(did) && !arkret_config.did_web_principal_allowed() {
        return Err(SessionGrantError::DidWebPrincipalNotExplicit);
    }
    Ok(())
}

/// Local OIDC subject for Account Authority-issued OAuth tokens.
///
/// This identifies the authenticated coauth account. Principal-server DIDs are
/// resolved later by the `session-grants` bridge for the requested audience.
pub(crate) fn oidc_subject_for_user(arkret_config: &ArkretConfig, user: &User) -> String {
    user_did_for(arkret_config, user)
}

#[derive(Debug, Clone)]
pub(crate) struct PrincipalDidBinding {
    pub did: String,
    pub audience: String,
    pub principal_server_did: Option<String>,
}

pub(crate) async fn principal_did_binding_for_user<R>(
    repo: &mut R,
    arkret_config: &ArkretConfig,
    user: &User,
) -> Result<Option<PrincipalDidBinding>, R::Error>
where
    R: RepositoryAccess,
{
    for server in &arkret_config.principal_servers {
        let Some(audience) = effective_audience(server, resolved_principal_audiences::shared())
        else {
            continue;
        };
        if let Some(row) = repo
            .principal_did()
            .get_for_user_and_audience(user, &audience)
            .await?
        {
            return Ok(Some(PrincipalDidBinding {
                did: row.did,
                audience,
                principal_server_did: server.did.clone(),
            }));
        }
    }

    Ok(None)
}

pub(crate) async fn principal_did_for_user<R>(
    repo: &mut R,
    arkret_config: &ArkretConfig,
    user: &User,
) -> Result<Option<String>, R::Error>
where
    R: RepositoryAccess,
{
    Ok(principal_did_binding_for_user(repo, arkret_config, user)
        .await?
        .map(|binding| binding.did))
}

/// Persisted principal DID that is allowed to leave the Account Authority.
///
/// The custom OAuth/UserInfo/viewer claims must not synthesize or publish a
/// `did:web` principal unless the deployment explicitly opted into the
/// personal-node profile and `did:web` principal method.
pub(crate) async fn published_principal_did_for_user<R>(
    repo: &mut R,
    arkret_config: &ArkretConfig,
    user: &User,
) -> Result<Option<String>, R::Error>
where
    R: RepositoryAccess,
{
    let did = principal_did_for_user(repo, arkret_config, user).await?;
    Ok(did.filter(|did| ensure_principal_did_method_allowed(arkret_config, did).is_ok()))
}

/// Display form `local@host` used by logging / display paths.
/// NOT the canonical handle form — use [`user_handle`]
/// (spec 7157ee8 §3.1) for `alsoKnownAs` / DID Document / claim emission.
pub(crate) fn user_handle_display(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}@{}",
        user.localpart,
        url_builder.public_hostname().to_lowercase()
    )
}

/// Canonical Arkret handle for a user per spec 7157ee8 §3.1:
/// `<lowercase-localpart>:<lowercase-domain>`. This is the form that MUST
/// appear in `alsoKnownAs`, on any handle claim `handle` field, and as
/// directory cache key. `acct:<local>@<host>` is interop-only and lives in
/// `handle_aliases[]` on the handle claim.
pub(crate) fn user_handle(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}:{}",
        user.localpart.to_lowercase(),
        url_builder.public_hostname().to_lowercase()
    )
}

/// `acct:` interop alias for [`user_handle`]. Use this for
/// `handle_aliases[]` on a `handle-claim.schema.json` payload.
pub(crate) fn user_handle_acct_alias(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "acct:{}@{}",
        user.localpart.to_lowercase(),
        url_builder.public_hostname().to_lowercase()
    )
}

/// Stable wire-level error code returned when a caller passes a non-canonical
/// handle string (`arkret://` URI, `acct:` alias, or other malformed input).
pub const HANDLE_NOT_CANONICAL_CODE: &str = ERROR_CODE_INVALID_PARAM;

/// Reject any inbound `handle` that is not in the canonical
/// `<localpart>:<domain>` shape (spec 7157ee8 §3.1). Returns a
/// [`ArkretRouteError::Coded`] wrapping the standard error envelope
/// `code = "invalid_param"`.
pub(crate) fn require_canonical_handle(input: &str) -> Result<&str, ArkretRouteError> {
    coauth_data::user::validate_canonical_handle(input).map_err(|(_code, message)| {
        ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            HANDLE_NOT_CANONICAL_CODE,
            format!("reason_code=handle_not_canonical; {message}"),
        )
    })
}

pub(crate) fn required_audience(url_builder: &UrlBuilder) -> String {
    url_builder.absolute_url("/_arkret").to_string()
}

pub(crate) fn trust_domain_for(url_builder: &UrlBuilder, arkret_config: &ArkretConfig) -> String {
    arkret_config.trust_domain.clone().unwrap_or_else(|| {
        let scope = derived_trust_domain_scope(url_builder.public_hostname());
        let trust_domain = format!("ak:trust_domain:{scope}");
        debug_assert!(ArkretConfig::validate_trust_domain(&trust_domain).is_ok());
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
    arkret_config: &ArkretConfig,
) -> String {
    arkret_config
        .admin_audience
        .clone()
        .unwrap_or_else(|| required_audience(url_builder))
}

pub(crate) fn is_allowed_session_grant_audience(
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    resolved: &ResolvedPrincipalAudiences,
    audience: &str,
) -> bool {
    let audience = audience.trim();
    if audience.is_empty() {
        return false;
    }

    audience == required_audience_for(url_builder, arkret_config)
        || arkret_config
            .principal_servers
            .iter()
            .any(|server| effective_audience(server, resolved).as_deref() == Some(audience))
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
    arkret_config: &ArkretConfig,
    resolved: &ResolvedPrincipalAudiences,
    requested_audience: Option<&str>,
) -> Result<SessionGrantTarget, SessionGrantTargetError> {
    if let Some(audience) = requested_audience.map(str::trim).filter(|a| !a.is_empty()) {
        if let Some((server, effective)) =
            arkret_config.principal_servers.iter().find_map(|server| {
                effective_audience(server, resolved)
                    .filter(|effective| effective == audience)
                    .map(|effective| (server, effective))
            })
        {
            return Ok(SessionGrantTarget {
                audience: effective,
                principal_server_name: Some(server.name.clone()),
                principal_server_endpoint: Some(server.endpoint.to_string()),
            });
        }

        // The local admin audience is allowed for OIDC bridge strands, but
        // not for password login session grants — there is no principal
        // server to bind the grant to.
        if audience == required_audience_for(url_builder, arkret_config) {
            return Err(SessionGrantTargetError::LocalAudienceNotAllowed);
        }

        return Err(SessionGrantTargetError::UnknownAudience);
    }

    match arkret_config.principal_servers.as_slice() {
        // A sole principal server with no explicit audience whose describe
        // probe has not yet landed fails closed (UnknownAudience) rather than
        // minting a grant with no bindable audience.
        // 此 fail-closed 是有意设计（见 services::resolved_principal_audiences
        // §设计定位），非缺陷：宁可启动初期短暂拒绝，也不盖一个无法绑定的 audience。
        [server] => Ok(SessionGrantTarget {
            audience: effective_audience(server, resolved)
                .ok_or(SessionGrantTargetError::UnknownAudience)?,
            principal_server_name: Some(server.name.clone()),
            principal_server_endpoint: Some(server.endpoint.to_string()),
        }),
        [] => Err(SessionGrantTargetError::UnknownAudience),
        _ => Err(SessionGrantTargetError::UnknownAudience),
    }
}

fn primary_device_id_from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Option<String> {
    tokens.into_iter().find_map(|token| {
        token
            .strip_prefix("urn:arkret:client:device:")
            .map(ToOwned::to_owned)
    })
}

pub(crate) fn primary_device_id(scope: &Scope) -> Option<String> {
    primary_device_id_from_tokens(
        scope
            .iter()
            .map(coauth_oauth_types::scope::ScopeToken::as_str),
    )
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

pub(crate) fn parse_local_user_did_for(arkret_config: &ArkretConfig, did: &str) -> Option<Ulid> {
    let prefix = format!("{}:users:", service_id_for(arkret_config));
    did.strip_prefix(&prefix)?.parse::<Ulid>().ok()
}

pub(crate) fn parse_local_handle(url_builder: &UrlBuilder, handle: &str) -> Option<String> {
    // Spec 7157ee8 §3.1 canonical form: `<localpart>:<domain>`.
    let trimmed = handle.trim();
    let host = url_builder.public_hostname().to_lowercase();
    let colon_suffix = format!(":{host}");
    trimmed
        .strip_suffix(&colon_suffix)
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
pub struct DebugIssueDpopGrantRequestBody {
    pub actor_id: String,
    pub device_id: String,
    pub dpop_jwk: serde_json::Value,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct DebugIssueDpopGrantOutcome {
    pub grant_id: String,
    pub grant_jwt: String,
    pub dpop_jkt: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
    /// The minted `did:webvh:…:webvh:<ulid>` principal DID this grant's subject
    /// is bound to (model B). The cotest harness MUST adopt this as the account
    /// identity so device enrollment / MLS KeyPackage publish resolve the DID
    /// document that designates coauth's enrollment authority — rather than the
    /// coauth-local `user_did_for` fallback (`…:users:<ulid>`, model A) whose
    /// soland document carries no such designation.
    pub principal_did: String,
}

/// Returns true when test-only endpoints are explicitly allowed at runtime.
/// The route is only mounted in debug builds, and this env gate must still
/// be enabled there.
#[must_use]
pub fn test_endpoints_enabled() -> bool {
    matches!(
        coauth_config::runtime_var("COAUTH_ENABLE_TEST_ENDPOINTS")
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
) -> Result<Json<DebugIssueDpopGrantOutcome>, ArkretRouteError> {
    use coauth_jose::jwk::{PublicJsonWebKey, Thumbprint};

    if !test_endpoints_enabled() {
        return Err(ArkretRouteError::NotFound);
    }

    let body: DebugIssueDpopGrantRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;

    if body.actor_id.trim().is_empty() {
        return Err(ArkretRouteError::BadRequest("missing actor_id".to_owned()));
    }
    if body.device_id.trim().is_empty() {
        return Err(ArkretRouteError::BadRequest("missing device_id".to_owned()));
    }

    let public_jwk: PublicJsonWebKey = serde_json::from_value(body.dpop_jwk.clone())
        .map_err(|error| ArkretRouteError::BadRequest(format!("invalid dpop_jwk: {error}")))?;
    let jkt = public_jwk.params().thumbprint_sha256_base64();

    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // Resolve the user identified by `actor_id` (the coauth-local
    // `user_did_for` form the harness passes). Scoped so its repo connection is
    // released before the principal-DID mint below opens its own transaction.
    let user_id = parse_local_user_did_for(&arkret_config, &body.actor_id).ok_or_else(|| {
        ArkretRouteError::BadRequest("actor_id is not a local Arkret user DID".to_owned())
    })?;
    let user = {
        let mut repo = depot.repo().await?;
        repo.user()
            .lookup(user_id)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
            .ok_or(ArkretRouteError::NotFound)?
    };

    let audience = body
        .audience
        .clone()
        .unwrap_or_else(|| required_audience_for(&url_builder, &arkret_config));
    let grant_target = password_login_session_grant_target(
        &url_builder,
        &arkret_config,
        resolved_principal_audiences::shared(),
        Some(&audience),
    )
    .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let scopes = body.scopes.clone().unwrap_or_else(|| {
        vec![
            format!("urn:arkret:client:device:{}", body.device_id),
            PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(),
        ]
    });

    // Mint (or reuse) the model-B principal DID, whose document designates
    // coauth's `ArkretDeviceEnrollmentAuthority`, BEFORE issuing the grant. The
    // grant subject MUST be this minted `did:webvh:…:webvh:<ulid>` (mirroring the
    // OIDC/password-login path, account/auth.rs), NOT the coauth-local
    // `user_did_for` fallback (`…:users:<ulid>`) whose soland document carries no
    // enrollment-authority designation. Binding the subject to the fallback is
    // exactly why the cotest DPoP debug seam could authenticate but never enroll a
    // device or publish an MLS KeyPackage.
    let http_client = depot.http_client()?;
    let encrypter = depot.encrypter()?;
    let principal_did =
        match crate::handlers::account::auth::oidc_bridge::ensure_principal_did_for_user_committed(
            depot,
            &mut rng,
            &clock,
            &encrypter,
            &http_client,
            &url_builder,
            &arkret_config,
            &user,
            &audience,
        )
        .await
        {
            Ok(did) => did,
            Err(message) => {
                return Err(ArkretRouteError::Internal(
                    format!("principal DID minting failed: {message}").into(),
                ));
            }
        };

    let account_handle =
        crate::handlers::account::auth::oidc_bridge::registration_handle_for_principal_endpoint(
            grant_target.principal_server_endpoint.as_deref(),
            &user.localpart,
        );
    let localpart_sync_bearer =
        crate::handlers::account::auth::oidc_bridge::principal_server_operation_bearer(
            &arkret_config,
            &grant_target.audience,
        );
    crate::handlers::account::auth::oidc_bridge::ensure_soland_account_registered(
        &http_client,
        grant_target.principal_server_endpoint.as_deref(),
        &principal_did,
        localpart_sync_bearer,
        Some(&user.localpart),
        account_handle.as_deref(),
        user.display_name.as_deref(),
        Some(body.device_id.as_str()),
    )
    .await
    .map_err(|message| {
        ArkretRouteError::Internal(
            format!("principal account registration failed: {message}").into(),
        )
    })?;

    // Issue + persist the grant against a fresh repo, binding the subject to the
    // minted principal DID.
    let mut repo = depot.repo().await?;
    let user_agent = Some(format!("coauth-test-harness/device:{}", body.device_id));
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &*clock, &user, user_agent)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    let material = issue_test_session_grant_for_audience(
        &*clock,
        &arkret_config,
        &key_store,
        &browser_session,
        public_jwk,
        audience,
        scopes,
        Some(&principal_did),
        Some(jkt.clone()),
    )
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    let persisted =
        persist_session_grant(&mut repo, &mut rng, &*clock, &browser_session, &material)
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(Json(DebugIssueDpopGrantOutcome {
        grant_id: persisted.grant_id.to_string(),
        grant_jwt: material.grant_jwt,
        dpop_jkt: jkt,
        audience: material.audience,
        scopes: material.scopes,
        expires_at: material.expires_at,
        principal_did,
    }))
}
