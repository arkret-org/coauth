mod account_handoff;
mod account_register;
mod account_status;
pub(crate) mod canonical_response;
mod controller_gate;
mod device_pairing;
mod did_document;
mod erasure_request;
#[cfg(test)]
mod handle_claim;
mod identity;
mod recovery_authority;
mod session_grant;
mod test_chaos;

pub use account_handoff::*;
pub use account_register::*;
pub use account_status::*;
pub use canonical_response::ArkretCanonicalJson;
pub use controller_gate::*;
pub use device_pairing::*;
pub use did_document::*;
pub use erasure_request::*;
#[cfg(test)]
pub use handle_claim::*;
pub use identity::*;
pub use recovery_authority::*;
pub use session_grant::*;

#[cfg(test)]
mod tests;

use anyhow::Error as AnyhowError;
use arkret_wire::Problem;
use coauth_config::ArkretConfig;
#[cfg(debug_assertions)]
use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
use coauth_data::{RepositoryAccess, UrlBuilder, User};
use coauth_jose::constraints::Constrainable;
use coauth_jose::jwt::JwtSignatureError;
use coauth_keyring::WrongAlgorithmError;
use coauth_oauth_types::scope::Scope;
use salvo::prelude::*;
#[cfg(debug_assertions)]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::handlers::common::{DepotExt, RouteError};
use crate::services::station_trust::{self, StationTrustResolver, effective_audience};

pub const CLAIM_PRINCIPAL_ID: &str = "org.arkret.principal_id";

pub const CLAIM_DEVICE_ID: &str = "org.arkret.device_id";

pub const CLAIM_SESSION_ID: &str = "org.arkret.session_id";

pub const STATION_SESSION_BIND_SCOPE: &str = "urn:arkret:station:session.bind";

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

    /// Canonical JSON or digest failure surfaced by the canonical owner crate.
    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    /// Wire construction or validation failure surfaced by the wire owner crate.
    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    /// R3.2 (HC-COAUTH-1/2) — the handle-claim issuance request failed the
    /// `claim_kind` allow-list or subject (holder/principal DID)
    /// validation. Carries the SDK / shared wire reason code.
    #[error(transparent)]
    HandleClaimSubject(#[from] crate::services::handle_subject_validator::HandleClaimSubjectError),

    #[error("principal_unknown")]
    PrincipalUnknown,

    /// Typed identifier parse failure surfaced by the identifiers owner crate.
    #[error(transparent)]
    Identifier(#[from] arkret_identifiers::IdentifierError),

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
    /// rather than being collapsed into `json_invalid`. This lets conformant
    /// clients discriminate the failure structurally (account-lifecycle §4.1,
    /// error-code-registry `codes`) instead of string-matching the message.
    #[error("{message}")]
    Coded {
        status: StatusCode,
        code: &'static str,
        message: String,
    },

    /// A [`Self::Coded`] failure that additionally carries structured
    /// `details` entries (e.g. the registry sub-`reason_code` of a
    /// `failed_precondition`), so conformant clients can discriminate the
    /// failure without string-matching the message.
    #[error("{message}")]
    CodedDetailed {
        status: StatusCode,
        code: &'static str,
        message: String,
        details: Vec<(&'static str, serde_json::Value)>,
    },

    /// A protocol rate limit with the mandatory structured retry hint.
    #[error("{message}")]
    RateLimited {
        message: String,
        retry_after_ms: u64,
    },

    /// Agent runtime must correlate this opaque request with an out-of-band
    /// controller approval flow. It renders as a closed `claim_required`
    /// details object and never as a browser challenge.
    #[error("controller approval required")]
    HumanApprovalRequired(arkret_wire::AgentHumanApprovalProblem),

    #[error("session grant exact replay has expired")]
    SessionGrantReplayExpired(arkret_wire::SessionGrantReplayExpiredProblem),

    #[error("session grant exact replay reached a terminal lifecycle state")]
    SessionGrantReplayTerminal(arkret_wire::SessionGrantReplayTerminalProblem),

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

    /// Build a `429 rate_limited` response with both canonical retry signals.
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self::RateLimited {
            message: message.into(),
            retry_after_ms,
        }
    }

    pub fn session_grant_replay_expired(grant_id: arkret_identifiers::SessionGrantId) -> Self {
        Self::SessionGrantReplayExpired(arkret_wire::SessionGrantReplayExpiredProblem::new(
            grant_id,
        ))
    }

    pub fn session_grant_replay_terminal(
        grant_id: arkret_identifiers::SessionGrantId,
        state: arkret_wire::SessionGrantReplayTerminalState,
    ) -> Self {
        Self::SessionGrantReplayTerminal(arkret_wire::SessionGrantReplayTerminalProblem::new(
            grant_id, state,
        ))
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

/// Declare `From<$error> for ArkretRouteError` mapping onto
/// [`ArkretRouteError::Internal`].
///
/// Only failures that a well-formed request can never provoke belong here:
/// canonicalisation and serialisation of server-built values, wire validation
/// of an outcome this process just constructed, and identifier construction
/// from server-side material. Anything derived from the request body or a
/// remote peer MUST keep an explicit `map_err` that picks the right 4xx code —
/// a bare `?` on such a value would silently answer `500` where the registry
/// requires `param_invalid`, `schema_violation` or a peer-specific code.
macro_rules! internal_route_error_from {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for ArkretRouteError {
                fn from(value: $error) -> Self {
                    Self::Internal(Box::new(value))
                }
            }
        )+
    };
}

internal_route_error_from!(
    arkret_canonical::CanonicalError,
    arkret_identifiers::IdentifierError,
    arkret_wire::WireError,
    serde_json::Error,
    SessionGrantError,
);

impl From<crate::AppError> for ArkretRouteError {
    fn from(value: crate::AppError) -> Self {
        let status = value.status();
        let message = value.message().to_owned();
        if let Some(code) = value.protocol_code() {
            return Self::coded(status, code, message);
        }
        match status {
            StatusCode::BAD_REQUEST => {
                Self::coded(status, arkret_wire::ErrorCode::PARAM_INVALID, message)
            }
            StatusCode::UNAUTHORIZED => Self::Unauthorized(message),
            StatusCode::FORBIDDEN => Self::Forbidden(message),
            StatusCode::NOT_FOUND => {
                Self::coded(status, arkret_wire::ErrorCode::NOT_FOUND, message)
            }
            StatusCode::CONFLICT => Self::coded(status, arkret_wire::ErrorCode::CONFLICT, message),
            StatusCode::GONE | StatusCode::PRECONDITION_FAILED => {
                Self::coded(status, arkret_wire::ErrorCode::FAILED_PRECONDITION, message)
            }
            StatusCode::UNPROCESSABLE_ENTITY => {
                Self::coded(status, arkret_wire::ErrorCode::SCHEMA_VIOLATION, message)
            }
            StatusCode::TOO_MANY_REQUESTS => {
                Self::coded(status, arkret_wire::ErrorCode::RATE_LIMITED, message)
            }
            StatusCode::NOT_IMPLEMENTED => {
                Self::coded(status, arkret_wire::ErrorCode::UNSUPPORTED_FEATURE, message)
            }
            StatusCode::INTERNAL_SERVER_ERROR => Self::Internal(Box::new(value)),
            _ => Self::coded(status, arkret_wire::ErrorCode::INTERNAL_ERROR, message),
        }
    }
}

/// Resolve the `kid` of the preferred service signing key.
///
/// A session-grant reservation stamps the operation with the key that will
/// later sign the credential, so the reservation and the issuance cannot drift
/// onto different keys. A keyring without a usable key is a deployment
/// misconfiguration, never a request failure, which is why both arms collapse
/// onto [`SessionGrantError::NoSigningKey`].
pub(crate) fn preferred_signing_key_id(
    keyring: &coauth_keyring::Keyring,
) -> Result<String, ArkretRouteError> {
    let (_, signing_key) = crate::services::preferred_service_signing_key(keyring)
        .ok_or(SessionGrantError::NoSigningKey)?;
    Ok(signing_key
        .kid()
        .ok_or(SessionGrantError::NoSigningKey)?
        .to_owned())
}

/// Authorization decision for a session-grant administrative endpoint.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SessionGrantAuthz {
    /// The caller presented an admin scope. Allowed for read and write.
    Admin,
    /// The caller presented the `server_name` `session.bind` scope.
    /// Allowed for read-only paths (list / introspect).
    Station,
}

/// Resolved session-grant caller: the authorization tier plus, for a
/// Station caller, the set of audiences it is allowed to read.
///
/// `allowed_audiences` is `None` for an admin caller (unrestricted) and
/// `Some(..)` for a Station caller. A Station is only ever
/// authorized for the audience(s) of the station configuration it
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

    fn station(allowed_audiences: Vec<String>) -> Self {
        Self {
            authz: SessionGrantAuthz::Station,
            allowed_audiences: Some(allowed_audiences),
        }
    }

    /// Resolve the audience a session-grant *read* query must be pinned to,
    /// given the audience the caller requested (if any).
    ///
    /// - An admin caller (`allowed_audiences == None`) is unrestricted: the requested audience is
    ///   honoured as-is and `None` means "all".
    /// - A Station caller MUST stay within its `allowed_audiences` (SEC-SG-ENUM). When it requests
    ///   an audience, that audience must be in the allow-list. When it requests none and exactly
    ///   one audience is configured for it, that single audience is auto-pinned. Otherwise the
    ///   caller must disambiguate, so cross-subject enumeration is refused.
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
                            "station caller may only query its own audience".to_owned(),
                        ))
                    }
                }
                None => match allowed.as_slice() {
                    [audience] => Ok(Some(audience.clone())),
                    _ => Err(ArkretRouteError::Forbidden(
                        "station caller must specify an allowed audience".to_owned(),
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
/// (SEC-SG-EXPIRY / REL-04). A scope check alone is not enough: it would
/// happily authorize a long-expired or revoked token.
pub(crate) async fn require_session_grant_caller(
    req: &Request,
    depot: &Depot,
    allow_internal_channel: bool,
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

    // Internal-channel fallback: only the private introspection route may
    // authenticate with `arkret.stations[].internal_authority_shared_secret`.
    // The product-facing list/revoke routes require a live scoped token.
    // This grants `Station`
    // authz only — never `Admin` — so it cannot revoke session grants. The
    // matching server's audience is the only one this caller may read.
    let arkret_config = depot.arkret_config()?;
    let static_bearer_audience = allow_internal_channel
        .then(|| station_internal_channel_caller(&arkret_config, token))
        .flatten();
    if let Some(static_bearer_audience) = static_bearer_audience {
        return Ok(SessionGrantCaller::station(vec![static_bearer_audience]));
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
                .await?
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
                .await?
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
                .await?
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
                .await?
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
    } else if scope.contains(STATION_SESSION_BIND_SCOPE) {
        // A `session.bind`-scoped caller is a Station. The scope does
        // not pin which configured server, so the caller may read any of the
        // configured station audiences (and only those). The list /
        // introspect handlers further require the caller to pin one of these
        // audiences before any subject/device enumeration is allowed.
        let allowed_audiences = arkret_config
            .stations
            .iter()
            .filter_map(|server| effective_audience(server, station_trust::shared()))
            .map(|audience| audience.to_string())
            .collect();
        Ok(SessionGrantCaller::station(allowed_audiences))
    } else {
        Err(ArkretRouteError::Forbidden(
            "missing admin or station scope".to_owned(),
        ))
    }
}

#[cfg(test)]
pub(crate) fn station_internal_authority_shared_secret_matches(
    arkret_config: &ArkretConfig,
    token: &str,
) -> bool {
    station_internal_channel_caller(arkret_config, token).is_some()
}

/// Callers authenticated on the deployment-internal channel
/// (`sync/service-http-binding.md` §2.2.3) by `credential`.
///
/// The identity is the one verified durable Station binding whose configured
/// channel credential matches, never a request header or body field.
/// Configuration validation rejects duplicate credentials, and this helper
/// independently rejects an ambiguous match rather than choosing the first.
pub(crate) fn station_internal_channel_caller(
    arkret_config: &ArkretConfig,
    token: &str,
) -> Option<String> {
    if token.trim().is_empty() || arkret_config.trust_domain.is_none() {
        return None;
    }
    let mut matches = arkret_config
        .stations
        .iter()
        .filter(|server| {
            server.has_internal_authority_peer()
                && server.trust_domain.is_some()
                && server
                    .internal_authority_shared_secret()
                    .is_some_and(|configured| {
                        crate::util::constant_time_token_eq(configured, token)
                    })
        })
        .filter_map(station_trust::effective_audience_shared)
        .map(|audience| audience.to_string());
    let caller = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(caller)
}

fn internal_error_envelope(
    error: &(dyn std::error::Error + Send + Sync + 'static),
    development_mode: bool,
) -> Problem {
    let message = if development_mode {
        format!("internal server error: {error}")
    } else {
        "internal server error".to_owned()
    };
    let envelope = Problem::from_code(arkret_wire::ErrorCode::INTERNAL_ERROR, message);
    if development_mode {
        envelope.with_extension("cause", serde_json::json!(error.to_string()))
    } else {
        envelope
    }
}

pub(crate) fn render_problem(res: &mut Response, status: StatusCode, envelope: Problem) {
    let problem = envelope.with_status(status.as_u16());
    let mut output = salvo::http::Problem::new(status)
        .kind(problem.problem_type)
        .title(problem.title)
        .detail(problem.detail)
        .with_extensions(
            problem
                .extensions
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        );
    if let Some(instance) = problem.instance {
        output = output.instance(instance);
    }
    res.render(output);
}

impl Scribe for ArkretRouteError {
    fn render(self, res: &mut Response) {
        let request_id = res
            .headers()
            .get(crate::server::ARKRET_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| arkret_identifiers::RequestId::new((*value).to_owned()).is_ok())
            .map(ToOwned::to_owned);
        let retry_after_ms = match &self {
            Self::RateLimited { retry_after_ms, .. } => Some(*retry_after_ms),
            _ => None,
        };
        let (status, envelope) = match self {
            Self::Internal(error) => {
                tracing::error!(request_id = request_id.as_deref().unwrap_or("unavailable"), error = %error, "Arkret route failed internally");
                let development_mode = crate::error::development_mode_from_env();
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    internal_error_envelope(error.as_ref(), development_mode),
                )
            }
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                Problem::from_code(arkret_wire::ErrorCode::NOT_FOUND, "not found"),
            ),
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                Problem::from_code(arkret_wire::ErrorCode::JSON_INVALID, message),
            ),
            Self::Coded {
                status,
                code,
                message,
            } => (status, Problem::from_code(code, message)),
            Self::CodedDetailed {
                status,
                code,
                message,
                details,
            } => {
                let mut envelope = Problem::from_code(code, message);
                for (key, value) in details {
                    envelope = envelope.with_extension(key, value);
                }
                (status, envelope)
            }
            Self::RateLimited {
                message,
                retry_after_ms,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                Problem::from_code(arkret_wire::ErrorCode::RATE_LIMITED, message)
                    .with_retry_after_ms(Some(retry_after_ms)),
            ),
            Self::HumanApprovalRequired(details) => (
                StatusCode::FORBIDDEN,
                Problem::claim_required_human_approval("controller approval required", details),
            ),
            Self::SessionGrantReplayExpired(details) => {
                let mut envelope = Problem::from_code(
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_EXPIRED,
                    "session grant exact replay has expired",
                );
                if let serde_json::Value::Object(values) =
                    serde_json::to_value(details).expect("typed replay details serialize")
                {
                    for (key, value) in values {
                        envelope = envelope.with_extension(key, value);
                    }
                }
                (StatusCode::GONE, envelope)
            }
            Self::SessionGrantReplayTerminal(details) => {
                let mut envelope = Problem::from_code(
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_TERMINAL,
                    "session grant exact replay is terminal",
                );
                if let serde_json::Value::Object(values) =
                    serde_json::to_value(details).expect("typed replay details serialize")
                {
                    for (key, value) in values {
                        envelope = envelope.with_extension(key, value);
                    }
                }
                (StatusCode::CONFLICT, envelope)
            }
            Self::Unauthorized(message) => (
                StatusCode::UNAUTHORIZED,
                Problem::from_code(arkret_wire::ErrorCode::UNAUTHENTICATED, message),
            ),
            Self::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                Problem::from_code(arkret_wire::ErrorCode::CAPABILITY_DENIED, message),
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

        if let Some(retry_after_ms) = retry_after_ms {
            let retry_after_seconds = retry_after_ms.div_ceil(1_000).max(1);
            if let Ok(value) = http::HeaderValue::try_from(retry_after_seconds.to_string()) {
                res.headers_mut().insert(http::header::RETRY_AFTER, value);
            }
        }

        let envelope = match request_id {
            Some(request_id) => envelope.with_instance(request_id),
            None => envelope,
        };
        render_problem(res, status, envelope);
    }
}

impl salvo::oapi::EndpointOutRegister for ArkretRouteError {
    fn register(_components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        use salvo::oapi::{BasicType, Content, Object, Response};

        let error_schema = Object::new()
            .property("type", Object::new().schema_type(BasicType::String))
            .property("title", Object::new().schema_type(BasicType::String))
            .property("status", Object::new().schema_type(BasicType::Integer))
            .property("detail", Object::new().schema_type(BasicType::String))
            .required("type")
            .required("title")
            .required("status");
        for (status, description) in [
            ("400", "Bad request"),
            ("401", "Unauthenticated"),
            ("403", "Forbidden"),
            ("404", "Not found"),
            ("409", "Conflict"),
            ("429", "Rate limited"),
            ("500", "Internal server error"),
            ("503", "Temporarily unavailable"),
        ] {
            operation.responses.insert(
                status,
                salvo::oapi::RefOr::Type(Response::new(description).add_content(
                    "application/problem+json",
                    Content::new(error_schema.clone()),
                )),
            );
        }
    }
}

fn owning_station_identity_for(
    arkret_config: &ArkretConfig,
) -> coauth_config::DelegatedStationIdentity {
    arkret_config
        .runtime_owning_station_identity
        .get()
        .expect("Station trust preflight verifies the owning Station before serving requests")
}

/// Stable authorization id delegated by the owning Station.
pub(crate) fn owning_station_id_for(arkret_config: &ArkretConfig) -> arkret_identifiers::DidCoreId {
    owning_station_identity_for(arkret_config).station_id
}

/// Full DID delegated by the owning Station for issuer/controller proofs.
pub(crate) fn owning_station_did_for(arkret_config: &ArkretConfig) -> arkret_identifiers::Did {
    owning_station_identity_for(arkret_config).did
}

/// Local OIDC subject for Account Authority-issued OAuth tokens.
///
/// This identifies the authenticated coauth account. Station DIDs are
/// resolved later by the `session-grants` bridge for the requested audience.
pub(crate) fn oidc_subject_for_user(_arkret_config: &ArkretConfig, user: &User) -> String {
    user.sub.clone()
}

#[derive(Debug, Clone)]
pub(crate) struct PrincipalDidBinding {
    pub principal_id: arkret_identifiers::DidCoreId,
    pub did: arkret_identifiers::Did,
}

pub(crate) async fn principal_did_binding_for_user<R>(
    repo: &mut R,
    arkret_config: &ArkretConfig,
    user: &User,
) -> Result<Option<PrincipalDidBinding>, R::Error>
where
    R: RepositoryAccess,
{
    for server in &arkret_config.stations {
        let Some(audience) = effective_audience(server, station_trust::shared()) else {
            continue;
        };
        if let Some(row) = repo
            .principal_did()
            .get_for_user_and_audience(user, audience.as_str())
            .await?
        {
            return Ok(Some(PrincipalDidBinding {
                principal_id: row.principal_id,
                did: row.verified_did,
            }));
        }
    }

    Ok(None)
}

pub(crate) async fn principal_id_for_user<R>(
    repo: &mut R,
    arkret_config: &ArkretConfig,
    user: &User,
) -> Result<Option<arkret_identifiers::DidCoreId>, R::Error>
where
    R: RepositoryAccess,
{
    Ok(principal_did_binding_for_user(repo, arkret_config, user)
        .await?
        .map(|binding| binding.principal_id))
}

/// Persisted stable principal identity that is allowed to leave the Account Authority.
pub(crate) async fn published_principal_id_for_user<R>(
    repo: &mut R,
    arkret_config: &ArkretConfig,
    user: &User,
) -> Result<Option<arkret_identifiers::DidCoreId>, R::Error>
where
    R: RepositoryAccess,
{
    principal_id_for_user(repo, arkret_config, user).await
}

/// Display form `local@host` used by logging / display paths.
/// NOT the canonical handle form — use [`user_handle`]
/// (spec 7157ee8 §3.1) for `alsoKnownAs` / DID Document / claim emission.
#[cfg(test)]
pub(crate) fn user_handle_display(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}@{}",
        user.localpart,
        url_builder.public_hostname().to_lowercase()
    )
}

/// Canonical Arkret handle for a user:
/// `<prepared-localpart>:<lowercase-A-label-domain>`. This is the form that MUST
/// appear in `alsoKnownAs`, on any handle claim `handle` field, and as
/// directory cache key. `acct:<percent-encoded-local>@<host>` is interop-only and lives in
/// `handle_aliases[]` on the handle claim.
pub(crate) fn user_handle(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}:{}",
        user.localpart,
        url_builder.public_hostname().to_ascii_lowercase()
    )
}

/// Reject any inbound `handle` that is not in the canonical
/// `<localpart>:<domain>` shape (spec 7157ee8 §3.1). Returns a
/// [`ArkretRouteError::Coded`] wrapping the standard error envelope
/// `code = "param_invalid"`.
pub(crate) fn require_canonical_handle(input: &str) -> Result<&str, ArkretRouteError> {
    coauth_data::user::validate_canonical_handle(input).map_err(|(_code, message)| {
        ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::PARAM_INVALID,
            format!("reason_code=handle_not_canonical; {message}"),
        )
    })
}

pub(crate) fn required_audience_for(
    _url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
) -> String {
    // Session-grant `audience` is a `did_core_id` on the wire (the target
    // service's stable authorization identity, account-operations schema), so
    // the default local-admin audience is this deployment's own runtime
    // service core id — never a URL.
    arkret_config
        .admin_audience
        .clone()
        .unwrap_or_else(|| owning_station_id_for(arkret_config).to_string())
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

pub(crate) fn is_allowed_session_grant_audience(
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    resolved: &StationTrustResolver,
    audience: &str,
) -> bool {
    let audience = audience.trim();
    if audience.is_empty() {
        return false;
    }

    audience == required_audience_for(url_builder, arkret_config)
        || arkret_config.stations.iter().any(|server| {
            effective_audience(server, resolved)
                .as_ref()
                .is_some_and(|effective| effective.as_str() == audience)
        })
}

/// Reasons why a caller-supplied station audience could not be
/// honoured. Distinct error variants let the HTTP layer return precise
/// 4xx codes instead of a generic "bad request".
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum SessionGrantTargetError {
    #[error("requested audience is not configured for this coauth service")]
    UnknownAudience,
    #[error("audience resolves to the local admin surface; specify a station audience instead")]
    LocalAudienceNotAllowed,
}

/// Resolve the station target for a password login session grant.
///
/// `requested_audience` is the audience the client proved during the login
/// ceremony (e.g. carried in a request body field or audience-bound state).
/// When supplied, only an exact match against a configured `server_name`
/// is accepted — falling back to "first `server_name` wins" silently
/// would let any caller mint a grant for an audience they never asked for.
///
/// When `requested_audience` is `None` and exactly one Station is
/// configured, that single server is used. With zero or multiple principal
/// servers and no explicit choice, returns `UnknownAudience` so the caller
/// must disambiguate.
pub(crate) fn password_login_session_grant_target(
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    resolved: &StationTrustResolver,
    requested_audience: Option<&str>,
) -> Result<SessionGrantTarget, SessionGrantTargetError> {
    if let Some(audience) = requested_audience.map(str::trim).filter(|a| !a.is_empty()) {
        if let Some((server, effective)) = arkret_config.stations.iter().find_map(|server| {
            effective_audience(server, resolved)
                .filter(|effective| effective.as_str() == audience)
                .map(|effective| (server, effective))
        }) {
            return Ok(SessionGrantTarget {
                audience_id: effective,
                station_name: Some(server.name.clone()),
                station_endpoint: Some(server.endpoint.to_string()),
            });
        }

        // The local admin audience never becomes a session-grant audience:
        // there is no Station to bind the grant to.
        if audience == required_audience_for(url_builder, arkret_config) {
            return Err(SessionGrantTargetError::LocalAudienceNotAllowed);
        }

        return Err(SessionGrantTargetError::UnknownAudience);
    }

    match arkret_config.stations.as_slice() {
        // A sole Station with no explicit audience whose describe
        // probe has not yet landed fails closed (UnknownAudience) rather than
        // minting a grant with no bindable audience.
        // This deliberate fail-closed behavior is documented in
        // `services::station_trust`: startup may reject briefly
        // rather than minting a grant with an audience that cannot be bound.
        [server] => Ok(SessionGrantTarget {
            audience_id: effective_audience(server, resolved)
                .ok_or(SessionGrantTargetError::UnknownAudience)?,
            station_name: Some(server.name.clone()),
            station_endpoint: Some(server.endpoint.to_string()),
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
#[cfg(debug_assertions)]
#[derive(Debug, Deserialize, Serialize)]
pub struct DebugIssueDpopGrantRequestBody {
    pub actor_id: String,
    pub device_id: String,
    pub dpop_jwk: serde_json::Value,
    #[serde(default)]
    pub audience_id: Option<arkret_identifiers::DidCoreId>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[cfg(debug_assertions)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DebugIssueDpopGrantOutcome {
    pub grant_id: String,
    pub grant_jwt: String,
    pub dpop_jkt: String,
    pub local_account_id: coauth_data::LocalAccountId,
    pub account_id: arkret_wire::AccountId,
    pub audience_id: arkret_identifiers::DidCoreId,
    pub scopes: Vec<String>,
    pub expires_at: String,
    /// Verified principal DID this grant is bound to.
    pub principal_id: arkret_identifiers::DidCoreId,
}

/// Byte-preserving response used by the live issuer-ledger fault seam.
#[cfg(debug_assertions)]
pub struct DebugIssueDpopGrantCanonicalJson(Vec<u8>);

#[cfg(debug_assertions)]
impl Scribe for DebugIssueDpopGrantCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("debug canonical JSON response body is writable");
    }
}

/// Returns true when test-only endpoints are explicitly allowed at runtime.
/// The route is only mounted in debug builds, and this env gate must still
/// be enabled there.
#[cfg(debug_assertions)]
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
#[cfg(debug_assertions)]
#[handler]
pub async fn debug_issue_dpop_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<DebugIssueDpopGrantCanonicalJson, ArkretRouteError> {
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
    let keyring = depot.keyring()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    let audience_id = body
        .audience_id
        .clone()
        .map_or_else(
            || {
                arkret_identifiers::DidCoreId::new(required_audience_for(
                    &url_builder,
                    &arkret_config,
                ))
            },
            Ok,
        )
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let mut repo = depot.repo().await?;
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(body.actor_id.trim(), audience_id.as_str())
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::PRECONDITION_FAILED,
                arkret_wire::ErrorCode::PRINCIPAL_UNKNOWN,
                "principal_unknown",
            )
        })?;
    let user = repo
        .user()
        .lookup(binding.user_id)
        .await?
        .ok_or(ArkretRouteError::NotFound)?;
    binding.account_id.validate().map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            error.to_string(),
        )
    })?;
    let account_id = binding.account_id;
    let principal_id = binding.principal_id;
    let scopes = body.scopes.clone().unwrap_or_else(|| {
        vec![
            format!("urn:arkret:client:device:{}", body.device_id),
            STATION_SESSION_BIND_SCOPE.to_owned(),
        ]
    });

    let canonical_intent = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "test_operation": "issue_dpop_grant",
        "request": body,
        "holder_jkt": jkt,
    }))?;
    let canonical_intent_digest: [u8; 32] = arkret_canonical::sha256_bytes(&canonical_intent);
    let request_identity = format!("cotest:sha256:{}", hex::encode(canonical_intent_digest));
    let not_before = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let expires_at = not_before + arkret_config.session_grant_ttl;
    let (_, signing_key) = crate::services::preferred_service_signing_key(&keyring)
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?;
    let signing_key_id = signing_key
        .kid()
        .ok_or_else(|| ArkretRouteError::Internal(Box::new(SessionGrantError::NoSigningKey)))?;
    let issuer_id = owning_station_id_for(&arkret_config);
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            &mut rng,
            &*clock,
            coauth_data::NewSessionGrantOperation {
                issuer_id,
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: Some(arkret_models_identity::SessionGrantProofKind::AccountHandoff),
                request_identity: &request_identity,
                canonical_intent_digest,
                canonical_intent: &canonical_intent,
                target_session_grant_id: None,
                issuance_nonce: None,
                session_id: None,
                grant_not_before: Some(not_before),
                grant_expires_at: Some(expires_at),
                signing_key_id: Some(signing_key_id),
                retained_until: expires_at + chrono::Duration::days(7),
            },
        )
        .await?;
    let operation = match reserved {
        coauth_data::SessionGrantReserveOutcome::Reserved(operation) => operation,
        coauth_data::SessionGrantReserveOutcome::Pending(operation)
            if operation.state == coauth_data::SessionGrantOperationState::Reserved =>
        {
            operation
        }
        coauth_data::SessionGrantReserveOutcome::Replay(operation) => {
            let bytes = operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "cotest grant replay has no canonical outcome",
                )
            })?;
            repo.cancel().await.ok();
            return Ok(DebugIssueDpopGrantCanonicalJson(bytes));
        }
        coauth_data::SessionGrantReserveOutcome::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "cotest grant identity conflicts with a different request",
            ));
        }
        coauth_data::SessionGrantReserveOutcome::Indeterminate(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "cotest grant outcome is indeterminate",
            ));
        }
        coauth_data::SessionGrantReserveOutcome::Pending(_) => {
            repo.cancel().await.ok();
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "cotest grant operation is incomplete",
            ));
        }
    };

    // Issue and persist a grant for the already-bound principal.
    let user_agent = Some(format!("coauth-test-harness/device:{}", body.device_id));
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &*clock, &user, user_agent)
        .await?;

    let material = issue_test_session_grant_for_audience(
        &SessionGrantIssuanceSeed::from_operation(&operation)?,
        &*clock,
        &arkret_config,
        &keyring,
        &browser_session,
        public_jwk,
        audience_id,
        arkret_identifiers::DeviceId::new(body.device_id.clone())?,
        scopes,
        Some(&principal_id),
        &account_id,
        jkt.clone(),
        arkret_models_identity::SessionGrantDeviceBinding {
            device_id: arkret_identifiers::DeviceId::new(body.device_id.clone())?,
            authorization_event_id: arkret_identifiers::EventId::new(
                "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
            )
            .expect("cotest fixture authorization Event id"),
            model_generation_ref: 1,
        },
        arkret_models_identity::SessionGrantProofKind::AccountHandoff,
    )?;
    let outcome = DebugIssueDpopGrantOutcome {
        grant_id: material.grant_id.to_string(),
        grant_jwt: material.grant_jwt.clone(),
        dpop_jkt: jkt,
        local_account_id: material.local_account_id.clone(),
        account_id,
        audience_id: material.audience_id.clone(),
        scopes: material.scopes.clone(),
        expires_at: material.expires_at.clone(),
        principal_id,
    };
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
    let checkpoint = serde_json::json!({
        "kind": "cotest_issue_dpop_grant",
        "request_identity": request_identity,
    });
    let committed = commit_session_grant_issuance(
        &mut repo,
        &mut rng,
        &*clock,
        operation.id,
        &request_identity,
        &checkpoint,
        expires_at,
        &canonical_outcome,
        Some(browser_session.id),
        &material,
    )
    .await?;
    let chaos_committed = matches!(
        &committed,
        coauth_data::SessionGrantCommitOutcome::Committed(_)
    );
    let response = match committed {
        coauth_data::SessionGrantCommitOutcome::Committed(_) => canonical_outcome,
        coauth_data::SessionGrantCommitOutcome::Replay(operation) => {
            operation.canonical_outcome.ok_or_else(|| {
                ArkretRouteError::coded(
                    StatusCode::SERVICE_UNAVAILABLE,
                    arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                    "cotest grant commit replay has no canonical outcome",
                )
            })?
        }
        coauth_data::SessionGrantCommitOutcome::Indeterminate(_) => {
            repo.save().await?;
            return Err(ArkretRouteError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
                "cotest grant commit is indeterminate",
            ));
        }
    };
    repo.save().await?;
    if chaos_committed {
        test_chaos::maybe_delay_post_commit(
            "session_grant_issue_post_commit_pre_response",
            &request_identity,
        )
        .await;
    }
    Ok(DebugIssueDpopGrantCanonicalJson(response))
}
