use anyhow::Error as AnyhowError;
use chrono::{DateTime, Duration, Utc};
use coauth_config::{ContrixConfig, IdentityRegistryKind};
use coauth_data::{
    BrowserSession, Clock, Pagination, RepositoryAccess, SessionGrant, UrlBuilder, User,
    oauth2::{NewSessionGrant, SessionGrantFilter},
};
use coauth_iana::jose::{JsonWebKeyOperation, JsonWebKeyUse, JsonWebSignatureAlg};
use coauth_jose::{
    constraints::Constrainable,
    jwk::{JsonWebKey, JsonWebKeyPublicParameters, PublicJsonWebKey, PublicJsonWebKeySet},
    jwt::{JsonWebSignatureHeader, Jwt, JwtSignatureError},
};
use coauth_keystore::{Keystore, PrivateKey, WrongAlgorithmError};
use der::pem::LineEnding;
use oauth2_types::scope::{Scope, ScopeToken};
use rand_core::{CryptoRngCore, RngCore};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::common::{DepotExt, RouteError};

const CONTRIX_PROTOCOL_VERSION: &str = "1.0";
const CONTRIX_HTTP_BINDING: &str = "http_json";
const SESSION_GRANT_TTL_MINUTES: i64 = 5;
pub const CLAIM_PRINCIPAL_DID: &str = "org.contrix.principal_did";
pub const CLAIM_DEVICE_ID: &str = "org.contrix.device_id";
pub const CLAIM_SESSION_ID: &str = "org.contrix.session_id";
pub const PRINCIPAL_SERVER_SESSION_BIND_SCOPE: &str = "urn:contrix:principal-server:session.bind";

#[derive(Debug, Error)]
pub enum SessionGrantError {
    #[error("no signing key is configured for Contrix session grants")]
    NoSigningKey,

    #[error(transparent)]
    JwtSignature(#[from] JwtSignatureError),

    #[error(transparent)]
    WrongAlgorithm(#[from] WrongAlgorithmError),

    #[error(transparent)]
    Serialize(#[from] serde_json::Error),

    #[error("failed to encode session private key as PEM: {0}")]
    PemEncode(String),

    #[error(transparent)]
    Other(#[from] AnyhowError),
}

#[derive(Debug, Error)]
pub enum ContrixRouteError {
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

impl From<RouteError> for ContrixRouteError {
    fn from(value: RouteError) -> Self {
        match value {
            RouteError::BadRequest(message) => Self::BadRequest(message),
            RouteError::NotFound => Self::NotFound,
            other => Self::Internal(Box::new(other)),
        }
    }
}

impl From<coauth_data::RepositoryError> for ContrixRouteError {
    fn from(value: coauth_data::RepositoryError) -> Self {
        Self::Internal(Box::new(value))
    }
}

/// Authorization decision for a session-grant administrative endpoint.
#[derive(Debug, Clone, Copy)]
enum SessionGrantAuthz {
    /// The caller presented an admin scope. Allowed for read and write.
    Admin,
    /// The caller presented the Principal Server `session.bind` scope.
    /// Allowed for read-only paths (list / introspect).
    PrincipalServer,
}

/// Resolve the bearer token on the request and require either an admin
/// scope or the Principal Server session-bind scope. Used by the
/// session-grant admin surface to gate access without going through the
/// heavier admin call-context extractor.
async fn require_session_grant_caller(
    req: &Request,
    depot: &Depot,
) -> Result<SessionGrantAuthz, ContrixRouteError> {
    use coauth_data::{RepositoryAccess, TokenType};

    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| {
            ContrixRouteError::Unauthorized("missing authorization header".to_owned())
        })?;
    let auth_str = auth_header
        .to_str()
        .map_err(|_| ContrixRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    let token = auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .ok_or_else(|| {
            ContrixRouteError::Unauthorized("invalid authorization header".to_owned())
        })?;

    let token_type = TokenType::check(token)
        .map_err(|_| ContrixRouteError::Unauthorized("invalid bearer token".to_owned()))?;

    let mut repo = depot.repo().await?;
    let scope = match token_type {
        TokenType::AccessToken => {
            let access = repo
                .oauth2_access_token()
                .find_by_token(token)
                .await
                .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ContrixRouteError::Unauthorized("unknown access token".to_owned())
                })?;
            let session = repo
                .oauth2_session()
                .lookup(access.session_id)
                .await
                .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ContrixRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
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
                .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ContrixRouteError::Unauthorized("unknown access token".to_owned())
                })?;
            let session = repo
                .personal_session()
                .lookup(access.session_id)
                .await
                .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ContrixRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                        "access token references missing session",
                    ))
                })?;
            session.scope.clone()
        }
        _ => {
            return Err(ContrixRouteError::Unauthorized(
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
        Err(ContrixRouteError::Forbidden(
            "missing admin or principal-server scope".to_owned(),
        ))
    }
}

impl Scribe for ContrixRouteError {
    fn render(self, res: &mut Response) {
        let (status, code, message) = match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error".to_owned(),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".to_owned()),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_json", message),
            Self::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", message)
            }
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message),
        };

        if status == StatusCode::UNAUTHORIZED {
            // RFC 7235 says 401 responses MUST include a WWW-Authenticate
            // challenge so the caller can negotiate.
            res.headers_mut().insert(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static(
                    "Bearer realm=\"contrix\", error=\"invalid_token\"",
                ),
            );
        }

        res.status_code(status);
        res.render(Json(serde_json::json!({
            "ok": false,
            "error": {
                "code": code,
                "message": message,
            }
        })));
    }
}

fn map_did_resolve_error(
    error: crate::services::did_resolver::DidResolveError,
) -> ContrixRouteError {
    match error {
        crate::services::did_resolver::DidResolveError::NotFound
        | crate::services::did_resolver::DidResolveError::UnsupportedMethod => {
            ContrixRouteError::NotFound
        }
        crate::services::did_resolver::DidResolveError::InvalidDid(message) => {
            ContrixRouteError::BadRequest(format!("invalid did: {message}"))
        }
        other => ContrixRouteError::Internal(Box::new(other)),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionGrantMaterial {
    pub grant_jwt: String,
    pub session_public_key: String,
    pub session_private_key_pem: String,
    pub expires_at: String,
    pub expires_at_timestamp: DateTime<Utc>,
    pub issuer: String,
    pub subject: String,
    pub device_id: Option<String>,
    pub audience: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionGrantTarget {
    pub audience: String,
    pub principal_server_name: Option<String>,
    pub principal_server_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,

    #[serde(rename = "alsoKnownAs")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,

    #[serde(rename = "verificationMethod")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,

    #[serde(rename = "assertionMethod")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: String,

    pub controller: String,

    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicJsonWebKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: String,

    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub issuer: String,
    pub subject: String,
    pub service_account_id: String,
    pub session_public_key: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revocation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub session_id: String,
    pub browser_session_id: String,
    pub proof: SessionGrantProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantProof {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: String,
    pub key_id: String,
    pub canonicalization: String,
    pub payload_hash_alg: String,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct SessionGrantPayloadClaims {
    #[serde(rename = "type")]
    kind: String,
    issuer: String,
    subject: String,
    service_account_id: String,
    session_public_key: String,
    audience: String,
    scopes: Vec<String>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revocation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    session_id: String,
    browser_session_id: String,
}

#[derive(Debug, Serialize)]
struct SupportedBinding {
    binding: &'static str,
    base_url: String,
}

#[derive(Debug, Clone, Serialize)]
struct PrincipalServerDescriptor {
    name: String,
    audience: String,
    endpoint: String,
    did: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdentityRegistryDescriptor {
    kind: &'static str,
    resolver: String,
    proof_required_for_pairwise: bool,
}

#[derive(Debug, Serialize)]
struct IdentityRegistryResolverDescriptor {
    mode: &'static str,
    endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegated_resolver: Option<IdentityRegistryDescriptor>,
}

#[derive(Debug, Serialize)]
struct ServiceBoundaryDescriptor {
    authoritative_for: Vec<&'static str>,
    not_authoritative_for: Vec<&'static str>,
    delegated_to: Vec<&'static str>,
    principal_server_authorization: &'static str,
}

#[derive(Debug, Serialize)]
struct StandardErrorEnvelopeDescriptor {
    schema: &'static str,
    content_type: &'static str,
    example: StandardErrorEnvelopeExample,
    codes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct StandardErrorEnvelopeExample {
    ok: bool,
    error: StandardErrorExampleBody,
}

#[derive(Debug, Serialize)]
struct StandardErrorExampleBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct ServiceLimitsDescriptor {
    max_body_bytes: u64,
    max_page_size: u32,
    session_grant_ttl_seconds: i64,
}

#[derive(Debug, Serialize)]
struct OAuthClientHintDescriptor {
    id: String,
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthMetadata {
    oauth_issuer: String,
    openid_configuration: String,
    issuer_did: String,
    supported_auth_methods: Vec<&'static str>,
    token_endpoint_auth_methods: Vec<&'static str>,
    supported_grant_types: Vec<&'static str>,
    did_binding_methods: Vec<&'static str>,
    required_audience: String,
    admin_audience: String,
    session_grant_scope: &'static str,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    oidc_clients: Vec<OAuthClientHintDescriptor>,
}

#[derive(Debug, Serialize)]
struct ServiceDescribeResponse {
    service_did: String,
    service_type: &'static str,
    protocol_version: &'static str,
    supported_profiles: Vec<&'static str>,
    supported_features: Vec<&'static str>,
    supported_bindings: Vec<SupportedBinding>,
    supported_operations: Vec<&'static str>,
    admin_audience: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    principal_servers: Vec<PrincipalServerDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    principal_server_delegation_targets: Vec<PrincipalServerDescriptor>,
    identity_registry_resolver: IdentityRegistryResolverDescriptor,
    service_boundary: ServiceBoundaryDescriptor,
    auth_metadata: AuthMetadata,
    limits: ServiceLimitsDescriptor,
    standard_error_envelope: StandardErrorEnvelopeDescriptor,
}

#[derive(Debug, Serialize)]
struct IdentityDescribeResponse {
    service_did: String,
    registry_mode: &'static str,
    supported_receipts: Vec<String>,
    protocol_version: &'static str,
    profiles: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_registry: Option<IdentityRegistryDescriptor>,
}

#[derive(Debug, Serialize)]
struct IdentityResolveResponse {
    did_document: DidDocument,
    key_log_head: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
    method_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct IdentityDocumentResponse {
    did_document: DidDocument,
    head_event_hash: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct DirectoryDescribeResponse {
    service_did: String,
    resource_types: Vec<&'static str>,
    discovery_profiles: Vec<&'static str>,
    restricted_query_proof: bool,
}

#[derive(Debug, Serialize)]
struct ResolveHandleResponse {
    did: String,
    handle: String,
    verified: bool,
    claims: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ResolveIdentityRequest {
    did: String,
    #[allow(dead_code)]
    include: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ResolveHandleRequest {
    handle: String,
    expected_did: Option<String>,
    #[allow(dead_code)]
    proof_challenge: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionGrantRecord {
    id: String,
    browser_session_id: String,
    issuer: String,
    subject: String,
    device_id: Option<String>,
    audience: String,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct SessionGrantListResponse {
    grants: Vec<SessionGrantRecord>,
}

#[derive(Debug, Serialize)]
struct SessionGrantRevokeResponse {
    grant: SessionGrantRecord,
}

#[derive(Debug, Deserialize)]
struct SessionGrantIntrospectionRequest {
    id: Option<String>,
    grant_jwt: Option<String>,
    audience: Option<String>,
    proof: Option<SessionGrantIntrospectionProofInput>,
}

#[derive(Debug, Deserialize)]
struct SessionGrantIntrospectionProofInput {
    challenge: String,
    proof_jwt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionGrantIntrospectionProofClaims {
    #[serde(rename = "type")]
    kind: String,
    grant_id: String,
    grant_jwt_hash: String,
    audience: String,
    challenge: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SessionGrantIntrospectionStatus {
    Active,
    Revoked,
    Expired,
    Locked,
    Suspended,
    AudienceMismatch,
    ProofRequired,
    InvalidProof,
    NotFound,
}

#[derive(Debug, Serialize)]
struct SessionGrantIntrospectionGrant {
    id: String,
    issuer: String,
    subject: String,
    service_account_id: String,
    device_id: Option<String>,
    audience: String,
    scopes: Vec<String>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revocation_ref: String,
}

#[derive(Debug, Serialize)]
struct SessionGrantIntrospectionResponse {
    active: bool,
    status: SessionGrantIntrospectionStatus,
    proof_required: bool,
    one_time_use_consumed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<SessionGrantIntrospectionGrant>,
}

impl From<SessionGrant> for SessionGrantRecord {
    fn from(value: SessionGrant) -> Self {
        Self {
            id: value.id.to_string(),
            browser_session_id: value.browser_session_id.to_string(),
            issuer: value.issuer,
            subject: value.subject,
            device_id: value.device_id,
            audience: value.audience,
            scopes: value
                .scope
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            created_at: value.created_at,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        }
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

pub(crate) fn service_did_for(url_builder: &UrlBuilder, contrix_config: &ContrixConfig) -> String {
    contrix_config
        .service_did
        .clone()
        .unwrap_or_else(|| service_did(url_builder))
}

pub(crate) fn issuer_did_for(url_builder: &UrlBuilder, contrix_config: &ContrixConfig) -> String {
    contrix_config
        .issuer_did
        .clone()
        .unwrap_or_else(|| service_did_for(url_builder, contrix_config))
}

pub(crate) fn user_did(url_builder: &UrlBuilder, user: &User) -> String {
    format!("{}:users:{}", service_did(url_builder), user.id)
}

pub(crate) fn user_did_for(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    user: &User,
) -> String {
    format!(
        "{}:users:{}",
        service_did_for(url_builder, contrix_config),
        user.id
    )
}

pub(crate) fn user_handle(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}@{}",
        user.username,
        url_builder.public_hostname().to_lowercase()
    )
}

pub(crate) fn required_audience(url_builder: &UrlBuilder) -> String {
    url_builder.absolute_url("/api/v1").to_string()
}

pub(crate) fn required_audience_for(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
) -> String {
    contrix_config
        .admin_audience
        .clone()
        .unwrap_or_else(|| required_audience(url_builder))
}

pub(crate) fn is_allowed_session_grant_audience(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    audience: &str,
) -> bool {
    let audience = audience.trim();
    if audience.is_empty() {
        return false;
    }

    audience == required_audience_for(url_builder, contrix_config)
        || contrix_config
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
/// When supplied, only an exact match against a configured principal server
/// is accepted — falling back to "first principal server wins" silently
/// would let any caller mint a grant for an audience they never asked for.
///
/// When `requested_audience` is `None` and exactly one principal server is
/// configured, that single server is used. With zero or multiple principal
/// servers and no explicit choice, returns `UnknownAudience` so the caller
/// must disambiguate.
pub(crate) fn password_login_session_grant_target(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    requested_audience: Option<&str>,
) -> Result<SessionGrantTarget, SessionGrantTargetError> {
    if let Some(audience) = requested_audience.map(str::trim).filter(|a| !a.is_empty()) {
        if let Some(server) = contrix_config
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
        if audience == required_audience_for(url_builder, contrix_config) {
            return Err(SessionGrantTargetError::LocalAudienceNotAllowed);
        }

        return Err(SessionGrantTargetError::UnknownAudience);
    }

    match contrix_config.principal_servers.as_slice() {
        [server] => Ok(SessionGrantTarget {
            audience: server.audience.clone(),
            principal_server_name: Some(server.name.clone()),
            principal_server_endpoint: Some(server.endpoint.to_string()),
        }),
        [] => Err(SessionGrantTargetError::UnknownAudience),
        _ => Err(SessionGrantTargetError::UnknownAudience),
    }
}

fn identity_registry_kind(kind: &IdentityRegistryKind) -> &'static str {
    match kind {
        IdentityRegistryKind::PublicDidResolver => "public_did_resolver",
        IdentityRegistryKind::External => "external",
    }
}

fn delegated_identity_registry_descriptor(
    contrix_config: &ContrixConfig,
) -> Option<IdentityRegistryDescriptor> {
    contrix_config
        .identity_registry
        .as_ref()
        .map(|registry| IdentityRegistryDescriptor {
            kind: identity_registry_kind(&registry.kind),
            resolver: registry.resolver.to_string(),
            proof_required_for_pairwise: registry.proof_required_for_pairwise,
        })
}

fn identity_registry_resolver_descriptor(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
) -> IdentityRegistryResolverDescriptor {
    let delegated_resolver = delegated_identity_registry_descriptor(contrix_config);
    IdentityRegistryResolverDescriptor {
        mode: if delegated_resolver.is_some() {
            "delegated_resolver"
        } else {
            "local_bindings"
        },
        endpoint: url_builder
            .absolute_url("/api/v1/identity/resolve")
            .to_string(),
        delegated_resolver,
    }
}

fn service_boundary_descriptor() -> ServiceBoundaryDescriptor {
    ServiceBoundaryDescriptor {
        authoritative_for: vec![
            "service_account",
            "device_session",
            "session_grant",
            "claim_attestation",
            "admin_action",
        ],
        not_authoritative_for: vec![
            "did_document_registry",
            "did_key_log",
            "identity_registry_receipt",
            "principal_server_write_authorization",
        ],
        delegated_to: vec!["identity_registry", "principal_server_authorization_engine"],
        principal_server_authorization: "Principal Server writes are decided by the downstream authorization engine from session grants, capabilities, and Space policy.",
    }
}

fn standard_error_envelope_descriptor() -> StandardErrorEnvelopeDescriptor {
    StandardErrorEnvelopeDescriptor {
        schema: "cx.error.envelope.v1",
        content_type: "application/json",
        example: StandardErrorEnvelopeExample {
            ok: false,
            error: StandardErrorExampleBody {
                code: "machine_readable_code",
                message: "human-readable message",
            },
        },
        codes: vec!["bad_json", "not_found", "internal_error"],
    }
}

fn service_describe_response(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
) -> ServiceDescribeResponse {
    let principal_servers: Vec<PrincipalServerDescriptor> = contrix_config
        .principal_servers
        .iter()
        .map(|server| PrincipalServerDescriptor {
            name: server.name.clone(),
            audience: server.audience.clone(),
            endpoint: server.endpoint.to_string(),
            did: server.did.clone(),
        })
        .collect();
    let admin_audience = required_audience_for(url_builder, contrix_config);

    ServiceDescribeResponse {
        service_did: service_did_for(url_builder, contrix_config),
        service_type: "auth_account_server",
        protocol_version: CONTRIX_PROTOCOL_VERSION,
        supported_profiles: vec![
            "cx.profile.auth_account.v1",
            "cx.profile.account_lifecycle.v1",
            "cx.profile.account_first_onboarding.v1",
            "cx.profile.did_binding.v1",
            "cx.profile.session_grant.v1",
            "cx.profile.claim_attestation.v1",
            "cx.profile.policy_hook.v1",
            "cx.profile.legacy_compatibility.v1",
        ],
        supported_features: vec![
            "oidc",
            "account_first_onboarding",
            "session_grant",
            "did_binding",
            "did_resolution",
            "handle_resolution",
            "account_recovery",
            "claim_attestation",
            "policy_hook",
        ],
        supported_bindings: vec![SupportedBinding {
            binding: CONTRIX_HTTP_BINDING,
            base_url: url_builder.http_base().to_string(),
        }],
        supported_operations: vec![
            "cx.server.describe",
            "cx.identity.describe_registry",
            "cx.identity.resolve",
            "cx.identity.get_document",
            "cx.directory.describe",
            "cx.directory.resolve_handle",
        ],
        admin_audience: admin_audience.clone(),
        principal_servers: principal_servers.clone(),
        principal_server_delegation_targets: principal_servers,
        identity_registry_resolver: identity_registry_resolver_descriptor(
            url_builder,
            contrix_config,
        ),
        service_boundary: service_boundary_descriptor(),
        auth_metadata: AuthMetadata {
            oauth_issuer: url_builder.oidc_issuer().to_string(),
            openid_configuration: url_builder.oidc_discovery().to_string(),
            issuer_did: issuer_did_for(url_builder, contrix_config),
            supported_auth_methods: vec![
                "password",
                "oidc",
                "device_pairing",
                "recovery_challenge",
            ],
            token_endpoint_auth_methods: vec![
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post",
            ],
            supported_grant_types: vec!["authorization_code", "refresh_token", "device_code"],
            did_binding_methods: vec![
                "did_controller_key",
                "device_key",
                "passkey",
                "oidc_binding_proof",
                "vc_presentation",
            ],
            required_audience: required_audience_for(url_builder, contrix_config),
            admin_audience,
            session_grant_scope: PRINCIPAL_SERVER_SESSION_BIND_SCOPE,
            oidc_clients: Vec::new(),
        },
        limits: ServiceLimitsDescriptor {
            max_body_bytes: 1_048_576,
            max_page_size: 100,
            session_grant_ttl_seconds: SESSION_GRANT_TTL_MINUTES * 60,
        },
        standard_error_envelope: standard_error_envelope_descriptor(),
    }
}

fn write_canonical_json(
    value: &serde_json::Value,
    out: &mut Vec<u8>,
) -> Result<(), serde_json::Error> {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => serde_json::to_writer(out, value),
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
            Ok(())
        }
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (idx, (key, item)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                write_canonical_json(item, out)?;
            }
            out.push(b'}');
            Ok(())
        }
    }
}

fn canonical_json_sha256(value: &impl Serialize) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let mut canonical = Vec::new();
    write_canonical_json(&value, &mut canonical)?;
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(&canonical))
    ))
}

fn session_grant_claims_hash(
    claims: &SessionGrantPayloadClaims,
) -> Result<String, serde_json::Error> {
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
    }
}

fn primary_device_id_from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Option<String> {
    tokens.into_iter().find_map(|token| {
        token
            .strip_prefix("urn:contrix:client:device:")
            .or_else(|| token.strip_prefix("urn:matrix:client:device:"))
            .or_else(|| token.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"))
            .map(ToOwned::to_owned)
    })
}

pub(crate) fn primary_device_id(scope: &Scope) -> Option<String> {
    primary_device_id_from_tokens(scope.iter().map(|token| token.as_str()))
}

pub(crate) fn service_did_document(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
) -> Result<DidDocument, SessionGrantError> {
    let did = service_did_for(url_builder, contrix_config);
    let mut verification_method = Vec::new();
    let mut authentication = Vec::new();
    let mut assertion_method = Vec::new();

    if let Some(public_key) = preferred_public_signing_key(key_store) {
        let key_id = format!("{did}#key-1");
        verification_method.push(VerificationMethod {
            id: key_id.clone(),
            kind: "JsonWebKey2020".to_owned(),
            controller: did.clone(),
            public_key_jwk: public_key,
        });
        authentication.push(key_id.clone());
        assertion_method.push(key_id);
    }

    Ok(DidDocument {
        id: did.clone(),
        also_known_as: Vec::new(),
        verification_method,
        authentication,
        assertion_method,
        service: vec![
            DidService {
                id: format!("{did}#auth-server"),
                kind: "ContrixAuthServer".to_owned(),
                service_endpoint: url_builder
                    .absolute_url("/api/v1/server/describe")
                    .to_string(),
            },
            DidService {
                id: format!("{did}#openid-configuration"),
                kind: "OpenIdConnectConfiguration".to_owned(),
                service_endpoint: url_builder.oidc_discovery().to_string(),
            },
        ],
    })
}

pub(crate) fn user_did_document(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    user: &User,
) -> DidDocument {
    let did = user_did_for(url_builder, contrix_config, user);

    DidDocument {
        id: did.clone(),
        also_known_as: vec![format!("contrix://{}", user_handle(url_builder, user))],
        verification_method: Vec::new(),
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        service: vec![DidService {
            id: format!("{did}#auth-server"),
            kind: "ContrixAuthServer".to_owned(),
            service_endpoint: url_builder
                .absolute_url("/api/v1/server/describe")
                .to_string(),
        }],
    }
}

pub(crate) fn issue_session_grant(
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    scopes: Vec<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience(
        rng,
        clock,
        url_builder,
        contrix_config,
        key_store,
        browser_session,
        required_audience_for(url_builder, contrix_config),
        scopes,
    )
}

pub(crate) fn issue_session_grant_for_audience(
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    audience: String,
    scopes: Vec<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let subject = user_did_for(url_builder, contrix_config, &browser_session.user);
    let session_key = PrivateKey::generate_ed25519(rng);
    let session_public_key = JsonWebKey::new(JsonWebKeyPublicParameters::from(&session_key))
        .with_use(JsonWebKeyUse::Sig)
        .with_key_ops(vec![JsonWebKeyOperation::Verify])
        .with_alg(JsonWebSignatureAlg::EdDsa)
        .with_kid(format!("session-{}", browser_session.id));
    let session_public_key = serde_json::to_string(&session_public_key)?;
    let session_private_key_pem = session_key
        .to_pem(LineEnding::LF)
        .map_err(|error| SessionGrantError::PemEncode(error.to_string()))?
        .to_string();

    let now = clock.now();
    let expires_at = now + Duration::try_minutes(SESSION_GRANT_TTL_MINUTES).unwrap();
    let device_id = primary_device_id_from_tokens(scopes.iter().map(String::as_str));
    let issuer = issuer_did_for(url_builder, contrix_config);
    let claims = SessionGrantPayloadClaims {
        kind: "cx.session.grant".to_owned(),
        issuer: issuer.clone(),
        subject: subject.clone(),
        service_account_id: browser_session.user.id.to_string(),
        session_public_key: session_public_key.clone(),
        audience: audience.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        revocation_ref: format!("cx:session:{}", browser_session.id),
        device_id: device_id.clone(),
        session_id: browser_session.id.to_string(),
        browser_session_id: browser_session.id.to_string(),
    };
    let payload_hash = session_grant_claims_hash(&claims)?;

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let payload = SessionGrantPayload {
        kind: claims.kind,
        issuer: claims.issuer,
        subject: claims.subject,
        service_account_id: claims.service_account_id,
        session_public_key: claims.session_public_key,
        audience: claims.audience,
        scopes: claims.scopes,
        not_before: claims.not_before,
        expires_at: claims.expires_at,
        revocation_ref: claims.revocation_ref,
        device_id: claims.device_id,
        session_id: claims.session_id,
        browser_session_id: claims.browser_session_id,
        proof: SessionGrantProof {
            kind: "cx.session.grant.proof.v1".to_owned(),
            alg: alg.to_string(),
            key_id: key_id.clone(),
            canonicalization: "json-c14n-object-key-sort-v1".to_owned(),
            payload_hash_alg: "sha-256".to_owned(),
            payload_hash,
        },
    };
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id);
    let signer = key.params().signing_key_for_alg(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &signer)?.into_string();

    Ok(SessionGrantMaterial {
        grant_jwt,
        session_public_key,
        session_private_key_pem,
        expires_at: expires_at.to_rfc3339(),
        expires_at_timestamp: expires_at,
        issuer,
        subject,
        device_id,
        audience,
        scopes,
    })
}

pub(crate) async fn persist_session_grant<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    browser_session: &BrowserSession,
    material: &SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    let scope: Scope = material
        .scopes
        .iter()
        .map(|scope| scope.parse::<ScopeToken>())
        .collect::<Result<Scope, _>>()
        // This can only fail if an internal caller constructed an invalid scope
        // string before signing the JWT.
        .expect("session grant scopes must be valid OAuth scope tokens");

    repo.oauth2_session_grant()
        .add(
            rng,
            clock,
            NewSessionGrant {
                browser_session_id: browser_session.id,
                issuer: &material.issuer,
                subject: &material.subject,
                device_id: material.device_id.as_deref(),
                audience: &material.audience,
                scope,
                grant_jwt: &material.grant_jwt,
                session_public_key: &material.session_public_key,
                expires_at: material.expires_at_timestamp,
            },
        )
        .await
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

pub(crate) fn parse_local_user_did(url_builder: &UrlBuilder, did: &str) -> Option<Ulid> {
    let prefix = format!("{}:users:", service_did(url_builder));
    did.strip_prefix(&prefix)?.parse::<Ulid>().ok()
}

pub(crate) fn parse_local_user_did_for(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    did: &str,
) -> Option<Ulid> {
    let prefix = format!("{}:users:", service_did_for(url_builder, contrix_config));
    did.strip_prefix(&prefix)?.parse::<Ulid>().ok()
}

pub(crate) fn parse_local_handle(url_builder: &UrlBuilder, handle: &str) -> Option<String> {
    let suffix = format!("@{}", url_builder.public_hostname().to_lowercase());
    handle
        .strip_suffix(&suffix)
        .filter(|localpart| !localpart.is_empty())
        .map(ToOwned::to_owned)
}

#[handler]
pub async fn server_describe(
    depot: &Depot,
) -> Result<Json<ServiceDescribeResponse>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let mut repo = depot.repo().await?;
    let oidc_clients = repo
        .oauth2_client()
        .all_static()
        .await?
        .into_iter()
        .filter(|client| {
            client.grant_types.iter().any(|grant_type| {
                matches!(
                    grant_type,
                    oauth2_types::requests::GrantType::AuthorizationCode
                )
            })
        })
        .map(|client| OAuthClientHintDescriptor {
            id: client.id.to_string(),
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            redirect_uris: client
                .redirect_uris
                .iter()
                .map(ToString::to_string)
                .collect(),
            grant_types: client.grant_types.iter().map(ToString::to_string).collect(),
            token_endpoint_auth_method: client
                .token_endpoint_auth_method
                .as_ref()
                .map(ToString::to_string),
        })
        .collect::<Vec<_>>();
    repo.cancel().await?;

    let mut response = service_describe_response(&url_builder, &contrix_config);
    response.auth_metadata.oidc_clients = oidc_clients;
    Ok(Json(response))
}

#[handler]
pub async fn identity_describe(
    depot: &Depot,
) -> Result<Json<IdentityDescribeResponse>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let identity_registry = delegated_identity_registry_descriptor(&contrix_config);

    Ok(Json(IdentityDescribeResponse {
        service_did: service_did_for(&url_builder, &contrix_config),
        registry_mode: if identity_registry.is_some() {
            "delegated_resolver"
        } else {
            "local_bindings"
        },
        supported_receipts: Vec::new(),
        protocol_version: CONTRIX_PROTOCOL_VERSION,
        profiles: vec!["cx.profile.identity_registry.v1"],
        identity_registry,
    }))
}

#[handler]
pub async fn identity_resolve(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityResolveResponse>, ContrixRouteError> {
    let body: ResolveIdentityRequest = req
        .parse_json()
        .await
        .map_err(|_| ContrixRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;
    let resolution = did_resolver
        .resolve_did_document(
            &http_client,
            &url_builder,
            &contrix_config,
            &key_store,
            &mut repo,
            &body.did,
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityResolveResponse {
        did_document: resolution.document,
        key_log_head: None,
        seq: None,
        receipts: None,
        method_evidence: Some(resolution.method_evidence),
    }))
}

#[handler]
pub async fn identity_document(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityDocumentResponse>, ContrixRouteError> {
    let did = req
        .query::<String>("did")
        .ok_or_else(|| ContrixRouteError::BadRequest("missing did query parameter".into()))?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;
    let resolution = did_resolver
        .resolve_did_document(
            &http_client,
            &url_builder,
            &contrix_config,
            &key_store,
            &mut repo,
            &did,
        )
        .await
        .map_err(map_did_resolve_error)?;
    repo.cancel()
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    Ok(Json(IdentityDocumentResponse {
        did_document: resolution.document,
        head_event_hash: None,
        seq: None,
        receipts: None,
    }))
}

#[handler]
pub async fn directory_describe(
    depot: &Depot,
) -> Result<Json<DirectoryDescribeResponse>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;

    Ok(Json(DirectoryDescribeResponse {
        service_did: service_did_for(&url_builder, &contrix_config),
        resource_types: vec!["actor", "handle"],
        discovery_profiles: vec!["cx.profile.directory.v1"],
        restricted_query_proof: false,
    }))
}

#[handler]
pub async fn directory_resolve_handle(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResolveHandleResponse>, ContrixRouteError> {
    let body: ResolveHandleRequest = req
        .parse_json()
        .await
        .map_err(|_| ContrixRouteError::BadRequest("invalid json body".into()))?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let Some(username) = parse_local_handle(&url_builder, &body.handle) else {
        return Err(ContrixRouteError::NotFound);
    };

    let mut repo = depot.repo().await?;
    let Some(user) = repo
        .user()
        .find_by_username(&username)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    else {
        return Err(ContrixRouteError::NotFound);
    };

    let did = did_resolver.user_did(&url_builder, &contrix_config, &user);
    let verified = body.expected_did.as_deref().is_none_or(|expected| {
        did_resolver.verify_user_binding(&url_builder, &contrix_config, &user, expected)
            == crate::services::did_resolver::DidBindingVerification::Verified
    });

    Ok(Json(ResolveHandleResponse {
        did,
        handle: user_handle(&url_builder, &user),
        verified,
        claims: Vec::new(),
    }))
}

#[handler]
pub async fn list_session_grants(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantListResponse>, ContrixRouteError> {
    let clock = crate::handlers::make_clock();
    let subject = req.query::<String>("subject");
    let device_id = req.query::<String>("device_id");
    let audience = req.query::<String>("audience");
    let mut filter = SessionGrantFilter::new();

    if let Some(subject) = subject.as_deref() {
        filter = filter.for_subject(subject);
    }

    if let Some(device_id) = device_id.as_deref() {
        filter = filter.for_device(device_id);
    }

    if let Some(audience) = audience.as_deref() {
        filter = filter.for_audience(audience);
    }

    if let Some(browser_session_id) = req.query::<String>("browser_session_id") {
        let browser_session_id = Ulid::from_string(&browser_session_id)
            .map_err(|_| ContrixRouteError::BadRequest("invalid browser_session_id".into()))?;
        filter = filter.for_browser_session(browser_session_id);
    }

    if req.query::<bool>("active_only").unwrap_or(false) {
        filter = filter.active_at(clock.now());
    }

    let _ = require_session_grant_caller(req, depot).await?;
    let mut repo = depot.repo().await?;
    let page = repo
        .oauth2_session_grant()
        .list(filter, Pagination::first(100))
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;
    repo.cancel()
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantListResponse {
        grants: page
            .edges
            .into_iter()
            .map(|edge| edge.node.into())
            .collect(),
    }))
}

#[handler]
pub async fn revoke_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantRevokeResponse>, ContrixRouteError> {
    let clock = crate::handlers::make_clock();
    let raw_id = req
        .param::<String>("id")
        .ok_or_else(|| ContrixRouteError::BadRequest("missing session grant id".into()))?;
    let id = Ulid::from_string(&raw_id)
        .map_err(|_| ContrixRouteError::BadRequest("invalid session grant id".into()))?;

    // Revocation is destructive — Principal Server scope is not enough.
    match require_session_grant_caller(req, depot).await? {
        SessionGrantAuthz::Admin => {}
        SessionGrantAuthz::PrincipalServer => {
            return Err(ContrixRouteError::Forbidden(
                "session-grant revocation requires admin scope".to_owned(),
            ));
        }
    }

    let mut repo = depot.repo().await?;
    let grant = repo
        .oauth2_session_grant()
        .lookup(id)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        .ok_or(ContrixRouteError::NotFound)?;

    let grant = repo
        .oauth2_session_grant()
        .revoke(&clock, grant)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;
    repo.save()
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantRevokeResponse {
        grant: grant.into(),
    }))
}

fn introspection_grant_record(grant: &SessionGrant) -> SessionGrantIntrospectionGrant {
    SessionGrantIntrospectionGrant {
        id: grant.id.to_string(),
        issuer: grant.issuer.clone(),
        subject: grant.subject.clone(),
        service_account_id: grant
            .subject
            .rsplit_once(":users:")
            .map(|(_, id)| id.to_owned())
            .unwrap_or_else(|| grant.browser_session_id.to_string()),
        device_id: grant.device_id.clone(),
        audience: grant.audience.clone(),
        scopes: grant
            .scope
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        expires_at: grant.expires_at,
        revoked_at: grant.revoked_at,
        revocation_ref: format!("cx:session:{}", grant.browser_session_id),
    }
}

fn introspection_status(
    grant: &SessionGrant,
    user: Option<&User>,
    now: DateTime<Utc>,
    audience: Option<&str>,
) -> SessionGrantIntrospectionStatus {
    if audience.is_some_and(|audience| audience != grant.audience) {
        return SessionGrantIntrospectionStatus::AudienceMismatch;
    }

    if grant.revoked_at.is_some() {
        return SessionGrantIntrospectionStatus::Revoked;
    }

    if grant.expires_at <= now {
        return SessionGrantIntrospectionStatus::Expired;
    }

    if let Some(user) = user {
        if user.locked_at.is_some() {
            return SessionGrantIntrospectionStatus::Locked;
        }

        if user.deactivated_at.is_some() {
            return SessionGrantIntrospectionStatus::Suspended;
        }
    }

    SessionGrantIntrospectionStatus::Active
}

fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(grant_jwt.as_bytes()))
    )
}

fn verify_session_grant_introspection_proof(
    grant: &SessionGrant,
    proof: Option<&SessionGrantIntrospectionProofInput>,
    now: DateTime<Utc>,
) -> SessionGrantIntrospectionStatus {
    let Some(proof) = proof else {
        return SessionGrantIntrospectionStatus::ProofRequired;
    };
    if proof.challenge.trim().is_empty() || proof.proof_jwt.trim().is_empty() {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    let Ok(jwt) = Jwt::<SessionGrantIntrospectionProofClaims>::try_from(proof.proof_jwt.as_str())
    else {
        return SessionGrantIntrospectionStatus::InvalidProof;
    };
    let Ok(public_key) = serde_json::from_str::<PublicJsonWebKey>(&grant.session_public_key) else {
        return SessionGrantIntrospectionStatus::InvalidProof;
    };
    let jwks = PublicJsonWebKeySet::new(vec![public_key]);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    let claims = jwt.payload();
    let max_future_skew = Duration::try_seconds(30).unwrap();
    if claims.kind != "cx.session_grant.introspection_proof.v1"
        || claims.grant_id != grant.id.to_string()
        || claims.grant_jwt_hash != session_grant_jwt_hash(&grant.grant_jwt)
        || claims.audience != grant.audience
        || claims.challenge != proof.challenge
        || claims.expires_at <= now
        || claims.issued_at > now + max_future_skew
    {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    SessionGrantIntrospectionStatus::Active
}

#[handler]
pub async fn introspect_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantIntrospectionResponse>, ContrixRouteError> {
    let body: SessionGrantIntrospectionRequest = req
        .parse_json()
        .await
        .map_err(|_| ContrixRouteError::BadRequest("invalid json body".into()))?;

    if body.id.is_none() && body.grant_jwt.is_none() {
        return Err(ContrixRouteError::BadRequest(
            "missing id or grant_jwt".to_owned(),
        ));
    }

    let _ = require_session_grant_caller(req, depot).await?;
    let clock = crate::handlers::make_clock();
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let mut repo = depot.repo().await?;

    let grant = if let Some(id) = body.id.as_deref() {
        let id = Ulid::from_string(id)
            .map_err(|_| ContrixRouteError::BadRequest("invalid session grant id".into()))?;
        repo.oauth2_session_grant()
            .lookup(id)
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    } else if let Some(grant_jwt) = body.grant_jwt.as_deref() {
        repo.oauth2_session_grant()
            .lookup_by_grant_jwt(grant_jwt)
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    } else {
        None
    };

    let Some(grant) = grant else {
        repo.cancel()
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;
        return Ok(Json(SessionGrantIntrospectionResponse {
            active: false,
            status: SessionGrantIntrospectionStatus::NotFound,
            proof_required: true,
            one_time_use_consumed: false,
            grant: None,
        }));
    };

    let user = if let Some(user_id) =
        parse_local_user_did_for(&url_builder, &contrix_config, &grant.subject)
    {
        repo.user()
            .lookup(user_id)
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    } else {
        None
    };
    let mut status =
        introspection_status(&grant, user.as_ref(), clock.now(), body.audience.as_deref());
    let proof_required = status == SessionGrantIntrospectionStatus::Active;
    if proof_required {
        status = verify_session_grant_introspection_proof(&grant, body.proof.as_ref(), clock.now());
    }
    let active = status == SessionGrantIntrospectionStatus::Active;
    let grant_record = (status != SessionGrantIntrospectionStatus::NotFound
        && status != SessionGrantIntrospectionStatus::AudienceMismatch)
        .then(|| introspection_grant_record(&grant));

    let one_time_use_consumed = active;
    if active {
        repo.oauth2_session_grant()
            .revoke(&*clock, grant.clone())
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;
        repo.save()
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;
    } else {
        repo.cancel()
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;
    }

    Ok(Json(SessionGrantIntrospectionResponse {
        active,
        status,
        proof_required,
        one_time_use_consumed,
        grant: grant_record,
    }))
}

#[handler]
pub async fn service_did_json(depot: &Depot) -> Result<Json<DidDocument>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let did_resolver = depot.did_resolver_service()?;

    did_resolver
        .service_did_document(&url_builder, &contrix_config, &key_store)
        .map(Json)
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))
}

#[handler]
pub async fn user_did_json(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DidDocument>, ContrixRouteError> {
    let raw_id = req
        .param::<String>("id")
        .ok_or_else(|| ContrixRouteError::BadRequest("missing user id".into()))?;
    let user_id = Ulid::from_string(&raw_id)
        .map_err(|_| ContrixRouteError::BadRequest("invalid user id".into()))?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;
    let Some(user) = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    else {
        return Err(ContrixRouteError::NotFound);
    };

    Ok(Json(did_resolver.user_did_document(
        &url_builder,
        &contrix_config,
        &user,
    )))
}

#[cfg(test)]
mod tests {
    use coauth_config::{
        ContrixConfig, IdentityRegistryConfig, IdentityRegistryKind, PrincipalServerConfig,
    };
    use coauth_data::{Clock, RepositoryAccess, SystemClock, User};
    use coauth_keystore::{JsonWebKeySet, PrivateKey};
    use hyper::{Request, StatusCode};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    use super::*;

    fn test_keystore() -> Keystore {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let eddsa = coauth_keystore::JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid("test-eddsa");
        Keystore::new(JsonWebKeySet::new(vec![eddsa]))
    }

    #[test]
    fn service_and_user_identifiers_follow_contrix_shape() {
        let url_builder = UrlBuilder::new(
            "https://auth.example.com/coauth/".parse().unwrap(),
            None,
            None,
        );
        let mut rng = ChaChaRng::seed_from_u64(7);
        let now = Utc::now();
        let user = User::samples(now, &mut rng).into_iter().next().unwrap();

        assert_eq!(service_did(&url_builder), "did:web:auth.example.com:coauth");
        assert_eq!(
            user_did(&url_builder, &user),
            format!("did:web:auth.example.com:coauth:users:{}", user.id)
        );
        assert_eq!(
            user_handle(&url_builder, &user),
            format!("{}@auth.example.com", user.username)
        );
    }

    #[test]
    fn service_describe_exposes_auth_account_boundary_profile() {
        let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
        let contrix_config = ContrixConfig {
            service_did: Some("did:web:auth.example.com".to_owned()),
            issuer_did: Some("did:web:issuer.example.com".to_owned()),
            admin_audience: Some("https://auth.example.com/api/admin".to_owned()),
            principal_servers: vec![PrincipalServerConfig {
                name: "soland-prod".to_owned(),
                audience: "https://soland.example.com/api".to_owned(),
                endpoint: "https://soland.example.com/contrix".parse().unwrap(),
                did: Some("did:web:soland.example.com".to_owned()),
            }],
            identity_registry: Some(IdentityRegistryConfig {
                kind: IdentityRegistryKind::PublicDidResolver,
                resolver: "https://resolver.example.com/resolve".parse().unwrap(),
                proof_required_for_pairwise: true,
            }),
            principal_server_url: None,
        };

        let body =
            serde_json::to_value(service_describe_response(&url_builder, &contrix_config)).unwrap();

        assert_eq!(body["service_did"], "did:web:auth.example.com");
        assert_eq!(body["service_type"], "auth_account_server");
        assert_eq!(body["admin_audience"], "https://auth.example.com/api/admin");
        assert_eq!(
            body["auth_metadata"]["issuer_did"],
            "did:web:issuer.example.com"
        );
        assert_eq!(
            body["auth_metadata"]["session_grant_scope"],
            PRINCIPAL_SERVER_SESSION_BIND_SCOPE
        );
        assert_eq!(
            body["principal_server_delegation_targets"][0]["audience"],
            "https://soland.example.com/api"
        );
        assert_eq!(
            body["identity_registry_resolver"]["mode"],
            "delegated_resolver"
        );
        assert_eq!(
            body["identity_registry_resolver"]["endpoint"],
            "https://auth.example.com/api/v1/identity/resolve"
        );
        assert_eq!(
            body["identity_registry_resolver"]["delegated_resolver"]["kind"],
            "public_did_resolver"
        );
        assert_eq!(
            body["identity_registry_resolver"]["delegated_resolver"]["resolver"],
            "https://resolver.example.com/resolve"
        );
        assert_eq!(
            body["standard_error_envelope"]["example"],
            serde_json::json!({
                "ok": false,
                "error": {
                    "code": "machine_readable_code",
                    "message": "human-readable message"
                }
            })
        );

        let supported_profiles = body["supported_profiles"].as_array().unwrap();
        assert!(supported_profiles.contains(&serde_json::json!("cx.profile.auth_account.v1")));
        assert!(supported_profiles.contains(&serde_json::json!("cx.profile.did_binding.v1")));
        assert!(supported_profiles.contains(&serde_json::json!("cx.profile.session_grant.v1")));
        let not_authoritative_for = body["service_boundary"]["not_authoritative_for"]
            .as_array()
            .unwrap();
        assert!(not_authoritative_for.contains(&serde_json::json!("did_key_log")));
        assert!(not_authoritative_for.contains(&serde_json::json!("identity_registry_receipt")));
    }

    #[test]
    fn service_describe_defaults_to_local_identity_binding_resolver() {
        let url_builder = UrlBuilder::new(
            "https://auth.example.com/coauth/".parse().unwrap(),
            None,
            None,
        );

        let body = serde_json::to_value(service_describe_response(
            &url_builder,
            &ContrixConfig::default(),
        ))
        .unwrap();

        assert_eq!(body["identity_registry_resolver"]["mode"], "local_bindings");
        assert_eq!(
            body["identity_registry_resolver"]["endpoint"],
            "https://auth.example.com/coauth/api/v1/identity/resolve"
        );
        assert!(body["identity_registry_resolver"]["delegated_resolver"].is_null());
    }

    #[test]
    fn session_grant_is_signed_for_the_user_did() {
        let clock = SystemClock::default();
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        let contrix_config = ContrixConfig::default();
        let key_store = test_keystore();
        let now = clock.now();
        let mut fixture_rng = ChaChaRng::seed_from_u64(9);
        let browser_session = BrowserSession::samples(now, &mut fixture_rng)
            .into_iter()
            .next()
            .unwrap();
        let mut signing_rng = ChaChaRng::seed_from_u64(11);

        let grant = issue_session_grant(
            &mut signing_rng,
            &clock,
            &url_builder,
            &contrix_config,
            &key_store,
            &browser_session,
            vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
        )
        .unwrap();

        let jwt = Jwt::<SessionGrantPayload>::try_from(grant.grant_jwt.as_str()).unwrap();
        jwt.verify_with_jwks(&key_store.public_jwks()).unwrap();

        let payload = jwt.payload();
        assert_eq!(payload.kind, "cx.session.grant");
        assert_eq!(
            payload.subject,
            user_did_for(&url_builder, &contrix_config, &browser_session.user)
        );
        assert_eq!(
            payload.service_account_id,
            browser_session.user.id.to_string()
        );
        assert_eq!(
            payload.issuer,
            issuer_did_for(&url_builder, &contrix_config)
        );
        assert_eq!(
            payload.audience,
            required_audience_for(&url_builder, &contrix_config)
        );
        assert_eq!(payload.scopes, vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE]);
        assert_eq!(payload.session_id, browser_session.id.to_string());
        assert_eq!(payload.device_id, None);
        assert!(payload.expires_at > payload.not_before);
        assert_eq!(payload.proof.kind, "cx.session.grant.proof.v1");
        assert_eq!(payload.proof.alg, "EdDSA");
        assert_eq!(payload.proof.key_id, "test-eddsa");
        assert_eq!(payload.proof.payload_hash_alg, "sha-256");
        assert_eq!(
            payload.proof.payload_hash,
            session_grant_claims_hash(&session_grant_claims_from_payload(payload)).unwrap()
        );
        assert!(grant.session_private_key_pem.contains("PRIVATE KEY"));
        assert!(payload.session_public_key.contains("\"kid\":\"session-"));
    }

    #[test]
    fn session_grant_record_exposes_metadata_without_secrets() {
        let now = Utc::now();
        let grant = SessionGrant {
            id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap(),
            browser_session_id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap(),
            issuer: "did:web:auth.example.com".to_owned(),
            subject: "did:web:auth.example.com:users:01J44Q10GR4AMTFZEEF936DTCP".to_owned(),
            device_id: Some("device-1".to_owned()),
            audience: "https://soland.example.com/api".to_owned(),
            scope: Scope::from_iter([PRINCIPAL_SERVER_SESSION_BIND_SCOPE.parse().unwrap()]),
            grant_jwt: "header.payload.signature".to_owned(),
            session_public_key: "{\"kty\":\"OKP\"}".to_owned(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            revoked_at: None,
        };

        let body = serde_json::to_value(SessionGrantRecord::from(grant)).unwrap();

        assert_eq!(body["audience"], "https://soland.example.com/api");
        assert_eq!(
            body["scopes"],
            serde_json::json!([PRINCIPAL_SERVER_SESSION_BIND_SCOPE])
        );
        assert!(body.get("grant_jwt").is_none());
        assert!(body.get("session_public_key").is_none());
        assert!(body.get("session_private_key_pem").is_none());
    }

    #[test]
    fn session_grant_introspection_statuses_are_minimal_and_standardized() {
        let now = Utc::now();
        let mut rng = ChaChaRng::seed_from_u64(14);
        let mut user = User::samples(now, &mut rng).into_iter().next().unwrap();
        let mut grant = SessionGrant {
            id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap(),
            browser_session_id: Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCN").unwrap(),
            issuer: "did:web:auth.example.com".to_owned(),
            subject: format!("did:web:auth.example.com:users:{}", user.id),
            device_id: Some("device-1".to_owned()),
            audience: "https://soland.example.com/api".to_owned(),
            scope: Scope::from_iter([PRINCIPAL_SERVER_SESSION_BIND_SCOPE.parse().unwrap()]),
            grant_jwt: "header.payload.signature".to_owned(),
            session_public_key: "{\"kty\":\"OKP\"}".to_owned(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            revoked_at: None,
        };

        assert_eq!(
            introspection_status(
                &grant,
                Some(&user),
                now,
                Some("https://soland.example.com/api")
            ),
            SessionGrantIntrospectionStatus::Active
        );
        assert_eq!(
            introspection_status(
                &grant,
                Some(&user),
                now,
                Some("https://other.example.com/api")
            ),
            SessionGrantIntrospectionStatus::AudienceMismatch
        );

        user.locked_at = Some(now);
        assert_eq!(
            introspection_status(&grant, Some(&user), now, None),
            SessionGrantIntrospectionStatus::Locked
        );

        user.locked_at = None;
        user.deactivated_at = Some(now);
        assert_eq!(
            introspection_status(&grant, Some(&user), now, None),
            SessionGrantIntrospectionStatus::Suspended
        );

        grant.revoked_at = Some(now);
        assert_eq!(
            introspection_status(&grant, Some(&user), now, None),
            SessionGrantIntrospectionStatus::Revoked
        );
    }

    async fn seed_persisted_session_grant(
        state: &TestState,
    ) -> (BrowserSession, SessionGrant, SessionGrantMaterial) {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &*state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(
                &mut rng,
                &*state.clock,
                &user,
                Some("Mozilla/5.0".to_owned()),
            )
            .await
            .unwrap();
        let material = issue_session_grant(
            &mut rng,
            &*state.clock,
            &state.url_builder,
            &state.contrix_config,
            &state.key_store,
            &browser_session,
            vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
        )
        .unwrap();
        let grant = persist_session_grant(
            &mut repo,
            &mut rng,
            &*state.clock,
            &browser_session,
            &material,
        )
        .await
        .unwrap();
        repo.save().await.unwrap();

        (browser_session, grant, material)
    }

    fn session_grant_introspection_proof(
        grant: &SessionGrant,
        material: &SessionGrantMaterial,
        challenge: &str,
    ) -> String {
        let now = Utc::now();
        let key = PrivateKey::load_pem(&material.session_private_key_pem).unwrap();
        let signer = key
            .signing_key_for_alg(&JsonWebSignatureAlg::EdDsa)
            .unwrap();
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::EdDsa);
        let claims = SessionGrantIntrospectionProofClaims {
            kind: "cx.session_grant.introspection_proof.v1".to_owned(),
            grant_id: grant.id.to_string(),
            grant_jwt_hash: session_grant_jwt_hash(&material.grant_jwt),
            audience: grant.audience.clone(),
            challenge: challenge.to_owned(),
            issued_at: now,
            expires_at: now + Duration::try_minutes(1).unwrap(),
        };
        Jwt::sign(header, claims, &signer).unwrap().into_string()
    }

    #[tokio::test]
    async fn session_grant_http_list_and_filter_work() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let (browser_session, grant, _material) = seed_persisted_session_grant(&state).await;

        let response = state
            .request(Request::get("/api/v1/session-grants").empty())
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["grants"].as_array().unwrap().len(), 1);
        assert_eq!(body["grants"][0]["id"], grant.id.to_string());
        assert_eq!(
            body["grants"][0]["browser_session_id"],
            browser_session.id.to_string()
        );
        assert_eq!(
            body["grants"][0]["scopes"],
            serde_json::json!([PRINCIPAL_SERVER_SESSION_BIND_SCOPE])
        );

        let response = state
            .request(
                Request::get(format!(
                    "/api/v1/session-grants?browser_session_id={}&active_only=true",
                    browser_session.id
                ))
                .empty(),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["grants"].as_array().unwrap().len(), 1);

        let response = state
            .request(Request::get("/api/v1/session-grants?browser_session_id=not-a-ulid").empty())
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"]["code"], "bad_json");
        assert_eq!(body["error"]["message"], "invalid browser_session_id");
    }

    #[tokio::test]
    async fn session_grant_http_introspection_returns_minimal_metadata() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let (_browser_session, grant, material) = seed_persisted_session_grant(&state).await;
        let challenge = format!("introspect-{}", grant.id);
        let proof_jwt = session_grant_introspection_proof(&grant, &material, &challenge);

        let response = state
            .request(
                Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                    "grant_jwt": material.grant_jwt,
                    "audience": grant.audience,
                    "proof": {
                        "challenge": challenge,
                        "proof_jwt": proof_jwt,
                    }
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["active"], true);
        assert_eq!(body["status"], "active");
        assert_eq!(body["proof_required"], true);
        assert_eq!(body["one_time_use_consumed"], true);
        assert_eq!(body["grant"]["id"], grant.id.to_string());
        assert_eq!(body["grant"]["subject"], grant.subject);
        assert_eq!(body["grant"]["audience"], grant.audience);
        assert_eq!(body["grant"]["revoked_at"], serde_json::Value::Null);
        assert!(body["grant"].get("grant_jwt").is_none());
        assert!(body["grant"].get("session_public_key").is_none());

        let response = state
            .request(
                Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                    "id": grant.id,
                    "audience": grant.audience,
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["active"], false);
        assert_eq!(body["status"], "revoked");

        let response = state
            .request(
                Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                    "id": grant.id,
                    "audience": "https://other.example.com/api",
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["active"], false);
        assert_eq!(body["status"], "audience_mismatch");
        assert_eq!(body["grant"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn session_grant_http_revoke_updates_followup_introspection() {
        setup();
        let pool = coauth_data::test_utils::setup_test_pool().await;
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let (_browser_session, grant, _material) = seed_persisted_session_grant(&state).await;

        let response = state
            .request(Request::post(format!("/api/v1/session-grants/{}/revoke", grant.id)).empty())
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["grant"]["id"], grant.id.to_string());
        assert!(body["grant"]["revoked_at"].is_string());

        let response = state
            .request(
                Request::post("/api/v1/session-grants/introspect").json(serde_json::json!({
                    "id": grant.id,
                    "audience": grant.audience,
                })),
            )
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["active"], false);
        assert_eq!(body["status"], "revoked");
        assert_eq!(body["grant"]["id"], grant.id.to_string());
        assert!(body["grant"]["revoked_at"].is_string());
    }

    #[test]
    fn parse_local_handle_round_trips_local_user_handle() {
        let url_builder = UrlBuilder::new(
            "https://auth.example.com/coauth/".parse().unwrap(),
            None,
            None,
        );
        let mut rng = ChaChaRng::seed_from_u64(12);
        let now = Utc::now();
        let user = User::samples(now, &mut rng).into_iter().next().unwrap();
        let handle = user_handle(&url_builder, &user);

        assert_eq!(
            parse_local_handle(&url_builder, &handle),
            Some(user.username.clone())
        );
        assert_eq!(
            parse_local_handle(&url_builder, "alice@elsewhere.example"),
            None
        );
    }

    #[test]
    fn identity_document_exposes_user_handle_binding() {
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        let contrix_config = ContrixConfig::default();
        let now = Utc::now();
        let mut rng = ChaChaRng::seed_from_u64(13);
        let user = User::samples(now, &mut rng).into_iter().next().unwrap();

        let document = user_did_document(&url_builder, &contrix_config, &user);

        assert_eq!(
            document.id,
            user_did_for(&url_builder, &contrix_config, &user)
        );
        assert_eq!(
            document.also_known_as,
            vec![format!("contrix://{}", user_handle(&url_builder, &user))]
        );
        assert_eq!(document.service[0].kind, "ContrixAuthServer");
        assert_eq!(
            document.service[0].service_endpoint,
            url_builder
                .absolute_url("/api/v1/server/describe")
                .to_string()
        );
    }
}
