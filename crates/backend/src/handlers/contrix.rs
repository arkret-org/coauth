use anyhow::Error as AnyhowError;
use chrono::{DateTime, Duration, Utc};
use coauth_config::{ContrixConfig, IdentityRegistryKind};
use coauth_data::{
    BrowserSession, Clock, Pagination, RepositoryAccess, SessionGrant, UrlBuilder, User,
    oauth::{NewSessionGrant, SessionGrantFilter},
};
use coauth_iana::jose::{JsonWebKeyOperation, JsonWebKeyUse, JsonWebSignatureAlg};
use coauth_jose::{
    constraints::Constrainable,
    jwk::{JsonWebKey, JsonWebKeyPublicParameters, PublicJsonWebKey, PublicJsonWebKeySet},
    jwt::{JsonWebSignatureHeader, Jwt, JwtSignatureError},
};
use coauth_keystore::{Keystore, PrivateKey, WrongAlgorithmError};
use der::pem::LineEnding;
use oauth_types::scope::{Scope, ScopeToken};
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

    // Static bearer fallback: a Principal Server may authenticate with a
    // token configured in `contrix.principal_servers[].
    // session_grant_introspection_bearer`. Mirrors the
    // `oauth_introspection_bearer` fallback on the OAuth introspection
    // endpoint and lets a server-to-server caller skip the DB-backed
    // PAT/OAuth-session lookup. Grants `PrincipalServer` authz only —
    // never `Admin` — so it cannot revoke session grants.
    let contrix_config = depot.contrix_config()?;
    if principal_server_static_session_grant_bearer_matches(&contrix_config, token) {
        return Ok(SessionGrantAuthz::PrincipalServer);
    }

    let token_type = TokenType::check(token)
        .map_err(|_| ContrixRouteError::Unauthorized("invalid bearer token".to_owned()))?;

    let mut repo = depot.repo().await?;
    let scope = match token_type {
        TokenType::AccessToken => {
            let access = repo
                .oauth_access_token()
                .find_by_token(token)
                .await
                .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    ContrixRouteError::Unauthorized("unknown access token".to_owned())
                })?;
            let session = repo
                .oauth_session()
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

fn principal_server_static_session_grant_bearer_matches(
    contrix_config: &ContrixConfig,
    token: &str,
) -> bool {
    !token.trim().is_empty()
        && contrix_config
            .principal_servers
            .iter()
            .filter_map(|server| server.session_grant_introspection_bearer.as_deref())
            .any(|configured| configured == token)
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
            Self::Unauthorized(message) => (StatusCode::UNAUTHORIZED, "unauthorized", message),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message),
        };

        if status == StatusCode::UNAUTHORIZED {
            // RFC 7235 says 401 responses MUST include a WWW-Authenticate
            // challenge so the caller can negotiate.
            res.headers_mut().insert(
                http::header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static("Bearer realm=\"contrix\", error=\"invalid_token\""),
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
    /// RFC 7638 JWK SHA-256 thumbprint (base64url) of the DPoP proof the
    /// grant is bound to, when issuance happened on a request that
    /// carried a `DPoP` header. `None` for legacy paths (e.g. internal
    /// admin minting, debug seeds without a `dpop_jwk`).
    pub dpop_jkt: Option<String>,
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
    /// RFC 9449 §6 confirmation — when the grant was issued bound to a
    /// DPoP proof, `cnf.jkt` carries the RFC 7638 SHA-256 thumbprint
    /// (base64url) of the proof's public key. The refresh path requires
    /// any follow-up proof to recompute the same thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<SessionGrantConfirmation>,
    pub proof: SessionGrantProof,
}

/// RFC 9449 / RFC 7800 confirmation claim, carrying the JWK thumbprint
/// that binds an access token (here a session grant) to the holder's
/// proof-of-possession key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantConfirmation {
    /// `jkt` — base64url SHA-256 JWK thumbprint per RFC 7638.
    pub jkt: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<SessionGrantConfirmation>,
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
    /// Round 4 (spec a77b995) — deployment-scope trust domain. Mirror
    /// of `ContrixConfig::trust_domain` (wire form
    /// `cx:trust_domain:<scope>`). Receivers MUST treat a missing
    /// `trust_domain` as the deployment failing closed — federation
    /// partners cannot bind their canonical transcript without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_domain: Option<String>,
    /// T6.3 — explicit Contrix v1 role declaration. A coauth instance can
    /// simultaneously act as `auth_server` (OIDC token issuer),
    /// `identity_resolver` (DID / handle resolution proxy), and
    /// `account_registry` (internal service-account management). The
    /// entries here are independent capability claims; each maps to a
    /// distinct subset of `supported_operations`. Consumers MUST NOT
    /// infer canonical identity-registry ownership from
    /// `identity_resolver` alone (that role is held by an upstream
    /// resolver such as starid / public DID network).
    service_roles: Vec<&'static str>,
    protocol_version: &'static str,
    supported_profiles: Vec<&'static str>,
    supported_features: Vec<&'static str>,
    supported_reducer_profiles: Vec<&'static str>,
    supported_schema_profiles: Vec<&'static str>,
    supported_bindings: Vec<SupportedBinding>,
    supported_operations: Vec<&'static str>,
    /// T6.1 — feature ids the service has implementation code for but
    /// does NOT claim conformance for. Schema:
    /// `cx.schema.service_describe.v1` (see service-surface.md §3.0).
    implemented_features: Vec<&'static str>,
    /// T6.1 — self-claimed profiles. `claim_kind` MUST be `self_claimed`.
    claimed_profiles: Vec<ClaimedProfileDescriptor>,
    /// T6.1 — cotest-verified profiles. MUST be empty when
    /// `development_mode=true` (§3.0).
    verified_profiles: Vec<VerifiedProfileDescriptor>,
    /// T6.1 — features the service exposes but does NOT promise stable
    /// interop for.
    experimental_features: Vec<&'static str>,
    /// T6.1 — legacy / external-interop surfaces exposed for compatibility,
    /// not as part of Contrix v1 conformance.
    compat_surfaces: Vec<CompatSurfaceDescriptor>,
    /// Mirror of the service's development-mode flag. coauth has no
    /// dedicated dev toggle today, so this is always `false`; if a toggle
    /// is added later the `verified_profiles=[]` invariant MUST be
    /// re-enforced.
    development_mode: bool,
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

/// T6.1 — self-claimed profile entry. `claim_kind = "self_claimed"`;
/// cotest-verified entries belong in `verified_profiles`.
#[derive(Debug, Serialize)]
struct ClaimedProfileDescriptor {
    profile_id: &'static str,
    claim_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
}

/// T6.1 — cotest-verified profile entry. Required `cotest_run_id`,
/// `artifact_hash`, `timestamp`. Dev-mode posture MUST NOT advertise any
/// such entry (§3.0).
#[derive(Debug, Serialize)]
struct VerifiedProfileDescriptor {
    profile_id: String,
    claim_kind: &'static str,
    cotest_run_id: String,
    artifact_hash: String,
    timestamp: String,
}

/// T6.1 — compat / external-interop surface entry. `kind` ∈
/// {`matrix_passthrough`, `mimi_passthrough`, `legacy_alias`,
/// `external_interop`, `deprecated_alias`}.
#[derive(Debug, Serialize)]
struct CompatSurfaceDescriptor {
    name: &'static str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct IdentityDescribeResBody {
    service_did: String,
    registry_mode: &'static str,
    supported_receipts: Vec<String>,
    protocol_version: &'static str,
    profiles: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_registry: Option<IdentityRegistryDescriptor>,
}

#[derive(Debug, Serialize)]
struct IdentityResolveResBody {
    did_document: DidDocument,
    key_log_head: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
    method_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct IdentityDocumentResBody {
    did_document: DidDocument,
    head_event_hash: Option<String>,
    seq: Option<u64>,
    receipts: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct DirectoryDescribeResBody {
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

/// Legacy display form `local@host` used by some logging / display
/// paths. NOT the canonical handle URI form — use [`user_handle_uri`]
/// (spec 0a5ab85) for `alsoKnownAs` / DID Document / claim emission.
pub(crate) fn user_handle(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "{}@{}",
        user.handle,
        url_builder.public_hostname().to_lowercase()
    )
}

/// Canonical Contrix handle URI for a user per spec 0a5ab85:
/// `contrix://<lowercase-host>/users/<lowercase-localpart>`. This is the
/// form that MUST appear in `alsoKnownAs` and on any handle claim
/// `handle_uri`. `acct:<local>@<host>` is interop-only and lives in
/// `handle_aliases[]` on the handle claim.
pub(crate) fn user_handle_uri(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "contrix://{}/users/{}",
        url_builder.public_hostname().to_lowercase(),
        user.handle.to_lowercase()
    )
}

/// `acct:` interop alias for [`user_handle_uri`]. Use this for
/// `handle_aliases[]` on a `handle-claim.schema.json` payload.
pub(crate) fn user_handle_acct_alias(url_builder: &UrlBuilder, user: &User) -> String {
    format!(
        "acct:{}@{}",
        user.handle.to_lowercase(),
        url_builder.public_hostname().to_lowercase()
    )
}

/// Stable wire-level error code returned when a caller passes an `acct:`
/// alias (or any other non-canonical string) as a `handle_uri` input.
///
/// Mirrored by [`coauth_data::users::HANDLE_URI_NOT_CANONICAL_CODE`] —
/// kept in sync so the audit / HTTP layers can refer to the same constant
/// without an extra dependency.
pub const HANDLE_URI_NOT_CANONICAL_CODE: &str = "handle_uri_not_canonical";

/// Reject any inbound `handle_uri` that is not in the canonical
/// `contrix://<host>/users/<localpart>` shape. Returns a
/// [`ContrixRouteError::BadRequest`] wrapping the standard error envelope
/// `code = "handle_uri_not_canonical"`.
pub(crate) fn require_canonical_handle_uri(input: &str) -> Result<&str, ContrixRouteError> {
    coauth_data::user::validate_canonical_handle_uri(input).map_err(|(_code, message)| {
        // The error envelope sets `code` from the variant; we embed the
        // reason text so callers see why their input was rejected.
        ContrixRouteError::BadRequest(format!("{HANDLE_URI_NOT_CANONICAL_CODE}: {message}"))
    })
}

/// Delivery-binding hint embedded in a `handle_claim`. Shape mirrors
/// `member-delivery-binding-candidate.schema.json#delivery_binding_hint`
/// (commit 0a5ab85). `binding_source` MUST be one of the five values
/// enumerated below — `did_document_default` is forbidden because handle-
/// resolved candidates and DID Document fallback are independent
/// materialisation paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleClaimDeliveryBindingHint {
    pub recipient_service_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_type: Option<String>,
    pub binding_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
}

/// Detached-JWS proof attached to a `handle_claim`. Lightweight mirror of
/// `event-schema.json#/$defs/proof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleClaimProof {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub canonicalization: String,
    pub payload_hash_alg: String,
    pub payload_hash: String,
    pub created_at: DateTime<Utc>,
    pub audience: String,
    pub jws: String,
}

/// Canonical `handle_claim` payload signed by coauth's audience-bound
/// session-grant signing key. Shape aligned with
/// `member-delivery-binding-candidate.schema.json` so a downstream
/// directory can pack this directly into a candidate without rewriting
/// fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleClaimPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub subject_did: String,
    pub handle_uri: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    pub issuer_service_did: String,
    pub audience: String,
    pub delivery_binding_hint: HandleClaimDeliveryBindingHint,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub proofs: Vec<HandleClaimProof>,
    /// `sha256:<hex>` digest of the canonical-JSON encoding of the claim
    /// minus the `proofs[]` field (proofs are produced *over* this hash).
    pub claim_digest: String,
}

/// Output of [`issue_handle_claim`]. Carries the signed JWT, the raw
/// payload (so the caller can persist or echo it), and the wire-level
/// claim digest used as the audit-chain anchor.
#[derive(Debug, Clone)]
pub struct HandleClaimMaterial {
    pub claim_jwt: String,
    pub payload: HandleClaimPayload,
    pub claim_digest: String,
    pub expires_at: DateTime<Utc>,
}

/// TTL applied to handle claim JWTs. Short by design — claims are meant
/// to round-trip through a directory / candidate builder in seconds, not
/// be stored as long-lived bearer credentials.
pub(crate) const HANDLE_CLAIM_TTL_MINUTES: i64 = 5;

/// Mint a handle-claim JWT bound to `audience`. The claim's
/// `delivery_binding_hint` MUST come from upstream policy (handed to this
/// function by the caller); we never default to `did_document_default`.
///
/// Signs with the same preferred ed25519 key used for session grants, so
/// downstream verifiers can use coauth's published DID Document
/// `verificationMethod` to validate both artefacts.
pub(crate) fn issue_handle_claim(
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
    user: &User,
    audience: String,
    delivery_binding_hint: HandleClaimDeliveryBindingHint,
) -> Result<HandleClaimMaterial, SessionGrantError> {
    let issuer_service_did = service_did_for(url_builder, contrix_config);
    let subject_did = user_did_for(url_builder, contrix_config, user);
    let handle_uri = user_handle_uri(url_builder, user);
    let mut aliases = vec![user_handle_acct_alias(url_builder, user)];
    aliases.extend(user.handle_aliases.iter().cloned());
    // De-duplicate while preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|s| seen.insert(s.clone()));

    let now = clock.now();
    let expires_at = now + Duration::try_minutes(HANDLE_CLAIM_TTL_MINUTES).unwrap();

    // Build the payload sans proofs so we can hash it deterministically.
    // The proof block then carries that hash; the JWT signs the complete
    // payload.
    let mut payload_no_proofs = HandleClaimPayload {
        kind: "cx.handle.claim".to_owned(),
        subject_did: subject_did.clone(),
        handle_uri,
        handle_aliases: aliases.clone(),
        issuer_service_did: issuer_service_did.clone(),
        audience: audience.clone(),
        delivery_binding_hint: delivery_binding_hint.clone(),
        issued_at: now,
        expires_at,
        proofs: Vec::new(),
        claim_digest: String::new(),
    };
    let claim_digest = canonical_json_sha256(&HandleClaimDigestInput {
        kind: &payload_no_proofs.kind,
        subject_did: &payload_no_proofs.subject_did,
        handle_uri: &payload_no_proofs.handle_uri,
        handle_aliases: &payload_no_proofs.handle_aliases,
        issuer_service_did: &payload_no_proofs.issuer_service_did,
        audience: &payload_no_proofs.audience,
        delivery_binding_hint: &payload_no_proofs.delivery_binding_hint,
        issued_at: payload_no_proofs.issued_at,
        expires_at: payload_no_proofs.expires_at,
    })?;
    payload_no_proofs.claim_digest = claim_digest.clone();

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let verification_method = format!("{issuer_service_did}#{key_id}");
    let proof_payload_hash = claim_digest.clone();

    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id.clone());
    let signer = key.params().signing_key_for_alg(&alg)?;
    let unsigned_payload = HandleClaimPayload {
        proofs: vec![HandleClaimProof {
            kind: "cx.handle.claim.proof.v1".to_owned(),
            alg: alg.to_string(),
            verification_method: verification_method.clone(),
            canonicalization: "json-c14n-object-key-sort-v1".to_owned(),
            payload_hash_alg: "sha-256".to_owned(),
            payload_hash: proof_payload_hash.clone(),
            created_at: now,
            audience: audience.clone(),
            // Placeholder — overwritten with the detached JWS below.
            jws: String::new(),
        }],
        ..payload_no_proofs.clone()
    };
    let claim_jwt = Jwt::sign(header, unsigned_payload.clone(), &signer)?.into_string();

    let final_payload = HandleClaimPayload {
        proofs: vec![HandleClaimProof {
            kind: "cx.handle.claim.proof.v1".to_owned(),
            alg: alg.to_string(),
            verification_method,
            canonicalization: "json-c14n-object-key-sort-v1".to_owned(),
            payload_hash_alg: "sha-256".to_owned(),
            payload_hash: proof_payload_hash,
            created_at: now,
            audience: audience.clone(),
            jws: claim_jwt.clone(),
        }],
        ..payload_no_proofs
    };

    Ok(HandleClaimMaterial {
        claim_jwt,
        payload: final_payload,
        claim_digest,
        expires_at,
    })
}

/// Helper struct used to canonicalise the *digest input* — i.e. the
/// payload minus the `proofs[]` and `claim_digest` fields. Sorting and
/// shape must match the wire shape of `HandleClaimPayload` for
/// downstream digesters to reproduce the hash.
#[derive(Debug, Serialize)]
struct HandleClaimDigestInput<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    subject_did: &'a str,
    handle_uri: &'a str,
    handle_aliases: &'a Vec<String>,
    issuer_service_did: &'a str,
    audience: &'a str,
    delivery_binding_hint: &'a HandleClaimDeliveryBindingHint,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
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
        principal_server_authorization: "server_name writes are decided by the downstream authorization engine from session grants, capabilities, and Space policy.",
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

/// G4.T3 — convert the loader's `VerifiedProfileDescriptor` into the wire
/// shape expected by `ServiceDescribeResponse.verified_profiles[]`. Also
/// enforces the local cross-check: any entry whose `profile_id` is not in
/// coauth's hard-coded claimed-profile set is dropped with a `warn!` line.
///
/// The claimed-profile set here MUST stay in lockstep with the
/// `claimed_profiles: vec![...]` literal inside `service_describe_response`.
/// If a future task widens coauth's claimed profiles (e.g. adds an
/// `identity_resolver` profile claim), this set MUST grow accordingly —
/// otherwise the cross-check will silently drop legitimate verified
/// entries.
fn build_verified_profile_descriptors(
    loaded: &[crate::services::verified_profiles::VerifiedProfileDescriptor],
) -> Vec<VerifiedProfileDescriptor> {
    const CLAIMED_PROFILE_IDS: &[&str] = &["cx.profile.auth_server.v1"];
    loaded
        .iter()
        .filter_map(|entry| {
            if !CLAIMED_PROFILE_IDS.contains(&entry.profile_id.as_str()) {
                tracing::warn!(
                    target: "verified_profiles",
                    profile_id = %entry.profile_id,
                    "dropping verified-profile entry: profile_id absent from coauth claimed_profiles"
                );
                return None;
            }
            Some(VerifiedProfileDescriptor {
                profile_id: entry.profile_id.clone(),
                claim_kind: "cotest_verified",
                cotest_run_id: entry.cotest_run_id.clone(),
                artifact_hash: entry.artifact_hash.clone(),
                timestamp: entry.timestamp.to_rfc3339(),
            })
        })
        .collect()
}

fn service_describe_response(
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    loaded_verified_profiles: &[crate::services::verified_profiles::VerifiedProfileDescriptor],
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
        // Round 4 — surface the deployment trust domain so federation
        // peers can verify cross-deployment replay protection (see
        // `contrix-spec` round-4 §f9bd7eb).
        trust_domain: contrix_config.trust_domain.clone(),
        // service_type is the SDK-side `ServiceType` discriminant. coauth's
        // primary role is OIDC issuance, so this is kept as "auth_server".
        // The richer multi-role posture is expressed via `service_roles`
        // (T6.3) — consumers that need the full picture MUST read that
        // array; legacy clients that only key off service_type still get
        // an answer compatible with the SDK's
        // `ProfileValidator::for_auth_server`.
        service_type: "auth_server",
        // T6.3 — declare all roles this coauth instance carries. Each
        // role is independent: any subset may be deployed off elsewhere
        // (e.g. dedicated starid for identity_resolver, dedicated
        // account-registry service) without affecting the others.
        //   - "auth_server"        : OIDC / token issuance, the
        //                            canonical role.
        //   - "identity_resolver"  : DID / handle resolution proxy.
        //                            NOT canonical identity registry;
        //                            backed by `cx.identity.*` proxy
        //                            operations that ultimately route
        //                            to an upstream registry (configured
        //                            via `identity_registry_resolver`).
        //   - "account_registry"   : internal service-account /
        //                            recovery / claim-attestation
        //                            management.
        service_roles: vec!["auth_server", "identity_resolver", "account_registry"],
        protocol_version: CONTRIX_PROTOCOL_VERSION,
        supported_profiles: Vec::new(),
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
        supported_reducer_profiles: vec!["cx.reducer.v1"],
        // T6.3 — replace the historical `cx.schema.v1` placeholder with
        // the actual spec-declared schemas this surface emits. The
        // `cx.schema.service_describe.v1` schema covers the very
        // payload being served here; `cx.schema.core.v1` matches the
        // soland / SDK convention for the core-event-store schema
        // profile and is the umbrella the OIDC + account artefacts hash
        // under. Older `cx.schema.v1` is no longer published.
        supported_schema_profiles: vec!["cx.schema.core.v1", "cx.schema.service_describe.v1"],
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
        // T6.1 — claim-level partition. See service-surface.md §3.0.
        //
        // implemented_features mirrors supported_features: coauth has
        // code for each of these but does not claim conformance for any
        // of them today. Any future cotest run that produces a passing
        // artifact for a coauth profile MUST land in `verified_profiles`,
        // never here.
        implemented_features: vec![
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
        // T6.3 / G3.C3 — claimed_profiles carries the auth-server slot.
        //
        // coauth wears three roles (see `service_roles` above). The only
        // canonical v1 profile whose role + required surface coauth
        // actually serves is `cx.profile.auth_server.v1` (added under
        // G3.C3 to `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json`).
        // The other directory-role profiles that would superficially
        // apply are NOT claimed and the reason is documented inline:
        //
        //   * `cx.profile.identity_registry.v1`   — role=directory.
        //     coauth's `cx.identity.*` ops are a DELEGATED proxy onto
        //     an upstream resolver, not a canonical registry. Claiming
        //     this profile would lie about authority over DID
        //     documents.
        //   * `cx.profile.directory_service.v1`   — role=directory.
        //     coauth exposes `cx.directory.resolve_handle` only for
        //     local handles it issued; it does NOT publish a
        //     network-wide actor directory.
        //   * `cx.profile.public_network_identity.v1` — role=directory.
        //     Same reason — coauth is a service-local issuer, not the
        //     network identity authority.
        //   * `cx.profile.principal_server.v1`    — role=server.
        //     coauth is not Realm-authoritative; principal-server
        //     event acceptance is soland's role.
        //
        // The boundary against those non-claimed profiles is still
        // surfaced via `service_roles` + `compat_surfaces` (the
        // delegated identity ops) so cotest's ProfileValidator does
        // not flag a role mismatch.
        claimed_profiles: vec![ClaimedProfileDescriptor {
            profile_id: "cx.profile.auth_server.v1",
            claim_kind: "self_claimed",
            notes: Some(
                "Auth-server-shaped profile: issues short-lived audience-bound cx.session.grant, exposes cx.server.describe, MAY expose cx.policy.check. NOT an identity registry (DID resolution is delegated; see compat_surfaces).",
            ),
        }],
        // G4.T3 — verified_profiles populated by the cotest artifact loader
        // (`crate::services::verified_profiles::load_from_env`). Every loaded
        // entry's profile_id is cross-checked against the local
        // `claimed_profiles[]` set; entries that fail the cross-check are
        // dropped here (warn-logged) so coauth never advertises a verified
        // profile it does not also self-claim.
        //
        // dev-mode invariant (service-surface.md §3.0): coauth has no
        // runtime dev toggle today, so the only way this surface contains
        // an entry is for COAUTH_VERIFIED_PROFILES_ARTIFACT to point at a
        // valid cotest-produced artifact. Env var unset → empty Vec → the
        // dev-mode posture is preserved without any extra branching here.
        verified_profiles: build_verified_profile_descriptors(loaded_verified_profiles),
        // experimental_features: surfaces still maturing inside coauth.
        // Listed here explicitly so callers don't treat them as stable
        // interop.
        experimental_features: vec![
            "session_grant_exchange",
            "did_webvh_embedded_registration",
            "principal_server_delegation_targets",
        ],
        // T6.3 — compat_surfaces declares non-canonical surfaces. The
        // `cx.identity.*` operations are exposed for client
        // convenience but are a DELEGATED resolver shim onto an
        // upstream registry (starid, public DID network, etc.); coauth
        // is NOT the canonical identity authority for any DID it
        // returns. The `delegated_resolver` kind disambiguates from
        // `external_interop` / `matrix_passthrough`.
        compat_surfaces: vec![
            CompatSurfaceDescriptor {
                name: "cx.identity.describe_registry",
                kind: "delegated_resolver",
                notes: Some(
                    "Reports the upstream registry coauth proxies to; does not assert canonical ownership.",
                ),
            },
            CompatSurfaceDescriptor {
                name: "cx.identity.resolve",
                kind: "delegated_resolver",
                notes: Some(
                    "DID resolution is performed against the configured identity_registry_resolver; coauth caches but does not author DID documents.",
                ),
            },
            CompatSurfaceDescriptor {
                name: "cx.identity.get_document",
                kind: "delegated_resolver",
                notes: Some(
                    "Returns the cached/resolved DID document; coauth holds no authoritative key log for external DIDs.",
                ),
            },
        ],
        development_mode: false,
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

// T5.3 (Round 22, 2026-05-20) — handle_claim digest convergence.
//
// The previous in-file `write_canonical_json` walker and
// `canonical_json_sha256` helper were a hand-rolled (but spec-equivalent)
// canonical-JSON implementation. They are now a thin shim over
// `contrix_core::canonical::canonical_sha256`, which is the single canonical
// JSON pipeline shared by soland / starid / yougen / floria. This keeps
// the handle-claim payload hash byte-identical to every other Contrix
// service computing `sha256(canonical_json(payload))`.
//
// The SDK encoder is *stricter* than the original (it rejects float
// numbers per `encoding.md` §3.2). Coauth's `HandleClaimDigestInput` is
// composed of strings, DateTime<Utc> (rendered as RFC 3339 strings), and
// an inner struct of strings, so no shape that previously hashed cleanly
// will now reject.
fn canonical_json_sha256(value: &impl Serialize) -> Result<String, serde_json::Error> {
    match contrix_core::canonical::canonical_sha256(value) {
        Ok(digest) => Ok(digest),
        Err(contrix_core::Error::CanonicalJson(err)) => Err(err),
        Err(other) => {
            // The SDK canonical encoder fails with `NonCanonicalNumber`
            // for any float, but handle_claim never carries floats and
            // upstream call-sites currently expect a serde_json::Error.
            // Mirror that via the `serde::ser::Error::custom` constructor
            // so failure is still surfaced rather than swallowed.
            Err(<serde_json::Error as serde::ser::Error>::custom(
                other.to_string(),
            ))
        }
    }
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
        cnf: payload.cnf.clone(),
    }
}

fn primary_device_id_from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Option<String> {
    tokens.into_iter().find_map(|token| {
        token
            .strip_prefix("urn:contrix:client:device:")
            .map(ToOwned::to_owned)
    })
}

pub(crate) fn primary_device_id(scope: &Scope) -> Option<String> {
    primary_device_id_from_tokens(scope.iter().map(oauth_types::scope::ScopeToken::as_str))
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
        // Spec 0a5ab85: canonical handle URI form is
        // `contrix://<host>/users/<localpart>`; `acct:` is interop-only.
        also_known_as: vec![user_handle_uri(url_builder, user)],
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
        None,
        None,
    )
}

// `subject_override` lets callers bind the grant to a non-default DID — e.g.
// an OIDC bridge that just minted a `did:webvh:…` for the user on the target
// principal server, where falling back to `user_did_for` would diverge from
// the `viewer.did` returned in the same response and the principal server
// would reject the exchange with `session grant subject does not match
// principal_did`.
pub(crate) fn issue_session_grant_for_audience(
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    contrix_config: &ContrixConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: Option<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let subject = subject_override
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| user_did_for(url_builder, contrix_config, &browser_session.user));
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
    let cnf = dpop_jkt
        .as_ref()
        .map(|jkt| SessionGrantConfirmation { jkt: jkt.clone() });
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
        cnf: cnf.clone(),
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
        cnf: claims.cnf,
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
        dpop_jkt,
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

    repo.oauth_session_grant()
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
        .filter(|h| !h.is_empty())
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
        .oauth_client()
        .all_static()
        .await?
        .into_iter()
        .filter(|client| {
            client.grant_types.iter().any(|grant_type| {
                matches!(
                    grant_type,
                    oauth_types::requests::GrantType::AuthorizationCode
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

    // G4.T3 — pull the loaded verified-profile descriptors out of the
    // depot. Empty Arc when COAUTH_VERIFIED_PROFILES_ARTIFACT is unset.
    let verified_profiles_loaded: std::sync::Arc<
        Vec<crate::services::verified_profiles::VerifiedProfileDescriptor>,
    > = depot
        .get::<std::sync::Arc<Vec<crate::services::verified_profiles::VerifiedProfileDescriptor>>>(
            "verified_profiles",
        )
        .cloned()
        .unwrap_or_else(|_| std::sync::Arc::new(Vec::new()));
    let mut response = service_describe_response(
        &url_builder,
        &contrix_config,
        verified_profiles_loaded.as_ref(),
    );
    response.auth_metadata.oidc_clients = oidc_clients;
    Ok(Json(response))
}

#[handler]
pub async fn identity_describe(
    depot: &Depot,
) -> Result<Json<IdentityDescribeResBody>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let identity_registry = delegated_identity_registry_descriptor(&contrix_config);

    Ok(Json(IdentityDescribeResBody {
        service_did: service_did_for(&url_builder, &contrix_config),
        registry_mode: if identity_registry.is_some() {
            "delegated_resolver"
        } else {
            "local_bindings"
        },
        supported_receipts: Vec::new(),
        protocol_version: CONTRIX_PROTOCOL_VERSION,
        profiles: Vec::new(),
        identity_registry,
    }))
}

#[handler]
pub async fn identity_resolve(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<IdentityResolveResBody>, ContrixRouteError> {
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

    Ok(Json(IdentityResolveResBody {
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
) -> Result<Json<IdentityDocumentResBody>, ContrixRouteError> {
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

    Ok(Json(IdentityDocumentResBody {
        did_document: resolution.document,
        head_event_hash: None,
        seq: None,
        receipts: None,
    }))
}

#[handler]
pub async fn directory_describe(
    depot: &Depot,
) -> Result<Json<DirectoryDescribeResBody>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;

    Ok(Json(DirectoryDescribeResBody {
        service_did: service_did_for(&url_builder, &contrix_config),
        resource_types: vec!["actor", "handle"],
        discovery_profiles: Vec::new(),
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
    let Some(handle) = parse_local_handle(&url_builder, &body.handle) else {
        return Err(ContrixRouteError::NotFound);
    };

    let mut repo = depot.repo().await?;
    let Some(user) = repo
        .user()
        .find_by_handle(&handle)
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
        .oauth_session_grant()
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

    // Revocation is destructive — server_name scope is not enough.
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
        .oauth_session_grant()
        .lookup(id)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        .ok_or(ContrixRouteError::NotFound)?;

    let grant = repo
        .oauth_session_grant()
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
        service_account_id: grant.subject.rsplit_once(":users:").map_or_else(
            || grant.browser_session_id.to_string(),
            |(_, id)| id.to_owned(),
        ),
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
        repo.oauth_session_grant()
            .lookup(id)
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    } else if let Some(grant_jwt) = body.grant_jwt.as_deref() {
        repo.oauth_session_grant()
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
        repo.oauth_session_grant()
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

// ── DPoP-bound session-grant refresh + debug seed ──────────────
//
// These two handlers were added in G3.C1 to complete the device-bound
// session-grant story: `refresh_session_grant` rotates an existing
// DPoP-bound grant onto a new access token (keeping `cnf.jkt` constant),
// and `debug_issue_dpop_grant` is the cotest harness seam that mints a
// fully signed grant without going through OIDC.

#[derive(Debug, Deserialize)]
pub struct RefreshSessionGrantRequest {
    /// The session grant currently associated with the device. Single-use
    /// — after a successful refresh the old grant is revoked.
    pub grant_jwt: String,
    /// Optional audience override; defaults to the grant's audience.
    #[serde(default)]
    pub audience: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RefreshSessionGrantResponse {
    pub grant_id: String,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub session_private_key_pem: String,
    pub expires_at: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub dpop_jkt: String,
    pub previous_grant_id: String,
}

/// `POST /api/v1/session-grants/refresh` — exchange a near-expiry
/// DPoP-bound session grant for a fresh one. The caller MUST present:
///
/// * A `DPoP` header that proves possession of the same key the existing
///   grant is bound to (`cnf.jkt` on the old grant must match the new
///   proof's `jkt`).
/// * A request body carrying the prior grant JWT.
///
/// On success the old grant is revoked (single-use semantics — its
/// `revoked_at` is persisted) and a new grant is issued with the same
/// `cnf.jkt`, a rotated id, and a fresh expiry.
#[handler]
pub async fn refresh_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RefreshSessionGrantResponse>, ContrixRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // 1. DPoP proof must be present — the refresh endpoint is the
    //    canonical proof-of-possession check.
    let dpop_header = dpop_header_from_request(req)
        .ok_or_else(|| ContrixRouteError::BadRequest("device_proof_required".to_owned()))?;

    let body: RefreshSessionGrantRequest = req
        .parse_json()
        .await
        .map_err(|_| ContrixRouteError::BadRequest("invalid json body".to_owned()))?;

    if body.grant_jwt.trim().is_empty() {
        return Err(ContrixRouteError::BadRequest(
            "missing grant_jwt".to_owned(),
        ));
    }

    // 2. Parse + load the existing grant. We never verify the JWT
    //    signature here — the persisted row IS the source of truth — but
    //    we DO read the `cnf.jkt` claim out of the JWT payload to bind
    //    the proof.
    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| ContrixRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let prior_payload = jwt.payload().clone();
    let expected_jkt = prior_payload
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.clone())
        .ok_or_else(|| {
            ContrixRouteError::BadRequest(
                "grant_jwt is not DPoP-bound (cnf.jkt missing)".to_owned(),
            )
        })?;

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&body.grant_jwt)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| ContrixRouteError::NotFound)?;

    // Single-use enforcement: a previously consumed grant can never be
    // refreshed again.
    if prior_grant.revoked_at.is_some() {
        repo.cancel()
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;
        return Err(ContrixRouteError::BadRequest(
            "refresh_token_already_consumed".to_owned(),
        ));
    }

    // 3. Verify the DPoP proof against this exact endpoint, with the
    //    prior grant_jwt as the bound access token (so `ath` MUST match).
    let verifier = DpopVerifier::shared();
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(Some(&public_base), req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, now, Some(&body.grant_jwt))
        .await
        .map_err(|error| ContrixRouteError::BadRequest(error.to_string()))?;

    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt)
        .map_err(|error| ContrixRouteError::BadRequest(error.to_string()))?;

    // 4. Resolve the underlying browser session so the new grant lives
    //    under the same authentication context.
    let browser_session = repo
        .browser_session()
        .lookup(prior_grant.browser_session_id)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            ContrixRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                "session grant references missing browser session",
            ))
        })?;

    // 5. Mint a new grant with the same subject + scope + audience.
    let audience = body
        .audience
        .clone()
        .unwrap_or_else(|| prior_grant.audience.clone());
    let scopes: Vec<String> = prior_grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let new_material = issue_session_grant_for_audience(
        &mut rng,
        &*clock,
        &url_builder,
        &contrix_config,
        &key_store,
        &browser_session,
        audience,
        scopes,
        Some(&prior_grant.subject),
        Some(verification.jkt.clone()),
    )
    .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    let persisted = persist_session_grant(
        &mut repo,
        &mut rng,
        &*clock,
        &browser_session,
        &new_material,
    )
    .await
    .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    // 6. Single-use semantics: revoke the prior grant only AFTER the new
    //    one is persisted.
    let revoked_prior = repo
        .oauth_session_grant()
        .revoke(&*clock, prior_grant.clone())
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    Ok(Json(RefreshSessionGrantResponse {
        grant_id: persisted.id.to_string(),
        grant_jwt: new_material.grant_jwt,
        session_public_key: new_material.session_public_key,
        session_private_key_pem: new_material.session_private_key_pem,
        expires_at: new_material.expires_at,
        audience: new_material.audience,
        scopes: new_material.scopes,
        dpop_jkt: verification.jkt,
        previous_grant_id: revoked_prior.id.to_string(),
    }))
}

// ── Test-only DPoP-bound grant seeding ──────────────────────────

/// Body for the cotest debug helper. `dpop_jwk` is the device's public
/// JWK (RFC 7517 shape) — we recompute its thumbprint and bake it in as
/// `cnf.jkt` on the issued grant. `actor_did` is the subject DID the
/// caller wants the grant bound to; we trust it because this endpoint
/// is gated behind `debug_assertions` / a `COAUTH_ENABLE_TEST_ENDPOINTS`
/// env var.
#[derive(Debug, Deserialize)]
pub struct DebugIssueDpopGrantRequest {
    pub actor_did: String,
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
        Some("1") | Some("true") | Some("yes")
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
) -> Result<Json<DebugIssueDpopGrantResponse>, ContrixRouteError> {
    use coauth_jose::jwk::{PublicJsonWebKey, Thumbprint};

    if !test_endpoints_enabled() {
        return Err(ContrixRouteError::NotFound);
    }

    let body: DebugIssueDpopGrantRequest = req
        .parse_json()
        .await
        .map_err(|_| ContrixRouteError::BadRequest("invalid json body".to_owned()))?;

    if body.actor_did.trim().is_empty() {
        return Err(ContrixRouteError::BadRequest(
            "missing actor_did".to_owned(),
        ));
    }
    if body.device_id.trim().is_empty() {
        return Err(ContrixRouteError::BadRequest(
            "missing device_id".to_owned(),
        ));
    }

    let public_jwk: PublicJsonWebKey = serde_json::from_value(body.dpop_jwk.clone())
        .map_err(|error| ContrixRouteError::BadRequest(format!("invalid dpop_jwk: {error}")))?;
    let jkt = public_jwk.params().thumbprint_sha256_base64();

    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    let mut repo = depot.repo().await?;

    // We need a browser session for the underlying grant row. Pick the
    // most recent one for the user identified by `actor_did`, or fail
    // closed when none exists. The cotest harness registers the user
    // first, so a session always exists in practice.
    let user_id = parse_local_user_did_for(&url_builder, &contrix_config, &body.actor_did)
        .ok_or_else(|| {
            ContrixRouteError::BadRequest("actor_did is not a local Contrix user DID".to_owned())
        })?;
    let user = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| ContrixRouteError::NotFound)?;

    let user_agent = Some(format!("coauth-test-harness/device:{}", body.device_id));
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &*clock, &user, user_agent)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    let audience = body
        .audience
        .clone()
        .unwrap_or_else(|| required_audience_for(&url_builder, &contrix_config));
    let scopes = body.scopes.clone().unwrap_or_else(|| {
        vec![
            format!("urn:contrix:client:device:{}", body.device_id),
            PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(),
        ]
    });

    let material = issue_session_grant_for_audience(
        &mut rng,
        &*clock,
        &url_builder,
        &contrix_config,
        &key_store,
        &browser_session,
        audience,
        scopes,
        Some(&body.actor_did),
        Some(jkt.clone()),
    )
    .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    let persisted =
        persist_session_grant(&mut repo, &mut rng, &*clock, &browser_session, &material)
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?;

    Ok(Json(DebugIssueDpopGrantResponse {
        grant_id: persisted.id.to_string(),
        grant_jwt: material.grant_jwt,
        dpop_jkt: jkt,
        audience: material.audience,
        scopes: material.scopes,
        expires_at: material.expires_at,
    }))
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
            format!("{}@auth.example.com", user.handle)
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
                oauth_introspection_bearer: None,
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: None,
            }],
            identity_registry: Some(IdentityRegistryConfig {
                kind: IdentityRegistryKind::PublicDidResolver,
                resolver: "https://resolver.example.com/resolve".parse().unwrap(),
                proof_required_for_pairwise: true,
            }),
            starid: None,
            principal_server_url: None,
            high_risk_threshold: 2,
            trust_domain: None,
            oob_code_kind: Default::default(),
            verification_service_did: None,
        };

        let body = serde_json::to_value(service_describe_response(
            &url_builder,
            &contrix_config,
            &[],
        ))
        .unwrap();

        assert_eq!(body["service_did"], "did:web:auth.example.com");
        assert_eq!(body["service_type"], "auth_server");
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
        assert!(supported_profiles.is_empty());
        let supported_reducer_profiles = body["supported_reducer_profiles"].as_array().unwrap();
        assert!(supported_reducer_profiles.contains(&serde_json::json!("cx.reducer.v1")));
        // T6.3 — `cx.schema.v1` was a coauth-only placeholder. The actual
        // schemas this surface emits are `cx.schema.core.v1` (umbrella
        // core schemas, soland / SDK convention) and
        // `cx.schema.service_describe.v1` (this very payload).
        let supported_schema_profiles = body["supported_schema_profiles"].as_array().unwrap();
        assert!(supported_schema_profiles.contains(&serde_json::json!("cx.schema.core.v1")));
        assert!(
            supported_schema_profiles.contains(&serde_json::json!("cx.schema.service_describe.v1"))
        );
        assert!(
            !supported_schema_profiles.contains(&serde_json::json!("cx.schema.v1")),
            "the legacy `cx.schema.v1` placeholder MUST NOT be advertised"
        );
        let not_authoritative_for = body["service_boundary"]["not_authoritative_for"]
            .as_array()
            .unwrap();
        assert!(not_authoritative_for.contains(&serde_json::json!("did_key_log")));
        assert!(not_authoritative_for.contains(&serde_json::json!("identity_registry_receipt")));

        // T6.3 — service_roles must list every role coauth carries.
        // Boundary check: account_registry + auth_server + identity_resolver.
        let service_roles = body["service_roles"]
            .as_array()
            .expect("service_roles array present");
        assert!(service_roles.contains(&serde_json::json!("auth_server")));
        assert!(service_roles.contains(&serde_json::json!("identity_resolver")));
        assert!(service_roles.contains(&serde_json::json!("account_registry")));

        // T6.3 — cx.identity.* operations MUST be declared delegated,
        // not as canonical identity registry surface.
        let compat: Vec<&str> = body["compat_surfaces"]
            .as_array()
            .expect("compat_surfaces array present")
            .iter()
            .filter(|entry| entry["kind"].as_str() == Some("delegated_resolver"))
            .filter_map(|entry| entry["name"].as_str())
            .collect();
        assert!(compat.contains(&"cx.identity.resolve"));
        assert!(compat.contains(&"cx.identity.get_document"));
        assert!(compat.contains(&"cx.identity.describe_registry"));
        // verified_profiles MUST NOT include cx.profile.identity_registry.v1
        // because coauth is a delegated resolver, not a registry.
        let verified = body["verified_profiles"]
            .as_array()
            .expect("verified_profiles array present");
        for entry in verified {
            assert_ne!(
                entry["profile_id"], "cx.profile.identity_registry.v1",
                "coauth MUST NOT advertise canonical identity registry conformance"
            );
        }
    }

    fn config_with_static_session_grant_bearer(bearer: &str) -> ContrixConfig {
        ContrixConfig {
            principal_servers: vec![PrincipalServerConfig {
                name: "soland-dev".to_owned(),
                audience: "did:web:local.host".to_owned(),
                endpoint: "https://local.host/".parse().unwrap(),
                did: Some("did:web:local.host".to_owned()),
                oauth_introspection_bearer: None,
                session_grant_introspection_bearer: Some(bearer.to_owned()),
                embedded_webvh_registration_bearer: None,
            }],
            ..ContrixConfig::default()
        }
    }

    #[test]
    fn principal_server_static_session_grant_bearer_matches_exact_token() {
        let config = config_with_static_session_grant_bearer("local-coauth-session-grant");
        assert!(principal_server_static_session_grant_bearer_matches(
            &config,
            "local-coauth-session-grant"
        ));
    }

    #[test]
    fn principal_server_static_session_grant_bearer_rejects_other_tokens() {
        let config = config_with_static_session_grant_bearer("local-coauth-session-grant");
        assert!(!principal_server_static_session_grant_bearer_matches(
            &config,
            "other-token"
        ));
        assert!(!principal_server_static_session_grant_bearer_matches(
            &config, ""
        ));
        assert!(!principal_server_static_session_grant_bearer_matches(
            &config, "   "
        ));
    }

    #[test]
    fn principal_server_static_session_grant_bearer_ignores_unset_field() {
        let mut config = config_with_static_session_grant_bearer("placeholder");
        config.principal_servers[0].session_grant_introspection_bearer = None;
        assert!(!principal_server_static_session_grant_bearer_matches(
            &config,
            "placeholder"
        ));
    }

    #[test]
    fn describe_separates_claim_levels() {
        // T6.1 — describe response MUST partition into
        // supported_operations (wire-callable) and the new claim-level
        // arrays. coauth has no dev toggle, but the spec invariant
        // (development_mode=true => verified_profiles=[]) is still
        // exercised: when development_mode is reported as `false`, the
        // assertion below ensures we never lazily populate verified
        // entries from self-claimed input.
        let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
        let body = serde_json::to_value(service_describe_response(
            &url_builder,
            &ContrixConfig::default(),
            &[],
        ))
        .unwrap();

        // verified_profiles MUST be present and (with no cotest run wired
        // in) empty.
        let verified = body["verified_profiles"]
            .as_array()
            .expect("verified_profiles array present");
        assert!(
            verified.is_empty(),
            "coauth must not advertise cotest_verified profiles without a verifier"
        );

        // claimed_profiles entries MUST carry claim_kind=self_claimed.
        for entry in body["claimed_profiles"]
            .as_array()
            .expect("claimed_profiles array present")
        {
            assert_eq!(
                entry["claim_kind"], "self_claimed",
                "claimed_profiles entries MUST be self_claimed"
            );
        }

        // implemented_features must be a non-empty subset of "code
        // exists" features.
        let implemented = body["implemented_features"]
            .as_array()
            .expect("implemented_features array present");
        assert!(!implemented.is_empty());

        // experimental_features and verified_profiles MUST NOT
        // intersect.
        let experimental: std::collections::HashSet<&str> = body["experimental_features"]
            .as_array()
            .expect("experimental_features array present")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        let verified_ids: std::collections::HashSet<&str> = verified
            .iter()
            .filter_map(|v| v["profile_id"].as_str())
            .collect();
        assert!(experimental.is_disjoint(&verified_ids));

        // compat_surfaces entries must declare a known kind.
        // T6.3 — `delegated_resolver` was added for coauth's
        // `cx.identity.*` proxy operations (it is NOT a canonical
        // identity registry; the ops are forwarded to an upstream
        // resolver such as starid).
        for surface in body["compat_surfaces"]
            .as_array()
            .expect("compat_surfaces array present")
        {
            let kind = surface["kind"].as_str().expect("compat surface kind");
            assert!(
                matches!(
                    kind,
                    "matrix_passthrough"
                        | "mimi_passthrough"
                        | "legacy_alias"
                        | "external_interop"
                        | "deprecated_alias"
                        | "delegated_resolver"
                ),
                "unknown compat_surface kind {kind}"
            );
        }

        // development_mode field must be present so downstream tools
        // (sodmin / cotest) can render the dev banner.
        assert!(body["development_mode"].is_boolean());
    }

    #[test]
    fn service_describe_emits_trust_domain_when_configured() {
        // Round 4 (spec a77b995) — trust_domain MUST surface on the
        // wire when the deployment sets it. Mirrors the SDK's
        // `Realm.trust_domain` / `ServiceDescribe.trust_domain`
        // requirement so federation peers can bind their canonical
        // transcript.
        let url_builder = UrlBuilder::new(
            "https://auth.example.com/coauth/".parse().unwrap(),
            None,
            None,
        );
        let mut config = ContrixConfig::default();
        config.trust_domain = Some("cx:trust_domain:example.net".to_owned());

        let body =
            serde_json::to_value(service_describe_response(&url_builder, &config, &[])).unwrap();
        assert_eq!(body["trust_domain"], "cx:trust_domain:example.net");
    }

    #[test]
    fn service_describe_omits_trust_domain_when_unset() {
        let url_builder = UrlBuilder::new(
            "https://auth.example.com/coauth/".parse().unwrap(),
            None,
            None,
        );
        let body = serde_json::to_value(service_describe_response(
            &url_builder,
            &ContrixConfig::default(),
            &[],
        ))
        .unwrap();
        assert!(
            body.get("trust_domain").is_none(),
            "trust_domain field MUST be omitted from the wire when unset (deployment fails closed)"
        );
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
            &[],
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
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
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
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
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
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
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
            Some(user.handle.clone())
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
        // Spec 0a5ab85: `alsoKnownAs` carries the canonical
        // `contrix://<host>/users/<localpart>` form; `acct:` aliases live
        // on `handle_claim.handle_aliases[]`, not on the DID document.
        assert_eq!(
            document.also_known_as,
            vec![user_handle_uri(&url_builder, &user)]
        );
        assert!(
            document.also_known_as[0].contains("/users/"),
            "alsoKnownAs MUST use the canonical handle URI form, got {}",
            document.also_known_as[0]
        );
        assert!(
            !document.also_known_as[0].starts_with("acct:"),
            "alsoKnownAs MUST NOT carry an acct: alias as the canonical form"
        );
        assert_eq!(document.service[0].kind, "ContrixAuthServer");
        assert_eq!(
            document.service[0].service_endpoint,
            url_builder
                .absolute_url("/api/v1/server/describe")
                .to_string()
        );
    }

    #[test]
    fn require_canonical_handle_uri_rejects_acct_aliases() {
        let err = require_canonical_handle_uri("acct:alice@example.com").unwrap_err();
        match err {
            ContrixRouteError::BadRequest(message) => {
                assert!(
                    message.starts_with(HANDLE_URI_NOT_CANONICAL_CODE),
                    "expected code prefix, got {message}"
                );
                assert!(
                    message.contains("acct:"),
                    "expected acct: in reason, got {message}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn require_canonical_handle_uri_rejects_bare_handle() {
        require_canonical_handle_uri("alice@example.com")
            .expect_err("bare host strings MUST be rejected as canonical handle URIs");
        require_canonical_handle_uri("contrix://example.com/users/")
            .expect_err("empty localpart MUST be rejected");
        require_canonical_handle_uri("contrix://Example.com/users/alice")
            .expect_err("uppercase host MUST be rejected");
        require_canonical_handle_uri("").expect_err("empty input MUST be rejected");
    }

    #[test]
    fn require_canonical_handle_uri_accepts_canonical_form() {
        let result = require_canonical_handle_uri("contrix://example.com/users/alice").unwrap();
        assert_eq!(result, "contrix://example.com/users/alice");
    }

    #[test]
    fn issue_handle_claim_emits_canonical_uri_and_aliases() {
        use coauth_data::clock::MockClock;
        let url_builder = UrlBuilder::new("https://auth.example.com/".parse().unwrap(), None, None);
        let contrix_config = ContrixConfig::default();
        let mut rng = ChaChaRng::seed_from_u64(0xc15a);
        let clock = MockClock::default();
        let now = clock.now();
        let user = User::samples(now, &mut rng).into_iter().next().unwrap();
        let key_store = test_keystore();

        let hint = HandleClaimDeliveryBindingHint {
            recipient_service_did: "did:web:soland.example".to_owned(),
            recipient_service_type: Some("principal_server".to_owned()),
            binding_source: "organization_policy".to_owned(),
            delivery_modes: vec!["events".to_owned()],
            service_acceptance_ref: None,
            policy_ref: None,
        };

        let material = issue_handle_claim(
            &clock,
            &url_builder,
            &contrix_config,
            &key_store,
            &user,
            "did:web:space.example".to_owned(),
            hint.clone(),
        )
        .expect("handle claim must mint with the test keystore");

        let canonical = user_handle_uri(&url_builder, &user);
        let acct = user_handle_acct_alias(&url_builder, &user);
        assert_eq!(material.payload.handle_uri, canonical);
        assert!(
            material.payload.handle_uri.starts_with("contrix://"),
            "handle_uri MUST be canonical contrix:// form"
        );
        assert!(
            !material.payload.handle_uri.starts_with("acct:"),
            "handle_uri MUST NOT be an acct: alias"
        );
        assert!(
            material.payload.handle_aliases.contains(&acct),
            "handle_aliases MUST carry the acct: interop form"
        );
        assert_eq!(material.payload.audience, "did:web:space.example");
        assert_eq!(
            material.payload.delivery_binding_hint.binding_source,
            hint.binding_source
        );
        assert!(material.payload.claim_digest.starts_with("sha256:"));
        assert_eq!(material.claim_digest, material.payload.claim_digest);
        assert!(material.expires_at > now);
        assert_eq!(material.payload.proofs.len(), 1);
        assert_eq!(material.payload.proofs[0].audience, "did:web:space.example");
        assert_eq!(material.payload.proofs[0].jws, material.claim_jwt);
    }
}
