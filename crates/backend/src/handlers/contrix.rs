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
    jwk::{JsonWebKey, JsonWebKeyPublicParameters, PublicJsonWebKey},
    jwt::{JsonWebSignatureHeader, Jwt, JwtSignatureError},
};
use coauth_keystore::{Keystore, PrivateKey, WrongAlgorithmError};
use der::pem::LineEnding;
use oauth2_types::scope::{Scope, ScopeToken};
use rand_core::{CryptoRngCore, RngCore};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
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
        };

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

#[derive(Debug, Clone, Serialize)]
pub struct DidDocument {
    pub id: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationMethod {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: &'static str,

    pub controller: String,
    pub public_key_jwk: PublicJsonWebKey,
}

#[derive(Debug, Clone, Serialize)]
pub struct DidService {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: &'static str,

    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub issuer: String,
    pub subject: String,
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
}

#[derive(Debug, Serialize)]
struct SupportedBinding {
    binding: &'static str,
    base_url: String,
}

#[derive(Debug, Serialize)]
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
}

#[derive(Debug, Serialize)]
struct ServiceDescribeResponse {
    service_did: String,
    service_type: &'static str,
    protocol_version: &'static str,
    supported_features: Vec<&'static str>,
    supported_bindings: Vec<SupportedBinding>,
    supported_operations: Vec<&'static str>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    principal_servers: Vec<PrincipalServerDescriptor>,
    auth_metadata: AuthMetadata,
    limits: serde_json::Value,
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
            kind: "JsonWebKey2020",
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
                kind: "ContrixAuthServer",
                service_endpoint: url_builder
                    .absolute_url("/api/v1/server/describe")
                    .to_string(),
            },
            DidService {
                id: format!("{did}#openid-configuration"),
                kind: "OpenIdConnectConfiguration",
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
            kind: "ContrixAuthServer",
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
    let audience = required_audience_for(url_builder, contrix_config);
    let payload = SessionGrantPayload {
        kind: "cx.session.grant".to_owned(),
        issuer: issuer.clone(),
        subject: subject.clone(),
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

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let header = JsonWebSignatureHeader::new(alg.clone())
        .with_kid(key.kid().ok_or(SessionGrantError::NoSigningKey)?);
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

fn preferred_public_signing_key(key_store: &Keystore) -> Option<PublicJsonWebKey> {
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
    let principal_servers = contrix_config
        .principal_servers
        .iter()
        .map(|server| PrincipalServerDescriptor {
            name: server.name.clone(),
            audience: server.audience.clone(),
            endpoint: server.endpoint.to_string(),
            did: server.did.clone(),
        })
        .collect();

    Ok(Json(ServiceDescribeResponse {
        service_did: service_did_for(&url_builder, &contrix_config),
        service_type: "auth_server",
        protocol_version: CONTRIX_PROTOCOL_VERSION,
        supported_features: vec![
            "oidc",
            "session_grant",
            "did_resolution",
            "handle_resolution",
            "account_recovery",
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
        principal_servers,
        auth_metadata: AuthMetadata {
            oauth_issuer: url_builder.oidc_issuer().to_string(),
            openid_configuration: url_builder.oidc_discovery().to_string(),
            issuer_did: issuer_did_for(&url_builder, &contrix_config),
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
            did_binding_methods: vec!["session_grant"],
            required_audience: required_audience_for(&url_builder, &contrix_config),
            admin_audience: required_audience_for(&url_builder, &contrix_config),
            session_grant_scope: PRINCIPAL_SERVER_SESSION_BIND_SCOPE,
        },
        limits: serde_json::json!({
            "max_body_bytes": 1_048_576,
            "session_grant_ttl_seconds": SESSION_GRANT_TTL_MINUTES * 60,
        }),
    }))
}

#[handler]
pub async fn identity_describe(
    depot: &Depot,
) -> Result<Json<IdentityDescribeResponse>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let identity_registry =
        contrix_config
            .identity_registry
            .as_ref()
            .map(|registry| IdentityRegistryDescriptor {
                kind: match registry.kind {
                    IdentityRegistryKind::Starid => "starid",
                    IdentityRegistryKind::External => "external",
                },
                resolver: registry.resolver.to_string(),
                proof_required_for_pairwise: registry.proof_required_for_pairwise,
            });

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

    let did_document = if body.did == service_did_for(&url_builder, &contrix_config) {
        service_did_document(&url_builder, &contrix_config, &key_store)
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    } else {
        let mut repo = depot.repo().await?;
        let Some(user_id) = parse_local_user_did_for(&url_builder, &contrix_config, &body.did)
        else {
            return Err(ContrixRouteError::NotFound);
        };
        let Some(user) = repo
            .user()
            .lookup(user_id)
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        else {
            return Err(ContrixRouteError::NotFound);
        };
        user_did_document(&url_builder, &contrix_config, &user)
    };

    Ok(Json(IdentityResolveResponse {
        did_document,
        key_log_head: None,
        seq: None,
        receipts: None,
        method_evidence: None,
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

    let did_document = if did == service_did_for(&url_builder, &contrix_config) {
        service_did_document(&url_builder, &contrix_config, &key_store)
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    } else {
        let mut repo = depot.repo().await?;
        let Some(user_id) = parse_local_user_did_for(&url_builder, &contrix_config, &did) else {
            return Err(ContrixRouteError::NotFound);
        };
        let Some(user) = repo
            .user()
            .lookup(user_id)
            .await
            .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        else {
            return Err(ContrixRouteError::NotFound);
        };
        user_did_document(&url_builder, &contrix_config, &user)
    };

    Ok(Json(IdentityDocumentResponse {
        did_document,
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

    let did = user_did_for(&url_builder, &contrix_config, &user);
    let verified = body
        .expected_did
        .as_deref()
        .is_none_or(|expected| expected == did);

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

    // TODO(contrix-authz): require Principal Server/admin authentication before
    // exposing this beyond trusted deployment boundaries.
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
    let mut repo = depot.repo().await?;
    let grant = repo
        .oauth2_session_grant()
        .lookup(id)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
        .ok_or(ContrixRouteError::NotFound)?;

    // TODO(contrix-authz): require admin/Principal Server authorization and
    // write audit actor/reason before enabling broad revoke access.
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

#[handler]
pub async fn service_did_json(depot: &Depot) -> Result<Json<DidDocument>, ContrixRouteError> {
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;

    service_did_document(&url_builder, &contrix_config, &key_store)
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
    let mut repo = depot.repo().await?;
    let Some(user) = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(|error| ContrixRouteError::Internal(Box::new(error)))?
    else {
        return Err(ContrixRouteError::NotFound);
    };

    Ok(Json(user_did_document(
        &url_builder,
        &contrix_config,
        &user,
    )))
}

#[cfg(test)]
mod tests {
    use coauth_config::ContrixConfig;
    use coauth_data::{Clock, SystemClock, User};
    use coauth_keystore::{JsonWebKeySet, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

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
        assert!(grant.session_private_key_pem.contains("PRIVATE KEY"));
        assert!(payload.session_public_key.contains("\"kid\":\"session-"));
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
