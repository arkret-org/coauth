#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;

use arkret_identifiers::Did;
use async_trait::async_trait;
use coauth_config::ArkretConfig;
use coauth_data::{BoxRepository, RepositoryAccess, UrlBuilder, User};
use coauth_keystore::Keystore;
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::handlers::arkret::{
    DidDocument, SessionGrantError, owning_station_did_for, owning_station_id_for,
};
use crate::outbound_http::RequestBuilderExt as _;

pub type DidResolverServiceHandle = Arc<dyn DidResolverService>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidResolutionSource {
    DidWeb,
    DidPlc,
    DidKey,
    DelegatedResolver,
}

impl DidResolutionSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DidWeb => "did_web",
            Self::DidPlc => "did_plc",
            Self::DidKey => "did_key",
            Self::DelegatedResolver => "delegated_resolver",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DidResolution {
    pub document: DidDocument,
    pub source: DidResolutionSource,
    pub verified_local_binding: bool,
    pub key_log_head: Option<arkret_identifiers::Hash>,
    pub method_evidence: Value,
    /// Closed method-native evidence returned only when explicitly requested.
    pub closed_method_evidence: Option<arkret_models_identity::IdentityMethodEvidence>,
    pub identity_fact_rejection: Option<DidResolutionIdentityFactRejection>,
}

impl DidResolution {
    #[must_use]
    pub const fn identity_fact_rejection(&self) -> Option<DidResolutionIdentityFactRejection> {
        self.identity_fact_rejection
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidResolutionIdentityFactRejection {
    CacheOnlyDegraded,
    DegradedResolverState,
    WebvhCacheTooStale,
    DidWebFallback,
    MissingWebvhHistoryEvidence,
    ControllerProofUnverified,
    WeakResolverEvidence,
}

impl DidResolutionIdentityFactRejection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CacheOnlyDegraded => "cache_only_degraded",
            Self::DegradedResolverState => "degraded_resolver_state",
            Self::WebvhCacheTooStale => "webvh_cache_too_stale",
            Self::DidWebFallback => "did_web_fallback",
            Self::MissingWebvhHistoryEvidence => "missing_webvh_history_evidence",
            Self::ControllerProofUnverified => "controller_proof_unverified",
            Self::WeakResolverEvidence => "weak_resolver_evidence",
        }
    }
}

#[derive(Debug, Error)]
pub enum DidResolveError {
    #[error("DID not found")]
    NotFound,

    #[error("unsupported DID method")]
    UnsupportedMethod,

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("DID document id mismatch: expected {expected}, got {actual}")]
    DocumentIdMismatch { expected: String, actual: String },

    #[error("DID document request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("DID resolver URL error: {0}")]
    Url(#[from] url::ParseError),

    #[error("DID document JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("DID resolver response error: {0}")]
    BadResolverResponse(String),

    #[error("repository error: {0}")]
    Repository(#[from] coauth_data::RepositoryError),

    #[error("local DID document error: {0}")]
    LocalDocument(#[from] SessionGrantError),

    /// SSRF guard: resolver URL is not HTTPS or its host is neither a public
    /// routable hostname nor a configured trusted outbound host (e.g.
    /// `localhost`, private RFC1918 / loopback, link-local, or an IP literal
    /// in a blocked range).
    #[error("DID resolver URL rejected by SSRF policy: {0}")]
    ForbiddenResolverUrl(String),

    /// SSRF guard: DID document body exceeded the maximum allowed size.
    #[error("DID document exceeded maximum size ({limit} bytes)")]
    DocumentTooLarge { limit: usize },

    #[error(
        "did:web principal requires arkret.deployment_profile=personal_node and arkret.principal_method=did:web"
    )]
    DidWebPrincipalNotExplicit,
}

/// Hard upper bound on the size of a fetched DID document. The value is
/// shared with the SDK so all did:web consumers apply the same limit.
pub const DID_DOCUMENT_MAX_BYTES: usize = arkret_models_identity::DID_WEB_MAX_DOCUMENT_BYTES;
const DID_WEBVH_LOG_MAX_BYTES: usize = DID_DOCUMENT_MAX_BYTES * 32;

/// Resolve the last cryptographically verified `did:webvh` service document
/// whose version time is not later than an immutable receipt timestamp.
/// Receipt verification must use the key that controlled the service DID when
/// the receipt was signed, not merely the current post-rotation document.
pub async fn resolve_verified_webvh_service_document_at(
    _http_client: &reqwest::Client,
    egress: &ResolverEgressPolicy,
    did: &arkret_identifiers::Did,
    decided_at: chrono::DateTime<chrono::Utc>,
) -> Result<DidDocument, DidResolveError> {
    if !did.as_str().starts_with("did:webvh:") {
        return Err(DidResolveError::UnsupportedMethod);
    }
    let log_url = Url::parse(
        &arkret_identity::DidWebvhResolver::log_url(did)
            .map_err(|error| DidResolveError::InvalidDid(error.to_string()))?,
    )?;
    let request_client = egress.request_client(&log_url).await?;
    let mut response = request_client.get(log_url.clone()).send_traced().await?;
    if !response.status().is_success() {
        return Err(DidResolveError::BadResolverResponse(format!(
            "historical did:webvh request {log_url} returned {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > DID_WEBVH_LOG_MAX_BYTES as u64)
    {
        return Err(DidResolveError::DocumentTooLarge {
            limit: DID_WEBVH_LOG_MAX_BYTES,
        });
    }
    let mut history = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if history.len().saturating_add(chunk.len()) > DID_WEBVH_LOG_MAX_BYTES {
            return Err(DidResolveError::DocumentTooLarge {
                limit: DID_WEBVH_LOG_MAX_BYTES,
            });
        }
        history.extend_from_slice(&chunk);
    }
    let verified = verify_historical_webvh_service_chain(did, &history)?;
    verified_webvh_document_at(did, &verified, decided_at)
}

fn verify_historical_webvh_service_chain(
    did: &arkret_identifiers::Did,
    history: &[u8],
) -> Result<arkret_identity::VerifiedDidWebvhLog, DidResolveError> {
    // Gate receipts are signed by the Station's service DID. Service
    // documents intentionally publish verification methods, so they require
    // generic WebVH chain verification rather than the human-principal
    // profile, which forbids device and business authority keys.
    arkret_identity::verify_did_webvh_v1_chain_bytes(did, history).map_err(|error| {
        DidResolveError::BadResolverResponse(format!(
            "historical did:webvh service log failed verification: {error}"
        ))
    })
}

fn verified_webvh_document_at(
    did: &arkret_identifiers::Did,
    verified: &arkret_identity::VerifiedDidWebvhLog,
    decided_at: chrono::DateTime<chrono::Utc>,
) -> Result<DidDocument, DidResolveError> {
    let state = verified
        .entries
        .iter()
        .rev()
        .find(|entry| entry.version_time <= decided_at)
        .map(|entry| entry.state.clone())
        .ok_or_else(|| {
            DidResolveError::BadResolverResponse(
                "receipt predates the first verified did:webvh version".to_owned(),
            )
        })?;
    let document: DidDocument = serde_json::from_value(state)?;
    if document.id != did.as_str() {
        return Err(DidResolveError::DocumentIdMismatch {
            expected: did.to_string(),
            actual: document.id,
        });
    }
    Ok(document)
}

#[async_trait]
pub trait DidResolverService: Send + Sync {
    fn service_id(&self, arkret_config: &ArkretConfig) -> arkret_identifiers::DidCoreId;
    fn issuer_did(&self, arkret_config: &ArkretConfig) -> Did;
    /// The resolver egress posture injected at startup. Shared by every fetch
    /// path — including the free-function historical service-document
    /// verifier — so no path falls back to process-wide environment state.
    fn resolver_egress_policy(&self) -> &ResolverEgressPolicy;
    /// Resolve the primary principal DID for a user.
    ///
    /// This returns only a persisted, verified principal binding.
    async fn primary_did_for_user(
        &self,
        repo: &mut BoxRepository,
        arkret_config: &ArkretConfig,
        user: &User,
    ) -> Result<Did, SessionGrantError>;
    fn delegated_resolver(&self, arkret_config: &ArkretConfig) -> Option<String>;
    fn proof_required_for_pairwise(&self, arkret_config: &ArkretConfig) -> bool;

    async fn resolve_did_document(
        &self,
        _http_client: &reqwest::Client,
        _url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        _key_store: &Keystore,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError>;

    /// Resolve a published DID while requiring the closed method-native pins
    /// needed to issue an account-registration control challenge.
    ///
    /// Required, not defaulted. A default body delegating to
    /// `resolve_did_document` would hand back an ordinary resolution — with no
    /// method-native evidence — under the name of binding evidence, and it
    /// would be a second `resolve_did_document` call site outside
    /// `services::did_binding::resolve_and_accept_binding`. Every implementor
    /// states its evidence requirement itself.
    async fn resolve_did_binding_evidence(
        &self,
        http_client: &reqwest::Client,
        url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        key_store: &Keystore,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError>;
}

pub struct DefaultDidResolverService {
    egress: ResolverEgressPolicy,
}

#[async_trait]
impl DidResolverService for DefaultDidResolverService {
    fn service_id(&self, arkret_config: &ArkretConfig) -> arkret_identifiers::DidCoreId {
        owning_station_id_for(arkret_config)
    }

    fn issuer_did(&self, arkret_config: &ArkretConfig) -> Did {
        owning_station_did_for(arkret_config)
    }

    fn resolver_egress_policy(&self) -> &ResolverEgressPolicy {
        &self.egress
    }

    async fn primary_did_for_user(
        &self,
        repo: &mut BoxRepository,
        arkret_config: &ArkretConfig,
        user: &User,
    ) -> Result<Did, SessionGrantError> {
        for server in &arkret_config.stations {
            let Some(audience) = crate::services::station_trust::effective_audience_shared(server)
            else {
                continue;
            };
            if let Some(binding) = repo
                .principal_did()
                .get_for_user_and_audience(user, audience.as_str())
                .await
                .map_err(|error| SessionGrantError::Other(error.into()))?
            {
                return Ok(binding.verified_did);
            }
        }
        Err(SessionGrantError::PrincipalUnknown)
    }

    fn delegated_resolver(&self, arkret_config: &ArkretConfig) -> Option<String> {
        arkret_config
            .identity_registry
            .as_ref()
            .map(|registry| registry.resolver.to_string())
    }

    fn proof_required_for_pairwise(&self, arkret_config: &ArkretConfig) -> bool {
        arkret_config
            .identity_registry
            .as_ref()
            .is_some_and(|registry| registry.proof_required_for_pairwise)
    }

    async fn resolve_did_document(
        &self,
        _http_client: &reqwest::Client,
        _url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        _key_store: &Keystore,
        _repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError> {
        match did_method(did).as_deref() {
            Some("web") => {
                resolve_http_did(
                    did,
                    did_web_document_url(did)?,
                    DidResolutionSource::DidWeb,
                    &self.egress,
                )
                .await
            }
            Some("plc") => {
                resolve_http_did(
                    did,
                    did_plc_document_url(did)?,
                    DidResolutionSource::DidPlc,
                    &self.egress,
                )
                .await
            }
            Some("key") => Ok(local_resolution(
                DidDocument {
                    id: did.to_owned(),
                    also_known_as: Vec::new(),
                    verification_method: Vec::new(),
                    authentication: Vec::new(),
                    assertion_method: Vec::new(),
                    service: Vec::new(),
                    // External `did:key` — coauth does not own its metadata.
                    metadata: None,
                },
                DidResolutionSource::DidKey,
                false,
            )),
            // RULING (2026-07 review, CAU-SPEC-02 closed): coauth deliberately
            // does NOT resolve/verify `did:webvh` natively. identity-did.md
            // §3.5 places webvh hosting and log/history verification authority
            // on the Station (soland); every other method —
            // including `did:webvh` — is delegated to the configured
            // `identity_registry.resolver`, and deployments without one
            // fail closed with `UnsupportedMethod`. Do not add a local webvh
            // history verifier here without a spec-level ruling moving that
            // authority boundary.
            Some(_) => match self.delegated_resolver(arkret_config) {
                Some(resolver) => {
                    let url = delegated_resolver_url(&resolver, &self.egress)?;
                    resolve_delegated_did(did, url, Vec::new(), &self.egress).await
                }
                None => Err(DidResolveError::UnsupportedMethod),
            },
            None => Err(DidResolveError::InvalidDid(did.to_owned())),
        }
    }

    async fn resolve_did_binding_evidence(
        &self,
        _http_client: &reqwest::Client,
        _url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        _key_store: &Keystore,
        _repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError> {
        if !did.starts_with("did:webvh:") {
            return Err(DidResolveError::UnsupportedMethod);
        }
        let resolver = self
            .delegated_resolver(arkret_config)
            .ok_or(DidResolveError::UnsupportedMethod)?;
        resolve_delegated_did(
            did,
            delegated_resolver_url(&resolver, &self.egress)?,
            vec![arkret_models_identity::IdentityMethodEvidenceKind::DidWebvh],
            &self.egress,
        )
        .await
    }
}

#[must_use]
pub fn default_did_resolver_service(arkret_config: &ArkretConfig) -> DidResolverServiceHandle {
    Arc::new(DefaultDidResolverService {
        egress: ResolverEgressPolicy::from_config(arkret_config),
    })
}

fn local_resolution(
    document: DidDocument,
    source: DidResolutionSource,
    verified_local_binding: bool,
) -> DidResolution {
    DidResolution {
        document,
        source,
        verified_local_binding,
        key_log_head: None,
        method_evidence: serde_json::json!({
            "resolver": source.as_str(),
            "verified_local_binding": verified_local_binding,
        }),
        closed_method_evidence: None,
        identity_fact_rejection: None,
    }
}

async fn resolve_http_did(
    did: &str,
    url: Url,
    source: DidResolutionSource,
    egress: &ResolverEgressPolicy,
) -> Result<DidResolution, DidResolveError> {
    // SSRF defence in depth: validate the URL, pre-resolve named hosts before
    // connecting, then pin the request client to that validated address set so
    // DNS cannot rebind between policy check and socket connection.
    let request_client = egress.request_client(&url).await?;

    let response = request_client
        .get(url.clone())
        .send_traced()
        .await?
        .error_for_status()?;

    parse_resolution_http_response(response, did, &url, source).await
}

async fn parse_resolution_http_response(
    response: reqwest::Response,
    did: &str,
    url: &Url,
    source: DidResolutionSource,
) -> Result<DidResolution, DidResolveError> {
    // Reject responses that declare an oversized payload before we ever
    // start streaming bytes. Servers that omit `Content-Length` still
    // get hit by the streaming guard below.
    if let Some(len) = response.content_length()
        && len > DID_DOCUMENT_MAX_BYTES as u64
    {
        return Err(DidResolveError::DocumentTooLarge {
            limit: DID_DOCUMENT_MAX_BYTES,
        });
    }

    // Stream the body so we can enforce the size cap even when the
    // server lies about (or omits) `Content-Length`. We buffer the
    // bytes ourselves instead of `.json::<Value>().await` because the
    // latter offers no easy way to bound input size.
    let mut bytes: Vec<u8> = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > DID_DOCUMENT_MAX_BYTES {
            return Err(DidResolveError::DocumentTooLarge {
                limit: DID_DOCUMENT_MAX_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }

    let body: Value = serde_json::from_slice(&bytes)?;
    let key_log_head = parse_key_log_head(&body)?;
    let (document, method_evidence, closed_method_evidence) =
        parse_resolution_response(did, url, source, body)?;
    if document.id != did {
        return Err(DidResolveError::DocumentIdMismatch {
            expected: did.to_owned(),
            actual: document.id,
        });
    }

    let identity_fact_rejection = identity_fact_rejection_for(did, &method_evidence);
    Ok(DidResolution {
        document,
        source,
        verified_local_binding: false,
        key_log_head,
        method_evidence,
        closed_method_evidence,
        identity_fact_rejection,
    })
}

fn parse_key_log_head(body: &Value) -> Result<Option<arkret_identifiers::Hash>, DidResolveError> {
    match body.get("key_log_head") {
        Some(Value::String(value)) => Ok(Some(
            arkret_identifiers::Hash::new(value.clone()).map_err(|error| {
                DidResolveError::BadResolverResponse(format!("invalid key_log_head: {error}"))
            })?,
        )),
        Some(_) => Err(DidResolveError::BadResolverResponse(
            "key_log_head must be a string".to_owned(),
        )),
        None => Ok(None),
    }
}

async fn resolve_delegated_did(
    did: &str,
    url: Url,
    requested_evidence_kinds: Vec<arkret_models_identity::IdentityMethodEvidenceKind>,
    egress: &ResolverEgressPolicy,
) -> Result<DidResolution, DidResolveError> {
    let request_client = egress.request_client(&url).await?;
    let response =
        delegated_resolver_request(&request_client, &url, did, requested_evidence_kinds)?
            .send_traced()
            .await?
            .error_for_status()?;
    parse_resolution_http_response(response, did, &url, DidResolutionSource::DelegatedResolver)
        .await
}

fn delegated_resolver_request(
    http_client: &reqwest::Client,
    url: &Url,
    did: &str,
    requested_evidence_kinds: Vec<arkret_models_identity::IdentityMethodEvidenceKind>,
) -> Result<reqwest::RequestBuilder, DidResolveError> {
    let typed_did = arkret_identifiers::Did::new(did.to_owned())
        .map_err(|error| DidResolveError::InvalidDid(error.to_string()))?;
    let body = arkret_models_identity::IdentityResolveRequestBody {
        did: typed_did,
        requested_evidence_kinds,
    };
    let body_bytes = arkret_canonical::canonical_json_bytes(&body).map_err(|error| {
        DidResolveError::BadResolverResponse(format!(
            "DID resolution request is not canonically serializable: {error}"
        ))
    })?;
    Ok(http_client
        .post(url.clone())
        .header(
            "arkret-operation",
            arkret_wire::ServiceOperationId::ROOT_IDENTITY_READ_RESOLVE_V1,
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body_bytes))
}

fn parse_resolution_response(
    did: &str,
    url: &Url,
    source: DidResolutionSource,
    body: Value,
) -> Result<
    (
        DidDocument,
        Value,
        Option<arkret_models_identity::IdentityMethodEvidence>,
    ),
    DidResolveError,
> {
    if let Ok(outcome) =
        serde_json::from_value::<arkret_models_identity::IdentityResolveOutcome>(body.clone())
    {
        let document =
            serde_json::from_value::<DidDocument>(serde_json::to_value(&outcome.did_document)?)?;
        let method_evidence = outcome
            .method_evidence
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or_else(|| default_method_evidence(source, url));
        return Ok((document, method_evidence, outcome.method_evidence));
    }
    if let Some(ref_value) = body.get("did_document") {
        if let Some(ref_did) = ref_value.get("did").and_then(Value::as_str)
            && ref_did != did
        {
            return Err(DidResolveError::DocumentIdMismatch {
                expected: did.to_owned(),
                actual: ref_did.to_owned(),
            });
        }
        let document_value = ref_value.get("document").cloned().ok_or_else(|| {
            DidResolveError::BadResolverResponse("did_document.document missing".to_owned())
        })?;
        let document = serde_json::from_value::<DidDocument>(document_value)?;
        let method_evidence = body
            .get("method_evidence")
            .cloned()
            .unwrap_or_else(|| default_method_evidence(source, url));
        return Ok((document, method_evidence, None));
    }

    let document_value = body
        .get("didDocument")
        .cloned()
        .unwrap_or_else(|| body.clone());
    let document = serde_json::from_value::<DidDocument>(document_value)?;
    let method_evidence = body
        .get("method_evidence")
        .cloned()
        .unwrap_or_else(|| default_method_evidence(source, url));
    Ok((document, method_evidence, None))
}

fn default_method_evidence(source: DidResolutionSource, url: &Url) -> Value {
    serde_json::json!({
        "resolver": source.as_str(),
        "document_url": url,
    })
}

fn identity_fact_rejection_for(
    did: &str,
    method_evidence: &Value,
) -> Option<DidResolutionIdentityFactRejection> {
    if contains_key(method_evidence, "fallback_to_did_web") {
        return Some(DidResolutionIdentityFactRejection::DidWebFallback);
    }
    if bool_at(method_evidence, &["degraded"]) == Some(true)
        || bool_at(method_evidence, &["webvh_unreachable"]) == Some(true)
        || bool_at(method_evidence, &["cache_only_degraded"]) == Some(true)
        || bool_at(method_evidence, &["single_witness_cache_degraded"]) == Some(true)
    {
        return Some(DidResolutionIdentityFactRejection::CacheOnlyDegraded);
    }
    if bool_at(method_evidence, &["webvh_cache_too_stale"]) == Some(true) {
        return Some(DidResolutionIdentityFactRejection::WebvhCacheTooStale);
    }
    if bool_at(method_evidence, &["controller_proof_verified"]) == Some(false)
        || bool_at(method_evidence, &["controller_proof", "verified"]) == Some(false)
    {
        return Some(DidResolutionIdentityFactRejection::ControllerProofUnverified);
    }
    if did.starts_with("did:webvh:") {
        if string_is_one_of(method_evidence, &["method"], &["did:web", "web", "did_web"]) {
            return Some(DidResolutionIdentityFactRejection::DidWebFallback);
        }
        if string_is_one_of(method_evidence, &["history_evidence_kind"], &["none"]) {
            return Some(DidResolutionIdentityFactRejection::MissingWebvhHistoryEvidence);
        }
    }
    if string_contains_any(
        method_evidence,
        &["resolver_state"],
        &[
            "degraded",
            "stale_history",
            "write_unavailable",
            "untrusted",
        ],
    ) || string_contains_any(
        method_evidence,
        &["health", "state"],
        &[
            "degraded",
            "stale_history",
            "write_unavailable",
            "untrusted",
        ],
    ) {
        return Some(DidResolutionIdentityFactRejection::DegradedResolverState);
    }
    if string_contains_any(
        method_evidence,
        &["outage_mode"],
        &["cache_only", "low_risk_read"],
    ) || string_contains_any(
        method_evidence,
        &["trust_profile"],
        &["limited", "weak", "read_only"],
    ) || string_contains_any(
        method_evidence,
        &["resolver_assurance"],
        &["limited", "weak", "read_only", "degraded"],
    ) {
        return Some(DidResolutionIdentityFactRejection::WeakResolverEvidence);
    }
    if let Some(age) = number_at(method_evidence, &["cached_evidence_age_ms"])
        && age > 7 * 24 * 60 * 60 * 1000
    {
        return Some(DidResolutionIdentityFactRejection::WebvhCacheTooStale);
    }

    None
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path).and_then(Value::as_bool)
}

fn number_at(value: &Value, path: &[&str]) -> Option<u64> {
    value_at(value, path).and_then(Value::as_u64)
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path).and_then(Value::as_str)
}

fn string_is_one_of(value: &Value, path: &[&str], needles: &[&str]) -> bool {
    string_at(value, path).is_some_and(|text| {
        let text = text.to_ascii_lowercase();
        needles.iter().any(|needle| text == *needle)
    })
}

fn string_contains_any(value: &Value, path: &[&str], needles: &[&str]) -> bool {
    string_at(value, path).is_some_and(|text| {
        let text = text.to_ascii_lowercase();
        needles.iter().any(|needle| text.contains(needle))
    })
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(candidate, child)| candidate == key || contains_key(child, key)),
        Value::Array(items) => items.iter().any(|child| contains_key(child, key)),
        _ => false,
    }
}

/// Outbound egress posture for every DID-resolution fetch.
///
/// Constructed once from the startup [`ArkretConfig`] and injected into the
/// resolver service, so every fetch path — direct `did:web` / `did:plc`,
/// the delegated resolver, and historical service-document reads — shares one
/// guard instead of re-reading process-wide environment state per request.
///
/// Rules:
/// - Scheme MUST be `https`. The DID method document URLs are always HTTPS, and the requirement
///   holds even for configured trusted-loopback hosts.
/// - The baseline is always `EgressGuard::public_https()`: hosts must resolve to globally routable
///   addresses only. Named hosts are resolved immediately before the request and rejected if any
///   returned address is non-public; the request is then dispatched through a client pinned to that
///   validated address set, closing the DNS rebinding window.
/// - The single widening is [`ArkretConfig::trusted_outbound_hosts`] — exact operator-owned host
///   names (configured station endpoints, identity services, and the delegated resolver) that may
///   resolve *wholly* to loopback. IP literals, `localhost`, `.local` / `.internal` names, private
///   addresses, and mixed public+loopback answers stay rejected.
#[derive(Clone, Debug)]
pub struct ResolverEgressPolicy {
    guard: arkret_egress_reqwest::EgressGuard,
}

impl ResolverEgressPolicy {
    /// Build the resolver posture from the startup configuration snapshot.
    #[must_use]
    pub fn from_config(config: &ArkretConfig) -> Self {
        Self {
            guard: arkret_egress_reqwest::EgressGuard::public_https()
                .with_trusted_loopback_https_hosts(config.trusted_outbound_hosts()),
        }
    }

    /// Judge a resolver target before any lookup. HTTPS stays mandatory even
    /// for configured trusted-loopback hosts.
    fn enforce_url_policy(&self, url: &Url) -> Result<(), DidResolveError> {
        if url.scheme() != "https" {
            return Err(DidResolveError::ForbiddenResolverUrl(format!(
                "scheme must be https, got {}",
                url.scheme()
            )));
        }
        self.guard
            .validate_url(url, "DID resolver")
            .map_err(|error| DidResolveError::ForbiddenResolverUrl(error.to_string()))
    }

    /// Validate, pre-resolve, and address-pin a request client for `url` so
    /// DNS cannot rebind between the policy check and the connection.
    async fn request_client(&self, url: &Url) -> Result<reqwest::Client, DidResolveError> {
        self.enforce_url_policy(url)?;
        let locked = self
            .guard
            .lock_url_async(url, "DID resolver")
            .await
            .map_err(|error| DidResolveError::ForbiddenResolverUrl(error.to_string()))?;
        Ok(crate::outbound_http::reqwest_client_for_locked_egress(
            &locked,
        ))
    }
}

fn delegated_resolver_url(
    resolver: &str,
    egress: &ResolverEgressPolicy,
) -> Result<Url, DidResolveError> {
    let url = Url::parse(resolver)?;
    // Reject the operator-supplied endpoint before the request is built.
    egress.enforce_url_policy(&url)?;
    Ok(url)
}

fn did_method(did: &str) -> Option<String> {
    // Round 4 (spec a77b995) — delegate DID acceptance to the SDK's
    // tightened regex `^did:[a-z0-9]+:[^\s]+$`. The method-name segment
    // MUST be lowercase ASCII alpha + digits only (no `.`/`-`/`_`/`:`);
    // any value the SDK validator rejects is wire-broken and MUST NOT
    // be routed by this resolver.
    Some(
        arkret_identifiers::Did::new(did.to_owned())
            .ok()?
            .method()
            .to_owned(),
    )
}

fn did_web_document_url(did: &str) -> Result<Url, DidResolveError> {
    let did = arkret_identifiers::Did::new(did.to_owned())
        .map_err(|_| DidResolveError::InvalidDid(did.to_owned()))?;
    let url = arkret_models_identity::did_web_document_url(&did)
        .map_err(|_| DidResolveError::InvalidDid(did.to_string()))?;
    Ok(Url::parse(&url)?)
}

fn did_plc_document_url(did: &str) -> Result<Url, DidResolveError> {
    let method_id = did
        .strip_prefix("did:plc:")
        .ok_or_else(|| DidResolveError::InvalidDid(did.to_owned()))?;
    if method_id.is_empty() || method_id.contains(':') {
        return Err(DidResolveError::InvalidDid(did.to_owned()));
    }
    Ok(Url::parse(&format!("https://plc.directory/{did}"))?)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};
    use rand_chacha_10::ChaCha20Rng;
    use rand_core_10::SeedableRng as _;

    use super::*;

    fn addr(value: &str) -> SocketAddr {
        value.parse().expect("test socket address must parse")
    }

    fn default_policy() -> ResolverEgressPolicy {
        ResolverEgressPolicy::from_config(&ArkretConfig::default())
    }

    #[test]
    fn resolver_url_policy_rejects_internal_names_and_ip_literals() {
        let policy = default_policy();
        for raw in [
            "http://example.com/.well-known/did.json",
            "https://localhost/.well-known/did.json",
            "https://auth.internal/.well-known/did.json",
            "https://metadata.google.internal/.well-known/did.json",
            "https://127.0.0.1/.well-known/did.json",
            "https://10.0.0.1/.well-known/did.json",
            "https://[::1]/.well-known/did.json",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                matches!(
                    policy.enforce_url_policy(&url),
                    Err(DidResolveError::ForbiddenResolverUrl(_))
                ),
                "{raw} should be rejected"
            );
        }
    }

    #[test]
    fn shared_resolver_guard_rejects_private_and_rebinding_targets() {
        let url = Url::parse("https://resolver.example/resolve").unwrap();
        for addrs in [
            vec![addr("10.0.0.1:443")],
            vec![addr("169.254.169.254:443")],
            vec![addr("100.64.0.1:443")],
            vec![addr("[fc00::1]:443")],
            vec![addr("8.8.8.8:443"), addr("192.168.1.10:443")],
        ] {
            assert!(
                default_policy()
                    .guard
                    .lock_url_with(&url, "DID resolver test", |_host, _port| Ok(addrs))
                    .is_err()
            );
        }
    }

    #[test]
    fn shared_resolver_guard_accepts_public_addresses() {
        let url = Url::parse("https://resolver.example/resolve").unwrap();
        default_policy()
            .guard
            .lock_url_with(&url, "DID resolver test", |_host, _port| {
                Ok(vec![
                    addr("8.8.8.8:443"),
                    addr("[2001:4860:4860::8888]:443"),
                ])
            })
            .expect("public resolver addresses should be accepted");
    }

    #[test]
    fn configured_trusted_hosts_are_the_only_loopback_widening() {
        let config = ArkretConfig {
            stations: vec![coauth_config::StationConfig {
                name: "soland-alpha".to_owned(),
                endpoint: "https://soland-alpha.local.host/".parse().unwrap(),
                service_id: None,
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: None,
            }],
            ..ArkretConfig::default()
        };
        let policy = ResolverEgressPolicy::from_config(&config);
        let trusted =
            Url::parse("https://soland-alpha.local.host/webvh/service/did.jsonl").unwrap();

        policy
            .enforce_url_policy(&trusted)
            .expect("a configured trusted host passes the URL policy");
        policy
            .guard
            .lock_url_with(&trusted, "DID resolver test", |_host, _port| {
                Ok(vec![addr("127.0.0.1:443")])
            })
            .expect("a configured trusted host may resolve wholly to loopback");

        assert!(
            policy
                .enforce_url_policy(&Url::parse("http://soland-alpha.local.host/resolve").unwrap())
                .is_err(),
            "HTTPS stays mandatory even for configured trusted hosts"
        );
        assert!(
            policy
                .guard
                .lock_url_with(&trusted, "DID resolver test", |_host, _port| {
                    Ok(vec![addr("8.8.8.8:443"), addr("127.0.0.1:443")])
                })
                .is_err(),
            "mixed public+loopback answers stay rejected"
        );
        let unregistered = Url::parse("https://soland-beta.local.host/resolve").unwrap();
        assert!(
            policy
                .guard
                .lock_url_with(&unregistered, "DID resolver test", |_host, _port| {
                    Ok(vec![addr("127.0.0.1:443")])
                })
                .is_err(),
            "an unregistered loopback-resolving host stays rejected"
        );
        assert!(
            policy
                .enforce_url_policy(&Url::parse("https://127.0.0.1/resolve").unwrap())
                .is_err(),
            "IP literals are never widened"
        );
    }

    #[test]
    fn sdk_identity_resolve_response_preserves_method_evidence() {
        let did = "did:webvh:ztest:resolver.example:users:alice";
        let url = Url::parse("https://resolver.example/_arkret/root/identity/resolve").unwrap();
        let body = serde_json::json!({
            "did_document": {
                "did": did,
                "document": {
                    "id": did,
                    "verificationMethod": []
                }
            },
            "method_evidence": {
                "method": "did:webvh",
                "resolver_state": "webvh_cache_only_degraded",
                "cached_evidence_age_ms": 1200
            }
        });

        let (document, evidence, closed_evidence) =
            parse_resolution_response(did, &url, DidResolutionSource::DelegatedResolver, body)
                .expect("SDK response should parse");

        assert_eq!(document.id, did);
        assert!(closed_evidence.is_none());
        assert_eq!(
            evidence["resolver_state"],
            serde_json::json!("webvh_cache_only_degraded")
        );
        assert_eq!(
            identity_fact_rejection_for(did, &evidence),
            Some(DidResolutionIdentityFactRejection::DegradedResolverState)
        );
    }

    #[test]
    fn delegated_resolver_uses_canonical_post_body() {
        let did = "did:webvh:ztest:resolver.example:users:alice";
        let url = delegated_resolver_url(
            "https://resolver.example/_arkret/root/identity/resolve",
            &default_policy(),
        )
        .expect("resolver URL should parse");
        let request = delegated_resolver_request(&reqwest::Client::new(), &url, did, Vec::new())
            .expect("request should build")
            .build()
            .expect("request should be valid");

        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url(), &url);
        assert_eq!(
            request
                .headers()
                .get("arkret-operation")
                .and_then(|value| value.to_str().ok()),
            Some(arkret_wire::ServiceOperationId::ROOT_IDENTITY_READ_RESOLVE_V1)
        );
        let body: Value = serde_json::from_slice(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .expect("JSON request body should be buffered"),
        )
        .expect("request body should be JSON");
        assert_eq!(body, serde_json::json!({"did": did}));
    }

    #[test]
    fn degraded_and_weak_webvh_evidence_is_not_an_authority_grade_did_fact() {
        let did = "did:webvh:ztest:resolver.example:users:alice";
        for (evidence, expected) in [
            (
                serde_json::json!({"degraded": true}),
                DidResolutionIdentityFactRejection::CacheOnlyDegraded,
            ),
            (
                serde_json::json!({"fallback_to_did_web": true}),
                DidResolutionIdentityFactRejection::DidWebFallback,
            ),
            (
                serde_json::json!({"method": "did:web", "history_evidence_kind": "none"}),
                DidResolutionIdentityFactRejection::DidWebFallback,
            ),
            (
                serde_json::json!({"method": "did:webvh", "history_evidence_kind": "none"}),
                DidResolutionIdentityFactRejection::MissingWebvhHistoryEvidence,
            ),
            (
                serde_json::json!({"controller_proof": {"verified": false}}),
                DidResolutionIdentityFactRejection::ControllerProofUnverified,
            ),
            (
                serde_json::json!({"cached_evidence_age_ms": 7 * 24 * 60 * 60 * 1000_u64 + 1}),
                DidResolutionIdentityFactRejection::WebvhCacheTooStale,
            ),
            (
                serde_json::json!({"resolver_assurance": "read_only_cache"}),
                DidResolutionIdentityFactRejection::WeakResolverEvidence,
            ),
        ] {
            assert_eq!(identity_fact_rejection_for(did, &evidence), Some(expected));
        }
    }

    #[test]
    fn healthy_webvh_evidence_can_back_identity_facts() {
        let did = "did:webvh:ztest:resolver.example:users:alice";
        let evidence = serde_json::json!({
            "method": "did:webvh",
            "history_evidence_kind": "webvh_key_log",
            "controller_proof_verified": true,
            "cached_evidence_age_ms": 60_000
        });

        assert_eq!(identity_fact_rejection_for(did, &evidence), None);
    }

    #[test]
    fn resolver_history_head_is_typed_and_invalid_values_fail_closed() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let parsed = parse_key_log_head(&serde_json::json!({"key_log_head": digest}))
            .expect("canonical history head should parse")
            .expect("history head should be present");
        assert_eq!(parsed.to_string(), format!("sha256:{}", "a".repeat(64)));

        for body in [
            serde_json::json!({"key_log_head": ""}),
            serde_json::json!({"key_log_head": 1}),
        ] {
            assert!(matches!(
                parse_key_log_head(&body),
                Err(DidResolveError::BadResolverResponse(_))
            ));
        }
    }

    #[test]
    fn verified_webvh_history_resolves_the_key_document_as_of_receipt_time() {
        let did =
            arkret_identifiers::Did::new("did:webvh:z6mkfixture:principal.example".to_owned())
                .unwrap();
        let old_time = Utc.with_ymd_and_hms(2026, 8, 8, 10, 0, 0).unwrap();
        let rotated_time = Utc.with_ymd_and_hms(2026, 8, 8, 11, 0, 0).unwrap();
        let document = |key: &str| {
            serde_json::json!({
                "id": did,
                "verificationMethod": [{
                    "id": format!("{}#{key}", did),
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": {"kty":"OKP","crv":"Ed25519","x":"11qYAYdk9JtJ7w"}
                }],
                "assertionMethod": [format!("{}#{key}", did)]
            })
        };
        let verified = arkret_identity::VerifiedDidWebvhLog {
            raw_entries: Vec::new(),
            entries: vec![
                arkret_identity::DidWebvhLogEntry {
                    version_id: "1-old".to_owned(),
                    version_time: old_time,
                    parameters: serde_json::json!({}),
                    state: document("old"),
                    proof: Vec::new(),
                },
                arkret_identity::DidWebvhLogEntry {
                    version_id: "2-new".to_owned(),
                    version_time: rotated_time,
                    parameters: serde_json::json!({}),
                    state: document("new"),
                    proof: Vec::new(),
                },
            ],
            head_version_id: "2-new".to_owned(),
            head_state: document("new"),
            active_update_keys: Vec::new(),
        };

        let old =
            verified_webvh_document_at(&did, &verified, old_time + chrono::Duration::minutes(30))
                .unwrap();
        assert_eq!(old.assertion_method, vec![format!("{did}#old")]);
        let current = verified_webvh_document_at(&did, &verified, rotated_time).unwrap();
        assert_eq!(current.assertion_method, vec![format!("{did}#new")]);
        assert!(
            verified_webvh_document_at(
                &did,
                &verified,
                old_time - chrono::Duration::milliseconds(1)
            )
            .is_err()
        );
    }

    #[test]
    fn historical_service_history_accepts_service_authority_keys() {
        let endpoint = Url::parse("https://principal.example/").unwrap();
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let prepared = arkret_signatures::webvh::prepare_service_inception(
            &mut rng,
            &arkret_signatures::webvh::ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "service",
                also_known_as: &[],
                version_time: Utc.with_ymd_and_hms(2026, 8, 18, 0, 0, 0).unwrap(),
                did_key_fragment: Some("account-authority"),
            },
        )
        .unwrap();
        let did = arkret_identifiers::Did::new(prepared.did.clone()).unwrap();
        let history = serde_json::to_vec(&prepared.log_entry).unwrap();

        assert!(
            arkret_identity::verify_did_webvh_v1_log_bytes(&did, &history).is_err(),
            "the human-principal profile must reject service authority keys"
        );
        let verified = verify_historical_webvh_service_chain(&did, &history).unwrap();
        let document = verified_webvh_document_at(
            &did,
            &verified,
            Utc.with_ymd_and_hms(2026, 8, 18, 0, 0, 1).unwrap(),
        )
        .unwrap();

        assert_eq!(document.id, did.as_str());
        assert!(
            document
                .verification_method
                .iter()
                .any(|method| { method.id == format!("{}#account-authority", did.as_str()) })
        );
        assert!(
            document
                .assertion_method
                .contains(&format!("{}#account-authority", did.as_str()))
        );
    }
}
