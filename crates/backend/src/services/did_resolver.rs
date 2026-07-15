use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use coauth_config::ArkretConfig;
use coauth_data::{BoxRepository, RepositoryAccess, UrlBuilder, User};
use coauth_keystore::Keystore;
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::handlers::arkret::{DidDocument, SessionGrantError, issuer_did_for, service_id_for};
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
    pub key_log_head: Option<arkret_core::Hash>,
    pub method_evidence: Value,
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

    /// SSRF guard: resolver URL is not HTTPS or its host is not a public
    /// routable hostname (e.g. `localhost`, private RFC1918 / loopback,
    /// link-local, or an IP literal in a blocked range).
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

/// Hard upper bound on the size of a fetched DID document. Anything
/// larger is treated as hostile (the caller may be trying to exhaust
/// memory via a slowloris-style response). 10 MiB is a deliberately
/// generous ceiling for any legitimate DID document.
pub const DID_DOCUMENT_MAX_BYTES: usize = 10 * 1024 * 1024;

#[async_trait]
pub trait DidResolverService: Send + Sync {
    fn service_id(&self, arkret_config: &ArkretConfig) -> String;
    fn issuer_did(&self, arkret_config: &ArkretConfig) -> String;
    /// Resolve the primary principal DID for a user.
    ///
    /// This returns only a persisted, verified principal binding.
    async fn primary_did_for_user(
        &self,
        repo: &mut BoxRepository,
        arkret_config: &ArkretConfig,
        user: &User,
    ) -> Result<String, SessionGrantError>;
    fn delegated_resolver(&self, arkret_config: &ArkretConfig) -> Option<String>;
    fn proof_required_for_pairwise(&self, arkret_config: &ArkretConfig) -> bool;

    async fn resolve_did_document(
        &self,
        http_client: &reqwest::Client,
        _url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        _key_store: &Keystore,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError>;
}

#[derive(Default)]
pub struct DefaultDidResolverService;

#[async_trait]
impl DidResolverService for DefaultDidResolverService {
    fn service_id(&self, arkret_config: &ArkretConfig) -> String {
        service_id_for(arkret_config).to_string()
    }

    fn issuer_did(&self, arkret_config: &ArkretConfig) -> String {
        issuer_did_for(arkret_config).to_string()
    }

    async fn primary_did_for_user(
        &self,
        repo: &mut BoxRepository,
        arkret_config: &ArkretConfig,
        user: &User,
    ) -> Result<String, SessionGrantError> {
        for server in &arkret_config.principal_servers {
            let Some(audience) =
                crate::services::resolved_principal_audiences::effective_audience_shared(server)
            else {
                continue;
            };
            if let Some(binding) = repo
                .principal_did()
                .get_for_user_and_audience(user, audience.as_str())
                .await
                .map_err(|error| SessionGrantError::Other(error.into()))?
            {
                return Ok(binding.principal_id);
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
        http_client: &reqwest::Client,
        _url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        _key_store: &Keystore,
        _repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError> {
        match did_method(did).as_deref() {
            Some("web") => {
                resolve_http_did(
                    http_client,
                    did,
                    did_web_document_url(did)?,
                    DidResolutionSource::DidWeb,
                )
                .await
            }
            Some("plc") => {
                resolve_http_did(
                    http_client,
                    did,
                    did_plc_document_url(did)?,
                    DidResolutionSource::DidPlc,
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
                    capability_delegation: Vec::new(),
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
            // on the principal server (soland / starid); every other method —
            // including `did:webvh` — is delegated to the configured
            // `identity_registry.resolver`, and deployments without one
            // fail closed with `UnsupportedMethod`. Do not add a local webvh
            // history verifier here without a spec-level ruling moving that
            // authority boundary.
            Some(_) => match self.delegated_resolver(arkret_config) {
                Some(resolver) => {
                    let url = delegated_resolver_url(&resolver)?;
                    resolve_delegated_did(http_client, did, url).await
                }
                None => Err(DidResolveError::UnsupportedMethod),
            },
            None => Err(DidResolveError::InvalidDid(did.to_owned())),
        }
    }
}

#[must_use]
pub fn default_did_resolver_service() -> DidResolverServiceHandle {
    Arc::new(DefaultDidResolverService)
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
        identity_fact_rejection: None,
    }
}

async fn resolve_http_did(
    http_client: &reqwest::Client,
    did: &str,
    url: Url,
    source: DidResolutionSource,
) -> Result<DidResolution, DidResolveError> {
    // SSRF defence in depth: validate the URL, pre-resolve named hosts before
    // connecting, then pin the request client to that validated address set so
    // DNS cannot rebind between policy check and socket connection.
    enforce_resolver_url_policy(&url)?;
    let pinned_resolution = enforce_resolver_dns_policy(&url).await?;
    let pinned_http_client;
    let request_client = if let Some((host, addrs)) = pinned_resolution.as_ref() {
        pinned_http_client =
            crate::outbound_http::reqwest_client_with_static_resolution(host, addrs);
        &pinned_http_client
    } else {
        http_client
    };

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
    let (document, method_evidence) = parse_resolution_response(did, url, source, body)?;
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
        identity_fact_rejection,
    })
}

fn parse_key_log_head(body: &Value) -> Result<Option<arkret_core::Hash>, DidResolveError> {
    match body.get("key_log_head") {
        Some(Value::String(value)) => Ok(Some(arkret_core::Hash::new(value.clone()).map_err(
            |error| DidResolveError::BadResolverResponse(format!("invalid key_log_head: {error}")),
        )?)),
        Some(_) => Err(DidResolveError::BadResolverResponse(
            "key_log_head must be a string".to_owned(),
        )),
        None => Ok(None),
    }
}

async fn resolve_delegated_did(
    http_client: &reqwest::Client,
    did: &str,
    url: Url,
) -> Result<DidResolution, DidResolveError> {
    enforce_resolver_url_policy(&url)?;
    let pinned_resolution = enforce_resolver_dns_policy(&url).await?;
    let pinned_http_client;
    let request_client = if let Some((host, addrs)) = pinned_resolution.as_ref() {
        pinned_http_client =
            crate::outbound_http::reqwest_client_with_static_resolution(host, addrs);
        &pinned_http_client
    } else {
        http_client
    };
    let response = delegated_resolver_request(request_client, &url, did)?
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
) -> Result<reqwest::RequestBuilder, DidResolveError> {
    let typed_did = arkret_core::Did::new(did.to_owned())
        .map_err(|error| DidResolveError::InvalidDid(error.to_string()))?;
    let body = arkret_core::IdentityResolveRequestBody {
        did: typed_did,
        requested_evidence_kinds: Vec::new(),
    };
    Ok(http_client.post(url.clone()).json(&body))
}

fn parse_resolution_response(
    did: &str,
    url: &Url,
    source: DidResolutionSource,
    body: Value,
) -> Result<(DidDocument, Value), DidResolveError> {
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
        return Ok((document, method_evidence));
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
    Ok((document, method_evidence))
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

/// SSRF policy for outbound DID-document fetches.
///
/// Rules:
/// - Scheme MUST be `https` (the DID method document URLs for `did:web` and `did:plc` are always
///   HTTPS; the delegated resolver URL is operator-supplied and must opt into HTTPS too).
/// - Host MUST be present and MUST NOT be a loopback / link-local / private / unspecified address.
///   IP literals in those ranges are blocked outright; named hosts are resolved immediately before
///   the request and rejected if any returned address is non-public. The request is then dispatched
///   through a static-resolution outbound client pinned to that validated address set, closing the
///   DNS rebinding window.
///
/// Loopback is allowed when the `COAUTH_DID_RESOLVER_ALLOW_LOOPBACK`
/// env var is set (the integration test harness uses this).
fn enforce_resolver_url_policy(url: &Url) -> Result<(), DidResolveError> {
    if url.scheme() != "https" {
        return Err(DidResolveError::ForbiddenResolverUrl(format!(
            "scheme must be https, got {}",
            url.scheme()
        )));
    }
    let allow_loopback =
        coauth_config::runtime_var_os("COAUTH_DID_RESOLVER_ALLOW_LOOPBACK").is_some();
    let Some(host) = url.host() else {
        return Err(DidResolveError::ForbiddenResolverUrl(
            "missing host".to_owned(),
        ));
    };
    match host {
        url::Host::Domain(name) => {
            // Reject obvious internal names. Full DNS-time resolution
            // checks would require a custom resolver; this catches the
            // common case where a config typo (or a malicious admin
            // mutation) lets a `did:web` document URL point at
            // localhost.
            let lower = name.to_ascii_lowercase();
            // `ends_with(".local")` is ASCII-only by construction (we just
            // lowercased the host above); the clippy lint that nudges toward
            // `Path::extension` doesn't apply here.
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            let blocked = lower == "localhost"
                || lower.ends_with(".localhost")
                || lower.ends_with(".local")
                || lower.ends_with(".internal")
                || lower == "metadata.google.internal";
            if blocked && !allow_loopback {
                return Err(DidResolveError::ForbiddenResolverUrl(format!(
                    "host {lower} is on the internal-name deny list"
                )));
            }
            Ok(())
        }
        url::Host::Ipv4(addr) => {
            if blocked_resolver_ip_reason(IpAddr::V4(addr), allow_loopback).is_some() {
                return Err(DidResolveError::ForbiddenResolverUrl(format!(
                    "IPv4 {addr} is in a blocked range"
                )));
            }
            Ok(())
        }
        url::Host::Ipv6(addr) => {
            if blocked_resolver_ip_reason(IpAddr::V6(addr), allow_loopback).is_some() {
                return Err(DidResolveError::ForbiddenResolverUrl(format!(
                    "IPv6 {addr} is in a blocked range"
                )));
            }
            Ok(())
        }
    }
}

async fn enforce_resolver_dns_policy(
    url: &Url,
) -> Result<Option<(String, Vec<SocketAddr>)>, DidResolveError> {
    let Some(url::Host::Domain(host)) = url.host() else {
        return Ok(None);
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DidResolveError::ForbiddenResolverUrl("missing port".to_owned()))?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| {
            DidResolveError::ForbiddenResolverUrl(format!("DNS lookup for {host} failed: {err}"))
        })?
        .collect();
    enforce_resolved_resolver_ip_policy(host, &addrs)?;
    Ok(Some((host.to_owned(), addrs)))
}

fn enforce_resolved_resolver_ip_policy(
    host: &str,
    addrs: &[SocketAddr],
) -> Result<(), DidResolveError> {
    if addrs.is_empty() {
        return Err(DidResolveError::ForbiddenResolverUrl(format!(
            "DNS lookup for {host} returned no addresses"
        )));
    }

    let allow_loopback =
        coauth_config::runtime_var_os("COAUTH_DID_RESOLVER_ALLOW_LOOPBACK").is_some();
    for addr in addrs {
        if let Some(reason) = blocked_resolver_ip_reason(addr.ip(), allow_loopback) {
            return Err(DidResolveError::ForbiddenResolverUrl(format!(
                "host {host} resolved to blocked address {} ({reason})",
                addr.ip()
            )));
        }
    }

    Ok(())
}

fn blocked_resolver_ip_reason(ip: IpAddr, allow_loopback: bool) -> Option<&'static str> {
    match ip {
        IpAddr::V4(addr) => blocked_resolver_ipv4_reason(addr, allow_loopback),
        IpAddr::V6(addr) => blocked_resolver_ipv6_reason(addr, allow_loopback),
    }
}

fn blocked_resolver_ipv4_reason(addr: Ipv4Addr, allow_loopback: bool) -> Option<&'static str> {
    let octets = addr.octets();
    if octets[0] == 0 {
        return Some("this-network IPv4 range");
    }
    if octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
    {
        return Some("private IPv4 range");
    }
    if octets[0] == 127 && !allow_loopback {
        return Some("loopback IPv4 range");
    }
    if octets[0] == 169 && octets[1] == 254 {
        return Some("link-local IPv4 range");
    }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return Some("carrier-grade NAT IPv4 range");
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return Some("IETF protocol-assignment IPv4 range");
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return Some("documentation IPv4 range");
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Some("benchmark IPv4 range");
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return Some("documentation IPv4 range");
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return Some("documentation IPv4 range");
    }
    if (224..=239).contains(&octets[0]) {
        return Some("multicast IPv4 range");
    }
    if octets[0] >= 240 {
        return Some("reserved IPv4 range");
    }
    if addr == Ipv4Addr::BROADCAST {
        return Some("broadcast IPv4 address");
    }
    None
}

fn blocked_resolver_ipv6_reason(addr: Ipv6Addr, allow_loopback: bool) -> Option<&'static str> {
    let segments = addr.segments();
    if addr.is_unspecified() {
        return Some("unspecified IPv6 address");
    }
    if addr.is_loopback() && !allow_loopback {
        return Some("loopback IPv6 address");
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Some("unique-local IPv6 range");
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some("link-local IPv6 range");
    }
    if segments[0] & 0xff00 == 0xff00 {
        return Some("multicast IPv6 range");
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some("documentation IPv6 range");
    }
    None
}

fn delegated_resolver_url(resolver: &str) -> Result<Url, DidResolveError> {
    let url = Url::parse(resolver)?;
    // Reject the operator-supplied endpoint before the request is built.
    enforce_resolver_url_policy(&url)?;
    Ok(url)
}

fn did_method(did: &str) -> Option<String> {
    // Round 4 (spec a77b995) — delegate DID acceptance to the SDK's
    // tightened regex `^did:[a-z0-9]+:[^\s]+$`. The method-name segment
    // MUST be lowercase ASCII alpha + digits only (no `.`/`-`/`_`/`:`);
    // any value the SDK validator rejects is wire-broken and MUST NOT
    // be routed by this resolver.
    arkret_core::Did::new(did.to_owned()).ok()?;
    let rest = did.strip_prefix("did:")?;
    let (method, _method_id) = rest.split_once(':')?;
    (!method.is_empty()).then(|| method.to_ascii_lowercase())
}

fn did_web_document_url(did: &str) -> Result<Url, DidResolveError> {
    let method_id = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidResolveError::InvalidDid(did.to_owned()))?;
    let mut parts = method_id.split(':');
    let host = parts
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| DidResolveError::InvalidDid(did.to_owned()))?
        .replace("%3A", ":")
        .replace("%3a", ":");
    let path: Vec<&str> = parts.filter(|part| !part.is_empty()).collect();
    let url = if path.is_empty() {
        format!("https://{host}/.well-known/did.json")
    } else {
        format!("https://{}/{}/did.json", host, path.join("/"))
    };
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
    use super::*;

    fn addr(value: &str) -> SocketAddr {
        value.parse().expect("test socket address must parse")
    }

    #[test]
    fn resolver_url_policy_rejects_internal_names_and_ip_literals() {
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
                    enforce_resolver_url_policy(&url),
                    Err(DidResolveError::ForbiddenResolverUrl(_))
                ),
                "{raw} should be rejected"
            );
        }
    }

    #[test]
    fn resolved_resolver_ip_policy_rejects_private_and_rebinding_targets() {
        for addrs in [
            vec![addr("10.0.0.1:443")],
            vec![addr("169.254.169.254:443")],
            vec![addr("100.64.0.1:443")],
            vec![addr("[fc00::1]:443")],
            vec![addr("8.8.8.8:443"), addr("192.168.1.10:443")],
        ] {
            assert!(matches!(
                enforce_resolved_resolver_ip_policy("resolver.example", &addrs),
                Err(DidResolveError::ForbiddenResolverUrl(_))
            ));
        }
    }

    #[test]
    fn resolved_resolver_ip_policy_accepts_public_addresses() {
        enforce_resolved_resolver_ip_policy(
            "resolver.example",
            &[addr("8.8.8.8:443"), addr("[2001:4860:4860::8888]:443")],
        )
        .expect("public resolver addresses should be accepted");
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

        let (document, evidence) =
            parse_resolution_response(did, &url, DidResolutionSource::DelegatedResolver, body)
                .expect("SDK response should parse");

        assert_eq!(document.id, did);
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
        let url = delegated_resolver_url("https://resolver.example/_arkret/root/identity/resolve")
            .expect("resolver URL should parse");
        let request = delegated_resolver_request(&reqwest::Client::new(), &url, did)
            .expect("request should build")
            .build()
            .expect("request should be valid");

        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url(), &url);
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
    fn degraded_and_weak_webvh_evidence_is_not_a_full_identity_fact() {
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
}
