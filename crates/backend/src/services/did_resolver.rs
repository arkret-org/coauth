use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use coauth_config::CokretConfig;
use coauth_data::{BoxRepository, RepositoryAccess, UrlBuilder, User};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::jwk::PublicJsonWebKey;
use coauth_keystore::Keystore;
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

use crate::{
    handlers::cokret::{
        DidDocument, DidService, SessionGrantError, VerificationMethod, issuer_did_for,
        service_did_for, user_did_for,
    },
    outbound_http::RequestBuilderExt as _,
};

pub type DidResolverServiceHandle = Arc<dyn DidResolverService>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidResolutionSource {
    LocalService,
    LocalUser,
    DidWeb,
    DidPlc,
    DidKey,
    DelegatedResolver,
}

impl DidResolutionSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalService => "local_service",
            Self::LocalUser => "local_user",
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
    pub method_evidence: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidBindingVerification {
    Verified,
    Mismatch,
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
}

/// Hard upper bound on the size of a fetched DID document. Anything
/// larger is treated as hostile (the caller may be trying to exhaust
/// memory via a slowloris-style response). 10 MiB matches the
/// `_improve_todos.md` A.2 guidance.
pub const DID_DOCUMENT_MAX_BYTES: usize = 10 * 1024 * 1024;

#[async_trait]
pub trait DidResolverService: Send + Sync {
    fn service_did(&self, url_builder: &UrlBuilder, cokret_config: &CokretConfig) -> String;
    fn issuer_did(&self, url_builder: &UrlBuilder, cokret_config: &CokretConfig) -> String;
    fn user_did(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        user: &User,
    ) -> String;
    fn parse_local_user_did(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        did: &str,
    ) -> Option<Ulid>;
    /// Resolve the primary principal DID for a user.
    ///
    /// Async because the starid-backed branch may need to call into the
    /// `starid` registry to look up the canonical `did:webvh:…` head.
    /// The default implementation only consults `user.starid_backend` +
    /// `cokret_config.starid` and returns a deterministic
    /// `did:web:<host>:<path_prefix>:<slug>` form for starid accounts —
    /// a bare network round-trip happens at *onboarding* time
    /// (`StaridRegistry::create_principal_did`), not on every read.
    async fn primary_did_for_user(&self, cokret_config: &CokretConfig, user: &User) -> String;
    fn delegated_resolver(&self, cokret_config: &CokretConfig) -> Option<String>;
    fn proof_required_for_pairwise(&self, cokret_config: &CokretConfig) -> bool;
    fn service_did_document(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        key_store: &Keystore,
    ) -> Result<DidDocument, SessionGrantError>;
    fn user_did_document(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        user: &User,
    ) -> DidDocument;
    fn verify_user_binding(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        user: &User,
        did: &str,
    ) -> DidBindingVerification;

    async fn resolve_did_document(
        &self,
        http_client: &reqwest::Client,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        key_store: &Keystore,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError>;
}

#[derive(Default)]
pub struct DefaultDidResolverService;

#[async_trait]
impl DidResolverService for DefaultDidResolverService {
    fn service_did(&self, url_builder: &UrlBuilder, cokret_config: &CokretConfig) -> String {
        service_did_for(url_builder, cokret_config)
    }

    fn issuer_did(&self, url_builder: &UrlBuilder, cokret_config: &CokretConfig) -> String {
        issuer_did_for(url_builder, cokret_config)
    }

    fn user_did(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        user: &User,
    ) -> String {
        user_did_for(url_builder, cokret_config, user)
    }

    fn parse_local_user_did(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        did: &str,
    ) -> Option<Ulid> {
        let prefix = format!("{}:users:", self.service_did(url_builder, cokret_config));
        did.strip_prefix(&prefix)?.parse::<Ulid>().ok()
    }

    async fn primary_did_for_user(&self, cokret_config: &CokretConfig, user: &User) -> String {
        // C35.0: when this account was onboarded against a configured
        // `[cokret.starid]` deployment, return the deterministic
        // `did:web:<host>:<path_prefix>:<slug>` form that the webvh DID
        // minted at onboarding aliases via its `alsoKnownAs` set. The
        // SCID-bearing `did:webvh:zXXXX:…` form is what `starid` returns
        // from starid's private WebVH DID create response — coauth doesn't persist it
        // separately because the deterministic alias is sufficient as a
        // *primary* identifier (subject of session grants, audit logs,
        // etc.). Verification & log-tail reads still go through
        // `StaridRegistry::verify_control_proof` which takes the full
        // webvh DID — those callers look up the alias from starid on
        // demand.
        //
        // For accounts without `starid_backend` (everything created
        // before the C35.0 backfill, or any account created while
        // `[cokret.starid]` was unset), fall back to the historical
        // local `did:web:coauth.invalid:…` derivation. The boolean acts
        // as the toggle so a deployment that turns starid on later
        // doesn't accidentally retroactively rewrite DIDs for
        // already-issued accounts.
        if user.starid_backend
            && let Some(starid) = cokret_config.starid.as_ref()
        {
            let host = starid
                .did_host
                .clone()
                .or_else(|| starid.base_url.host_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "starid.local".to_owned());
            let path_prefix = starid.path_prefix.trim_matches('/');
            let slug = binding_slug(&user.id.to_string());
            return if path_prefix.is_empty() {
                format!("did:web:{host}:{slug}")
            } else {
                format!("did:web:{host}:{path_prefix}:{slug}")
            };
        }
        format!(
            "did:web:coauth.invalid:accounts:{}",
            binding_slug(&user.id.to_string())
        )
    }

    fn delegated_resolver(&self, cokret_config: &CokretConfig) -> Option<String> {
        cokret_config
            .identity_registry
            .as_ref()
            .map(|registry| registry.resolver.to_string())
    }

    fn proof_required_for_pairwise(&self, cokret_config: &CokretConfig) -> bool {
        cokret_config
            .identity_registry
            .as_ref()
            .is_some_and(|registry| registry.proof_required_for_pairwise)
    }

    fn service_did_document(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        key_store: &Keystore,
    ) -> Result<DidDocument, SessionGrantError> {
        let did = self.service_did(url_builder, cokret_config);
        let mut verification_method = Vec::new();
        let mut authentication = Vec::new();
        let mut assertion_method = Vec::new();

        if let Some(public_key) = crate::handlers::cokret::preferred_public_signing_key(key_store) {
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
                    kind: "CokretAuthServer".to_owned(),
                    service_endpoint: url_builder.absolute_url("/_cokret/describe").to_string(),
                },
                DidService {
                    id: format!("{did}#openid-configuration"),
                    kind: "OpenIdConnectConfiguration".to_owned(),
                    service_endpoint: url_builder.oidc_discovery().to_string(),
                },
            ],
            // A service DID is not a handle holder — no primary_handle.
            metadata: None,
        })
    }

    fn user_did_document(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        user: &User,
    ) -> DidDocument {
        // Delegate to the canonical builder in `handlers::cokret` so the
        // R3.2 `metadata.primary_handle` holder-preference logic
        // (DID-COAUTH-1) lives in exactly one place.
        crate::handlers::cokret::user_did_document(url_builder, cokret_config, user)
    }

    fn verify_user_binding(
        &self,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        user: &User,
        did: &str,
    ) -> DidBindingVerification {
        if self.user_did(url_builder, cokret_config, user) == did {
            DidBindingVerification::Verified
        } else {
            DidBindingVerification::Mismatch
        }
    }

    async fn resolve_did_document(
        &self,
        http_client: &reqwest::Client,
        url_builder: &UrlBuilder,
        cokret_config: &CokretConfig,
        key_store: &Keystore,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError> {
        if did == self.service_did(url_builder, cokret_config) {
            return Ok(local_resolution(
                self.service_did_document(url_builder, cokret_config, key_store)?,
                DidResolutionSource::LocalService,
                true,
            ));
        }

        if let Some(user_id) = self.parse_local_user_did(url_builder, cokret_config, did) {
            let Some(user) = repo.user().lookup(user_id).await? else {
                return Err(DidResolveError::NotFound);
            };
            return Ok(local_resolution(
                self.user_did_document(url_builder, cokret_config, &user),
                DidResolutionSource::LocalUser,
                true,
            ));
        }

        if let Some(user_id) = parse_local_primary_account_did(did) {
            let Some(user) = repo.user().lookup(user_id).await? else {
                return Err(DidResolveError::NotFound);
            };
            return Ok(local_resolution(
                local_primary_account_did_document(url_builder, did, &user, key_store),
                DidResolutionSource::LocalUser,
                true,
            ));
        }

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
                    service: Vec::new(),
                    // External `did:key` — coauth does not own its metadata.
                    metadata: None,
                },
                DidResolutionSource::DidKey,
                false,
            )),
            Some(_) => match self.delegated_resolver(cokret_config) {
                Some(resolver) => {
                    let url = delegated_resolver_url(&resolver, did)?;
                    resolve_http_did(
                        http_client,
                        did,
                        url,
                        DidResolutionSource::DelegatedResolver,
                    )
                    .await
                }
                None => Err(DidResolveError::UnsupportedMethod),
            },
            None => Err(DidResolveError::InvalidDid(did.to_owned())),
        }
    }
}

fn parse_local_primary_account_did(did: &str) -> Option<Ulid> {
    let slug = did.strip_prefix("did:web:coauth.invalid:accounts:")?;
    Ulid::from_string(&slug.to_ascii_uppercase()).ok()
}

fn local_primary_account_did_document(
    url_builder: &UrlBuilder,
    did: &str,
    user: &User,
    key_store: &Keystore,
) -> DidDocument {
    let mut verification_method = Vec::new();
    let mut authentication = Vec::new();
    let mut assertion_method = Vec::new();
    if let Some(public_key) = preferred_public_eddsa_key(key_store) {
        let key_id = format!("{did}#key-1");
        verification_method.push(VerificationMethod {
            id: key_id.clone(),
            kind: "JsonWebKey2020".to_owned(),
            controller: did.to_owned(),
            public_key_jwk: public_key,
        });
        authentication.push(key_id.clone());
        assertion_method.push(key_id);
    }

    DidDocument {
        id: did.to_owned(),
        also_known_as: vec![crate::handlers::cokret::user_handle(url_builder, user)],
        verification_method,
        authentication,
        assertion_method,
        service: Vec::new(),
        metadata: Some(crate::handlers::cokret::DidDocumentMetadata::current_for_holder(None)),
    }
}

fn preferred_public_eddsa_key(key_store: &Keystore) -> Option<PublicJsonWebKey> {
    key_store
        .public_jwks()
        .iter()
        .find(|candidate| candidate.alg() == Some(&JsonWebSignatureAlg::EdDsa))
        .cloned()
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
        method_evidence: serde_json::json!({
            "resolver": source.as_str(),
            "verified_local_binding": verified_local_binding,
        }),
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
    let document_value = body
        .get("didDocument")
        .cloned()
        .unwrap_or_else(|| body.clone());
    let document = serde_json::from_value::<DidDocument>(document_value)?;
    if document.id != did {
        return Err(DidResolveError::DocumentIdMismatch {
            expected: did.to_owned(),
            actual: document.id,
        });
    }

    Ok(DidResolution {
        document,
        source,
        verified_local_binding: false,
        method_evidence: serde_json::json!({
            "resolver": source.as_str(),
            "document_url": url,
        }),
    })
}

/// SSRF policy for outbound DID-document fetches.
///
/// Rules:
/// - Scheme MUST be `https` (the DID method document URLs for `did:web` and
///   `did:plc` are always HTTPS; the delegated resolver URL is
///   operator-supplied and must opt into HTTPS too).
/// - Host MUST be present and MUST NOT be a loopback / link-local / private /
///   unspecified address. IP literals in those ranges are blocked outright;
///   named hosts are resolved immediately before the request and rejected if
///   any returned address is non-public. The request is then dispatched through
///   a static-resolution outbound client pinned to that validated address set,
///   closing the DNS rebinding window.
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
    let allow_loopback = std::env::var_os("COAUTH_DID_RESOLVER_ALLOW_LOOPBACK").is_some();
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

    let allow_loopback = std::env::var_os("COAUTH_DID_RESOLVER_ALLOW_LOOPBACK").is_some();
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

fn delegated_resolver_url(resolver: &str, did: &str) -> Result<Url, DidResolveError> {
    let mut url = Url::parse(resolver)?;
    // Reject the URL before we even build the query so an
    // operator-supplied `http://localhost/...` resolver is caught at
    // config-load + first-use time rather than executed.
    enforce_resolver_url_policy(&url)?;
    url.query_pairs_mut().append_pair("did", did);
    Ok(url)
}

fn did_method(did: &str) -> Option<String> {
    // Round 4 (spec a77b995) — delegate DID acceptance to the SDK's
    // tightened regex `^did:[a-z0-9]+:[^\s]+$`. The method-name segment
    // MUST be lowercase ASCII alpha + digits only (no `.`/`-`/`_`/`:`);
    // any value the SDK validator rejects is wire-broken and MUST NOT
    // be routed by this resolver.
    cokret_core::Did::new(did.to_owned()).ok()?;
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

fn binding_slug(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
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
}
