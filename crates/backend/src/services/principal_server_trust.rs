//! Principal Server trust resolution: three-layer pin resolution, mandatory
//! online startup preflight, one-time bootstrap and explicit replacement.
//!
//! ## Why
//!
//! `/_arkret/describe` is capability metadata, not an authorization root.
//! The effective audience pin for each configured Principal Server is
//! resolved from exactly one of three layers, in priority order:
//!
//! 1. the explicit config pin (`principal_servers[].service_id`);
//! 2. the persisted trust enrollment written by an explicit `coauth principal-server trust
//!    bootstrap` / `replace` (or the narrowly scoped development auto-enrollment);
//! 3. nothing — startup refuses to bind the business listener and points at the bootstrap command.
//!
//! A remote describe response only ever *confirms* a pin. It can never
//! create or replace one outside the explicit bootstrap/replace operations.
//!
//! ## Concurrency
//!
//! The request-path cache is a bounded `std::sync::RwLock<HashMap>` keyed by
//! canonical endpoint. It is populated by [`preflight_and_spawn`] before any
//! business listener binds and refreshed by the background revalidation task,
//! so synchronous audience checks never perform I/O. Correctness never
//! depends on the cache: a missing or expired entry fails closed, and the
//! revalidation task fatally shuts the process down once a verified value
//! exceeds [`MAX_TRUSTED_AUDIENCE_AGE`] without refresh, or immediately on a
//! cryptographic identity conflict.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use arkret_identity::DidWebvhResolver;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, ResolutionCommitment,
    canonical_service_current_record_path,
};
use arkret_wire::{BindingKind, DidCoreId, DidFullId, Hash, ServiceKind};
use chrono::Utc;
use coauth_config::{ArkretConfig, PrincipalServerConfig};
use coauth_data::storage::principal_server_trust::{
    NewPrincipalServerTrustAudit, NewPrincipalServerTrustEnrollment,
    PrincipalServerTrustAuditAction, PrincipalServerTrustEnrollment, PrincipalServerTrustSource,
};
use coauth_data::{RepositoryAccess, RepositoryError, RepositoryFactory, SystemClock};
use coauth_storage_postgres::PgRepositoryFactory;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::outbound_http;

/// Root-relative describe path served by every Arkret Principal Server.
pub(crate) const DESCRIBE_PATH: &str = "_arkret/describe";

/// Revalidation-interval floor: faster than this just hammers the Principal
/// Server's describe surface.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_mins(1);

/// Revalidation-interval ceiling. Keeping this well below
/// [`MAX_TRUSTED_AUDIENCE_AGE`] guarantees repeated revalidation opportunities
/// before a previously verified value expires.
const MAX_REFRESH_INTERVAL: Duration = Duration::from_hours(1);

/// Default revalidation cadence used at server startup.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

/// Maximum age of a verified audience. Once this age is reached, request-path
/// lookups return `None` and the background revalidation task treats the
/// state as expired, terminating the service.
pub const MAX_TRUSTED_AUDIENCE_AGE: Duration = Duration::from_hours(24);

/// Hard upper bound on a fetched authenticated service resolution, matching
/// the SDK transport bound (`SERVICE_RESOLUTION_FETCH_MAX_BYTES`).
const AUTHENTICATED_RESOLUTION_MAX_BYTES: usize =
    arkret_http_client::SERVICE_RESOLUTION_FETCH_MAX_BYTES;

/// Defensive cache bound. The cache only ever holds one entry per configured
/// Principal Server; this cap bounds damage if that invariant ever breaks.
const MAX_CACHE_ENTRIES: usize = 64;

/// Bounded audit detail length. Audit entries never carry bearer tokens,
/// private keys or raw evidence.
const AUDIT_DETAIL_MAX_CHARS: usize = 256;

/// Process-wide shared resolver. Populated by [`preflight_and_spawn`] before
/// the business listener binds and read by the request-path audience checks
/// via [`shared`].
static SHARED: LazyLock<PrincipalServerTrustResolver> =
    LazyLock::new(PrincipalServerTrustResolver::new);

/// The process-wide Principal Server trust resolver.
#[must_use]
pub fn shared() -> &'static PrincipalServerTrustResolver {
    &SHARED
}

/// Canonical endpoint (normalized string) → verified `service_id` pin and the
/// time it was last verified online. Cheap to clone (the map is behind an
/// `Arc`); all clones share the same underlying cache.
#[derive(Debug, Clone)]
pub struct PrincipalServerTrustResolver {
    inner: Arc<RwLock<HashMap<String, ResolvedPin>>>,
    max_trusted_age: Duration,
}

#[derive(Debug, Clone)]
struct ResolvedPin {
    value: DidCoreId,
    last_verified_at: Instant,
}

impl Default for PrincipalServerTrustResolver {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            max_trusted_age: MAX_TRUSTED_AUDIENCE_AGE,
        }
    }
}

impl PrincipalServerTrustResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current verified `service_id` pin for `endpoint`, if it was verified
    /// within [`MAX_TRUSTED_AUDIENCE_AGE`]. Synchronous — safe to call from
    /// the request-path audience checks. Returns `None` before the first
    /// successful verification and after expiry, so callers MUST fail closed
    /// on `None`.
    #[must_use]
    pub fn resolve(&self, endpoint: &Url) -> Option<DidCoreId> {
        self.resolve_at(endpoint, Instant::now())
    }

    fn resolve_at(&self, endpoint: &Url, now: Instant) -> Option<DidCoreId> {
        let key = canonical_endpoint_key(endpoint)?;
        let map = self.inner.read().ok()?;
        let resolved = map.get(&key)?;
        (now.saturating_duration_since(resolved.last_verified_at) < self.max_trusted_age)
            .then(|| resolved.value.clone())
    }

    /// Age of the last successful online verification for `endpoint`.
    fn last_verified_age(&self, endpoint: &Url, now: Instant) -> Option<Duration> {
        let key = canonical_endpoint_key(endpoint)?;
        let map = self.inner.read().ok()?;
        let resolved = map.get(&key)?;
        Some(now.saturating_duration_since(resolved.last_verified_at))
    }

    /// Record a freshly verified pin. Callers only pass endpoints from the
    /// deployment configuration; [`MAX_CACHE_ENTRIES`] is a defensive bound.
    pub(crate) fn note_verified(&self, endpoint: &Url, service_id: DidCoreId) {
        self.note_verified_at(endpoint, service_id, Instant::now());
    }

    fn note_verified_at(&self, endpoint: &Url, service_id: DidCoreId, now: Instant) {
        let Some(key) = canonical_endpoint_key(endpoint) else {
            return;
        };
        if let Ok(mut map) = self.inner.write() {
            if let Some(existing) = map.get_mut(&key) {
                if existing.value == service_id {
                    existing.last_verified_at = now;
                } else {
                    // A pin change only lands here after an explicit
                    // `trust replace`; the runtime never adopts a new
                    // identity from a remote self-assertion.
                    *existing = ResolvedPin {
                        value: service_id,
                        last_verified_at: now,
                    };
                }
            } else if map.len() < MAX_CACHE_ENTRIES {
                map.insert(
                    key,
                    ResolvedPin {
                        value: service_id,
                        last_verified_at: now,
                    },
                );
            } else {
                tracing::error!(
                    endpoint = %endpoint,
                    "principal-server trust cache is full; refusing to cache pin",
                );
            }
        }
    }

    /// Test/seed helper: insert a resolved value directly without a probe.
    #[cfg(test)]
    pub fn insert_for_test(&self, endpoint: &Url, service_id: impl Into<String>) {
        let service_id = DidCoreId::new(service_id.into()).expect("valid test service core ID");
        self.note_verified_at(endpoint, service_id, Instant::now());
    }
}

/// The effective authorization audience for `server`.
///
/// Three-layer resolution: the explicit config pin wins when present; the
/// verified persisted enrollment pin (cached by preflight) is used when the
/// config omits the pin; otherwise `None` and callers fail closed. Describe
/// metadata never supplies this value.
#[must_use]
pub fn effective_audience(
    server: &PrincipalServerConfig,
    resolver: &PrincipalServerTrustResolver,
) -> Option<DidCoreId> {
    server
        .service_id
        .clone()
        .or_else(|| resolver.resolve(&server.endpoint))
}

/// [`effective_audience`] against the process-wide [`shared`] resolver — the
/// common form for call sites that don't thread a resolver handle.
#[must_use]
pub fn effective_audience_shared(server: &PrincipalServerConfig) -> Option<DidCoreId> {
    effective_audience(server, shared())
}

/// Canonical cache/storage key for an endpoint.
fn canonical_endpoint_key(endpoint: &Url) -> Option<String> {
    CanonicalServiceUrl::canonicalize(endpoint.as_str())
        .ok()
        .map(|canonical| canonical.to_string())
}

/// Classification of an online Principal Server identity verification
/// failure.
#[derive(Debug, thiserror::Error)]
pub enum TrustVerificationError {
    /// The endpoint is not a canonical HTTPS base URL.
    #[error("principal-server endpoint is not a canonical HTTPS base URL: {0}")]
    InvalidEndpoint(String),
    /// Transient network failure: connect, DNS or timeout. This is the only
    /// class the runtime revalidation tolerates for a bounded last-verified
    /// age.
    #[error("principal-server is unreachable: {0}")]
    Unreachable(String),
    /// The target was denied by the outbound egress policy (SSRF/DNS
    /// rebinding protection).
    #[error("principal-server target denied by egress policy: {0}")]
    EgressDenied(String),
    /// The response carried the wrong service role.
    #[error("wrong service kind: expected principal_server, observed {0}")]
    WrongServiceKind(String),
    /// DID Document, WebVH history, resolution proof or freshness failed
    /// verification.
    #[error("invalid principal-server identity evidence: {0}")]
    InvalidEvidence(String),
    /// The observed service id does not equal the effective pin.
    #[error("observed service_id {observed} does not match the effective pin {expected}")]
    IdentityMismatch {
        /// The effective pin (config or persisted enrollment).
        expected: String,
        /// The service id the endpoint currently presents.
        observed: String,
    },
    /// The signed record does not bind to the configured endpoint.
    #[error("endpoint binding mismatch: {0}")]
    EndpointBinding(String),
    /// The verified method history regressed below the stored floor.
    #[error("method-history rollback: {0}")]
    HistoryRollback(String),
}

impl TrustVerificationError {
    /// Whether this failure is a transient network problem that may use a
    /// bounded-age last-verified state at runtime.
    #[must_use]
    pub const fn is_transient_network(&self) -> bool {
        matches!(self, Self::Unreachable(_))
    }
}

/// Fully verified Principal Server identity material, ready to persist as a
/// trust enrollment or to confirm an existing pin.
#[derive(Debug, Clone)]
pub struct VerifiedPrincipalServerIdentity {
    /// Stable service core id (the pin).
    pub service_id: DidCoreId,
    /// Complete service DID verified against its WebVH history.
    pub full_id: DidFullId,
    /// Verified WebVH method-history head (`sha256:` digest of the head
    /// entry) — the anti-rollback floor.
    pub method_history_head: String,
    /// Verified WebVH version id of the head entry.
    pub version_id: String,
    /// `sha256:` digest of the canonical signed resolution record.
    pub resolution_record_digest: String,
    /// Canonical endpoint the identity is bound to.
    pub canonical_endpoint: String,
}

/// Route-binding projection whose canonical digest is published as
/// `describe_digest` in the signed service resolution record. The shape is
/// normative (see the SDK resolution-record transcript); field order and
/// names must not change.
#[derive(Serialize)]
struct RouteBindingProjection<'a> {
    service_id: &'a DidCoreId,
    service_kind: ServiceKind,
    service_resolution: &'a ResolutionCommitment,
    http_json_base_url: &'a str,
}

async fn fetch_bounded(
    http_client: &reqwest::Client,
    operation: &'static str,
    url: Url,
    max_bytes: usize,
) -> Result<Vec<u8>, TrustVerificationError> {
    outbound_http::fetch_bounded(
        http_client,
        outbound_http::principal_trust_policy(operation),
        url,
        max_bytes,
    )
    .await
    .map_err(|error| match error {
        outbound_http::BoundedFetchError::Unreachable(message) => {
            TrustVerificationError::Unreachable(message)
        }
        outbound_http::BoundedFetchError::EgressDenied(message) => {
            TrustVerificationError::EgressDenied(message)
        }
        outbound_http::BoundedFetchError::TooLarge(message) => {
            TrustVerificationError::InvalidEvidence(message)
        }
    })
}

/// The numeric sequence component of a `did:webvh` version id
/// (`<seq>-<entry_hash>`), used for anti-rollback comparison.
fn webvh_version_sequence(version_id: &str) -> Option<u64> {
    version_id.split_once('-')?.0.parse().ok()
}

/// Fail closed when the newly verified method-history coordinates regress
/// below the stored anti-rollback floor.
fn check_anti_rollback(
    floor_head: &str,
    floor_version_id: &str,
    new_head: &str,
    new_version_id: &str,
) -> Result<(), TrustVerificationError> {
    let floor_seq = webvh_version_sequence(floor_version_id).ok_or_else(|| {
        TrustVerificationError::HistoryRollback(format!(
            "stored floor version id {floor_version_id:?} is malformed"
        ))
    })?;
    let new_seq = webvh_version_sequence(new_version_id).ok_or_else(|| {
        TrustVerificationError::HistoryRollback(format!(
            "observed version id {new_version_id:?} is malformed"
        ))
    })?;
    if new_seq < floor_seq || (new_seq == floor_seq && new_head != floor_head) {
        return Err(TrustVerificationError::HistoryRollback(format!(
            "observed head {new_version_id}/{new_head} is below the enrolled floor {floor_version_id}/{floor_head}"
        )));
    }
    Ok(())
}

/// Fetch and fully verify the current Principal Server identity material for
/// `endpoint`.
///
/// Verification chain, all fail-closed:
///
/// 1. canonical HTTPS endpoint under the configured egress policy;
/// 2. role-scoped typed `ServiceDescribe` with `service_kind == principal_server`;
/// 3. `project(full_id) == service_id`;
/// 4. full WebVH history verification; the describe resolution commitment must equal the verified
///    head (version id and head digest);
/// 5. signed `ServiceResolutionRecord` from the canonical path, proof verified against the
///    WebVH-anchored DID Document, freshness checked;
/// 6. endpoint binding: record `base_url` must be the canonical configured endpoint,
///    `current_record_url` must derive from it, and the route-binding projection digest must match
///    `describe_digest`;
/// 7. the observed `service_id` must equal `expected_service_id` when given;
/// 8. anti-rollback: the verified coordinates must not regress below `floor` when given.
pub async fn verify_principal_server_identity(
    http_client: &reqwest::Client,
    endpoint: &Url,
    expected_service_id: Option<&DidCoreId>,
    floor: Option<(&str, &str)>,
) -> Result<VerifiedPrincipalServerIdentity, TrustVerificationError> {
    let canonical = CanonicalServiceUrl::canonicalize(endpoint.as_str())
        .map_err(|error| TrustVerificationError::InvalidEndpoint(error.to_string()))?;
    canonical
        .require_https()
        .map_err(|error| TrustVerificationError::InvalidEndpoint(error.to_string()))?;
    let canonical_endpoint = canonical.to_string();

    // 2. Role-scoped describe.
    let mut describe_url = Url::parse(&format!("{canonical_endpoint}{DESCRIBE_PATH}"))
        .map_err(|error| TrustVerificationError::InvalidEndpoint(error.to_string()))?;
    describe_url
        .query_pairs_mut()
        .append_pair("service_kind", ServiceKind::PrincipalServer.as_str());
    let describe_bytes = fetch_bounded(
        http_client,
        "principal_trust_describe",
        describe_url,
        outbound_http::DESCRIBE_MAX_BYTES,
    )
    .await?;
    let description: ServiceDescribe = serde_json::from_slice(&describe_bytes)
        .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    description
        .validate()
        .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if description.service_kind != ServiceKind::PrincipalServer {
        return Err(TrustVerificationError::WrongServiceKind(
            description.service_kind.as_str().to_owned(),
        ));
    }
    if description.protocol_version != arkret_wire::PROTOCOL_VERSION {
        return Err(TrustVerificationError::InvalidEvidence(format!(
            "unsupported protocol version {:?}",
            description.protocol_version
        )));
    }
    if let Some(expected) = expected_service_id
        && &description.service_id != expected
    {
        return Err(TrustVerificationError::IdentityMismatch {
            expected: expected.to_string(),
            observed: description.service_id.to_string(),
        });
    }
    let service_id = description.service_id.clone();
    let commitment = description.service_resolution.clone();

    // 3. full/core projection.
    arkret_signatures::service_resolution::verify_full_to_core_binding(
        &commitment.full_id,
        &service_id,
    )
    .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;

    // 4. WebVH history verification; the describe commitment must equal the
    // verified head.
    let log_url = Url::parse(
        &DidWebvhResolver::log_url(&commitment.full_id)
            .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?,
    )
    .map_err(|error| TrustVerificationError::InvalidEndpoint(error.to_string()))?;
    let log_bytes = fetch_bounded(
        http_client,
        "principal_trust_webvh_log",
        log_url,
        outbound_http::WEBVH_LOG_MAX_BYTES,
    )
    .await?;
    let verified_log =
        arkret_identity::verify_did_webvh_v1_chain_bytes(&commitment.full_id, &log_bytes)
            .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if verified_log.head_version_id != commitment.version_id {
        return Err(TrustVerificationError::InvalidEvidence(format!(
            "describe version id {} is not the verified WebVH head {}",
            commitment.version_id, verified_log.head_version_id
        )));
    }
    let head_entry = verified_log.raw_entries.last().ok_or_else(|| {
        TrustVerificationError::InvalidEvidence("verified did:webvh history has no head".to_owned())
    })?;
    let head_digest = Hash::new(
        arkret_canonical::canonical_sha256(head_entry)
            .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?,
    )
    .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if head_digest.as_str() != commitment.method_history_head {
        return Err(TrustVerificationError::InvalidEvidence(format!(
            "describe method-history head {} is not the verified WebVH head digest {}",
            commitment.method_history_head,
            head_digest.as_str()
        )));
    }
    let document: DidDocument = serde_json::from_value(verified_log.head_state.clone())
        .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if document.id != commitment.full_id {
        return Err(TrustVerificationError::InvalidEvidence(format!(
            "verified DID Document id {} does not match {}",
            document.id, commitment.full_id
        )));
    }

    // 8. Anti-rollback floor before accepting any derived state.
    if let Some((floor_head, floor_version_id)) = floor {
        check_anti_rollback(
            floor_head,
            floor_version_id,
            &commitment.method_history_head,
            &commitment.version_id,
        )?;
    }

    // 5. Complete authenticated resolution from the canonical path. The open
    // endpoint carries the signed record together with its retained method
    // history and normalized DID Document; the signed record remains the
    // persisted digest/pin material.
    let record_url = Url::parse(&format!(
        "{canonical_endpoint}{}",
        canonical_service_current_record_path(&service_id).trim_start_matches('/')
    ))
    .map_err(|error| TrustVerificationError::InvalidEndpoint(error.to_string()))?;
    let record_bytes = fetch_bounded(
        http_client,
        "principal_trust_resolution_record",
        record_url.clone(),
        AUTHENTICATED_RESOLUTION_MAX_BYTES,
    )
    .await?;
    let authenticated_resolution: AuthenticatedServiceResolution =
        arkret_canonical::canonical::from_canonical_json_slice(&record_bytes)
            .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    let record = &authenticated_resolution.service_resolution_record;
    let resolution_record_digest = Hash::new(
        arkret_canonical::canonical_sha256(record)
            .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?,
    )
    .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if record.record.service_id != service_id {
        return Err(TrustVerificationError::InvalidEvidence(
            "resolution record targets a different service".to_owned(),
        ));
    }
    if record.record.service_kind != ServiceKind::PrincipalServer.as_str() {
        return Err(TrustVerificationError::WrongServiceKind(
            record.record.service_kind.clone(),
        ));
    }
    if record.record.full_id != commitment.full_id
        || record.record.method_history_head != commitment.method_history_head
        || record.record.version_id != commitment.version_id
    {
        return Err(TrustVerificationError::InvalidEvidence(
            "resolution record does not match the describe resolution commitment".to_owned(),
        ));
    }

    // 6. Endpoint binding.
    let record_base = CanonicalServiceUrl::canonicalize(&record.record.base_url)
        .map_err(|error| TrustVerificationError::EndpointBinding(error.to_string()))?;
    if record_base.to_string() != record.record.base_url {
        return Err(TrustVerificationError::EndpointBinding(
            "resolution record base_url is not canonical".to_owned(),
        ));
    }
    if record_base.to_string() != canonical_endpoint {
        return Err(TrustVerificationError::EndpointBinding(format!(
            "resolution record base_url {} does not match the configured endpoint {}",
            record.record.base_url, canonical_endpoint
        )));
    }
    if record.record.current_record_url != record_url.as_str() {
        return Err(TrustVerificationError::EndpointBinding(format!(
            "resolution record current_record_url {} is not the canonical locator {}",
            record.record.current_record_url,
            record_url.as_str()
        )));
    }
    let history_hex = commitment
        .method_history_head
        .strip_prefix("sha256:")
        .ok_or_else(|| {
            TrustVerificationError::InvalidEvidence(
                "method-history head is not a sha256 digest".to_owned(),
            )
        })?;
    if record.record.resolution_event_ref != format!("did-webvh-entry-sha256:{history_hex}") {
        return Err(TrustVerificationError::InvalidEvidence(
            "resolution event ref does not match the verified method-history head".to_owned(),
        ));
    }
    let mut http_json_bindings = description
        .supported_bindings
        .iter()
        .filter(|binding| binding.kind == BindingKind::HttpJson);
    let binding = http_json_bindings.next().ok_or_else(|| {
        TrustVerificationError::EndpointBinding(
            "ServiceDescribe has no http_json binding".to_owned(),
        )
    })?;
    if http_json_bindings.next().is_some() {
        return Err(TrustVerificationError::EndpointBinding(
            "ServiceDescribe has multiple http_json bindings".to_owned(),
        ));
    }
    let advertised_base = binding.base_url.as_deref().ok_or_else(|| {
        TrustVerificationError::EndpointBinding(
            "ServiceDescribe http_json binding has no base_url".to_owned(),
        )
    })?;
    if advertised_base != record.record.base_url {
        return Err(TrustVerificationError::EndpointBinding(format!(
            "ServiceDescribe http_json base {advertised_base} does not match the signed record target {}",
            record.record.base_url
        )));
    }
    let route_binding_digest = Hash::new(
        arkret_canonical::canonical_sha256(&RouteBindingProjection {
            service_id: &service_id,
            service_kind: ServiceKind::PrincipalServer,
            service_resolution: &commitment,
            http_json_base_url: advertised_base,
        })
        .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?,
    )
    .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if route_binding_digest != record.record.describe_digest {
        return Err(TrustVerificationError::EndpointBinding(
            "route-binding projection digest does not match the signed record".to_owned(),
        ));
    }

    // 5b. Verify the complete retained history, record proof and freshness.
    // The independently fetched describe/history chain above and the
    // authenticated resolution must converge on the same normalized document.
    if authenticated_resolution.normalized_did_document != document {
        return Err(TrustVerificationError::InvalidEvidence(
            "authenticated resolution DID Document differs from the verified describe history"
                .to_owned(),
        ));
    }
    arkret_identity::verify_authenticated_service_resolution_history(
        &authenticated_resolution,
        &service_id,
        Utc::now(),
    )
    .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;

    Ok(VerifiedPrincipalServerIdentity {
        service_id,
        full_id: commitment.full_id,
        method_history_head: commitment.method_history_head,
        version_id: commitment.version_id,
        resolution_record_digest: resolution_record_digest.as_str().to_owned(),
        canonical_endpoint,
    })
}

/// Failure of a bootstrap / replace operation.
#[derive(Debug, thiserror::Error)]
pub enum TrustEnrollmentError {
    /// Online identity verification failed.
    #[error("identity verification failed: {0}")]
    Verification(#[from] TrustVerificationError),
    /// The endpoint is already enrolled with a different identity.
    #[error(
        "endpoint {endpoint} is already enrolled with service_id {existing}; use `coauth principal-server trust replace` to change it"
    )]
    ConflictingEnrollment {
        /// Canonical endpoint.
        endpoint: String,
        /// Currently enrolled service id.
        existing: String,
    },
    /// The operator-facing name is bound to a different endpoint.
    #[error("name {name} is already enrolled for a different endpoint ({existing})")]
    ConflictingName {
        /// Operator-facing name.
        name: String,
        /// Currently enrolled endpoint.
        existing: String,
    },
    /// No enrollment exists to replace.
    #[error("no trust enrollment named {name} exists")]
    UnknownEnrollment {
        /// Operator-facing name.
        name: String,
    },
    /// The stored pin does not match the expected-old compare-and-swap
    /// expectation.
    #[error("stored pin {stored} does not match --expect-old {expected}")]
    ExpectOldMismatch {
        /// Caller-supplied expectation.
        expected: String,
        /// Currently stored pin.
        stored: String,
    },
    /// The verified identity already equals the stored pin.
    #[error("the verified identity {0} already equals the stored pin; nothing to replace")]
    AlreadyCurrent(String),
    /// The configured explicit pin disagrees with the verified identity.
    #[error(
        "the configured service_id pin {configured} does not match the verified identity {verified}"
    )]
    ConfiguredPinMismatch {
        /// Configured pin.
        configured: String,
        /// Verified identity.
        verified: String,
    },
    /// Storage failure.
    #[error("storage failure: {0}")]
    Storage(#[from] RepositoryError),
}

/// Outcome of a successful bootstrap.
#[derive(Debug)]
pub struct BootstrapOutcome {
    /// The persisted (or pre-existing, for idempotent reruns) enrollment.
    pub enrollment: PrincipalServerTrustEnrollment,
    /// Whether the enrollment already existed with the same identity.
    pub already_enrolled: bool,
}

fn enrollment_params(
    server: &PrincipalServerConfig,
    verified: &VerifiedPrincipalServerIdentity,
    source: PrincipalServerTrustSource,
) -> NewPrincipalServerTrustEnrollment {
    NewPrincipalServerTrustEnrollment {
        name: server.name.clone(),
        canonical_endpoint: verified.canonical_endpoint.clone(),
        service_id: verified.service_id.clone(),
        full_id: verified.full_id.clone(),
        method_history_head: verified.method_history_head.clone(),
        version_id: verified.version_id.clone(),
        resolution_record_digest: verified.resolution_record_digest.clone(),
        source,
    }
}

async fn record_failure_audit(
    repository_factory: &PgRepositoryFactory,
    name: &str,
    service_id: Option<DidCoreId>,
    detail: String,
) {
    let mut rng = ChaCha20Rng::from_entropy();
    let detail: String = detail.chars().take(AUDIT_DETAIL_MAX_CHARS).collect();
    match repository_factory.create().await {
        Ok(mut repo) => {
            let recorded = repo
                .principal_server_trust()
                .record_audit(
                    &mut rng,
                    &SystemClock::default(),
                    NewPrincipalServerTrustAudit {
                        enrollment_name: name.to_owned(),
                        action: PrincipalServerTrustAuditAction::VerificationFailed,
                        service_id,
                        previous_service_id: None,
                        detail: detail.clone(),
                    },
                )
                .await;
            match recorded {
                Ok(_) => {
                    if let Err(error) = repo.save().await {
                        tracing::warn!(%error, "failed to commit trust verification audit");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to record trust verification audit");
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "failed to open repository for trust verification audit");
        }
    }
}

/// One-time idempotent trust bootstrap for one configured Principal Server.
///
/// Verifies the full identity chain online, then creates the enrollment and
/// its audit entry in a single transaction. Re-running with an unchanged
/// identity succeeds without altering the pin; an endpoint enrolled with a
/// different identity is rejected in favour of the explicit replace flow.
pub async fn bootstrap(
    repository_factory: &PgRepositoryFactory,
    http_client: &reqwest::Client,
    server: &PrincipalServerConfig,
    source: PrincipalServerTrustSource,
) -> Result<BootstrapOutcome, TrustEnrollmentError> {
    let verified = match verify_principal_server_identity(
        http_client,
        &server.endpoint,
        server.service_id.as_ref(),
        None,
    )
    .await
    {
        Ok(verified) => verified,
        Err(error) => {
            record_failure_audit(
                repository_factory,
                &server.name,
                server.service_id.clone(),
                error.to_string(),
            )
            .await;
            return Err(error.into());
        }
    };

    let mut repo = repository_factory.create().await?;
    // Bind the lookup result first: the repository guard borrows `repo`
    // mutably, and holding it across the `if let` scrutinee would block the
    // writes in the idempotent-rerun path.
    let existing_by_endpoint = repo
        .principal_server_trust()
        .find_by_endpoint(&verified.canonical_endpoint)
        .await?;
    if let Some(existing) = existing_by_endpoint {
        if existing.service_id != verified.service_id {
            return Err(TrustEnrollmentError::ConflictingEnrollment {
                endpoint: verified.canonical_endpoint.clone(),
                existing: existing.service_id.to_string(),
            });
        }
        if existing.name != server.name {
            return Err(TrustEnrollmentError::ConflictingName {
                name: server.name.clone(),
                existing: existing.name,
            });
        }
        // Idempotent rerun: advance the anti-rollback floor and the
        // last-verified timestamp, never the pin.
        repo.principal_server_trust()
            .record_verification(
                &SystemClock::default(),
                &verified.canonical_endpoint,
                &verified.method_history_head,
                &verified.version_id,
                &verified.resolution_record_digest,
            )
            .await?;
        repo.save().await?;
        shared().note_verified(&server.endpoint, verified.service_id.clone());
        return Ok(BootstrapOutcome {
            enrollment: existing,
            already_enrolled: true,
        });
    }
    if let Some(existing) = repo
        .principal_server_trust()
        .find_by_name(&server.name)
        .await?
    {
        return Err(TrustEnrollmentError::ConflictingName {
            name: server.name.clone(),
            existing: existing.canonical_endpoint,
        });
    }

    let params = enrollment_params(server, &verified, source);
    let enrollment = repo
        .principal_server_trust()
        .enroll(&SystemClock::default(), params)
        .await?;
    let mut rng = ChaCha20Rng::from_entropy();
    repo.principal_server_trust()
        .record_audit(
            &mut rng,
            &SystemClock::default(),
            NewPrincipalServerTrustAudit {
                enrollment_name: server.name.clone(),
                action: PrincipalServerTrustAuditAction::Enrolled,
                service_id: Some(verified.service_id.clone()),
                previous_service_id: None,
                detail: format!(
                    "enrolled via {} at {}",
                    source.as_str(),
                    verified.canonical_endpoint
                ),
            },
        )
        .await?;
    repo.save().await?;
    shared().note_verified(&server.endpoint, verified.service_id.clone());
    Ok(BootstrapOutcome {
        enrollment,
        already_enrolled: false,
    })
}

/// Outcome of a successful explicit replacement.
#[derive(Debug)]
pub struct ReplaceOutcome {
    /// The enrollment after replacement.
    pub enrollment: PrincipalServerTrustEnrollment,
    /// Number of active session grants bound to the old audience that were
    /// revoked in the same transaction.
    pub revoked_session_grants: usize,
}

/// Explicit high-risk replacement of an enrollment pin.
///
/// Re-runs the full online verification for the new identity, applies an
/// expected-old compare-and-swap so concurrent operators cannot clobber each
/// other, revokes session grants bound to the old audience, and appends an
/// audit entry — all in one transaction. When `accept_new` is given, the
/// verified identity must equal it exactly.
pub async fn replace(
    repository_factory: &PgRepositoryFactory,
    http_client: &reqwest::Client,
    server: &PrincipalServerConfig,
    expect_old: &DidCoreId,
    accept_new: Option<&DidCoreId>,
) -> Result<ReplaceOutcome, TrustEnrollmentError> {
    let verified =
        verify_principal_server_identity(http_client, &server.endpoint, accept_new, None)
            .await
            .map_err(TrustEnrollmentError::Verification)?;

    let mut repo = repository_factory.create().await?;
    let Some(existing) = repo
        .principal_server_trust()
        .find_by_name(&server.name)
        .await?
    else {
        return Err(TrustEnrollmentError::UnknownEnrollment {
            name: server.name.clone(),
        });
    };
    if &existing.service_id != expect_old {
        return Err(TrustEnrollmentError::ExpectOldMismatch {
            expected: expect_old.to_string(),
            stored: existing.service_id.to_string(),
        });
    }
    if existing.service_id == verified.service_id {
        return Err(TrustEnrollmentError::AlreadyCurrent(
            verified.service_id.to_string(),
        ));
    }
    if let Some(configured) = server.service_id.as_ref()
        && configured != &verified.service_id
    {
        // The explicit config pin has highest priority; replacing the
        // persisted enrollment underneath it would split the deployment's
        // view of the authorization root.
        return Err(TrustEnrollmentError::ConfiguredPinMismatch {
            configured: configured.to_string(),
            verified: verified.service_id.to_string(),
        });
    }

    let applied = repo
        .principal_server_trust()
        .replace(
            &SystemClock::default(),
            &server.name,
            expect_old,
            enrollment_params(server, &verified, PrincipalServerTrustSource::OperatorCli),
        )
        .await?;
    if !applied {
        return Err(TrustEnrollmentError::ExpectOldMismatch {
            expected: expect_old.to_string(),
            stored: existing.service_id.to_string(),
        });
    }
    // Session grants minted for the old audience must not outlive the pin
    // they were issued under. Pending handoffs fail closed on their own:
    // the old audience no longer resolves to an accepted pin after the
    // replacement commits.
    let revoked_session_grants = repo
        .oauth_session_grant()
        .revoke_active_for_audience(&SystemClock::default(), expect_old.as_str())
        .await?;
    let mut rng = ChaCha20Rng::from_entropy();
    repo.principal_server_trust()
        .record_audit(
            &mut rng,
            &SystemClock::default(),
            NewPrincipalServerTrustAudit {
                enrollment_name: server.name.clone(),
                action: PrincipalServerTrustAuditAction::Replaced,
                service_id: Some(verified.service_id.clone()),
                previous_service_id: Some(expect_old.clone()),
                detail: format!(
                    "replaced pin at {}; revoked {revoked_session_grants} session grants",
                    verified.canonical_endpoint
                ),
            },
        )
        .await?;
    repo.save().await?;
    shared().note_verified(&server.endpoint, verified.service_id.clone());
    Ok(ReplaceOutcome {
        enrollment: PrincipalServerTrustEnrollment {
            name: server.name.clone(),
            canonical_endpoint: verified.canonical_endpoint.clone(),
            service_id: verified.service_id.clone(),
            full_id: verified.full_id.clone(),
            method_history_head: verified.method_history_head.clone(),
            version_id: verified.version_id.clone(),
            resolution_record_digest: verified.resolution_record_digest.clone(),
            source: PrincipalServerTrustSource::OperatorCli,
            enrolled_at: existing.enrolled_at,
            last_verified_at: Utc::now(),
        },
        revoked_session_grants,
    })
}

/// Explicit revocation of an enrollment pin.
pub async fn revoke(
    repository_factory: &PgRepositoryFactory,
    name: &str,
) -> Result<bool, TrustEnrollmentError> {
    let mut repo = repository_factory.create().await?;
    let Some(existing) = repo.principal_server_trust().find_by_name(name).await? else {
        return Err(TrustEnrollmentError::UnknownEnrollment {
            name: name.to_owned(),
        });
    };
    let revoked = repo.principal_server_trust().revoke(name).await?;
    if revoked {
        let mut rng = ChaCha20Rng::from_entropy();
        repo.principal_server_trust()
            .record_audit(
                &mut rng,
                &SystemClock::default(),
                NewPrincipalServerTrustAudit {
                    enrollment_name: name.to_owned(),
                    action: PrincipalServerTrustAuditAction::Revoked,
                    service_id: None,
                    previous_service_id: Some(existing.service_id),
                    detail: "enrollment revoked by operator".to_owned(),
                },
            )
            .await?;
    }
    repo.save().await?;
    Ok(revoked)
}

/// Whether the narrowly-scoped development auto-enrollment may run for
/// `server`: explicit development mode, an exact configured local host
/// allowlist entry, HTTPS scheme, and no existing pin of either layer.
#[must_use]
pub fn development_auto_enrollment_allowed(
    arkret_config: &ArkretConfig,
    server: &PrincipalServerConfig,
    development_mode: bool,
) -> bool {
    development_mode
        && server.endpoint.scheme() == "https"
        && server.endpoint.host_str().is_some_and(|host| {
            arkret_config.is_development_auto_enrollment_host(&host.to_ascii_lowercase())
        })
}

/// Mandatory online startup preflight for every configured Principal Server.
///
/// Resolves the effective pin (config layer, then persisted enrollment),
/// verifies the full identity chain online for each server, advances the
/// persisted anti-rollback floor, populates the request-path cache, and only
/// then returns. Any missing pin, unreachable server, invalid evidence,
/// rollback or identity mismatch fails the whole startup before the business
/// listener binds.
///
/// On success, spawns the background revalidation task which fatally shuts
/// the process down (via `soft_shutdown`) on any cryptographic identity
/// conflict, or once a last-verified value ages past
/// [`MAX_TRUSTED_AUDIENCE_AGE`] during transient network failures.
pub async fn preflight_and_spawn(
    repository_factory: PgRepositoryFactory,
    arkret_config: ArkretConfig,
    http_client: reqwest::Client,
    development_mode: bool,
    first_provisioning: bool,
    soft_shutdown: CancellationToken,
    refresh_interval: Duration,
) -> anyhow::Result<()> {
    for server in &arkret_config.principal_servers {
        preflight_server(
            &repository_factory,
            &arkret_config,
            &http_client,
            server,
            development_mode,
            first_provisioning,
        )
        .await?;
    }

    let interval = refresh_interval.clamp(MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL);
    let this = shared().clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            revalidate_all(
                &repository_factory,
                &arkret_config,
                &http_client,
                &this,
                &soft_shutdown,
            )
            .await;
        }
    });
    Ok(())
}

async fn preflight_server(
    repository_factory: &PgRepositoryFactory,
    arkret_config: &ArkretConfig,
    http_client: &reqwest::Client,
    server: &PrincipalServerConfig,
    development_mode: bool,
    first_provisioning: bool,
) -> anyhow::Result<()> {
    let canonical_endpoint = canonical_endpoint_key(&server.endpoint)
        .ok_or_else(|| anyhow::anyhow!("principal server {:?} endpoint is invalid", server.name))?;
    let mut repo = repository_factory.create().await?;
    let enrollment = repo
        .principal_server_trust()
        .find_by_endpoint(&canonical_endpoint)
        .await?;

    // Layer resolution. A config pin that disagrees with the persisted
    // enrollment is a hard conflict, never a silent choice.
    let effective = match (server.service_id.as_ref(), enrollment.as_ref()) {
        (Some(configured), Some(persisted)) if configured != &persisted.service_id => {
            anyhow::bail!(
                "principal server {:?} ({canonical_endpoint}): configured service_id {configured} conflicts with the persisted enrollment {}; resolve with `coauth principal-server trust replace` or fix the configuration",
                server.name,
                persisted.service_id,
            );
        }
        (Some(configured), _) => configured.clone(),
        (None, Some(persisted)) => persisted.service_id.clone(),
        (None, None) => {
            let auto_enroll =
                development_auto_enrollment_allowed(arkret_config, server, development_mode);
            if !auto_enroll && !first_provisioning {
                anyhow::bail!(
                    "principal server {:?} ({canonical_endpoint}) is not enrolled: no config service_id pin and no persisted trust enrollment; run `coauth principal-server trust bootstrap --name {}` first",
                    server.name,
                    server.name,
                );
            }
            let source = if auto_enroll {
                PrincipalServerTrustSource::DevelopmentAuto
            } else {
                PrincipalServerTrustSource::OperatorCli
            };
            let outcome = bootstrap(repository_factory, http_client, server, source)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "principal server {:?} trust bootstrap failed: {error}",
                        server.name
                    )
                })?;
            tracing::info!(
                name = %server.name,
                endpoint = %canonical_endpoint,
                service_id = %outcome.enrollment.service_id,
                source = source.as_str(),
                "enrolled principal-server trust pin",
            );
            return Ok(());
        }
    };

    let floor = enrollment.as_ref().map(|persisted| {
        (
            persisted.method_history_head.as_str(),
            persisted.version_id.as_str(),
        )
    });
    let verified = verify_principal_server_identity(
        http_client,
        &server.endpoint,
        Some(&effective),
        floor,
    )
    .await
    .map_err(|error| {
        anyhow::anyhow!(
            "principal server {:?} ({canonical_endpoint}) failed startup verification: {error}",
            server.name
        )
    })?;
    if enrollment.is_some() {
        repo.principal_server_trust()
            .record_verification(
                &SystemClock::default(),
                &canonical_endpoint,
                &verified.method_history_head,
                &verified.version_id,
                &verified.resolution_record_digest,
            )
            .await?;
        repo.save().await?;
    }
    shared().note_verified(&server.endpoint, effective);
    Ok(())
}

async fn revalidate_all(
    repository_factory: &PgRepositoryFactory,
    arkret_config: &ArkretConfig,
    http_client: &reqwest::Client,
    resolver: &PrincipalServerTrustResolver,
    soft_shutdown: &CancellationToken,
) {
    for server in &arkret_config.principal_servers {
        let Some(pin) = effective_audience(server, resolver) else {
            tracing::error!(
                name = %server.name,
                endpoint = %server.endpoint,
                "principal-server has no effective pin at runtime; initiating fatal shutdown",
            );
            soft_shutdown.cancel();
            return;
        };
        let floor = match repository_factory.create().await {
            Ok(mut repo) => match canonical_endpoint_key(&server.endpoint) {
                Some(endpoint) => match repo
                    .principal_server_trust()
                    .find_by_endpoint(&endpoint)
                    .await
                {
                    Ok(Some(enrollment)) => Some((
                        enrollment.method_history_head.clone(),
                        enrollment.version_id.clone(),
                    )),
                    Ok(None) => None,
                    Err(error) => {
                        tracing::warn!(%error, "failed to load trust enrollment floor; keeping last-verified state");
                        continue;
                    }
                },
                None => None,
            },
            Err(error) => {
                tracing::warn!(%error, "failed to open repository for trust revalidation; keeping last-verified state");
                continue;
            }
        };
        match verify_principal_server_identity(
            http_client,
            &server.endpoint,
            Some(&pin),
            floor
                .as_ref()
                .map(|(head, version)| (head.as_str(), version.as_str())),
        )
        .await
        {
            Ok(verified) => {
                resolver.note_verified(&server.endpoint, verified.service_id.clone());
                if let Ok(mut repo) = repository_factory.create().await
                    && let Some(endpoint) = canonical_endpoint_key(&server.endpoint)
                {
                    let result = repo
                        .principal_server_trust()
                        .record_verification(
                            &SystemClock::default(),
                            &endpoint,
                            &verified.method_history_head,
                            &verified.version_id,
                            &verified.resolution_record_digest,
                        )
                        .await;
                    match result {
                        Ok(true) => {
                            if let Err(error) = repo.save().await {
                                tracing::warn!(%error, "failed to commit trust reverification");
                            }
                        }
                        Ok(false) => {}
                        Err(error) => {
                            tracing::warn!(%error, "failed to persist trust reverification");
                        }
                    }
                }
            }
            Err(error) if error.is_transient_network() => {
                let now = Instant::now();
                match resolver.last_verified_age(&server.endpoint, now) {
                    Some(age) if age < resolver.max_trusted_age => {
                        tracing::warn!(
                            name = %server.name,
                            endpoint = %server.endpoint,
                            %error,
                            remaining_trust_seconds = resolver.max_trusted_age.saturating_sub(age).as_secs(),
                            "principal-server revalidation failed transiently; retaining last-verified pin",
                        );
                    }
                    _ => {
                        tracing::error!(
                            name = %server.name,
                            endpoint = %server.endpoint,
                            %error,
                            "principal-server unreachable beyond the maximum trusted age; initiating fatal shutdown",
                        );
                        soft_shutdown.cancel();
                        return;
                    }
                }
            }
            Err(error) => {
                tracing::error!(
                    name = %server.name,
                    endpoint = %server.endpoint,
                    %error,
                    "principal-server identity conflict detected at runtime; initiating fatal shutdown",
                );
                soft_shutdown.cancel();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(endpoint: &str) -> PrincipalServerConfig {
        PrincipalServerConfig {
            name: "soland".to_owned(),
            endpoint: Url::parse(endpoint).unwrap(),
            service_id: Some(DidCoreId::new("ak:did_core:webvh:configured".to_owned()).unwrap()),
            session_grant_introspection_bearer: None,
            embedded_webvh_registration_bearer: None,
        }
    }

    #[test]
    fn configured_pin_wins_over_cached_enrollment_value() {
        let resolver = PrincipalServerTrustResolver::new();
        let endpoint = "https://local.host/";
        resolver.insert_for_test(
            &Url::parse(endpoint).unwrap(),
            "ak:did_core:webvh:persisted",
        );
        let server = server(endpoint);
        assert_eq!(
            effective_audience(&server, &resolver)
                .as_ref()
                .map(arkret_identifiers::DidCoreId::as_str),
            Some("ak:did_core:webvh:configured"),
        );
    }

    #[test]
    fn persisted_pin_resolves_when_config_omits_pin() {
        let resolver = PrincipalServerTrustResolver::new();
        let endpoint = Url::parse("https://local.host/").unwrap();
        resolver.insert_for_test(&endpoint, "ak:did_core:webvh:persisted");
        let mut server = server(endpoint.as_str());
        server.service_id = None;
        assert_eq!(
            effective_audience(&server, &resolver)
                .as_ref()
                .map(DidCoreId::as_str),
            Some("ak:did_core:webvh:persisted"),
        );
    }

    #[test]
    fn missing_pin_in_both_layers_fails_closed() {
        let resolver = PrincipalServerTrustResolver::new();
        let mut server = server("https://local.host/");
        server.service_id = None;
        assert_eq!(effective_audience(&server, &resolver), None);
    }

    #[test]
    fn canonical_endpoint_key_ignores_trailing_slash() {
        assert_eq!(
            canonical_endpoint_key(&Url::parse("https://local.host/").unwrap()),
            canonical_endpoint_key(&Url::parse("https://local.host").unwrap()),
        );
    }

    #[test]
    fn cached_pin_expires_at_maximum_trusted_age() {
        let resolver = PrincipalServerTrustResolver::new();
        let endpoint = Url::parse("https://local.host/").unwrap();
        let verified_at = Instant::now();
        resolver.note_verified_at(
            &endpoint,
            DidCoreId::new("ak:did_core:webvh:persisted".to_owned()).unwrap(),
            verified_at,
        );

        let before_expiry = (verified_at + MAX_TRUSTED_AUDIENCE_AGE)
            .checked_sub(Duration::from_nanos(1))
            .unwrap();
        assert!(resolver.resolve_at(&endpoint, before_expiry).is_some());
        assert_eq!(
            resolver.resolve_at(&endpoint, verified_at + MAX_TRUSTED_AUDIENCE_AGE),
            None
        );
    }

    #[test]
    fn anti_rollback_accepts_monotone_history() {
        check_anti_rollback("sha256:aa", "1-aa", "sha256:bb", "2-bb").unwrap();
        check_anti_rollback("sha256:aa", "1-aa", "sha256:aa", "1-aa").unwrap();
    }

    #[test]
    fn anti_rollback_rejects_regression() {
        assert!(check_anti_rollback("sha256:bb", "2-bb", "sha256:aa", "1-aa").is_err());
        // Same sequence with a different head is a fork, not progress.
        assert!(check_anti_rollback("sha256:aa", "1-aa", "sha256:cc", "1-cc").is_err());
    }

    #[test]
    fn development_auto_enrollment_requires_conjunction() {
        let config = ArkretConfig {
            development_auto_enrollment_hosts: vec!["localhost".to_owned()],
            ..ArkretConfig::default()
        };
        let mut server = server("https://localhost:8448/");
        server.service_id = None;

        assert!(development_auto_enrollment_allowed(&config, &server, true));
        // Not in development mode.
        assert!(!development_auto_enrollment_allowed(
            &config, &server, false
        ));
        // Host not in the exact allowlist.
        let other = PrincipalServerConfig {
            endpoint: Url::parse("https://soland.local/").unwrap(),
            ..server.clone()
        };
        assert!(!development_auto_enrollment_allowed(&config, &other, true));
        // Plain HTTP is never auto-enrolled.
        let insecure = PrincipalServerConfig {
            endpoint: Url::parse("http://localhost:8448/").unwrap(),
            ..server.clone()
        };
        assert!(!development_auto_enrollment_allowed(
            &config, &insecure, true
        ));
    }
}
