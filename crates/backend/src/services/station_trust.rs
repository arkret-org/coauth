//! Station trust resolution: three-layer pin resolution, asynchronous server
//! startup verification, mandatory worker preflight, one-time bootstrap and
//! explicit replacement.
//!
//! ## Why
//!
//! `/_arkret/describe` is capability metadata, not an authorization root.
//! `overview/architecture.md` §2.8 makes the owning Station's identity,
//! endpoint and trust domain explicit deployment configuration: a missing or
//! conflicting configuration MUST be rejected, a target change MUST go through
//! an explicit rebinding, and the runtime MUST NOT fall back to guessing the
//! peer from `describe`, from the first `stations[]` entry or from a network
//! error. The effective audience pin for each configured Station is
//! resolved from exactly one of three layers, in priority order:
//!
//! 1. the explicit config pin (`stations[].service_id`);
//! 2. the persisted trust enrollment written by an explicit `coauth station trust bootstrap` /
//!    `replace` (or, in development mode only, the host-allowlisted auto-enrollment);
//! 3. nothing — business routes remain unavailable and point at the bootstrap command.
//!
//! A remote describe response only ever *confirms* a pin. It can never
//! create or replace one outside the explicit bootstrap/replace operations,
//! and an endpoint that starts presenting a different identity keeps its
//! pinned one until an operator rebinds it.
//!
//! ## Concurrency
//!
//! The request-path cache is a bounded `std::sync::RwLock<HashMap>` keyed by
//! canonical endpoint. Servers populate it asynchronously while exposing only
//! discovery, JWKS and health; workers populate it with
//! [`preflight_and_spawn`] before processing jobs. It is refreshed by the
//! background revalidation task, so synchronous audience checks never perform
//! I/O. Correctness never depends on the cache: a missing or expired entry
//! fails closed, and the revalidation task fatally shuts the process down once
//! a verified value exceeds [`MAX_TRUSTED_AUDIENCE_AGE`] without refresh, or
//! immediately on a cryptographic identity conflict.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use arkret_identity::{DidResolver as _, DidWebvhResolver};
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, canonical_service_resolution_path,
};
use arkret_wire::{Did, DidCoreId, Hash, ServiceKind};
use chrono::Utc;
use coauth_config::{ArkretConfig, StationConfig};
use coauth_data::storage::station_trust::{
    NewStationTrustAudit, NewStationTrustEnrollment, StationTrustAuditAction,
    StationTrustEnrollment, StationTrustSource,
};
use coauth_data::{RepositoryAccess, RepositoryError, RepositoryFactory, SystemClock};
use coauth_storage_postgres::PgRepositoryFactory;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::outbound_http;

/// Root-relative describe path served by every Arkret Station.
pub(crate) const DESCRIBE_PATH: &str = "_arkret/describe";

/// Revalidation-interval floor: faster than this just hammers the Station's
/// describe surface.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_mins(1);

/// Revalidation-interval ceiling. Keeping this well below
/// [`MAX_TRUSTED_AUDIENCE_AGE`] guarantees repeated revalidation opportunities
/// before a previously verified value expires.
const MAX_REFRESH_INTERVAL: Duration = Duration::from_hours(1);

/// Default revalidation cadence used at server startup.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

/// Retry cadence while the owning Station has not completed its own startup.
///
/// Coauth must publish OIDC discovery and its public JWKS before a fresh
/// Station can authorize the Account Authority key in its DID document.  The
/// business surface remains fail-closed until this retry loop verifies every
/// configured Station.
pub const DEFAULT_INITIAL_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum age of a verified audience. Once this age is reached, request-path
/// lookups return `None` and the background revalidation task treats the
/// state as expired, terminating the service.
pub const MAX_TRUSTED_AUDIENCE_AGE: Duration = Duration::from_hours(24);

/// Hard upper bound on a fetched authenticated service resolution, matching
/// the SDK transport bound (`SERVICE_RESOLUTION_FETCH_MAX_BYTES`).
const AUTHENTICATED_RESOLUTION_MAX_BYTES: usize =
    arkret_http_client::SERVICE_RESOLUTION_FETCH_MAX_BYTES;

/// Defensive cache bound. The cache only ever holds one entry per configured
/// Station; this cap bounds damage if that invariant ever breaks.
const MAX_CACHE_ENTRIES: usize = 64;

/// Bounded audit detail length. Audit entries never carry bearer tokens,
/// private keys or raw evidence.
const AUDIT_DETAIL_MAX_CHARS: usize = 256;

/// Process-wide shared resolver. Populated by [`preflight_and_spawn`] before
/// the business listener binds and read by the request-path audience checks
/// via [`shared`].
static SHARED: LazyLock<StationTrustResolver> = LazyLock::new(StationTrustResolver::new);

/// The process-wide Station trust resolver.
#[must_use]
pub fn shared() -> &'static StationTrustResolver {
    &SHARED
}

/// Canonical endpoint (normalized string) → verified `service_id` pin and the
/// time it was last verified online. Cheap to clone (the map is behind an
/// `Arc`); all clones share the same underlying cache.
#[derive(Debug, Clone)]
pub struct StationTrustResolver {
    inner: Arc<RwLock<HashMap<String, ResolvedPin>>>,
    max_trusted_age: Duration,
}

#[derive(Debug, Clone)]
struct ResolvedPin {
    value: DidCoreId,
    last_verified_at: Instant,
}

impl Default for StationTrustResolver {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            max_trusted_age: MAX_TRUSTED_AUDIENCE_AGE,
        }
    }
}

impl StationTrustResolver {
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
    ///
    /// A target change never rides in here: if the endpoint already holds a
    /// different identity, this refuses the write and leaves the previous pin
    /// in place. Moving an endpoint to a new identity MUST go through the
    /// explicit rebinding operation ([`replace`], via [`Self::note_rebound`]).
    pub(crate) fn note_verified(&self, endpoint: &Url, service_id: DidCoreId) {
        self.write_pin(endpoint, service_id, Instant::now(), PinWrite::Verified);
    }

    /// Record the outcome of an explicit rebinding, which is the only path
    /// allowed to move an endpoint to a different identity.
    pub(crate) fn note_rebound(&self, endpoint: &Url, service_id: DidCoreId) {
        self.write_pin(endpoint, service_id, Instant::now(), PinWrite::Rebound);
    }

    fn write_pin(&self, endpoint: &Url, service_id: DidCoreId, now: Instant, write: PinWrite) {
        let Some(key) = canonical_endpoint_key(endpoint) else {
            return;
        };
        if let Ok(mut map) = self.inner.write() {
            if let Some(existing) = map.get_mut(&key) {
                if existing.value == service_id {
                    existing.last_verified_at = now;
                } else if write == PinWrite::Rebound {
                    *existing = ResolvedPin {
                        value: service_id,
                        last_verified_at: now,
                    };
                } else {
                    tracing::error!(
                        endpoint = %endpoint,
                        pinned = %existing.value,
                        observed = %service_id,
                        "station identity changed without an explicit rebinding; keeping the pinned identity",
                    );
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
                    "station trust cache is full; refusing to cache pin",
                );
            }
        }
    }

    /// Test/seed helper: insert a resolved value directly without a probe.
    #[cfg(test)]
    pub fn insert_for_test(&self, endpoint: &Url, service_id: impl Into<String>) {
        let service_id = DidCoreId::new(service_id.into()).expect("valid test Station core ID");
        self.write_pin(endpoint, service_id, Instant::now(), PinWrite::Rebound);
    }
}

/// Which caller is writing a pin: an ordinary verification, which MUST NOT
/// move an endpoint to a different identity, or an explicit rebinding, which
/// is the only operation allowed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinWrite {
    Verified,
    Rebound,
}

/// The effective authorization audience for `server`.
///
/// Three-layer resolution: the explicit config pin wins when present; the
/// verified persisted enrollment pin (cached by preflight) is used when the
/// config omits the pin; otherwise `None` and callers fail closed. Describe
/// metadata never supplies this value.
#[must_use]
pub fn effective_audience(
    server: &StationConfig,
    resolver: &StationTrustResolver,
) -> Option<DidCoreId> {
    server
        .service_id
        .clone()
        .or_else(|| resolver.resolve(&server.endpoint))
}

/// [`effective_audience`] against the process-wide [`shared`] resolver — the
/// common form for call sites that don't thread a resolver handle.
#[must_use]
pub fn effective_audience_shared(server: &StationConfig) -> Option<DidCoreId> {
    effective_audience(server, shared())
}

/// Whether every configured Station has been verified online in this process
/// and the owning Station identity has been delegated to the Account
/// Authority runtime.
///
/// An empty Station list needs no trust gate. A configured static `service_id`
/// is not sufficient here: readiness requires fresh endpoint verification,
/// represented by the resolver cache populated by the verifier.
#[must_use]
pub fn is_ready(arkret_config: &ArkretConfig) -> bool {
    if arkret_config.stations.is_empty() {
        return true;
    }
    arkret_config
        .stations
        .iter()
        .all(|server| shared().resolve(&server.endpoint).is_some())
        && arkret_config
            .runtime_owning_station_identity
            .get()
            .is_some()
}

/// Canonical cache/storage key for an endpoint.
fn canonical_endpoint_key(endpoint: &Url) -> Option<String> {
    CanonicalServiceUrl::canonicalize(endpoint.as_str())
        .ok()
        .map(|canonical| canonical.to_string())
}

/// Classification of an online Station identity verification
/// failure.
#[derive(Debug, thiserror::Error)]
pub enum TrustVerificationError {
    /// The endpoint is not a canonical HTTPS base URL.
    #[error("station endpoint is not a canonical HTTPS base URL: {0}")]
    InvalidEndpoint(String),
    /// Transient network failure: connect, DNS or timeout. This is the only
    /// class the runtime revalidation tolerates for a bounded last-verified
    /// age.
    #[error("station is unreachable: {0}")]
    Unreachable(String),
    /// The target was denied by the outbound egress policy (SSRF/DNS
    /// rebinding protection).
    #[error("station target denied by egress policy: {0}")]
    EgressDenied(String),
    /// The response carried the wrong service role.
    #[error("wrong service kind: expected station, observed {0}")]
    WrongServiceKind(String),
    /// DID Document, WebVH history, resolution proof or freshness failed
    /// verification.
    #[error("invalid station identity evidence: {0}")]
    InvalidEvidence(String),
    /// The observed service id does not equal the effective pin.
    #[error("observed service_id {observed} does not match the effective pin {expected}")]
    IdentityMismatch {
        /// The effective pin (config or persisted enrollment).
        expected: String,
        /// The service id the endpoint currently presents.
        observed: String,
    },
    /// The DID service state does not bind to the configured endpoint.
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

/// Fully verified Station identity material, ready to persist as a
/// trust enrollment or to confirm an existing pin.
#[derive(Debug, Clone)]
pub struct VerifiedStationIdentity {
    /// Stable service core id (the pin).
    pub service_id: DidCoreId,
    /// Service DID verified against its WebVH history.
    pub did: Did,
    /// Verified WebVH method-history head (`sha256:` digest of the head
    /// entry) — the anti-rollback floor.
    pub method_history_head: String,
    /// Verified WebVH version id of the head entry.
    pub version_id: String,
    /// Canonical endpoint the identity is bound to.
    pub canonical_endpoint: String,
}

async fn fetch_bounded(
    http_client: &reqwest::Client,
    operation: &'static str,
    url: Url,
    max_bytes: usize,
    arkret_operation: Option<&str>,
) -> Result<Vec<u8>, TrustVerificationError> {
    let policy = outbound_http::principal_trust_policy(operation);
    let result = if let Some(operation_id) = arkret_operation {
        outbound_http::fetch_bounded_arkret(http_client, policy, url, max_bytes, operation_id).await
    } else {
        outbound_http::fetch_bounded(http_client, policy, url, max_bytes).await
    };
    result.map_err(|error| match error {
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

/// Fetch and fully verify the current Station identity material for
/// `endpoint`.
///
/// Verification chain, all fail-closed:
///
/// 1. canonical HTTPS endpoint under the configured egress policy;
/// 2. role-scoped typed `ServiceDescribe` with `service_kind == station`;
/// 3. `project(did) == service_id`;
/// 4. full WebVH history verification; the describe resolution commitment must equal the verified
///    head (version id and head digest);
/// 5. complete DID service resolution from the canonical path, proof verified against the
///    WebVH-anchored DID Document, freshness checked;
/// 6. the verified DID endpoint matches the configured endpoint and Describe transport;
/// 7. the observed `service_id` must equal `expected_service_id` when given;
/// 8. anti-rollback: the verified coordinates must not regress below `floor` when given.
pub async fn verify_station_identity(
    http_client: &reqwest::Client,
    endpoint: &Url,
    expected_service_id: Option<&DidCoreId>,
    floor: Option<(&str, &str)>,
) -> Result<VerifiedStationIdentity, TrustVerificationError> {
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
        .append_pair("service_kind", ServiceKind::Station.as_str());
    let describe_bytes = fetch_bounded(
        http_client,
        "principal_trust_describe",
        describe_url,
        outbound_http::DESCRIBE_MAX_BYTES,
        Some(arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1),
    )
    .await?;
    let description: ServiceDescribe = serde_json::from_slice(&describe_bytes)
        .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    description
        .validate()
        .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if description.service_kind != ServiceKind::Station {
        return Err(TrustVerificationError::WrongServiceKind(
            description.service_kind.as_str().to_owned(),
        ));
    }
    if description.protocol_version.as_str() != arkret_wire::PROTOCOL_VERSION {
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
        &commitment.did,
        &service_id,
    )
    .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;

    // 4. WebVH history verification; the describe commitment must equal the
    // verified head.
    let log_url = Url::parse(
        &DidWebvhResolver::log_url(&commitment.did)
            .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?,
    )
    .map_err(|error| TrustVerificationError::InvalidEndpoint(error.to_string()))?;
    let log_bytes = fetch_bounded(
        http_client,
        "principal_trust_webvh_log",
        log_url,
        outbound_http::WEBVH_LOG_MAX_BYTES,
        None,
    )
    .await?;
    let verified_log =
        arkret_identity::verify_did_webvh_v1_chain_bytes(&commitment.did, &log_bytes)
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
    if document.id != commitment.did {
        return Err(TrustVerificationError::InvalidEvidence(format!(
            "verified DID Document id {} does not match {}",
            document.id, commitment.did
        )));
    }

    // The accepted native head must occur in the independently fetched history.
    if let Some((floor_head, floor_version_id)) = floor {
        check_anti_rollback(
            floor_head,
            floor_version_id,
            &commitment.method_history_head,
            &commitment.version_id,
        )?;
        let accepted_present = verified_log.raw_entries.iter().any(|entry| {
            entry.get("versionId").and_then(serde_json::Value::as_str) == Some(floor_version_id)
                && arkret_canonical::canonical_sha256(entry).ok().as_deref() == Some(floor_head)
        });
        if !accepted_present {
            return Err(TrustVerificationError::InvalidEvidence(
                "current DID history omits the accepted native state".into(),
            ));
        }
    }

    // 5. Complete authenticated resolution from the canonical path. The open
    // endpoint carries the DID service state together with its retained method
    // history and normalized DID Document; the DID service state remains the
    // persisted digest/pin material.
    let record_url = Url::parse(&format!(
        "{canonical_endpoint}{}",
        canonical_service_resolution_path(&service_id).trim_start_matches('/')
    ))
    .map_err(|error| TrustVerificationError::InvalidEndpoint(error.to_string()))?;
    let record_bytes = fetch_bounded(
        http_client,
        "principal_trust_resolution_record",
        record_url.clone(),
        AUTHENTICATED_RESOLUTION_MAX_BYTES,
        Some(arkret_wire::ServiceOperationId::OPEN_SERVICE_READ_RESOLUTION_V1),
    )
    .await?;
    let authenticated_resolution: AuthenticatedServiceResolution =
        arkret_canonical::canonical::from_canonical_json_slice(&record_bytes)
            .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    let current = resolve_current_service_did(http_client, &commitment.did).await?;
    let projection = arkret_identity::verify_current_service_resolution(
        &authenticated_resolution,
        &service_id,
        ServiceKind::Station.as_str(),
        &current,
        Utc::now(),
    )
    .map_err(|error| TrustVerificationError::InvalidEvidence(error.to_string()))?;
    if projection.did != commitment.did
        || projection.method_history_head != commitment.method_history_head
        || projection.version_id != commitment.version_id
    {
        return Err(TrustVerificationError::InvalidEvidence(
            "resolution disagrees with describe method commitment".into(),
        ));
    }
    if projection.base_url != canonical_endpoint {
        return Err(TrustVerificationError::EndpointBinding(
            "DID service endpoint differs from configured endpoint".into(),
        ));
    }
    description
        .validate_route_projection(&projection)
        .map_err(|error| TrustVerificationError::EndpointBinding(error.to_string()))?;

    Ok(VerifiedStationIdentity {
        service_id,
        did: commitment.did,
        method_history_head: commitment.method_history_head,
        version_id: commitment.version_id,
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
        "endpoint {endpoint} is already enrolled with service_id {existing}; use `coauth station trust replace` to change it"
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
    pub enrollment: StationTrustEnrollment,
    /// Whether the enrollment already existed with the same identity.
    pub already_enrolled: bool,
}

fn enrollment_params(
    server: &StationConfig,
    verified: &VerifiedStationIdentity,
    source: StationTrustSource,
) -> NewStationTrustEnrollment {
    NewStationTrustEnrollment {
        name: server.name.clone(),
        canonical_endpoint: verified.canonical_endpoint.clone(),
        service_id: verified.service_id.clone(),
        did: verified.did.clone(),
        method_history_head: verified.method_history_head.clone(),
        version_id: verified.version_id.clone(),
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
                .station_trust()
                .record_audit(
                    &mut rng,
                    &SystemClock::default(),
                    NewStationTrustAudit {
                        enrollment_name: name.to_owned(),
                        action: StationTrustAuditAction::VerificationFailed,
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

/// One-time idempotent trust bootstrap for one configured Station.
///
/// Verifies the DID control chain online, then creates the enrollment and
/// its audit entry in a single transaction. Re-running with an unchanged
/// identity succeeds without altering the pin; an endpoint enrolled with a
/// different identity is rejected in favour of the explicit replace flow.
pub async fn bootstrap(
    repository_factory: &PgRepositoryFactory,
    http_client: &reqwest::Client,
    server: &StationConfig,
    source: StationTrustSource,
) -> Result<BootstrapOutcome, TrustEnrollmentError> {
    let verified = match verify_station_identity(
        http_client,
        &server.endpoint,
        server.service_id.as_ref(),
        None,
    )
    .await
    {
        Ok(verified) => verified,
        Err(error) => {
            // The asynchronous server bootstrap retries ordinary outages.
            // Recording every 5-second 502/timeout would turn expected startup
            // ordering into an unbounded audit-log write loop. Evidence and
            // policy failures remain durable audit events.
            if !error.is_transient_network() {
                record_failure_audit(
                    repository_factory,
                    &server.name,
                    server.service_id.clone(),
                    error.to_string(),
                )
                .await;
            }
            return Err(error.into());
        }
    };

    let mut repo = repository_factory.create().await?;
    // Bind the lookup result first: the repository guard borrows `repo`
    // mutably, and holding it across the `if let` scrutinee would block the
    // writes in the idempotent-rerun path.
    let existing_by_endpoint = repo
        .station_trust()
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
        repo.station_trust()
            .record_verification(
                &SystemClock::default(),
                &verified.canonical_endpoint,
                &verified.did,
                &verified.method_history_head,
                &verified.version_id,
            )
            .await?;
        repo.save().await?;
        shared().note_verified(&server.endpoint, verified.service_id.clone());
        return Ok(BootstrapOutcome {
            enrollment: existing,
            already_enrolled: true,
        });
    }
    if let Some(existing) = repo.station_trust().find_by_name(&server.name).await? {
        return Err(TrustEnrollmentError::ConflictingName {
            name: server.name.clone(),
            existing: existing.canonical_endpoint,
        });
    }

    let params = enrollment_params(server, &verified, source);
    let enrollment = repo
        .station_trust()
        .enroll(&SystemClock::default(), params)
        .await?;
    let mut rng = ChaCha20Rng::from_entropy();
    repo.station_trust()
        .record_audit(
            &mut rng,
            &SystemClock::default(),
            NewStationTrustAudit {
                enrollment_name: server.name.clone(),
                action: StationTrustAuditAction::Enrolled,
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
    pub enrollment: StationTrustEnrollment,
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
    server: &StationConfig,
    expect_old: &DidCoreId,
    accept_new: Option<&DidCoreId>,
) -> Result<ReplaceOutcome, TrustEnrollmentError> {
    let verified = verify_station_identity(http_client, &server.endpoint, accept_new, None)
        .await
        .map_err(TrustEnrollmentError::Verification)?;

    let mut repo = repository_factory.create().await?;
    let Some(existing) = repo.station_trust().find_by_name(&server.name).await? else {
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
        .station_trust()
        .replace(
            &SystemClock::default(),
            &server.name,
            expect_old,
            enrollment_params(server, &verified, StationTrustSource::OperatorCli),
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
        .revoke_active_for_audience(&SystemClock::default(), expect_old)
        .await?;
    let mut rng = ChaCha20Rng::from_entropy();
    repo.station_trust()
        .record_audit(
            &mut rng,
            &SystemClock::default(),
            NewStationTrustAudit {
                enrollment_name: server.name.clone(),
                action: StationTrustAuditAction::Replaced,
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
    // The one operation allowed to move this endpoint to a different identity.
    shared().note_rebound(&server.endpoint, verified.service_id.clone());
    Ok(ReplaceOutcome {
        enrollment: StationTrustEnrollment {
            name: server.name.clone(),
            canonical_endpoint: verified.canonical_endpoint.clone(),
            service_id: verified.service_id.clone(),
            did: verified.did.clone(),
            method_history_head: verified.method_history_head.clone(),
            version_id: verified.version_id.clone(),
            source: StationTrustSource::OperatorCli,
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
    let Some(existing) = repo.station_trust().find_by_name(name).await? else {
        return Err(TrustEnrollmentError::UnknownEnrollment {
            name: name.to_owned(),
        });
    };
    let revoked = repo.station_trust().revoke(name).await?;
    if revoked {
        let mut rng = ChaCha20Rng::from_entropy();
        repo.station_trust()
            .record_audit(
                &mut rng,
                &SystemClock::default(),
                NewStationTrustAudit {
                    enrollment_name: name.to_owned(),
                    action: StationTrustAuditAction::Revoked,
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
    server: &StationConfig,
    development_mode: bool,
) -> bool {
    development_mode
        && server.endpoint.scheme() == "https"
        && server.endpoint.host_str().is_some_and(|host| {
            arkret_config.is_development_auto_enrollment_host(&host.to_ascii_lowercase())
        })
}

/// Mandatory online startup preflight for every configured Station.
///
/// Resolves the effective pin (config layer, then persisted enrollment),
/// verifies the DID control chain online for each server, advances the
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
    soft_shutdown: CancellationToken,
    refresh_interval: Duration,
) -> anyhow::Result<()> {
    for server in &arkret_config.stations {
        preflight_server(
            &repository_factory,
            &arkret_config,
            &http_client,
            server,
            development_mode,
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

/// How often the background verifier retries a cold Station and how often it
/// revalidates a warm one.
///
/// The two intervals are one decision — the retry cadence before trust is
/// ready and the refresh cadence after — so they travel together rather than
/// as two adjacent `Duration` parameters a caller can silently transpose.
#[derive(Clone, Copy, Debug)]
pub struct RevalidationSchedule {
    pub initial_retry: Duration,
    pub refresh: Duration,
}

impl RevalidationSchedule {
    pub const DEFAULT: Self = Self {
        initial_retry: DEFAULT_INITIAL_RETRY_INTERVAL,
        refresh: DEFAULT_REFRESH_INTERVAL,
    };
}

/// Start Station trust verification without delaying the HTTP listener.
///
/// This is the server startup path. A fresh Station needs Coauth's public JWK
/// before it can finish provisioning, so requiring the Station to be online
/// before Coauth binds creates a cold-start cycle. The router exposes only
/// discovery, JWKS and health while [`is_ready`] is false; all business
/// requests fail closed with 503.
///
/// Workers still use [`preflight_and_spawn`], because they expose no bootstrap
/// HTTP surface and must not process jobs before Station trust is ready.
pub fn spawn_preflight_and_revalidation(
    repository_factory: PgRepositoryFactory,
    arkret_config: ArkretConfig,
    http_client: reqwest::Client,
    development_mode: bool,
    soft_shutdown: CancellationToken,
    schedule: RevalidationSchedule,
) {
    let initial_retry_interval = schedule.initial_retry.max(Duration::from_secs(1));
    let refresh_interval = schedule
        .refresh
        .clamp(MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL);
    let resolver = shared().clone();
    tokio::spawn(async move {
        loop {
            let mut failure = None;
            for server in &arkret_config.stations {
                if let Err(error) = preflight_server(
                    &repository_factory,
                    &arkret_config,
                    &http_client,
                    server,
                    development_mode,
                )
                .await
                {
                    failure = Some((server, error));
                    break;
                }
            }

            match failure {
                None => {
                    tracing::info!("Station trust is ready; enabling Coauth business routes");
                    break;
                }
                Some((server, error)) => {
                    tracing::warn!(
                        name = %server.name,
                        endpoint = %server.endpoint,
                        %error,
                        retry_seconds = initial_retry_interval.as_secs(),
                        "Station trust is not ready; Coauth bootstrap routes remain available",
                    );
                }
            }

            tokio::select! {
                () = tokio::time::sleep(initial_retry_interval) => {}
                () = soft_shutdown.cancelled() => return,
            }
        }

        loop {
            tokio::select! {
                () = tokio::time::sleep(refresh_interval) => {
                    revalidate_all(
                        &repository_factory,
                        &arkret_config,
                        &http_client,
                        &resolver,
                        &soft_shutdown,
                    )
                    .await;
                }
                () = soft_shutdown.cancelled() => return,
            }
        }
    });
}

fn delegate_owning_station_identity(
    arkret_config: &ArkretConfig,
    server: &StationConfig,
    station_id: DidCoreId,
    did: Did,
) {
    if arkret_config
        .owning_station()
        .is_some_and(|owner| owner.name == server.name)
    {
        arkret_config
            .runtime_owning_station_identity
            .store(station_id, did);
    }
}

async fn preflight_server(
    repository_factory: &PgRepositoryFactory,
    arkret_config: &ArkretConfig,
    http_client: &reqwest::Client,
    server: &StationConfig,
    development_mode: bool,
) -> anyhow::Result<()> {
    let canonical_endpoint = canonical_endpoint_key(&server.endpoint)
        .ok_or_else(|| anyhow::anyhow!("Station {:?} endpoint is invalid", server.name))?;
    let mut repo = repository_factory.create().await?;
    let enrollment = repo
        .station_trust()
        .find_by_endpoint(&canonical_endpoint)
        .await?;

    // Layer resolution. A config pin that disagrees with the persisted
    // enrollment is a hard conflict, never a silent choice.
    // `overview/architecture.md` §2.8 / `service-http-binding.md` §2.2.3: the
    // owning Station's identity, endpoint and trust domain come from explicit
    // deployment configuration. A missing pin is a rejection and a conflicting
    // pin is a hard failure; neither is ever resolved by adopting whatever
    // identity `describe` currently asserts.
    let effective = match (server.service_id.as_ref(), enrollment.as_ref()) {
        (Some(configured), Some(persisted)) if configured != &persisted.service_id => {
            anyhow::bail!(
                "Station {:?} ({canonical_endpoint}): configured service_id {configured} conflicts with the persisted enrollment {}; resolve with `coauth station trust replace` or fix the configuration",
                server.name,
                persisted.service_id,
            );
        }
        (Some(configured), _) => configured.clone(),
        (None, Some(persisted)) => persisted.service_id.clone(),
        (None, None) => {
            if !development_auto_enrollment_allowed(arkret_config, server, development_mode) {
                anyhow::bail!(
                    "Station {:?} ({canonical_endpoint}) is not enrolled: no config service_id pin and no persisted trust enrollment; set `stations[].service_id` or run `coauth station trust bootstrap --name {}` first",
                    server.name,
                    server.name,
                );
            }
            let source = StationTrustSource::DevelopmentAuto;
            let outcome = bootstrap(repository_factory, http_client, server, source)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Station {:?} trust bootstrap failed: {error}", server.name)
                })?;
            tracing::info!(
                name = %server.name,
                endpoint = %canonical_endpoint,
                service_id = %outcome.enrollment.service_id,
                source = source.as_str(),
                "enrolled station trust pin",
            );
            delegate_owning_station_identity(
                arkret_config,
                server,
                outcome.enrollment.service_id,
                outcome.enrollment.did,
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
    let verified = verify_station_identity(http_client, &server.endpoint, Some(&effective), floor)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "Station {:?} ({canonical_endpoint}) failed startup verification: {error}",
                server.name
            )
        })?;
    if enrollment.is_some() {
        repo.station_trust()
            .record_verification(
                &SystemClock::default(),
                &canonical_endpoint,
                &verified.did,
                &verified.method_history_head,
                &verified.version_id,
            )
            .await?;
        repo.save().await?;
    }
    shared().note_verified(&server.endpoint, effective.clone());
    delegate_owning_station_identity(arkret_config, server, effective, verified.did);
    Ok(())
}

async fn revalidate_all(
    repository_factory: &PgRepositoryFactory,
    arkret_config: &ArkretConfig,
    http_client: &reqwest::Client,
    resolver: &StationTrustResolver,
    soft_shutdown: &CancellationToken,
) {
    for server in &arkret_config.stations {
        let Some(pin) = effective_audience(server, resolver) else {
            tracing::error!(
                name = %server.name,
                endpoint = %server.endpoint,
                "station has no effective pin at runtime; initiating fatal shutdown",
            );
            soft_shutdown.cancel();
            return;
        };
        let floor = match repository_factory.create().await {
            Ok(mut repo) => match canonical_endpoint_key(&server.endpoint) {
                Some(endpoint) => match repo.station_trust().find_by_endpoint(&endpoint).await {
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
        match verify_station_identity(
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
                delegate_owning_station_identity(
                    arkret_config,
                    server,
                    verified.service_id.clone(),
                    verified.did.clone(),
                );
                if let Ok(mut repo) = repository_factory.create().await
                    && let Some(endpoint) = canonical_endpoint_key(&server.endpoint)
                {
                    let result = repo
                        .station_trust()
                        .record_verification(
                            &SystemClock::default(),
                            &endpoint,
                            &verified.did,
                            &verified.method_history_head,
                            &verified.version_id,
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
                            "station revalidation failed transiently; retaining last-verified pin",
                        );
                    }
                    _ => {
                        tracing::error!(
                            name = %server.name,
                            endpoint = %server.endpoint,
                            %error,
                            "station unreachable beyond the maximum trusted age; initiating fatal shutdown",
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
                    "station identity conflict detected at runtime; initiating fatal shutdown",
                );
                soft_shutdown.cancel();
                return;
            }
        }
    }
}

/// Fetch the method authority independently of carried evidence, with the shared egress policy.
pub(crate) async fn resolve_current_service_did(
    http: &reqwest::Client,
    did: &Did,
) -> Result<arkret_identity::ResolvedDid, TrustVerificationError> {
    let invalid =
        |e: arkret_identity::IdentityError| TrustVerificationError::InvalidEvidence(e.to_string());
    let doc_url = DidWebvhResolver::document_url(did).map_err(invalid)?;
    let log_url = DidWebvhResolver::log_url(did).map_err(invalid)?;
    let parse_url = |value: &str| {
        Url::parse(value).map_err(|e| TrustVerificationError::InvalidEndpoint(e.to_string()))
    };
    let (doc_type, doc) = fetch_method_response(
        http,
        "service_current_document",
        parse_url(&doc_url)?,
        AUTHENTICATED_RESOLUTION_MAX_BYTES,
    )
    .await?;
    let (log_type, log) = fetch_method_response(
        http,
        "service_current_log",
        parse_url(&log_url)?,
        outbound_http::WEBVH_LOG_MAX_BYTES,
    )
    .await?;
    let mut resolver = DidWebvhResolver::new();
    resolver
        .insert_from_https_response(
            did,
            arkret_identity::DidWebvhDocumentOutcome {
                url: doc_url,
                content_type: doc_type,
                body: doc,
            },
        )
        .map_err(invalid)?;
    resolver
        .ingest_log(
            did,
            arkret_identity::DidWebvhLogOutcome {
                url: log_url,
                content_type: log_type,
                body: log,
            },
        )
        .map_err(invalid)?;
    let witness_url = DidWebvhResolver::witness_url(did).map_err(invalid)?;
    if let Ok(witness) = fetch_bounded(
        http,
        "service_current_witness",
        parse_url(&witness_url)?,
        AUTHENTICATED_RESOLUTION_MAX_BYTES,
        None,
    )
    .await
    {
        resolver
            .ingest_witness_records(did, &witness)
            .map_err(invalid)?;
    }
    resolver.resolve_did(did).map_err(invalid)
}

async fn fetch_method_response(
    http: &reqwest::Client,
    operation: &'static str,
    url: Url,
    max_bytes: usize,
) -> Result<(String, Vec<u8>), TrustVerificationError> {
    outbound_http::fetch_bounded_with_content_type(
        http,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn server(endpoint: &str) -> StationConfig {
        StationConfig {
            name: "soland".to_owned(),
            endpoint: Url::parse(endpoint).unwrap(),
            service_id: Some(DidCoreId::new("ak:did_core:webvh:configured".to_owned()).unwrap()),
            session_grant_introspection_bearer: None,
            embedded_webvh_registration_bearer: None,
            trust_domain: None,
        }
    }

    #[test]
    fn configured_pin_wins_over_cached_enrollment_value() {
        let resolver = StationTrustResolver::new();
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
        let resolver = StationTrustResolver::new();
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
        let resolver = StationTrustResolver::new();
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
        let resolver = StationTrustResolver::new();
        let endpoint = Url::parse("https://local.host/").unwrap();
        let verified_at = Instant::now();
        resolver.write_pin(
            &endpoint,
            DidCoreId::new("ak:did_core:webvh:persisted".to_owned()).unwrap(),
            verified_at,
            PinWrite::Verified,
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

    /// A target change MUST go through an explicit rebinding; an endpoint that
    /// starts presenting a different identity never silently takes over the
    /// pin an ordinary verification refreshes.
    #[test]
    fn changed_station_identity_keeps_the_pin_until_an_explicit_rebinding() {
        let resolver = StationTrustResolver::new();
        let endpoint = Url::parse("https://local.host/").unwrap();
        let pinned = DidCoreId::new("ak:did_core:webvh:pinned".to_owned()).unwrap();
        let replacement = DidCoreId::new("ak:did_core:webvh:replacement".to_owned()).unwrap();
        let at = Instant::now();

        resolver.write_pin(&endpoint, pinned.clone(), at, PinWrite::Verified);
        resolver.write_pin(&endpoint, replacement.clone(), at, PinWrite::Verified);
        assert_eq!(resolver.resolve_at(&endpoint, at), Some(pinned));

        resolver.write_pin(&endpoint, replacement.clone(), at, PinWrite::Rebound);
        assert_eq!(resolver.resolve_at(&endpoint, at), Some(replacement));
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
        let other = StationConfig {
            endpoint: Url::parse("https://soland.local/").unwrap(),
            ..server.clone()
        };
        assert!(!development_auto_enrollment_allowed(&config, &other, true));
        // Plain HTTP is never auto-enrolled.
        let insecure = StationConfig {
            endpoint: Url::parse("http://localhost:8448/").unwrap(),
            ..server.clone()
        };
        assert!(!development_auto_enrollment_allowed(
            &config, &insecure, true
        ));
    }
}
