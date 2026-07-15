//! Dynamic resolution of a Principal Server's *current* service DID for
//! `arkret.principal_servers[]` entries that omit an explicit `audience`.
//!
//! ## Why
//!
//! A Principal Server's `service_id` is a `did:webvh:<SCID>:<domain>:webvh:service`
//! where `<SCID>` is the content hash of the DID genesis (its signing key). A
//! data / key reset rotates the SCID. When coauth pins `audience` statically,
//! the reset silently invalidates the whitelist and every session-grant
//! exchange fails with `audience_mismatch`.
//!
//! When a `principal_servers[]` entry omits `audience`, coauth instead resolves
//! the Principal Server's current `service_id` from `<endpoint>/_arkret/describe`
//! and refreshes it on a background interval. The trust anchor moves from "the
//! pinned SCID" down to "the configured `endpoint` host (+ TLS)" — the
//! deliberate self-hosted / dev trade-off. Entries that DO pin `audience` keep
//! the strict SCID check.
//!
//! ## Concurrency
//!
//! The cache is a `std::sync::RwLock<HashMap>` so the synchronous request-path
//! audience checks can read a snapshot without becoming `async`. The background
//! refresh task holds the write lock only for the brief map insert, never
//! across an `.await`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use coauth_config::{ArkretConfig, PrincipalServerConfig};
use url::Url;

use crate::outbound_http;

/// Root-relative describe path served by every Arkret Principal Server.
const DESCRIBE_PATH: &str = "/_arkret/describe";

/// Refresh-interval floor: faster than this just hammers the Principal
/// Server's describe surface.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_mins(1);

/// Refresh-interval ceiling. Keeping this well below
/// [`MAX_TRUSTED_AUDIENCE_AGE`] guarantees repeated refresh opportunities
/// before a previously resolved value expires.
const MAX_REFRESH_INTERVAL: Duration = Duration::from_hours(1);

/// Default refresh cadence used at server startup.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

/// Maximum age of a dynamically discovered audience. Once this age is
/// reached, request-path lookups return `None` until discovery succeeds again.
pub const MAX_TRUSTED_AUDIENCE_AGE: Duration = Duration::from_hours(24);

/// Process-wide shared cache. Populated by [`ResolvedPrincipalAudiences::warm_up_and_spawn`]
/// at server startup and read by the request-path audience checks via
/// [`shared`]. Mirrors the `JWKS_CACHE` singleton pattern in `app_state`.
static SHARED: LazyLock<ResolvedPrincipalAudiences> =
    LazyLock::new(ResolvedPrincipalAudiences::new);

/// The process-wide resolved-audience cache.
#[must_use]
pub fn shared() -> &'static ResolvedPrincipalAudiences {
    &SHARED
}

/// Endpoint (normalized string) → current resolved `service_id` and the time
/// it was observed for principal servers whose `audience` is not explicitly
/// pinned. Cheap to clone (the map is behind an `Arc`); all clones share the
/// same underlying cache.
#[derive(Debug, Clone)]
pub struct ResolvedPrincipalAudiences {
    inner: Arc<RwLock<HashMap<String, ResolvedAudience>>>,
    max_trusted_age: Duration,
}

#[derive(Debug, Clone)]
struct ResolvedAudience {
    value: String,
    resolved_at: Instant,
}

impl Default for ResolvedPrincipalAudiences {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            max_trusted_age: MAX_TRUSTED_AUDIENCE_AGE,
        }
    }
}

impl ResolvedPrincipalAudiences {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn with_max_trusted_age_for_test(max_trusted_age: Duration) -> Self {
        Self {
            inner: Arc::default(),
            max_trusted_age,
        }
    }

    /// Current resolved `service_id` for `endpoint`, if a describe probe has
    /// succeeded within [`MAX_TRUSTED_AUDIENCE_AGE`]. Synchronous — safe to
    /// call from the request-path audience checks. Returns `None` before the
    /// first successful probe and after expiry, so callers MUST fail closed on
    /// `None`.
    #[must_use]
    pub fn resolve(&self, endpoint: &Url) -> Option<String> {
        self.resolve_at(endpoint, Instant::now())
    }

    fn resolve_at(&self, endpoint: &Url, now: Instant) -> Option<String> {
        let key = endpoint_key(endpoint);
        let map = self.inner.read().ok()?;
        let resolved = map.get(&key)?;
        (now.saturating_duration_since(resolved.resolved_at) < self.max_trusted_age)
            .then(|| resolved.value.clone())
    }

    /// Test/seed helper: insert a resolved value directly without a probe.
    #[cfg(test)]
    pub fn insert_for_test(&self, endpoint: &Url, service_id: impl Into<String>) {
        self.insert_at_for_test(endpoint, service_id, Instant::now());
    }

    #[cfg(test)]
    fn insert_at_for_test(
        &self,
        endpoint: &Url,
        service_id: impl Into<String>,
        resolved_at: Instant,
    ) {
        self.inner
            .write()
            .expect("resolved-audience lock poisoned")
            .insert(
                endpoint_key(endpoint),
                ResolvedAudience {
                    value: service_id.into(),
                    resolved_at,
                },
            );
    }

    /// Probe every principal server that omits an explicit `audience` once
    /// (synchronously awaited), then spawn a background task that re-probes at
    /// `interval` (clamped into `[MIN, MAX]`). The initial probe remains
    /// synchronously awaited before the refresh task is spawned. Probe
    /// failures retain a still-trusted last-known value, but an expired value
    /// fails closed and produces a high-visibility error.
    pub async fn warm_up_and_spawn(
        &self,
        http_client: reqwest::Client,
        arkret_config: ArkretConfig,
        interval: Duration,
    ) {
        let interval = interval.clamp(MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL);
        self.refresh_all(&http_client, &arkret_config).await;

        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                this.refresh_all(&http_client, &arkret_config).await;
            }
        });
    }

    async fn refresh_all(&self, http_client: &reqwest::Client, arkret_config: &ArkretConfig) {
        for server in &arkret_config.principal_servers {
            // Explicitly-pinned entries keep their strict SCID check; never
            // override them from the (mutable) describe document.
            if server.normalized_audience().is_some() {
                continue;
            }
            let result = fetch_service_id(http_client, &server.endpoint).await;
            self.apply_refresh_result(server, result, Instant::now());
        }
    }

    fn apply_refresh_result(
        &self,
        server: &PrincipalServerConfig,
        result: Result<String, String>,
        now: Instant,
    ) {
        let key = endpoint_key(&server.endpoint);
        match result {
            Ok(service_id) => {
                if let Ok(mut map) = self.inner.write() {
                    map.insert(
                        key,
                        ResolvedAudience {
                            value: service_id,
                            resolved_at: now,
                        },
                    );
                }
            }
            Err(error) => match self.cached_age(&key, now) {
                Some(age) if age >= self.max_trusted_age => {
                    tracing::error!(
                        endpoint = %server.endpoint,
                        name = %server.name,
                        %error,
                        cached_age_seconds = age.as_secs(),
                        max_trusted_age_seconds = self.max_trusted_age.as_secs(),
                        "failed to refresh principal-server audience and the cached value has expired; authentication is failing closed until discovery recovers",
                    );
                }
                Some(age) => {
                    tracing::warn!(
                        endpoint = %server.endpoint,
                        name = %server.name,
                        %error,
                        cached_age_seconds = age.as_secs(),
                        remaining_trust_seconds = (self.max_trusted_age - age).as_secs(),
                        "failed to refresh principal-server audience; retaining the last known value until its maximum trusted age",
                    );
                }
                None => {
                    tracing::error!(
                        endpoint = %server.endpoint,
                        name = %server.name,
                        %error,
                        "failed to resolve principal-server audience and no trusted cached value exists; authentication is failing closed until discovery succeeds",
                    );
                }
            },
        }
    }

    fn cached_age(&self, key: &str, now: Instant) -> Option<Duration> {
        let map = self.inner.read().ok()?;
        let resolved = map.get(key)?;
        Some(now.saturating_duration_since(resolved.resolved_at))
    }
}

/// The audience to enforce for `server`: the explicit pin when configured,
/// else the dynamically-resolved current `service_id`. Returns `None` for an
/// unpinned server whose describe probe has not yet succeeded or whose cached
/// value expired — callers MUST fail closed (do not admit an unknown or stale
/// audience).
#[must_use]
pub fn effective_audience(
    server: &PrincipalServerConfig,
    resolved: &ResolvedPrincipalAudiences,
) -> Option<String> {
    match server.normalized_audience() {
        Some(explicit) => Some(explicit.to_owned()),
        None => resolved.resolve(&server.endpoint),
    }
}

/// [`effective_audience`] against the process-wide [`shared`] cache — the
/// common form for call sites that don't thread a cache handle.
#[must_use]
pub fn effective_audience_shared(server: &PrincipalServerConfig) -> Option<String> {
    effective_audience(server, shared())
}

/// Normalized cache key for an endpoint (trailing slash stripped so
/// `https://h/` and `https://h` collide).
fn endpoint_key(endpoint: &Url) -> String {
    endpoint.as_str().trim_end_matches('/').to_owned()
}

async fn fetch_service_id(http_client: &reqwest::Client, endpoint: &Url) -> Result<String, String> {
    let describe_url = endpoint
        .join(DESCRIBE_PATH)
        .map_err(|error| format!("invalid principal-server endpoint: {error}"))?;

    let response =
        outbound_http::send_with_policy(outbound_http::soland_policy("principal_describe"), || {
            http_client.get(describe_url.clone())
        })
        .await
        .map_err(|error| format!("transport error: {error}"))?;

    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "describe returned status {status}: {}",
            text.chars().take(256).collect::<String>()
        ));
    }

    // `/_arkret/describe` returns `ServerDescribeOutcome(ServiceDescribe)`,
    // a transparent newtype, so the wire body deserializes straight into
    // `ServiceDescribe`.
    let description: arkret_core::ServiceDescribe =
        serde_json::from_str(&text).map_err(|error| format!("invalid describe body: {error}"))?;

    let service_id = description.service_id.as_str().trim().to_owned();
    if service_id.is_empty() {
        return Err("describe published an empty service_id".to_owned());
    }
    Ok(service_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(audience: Option<&str>, endpoint: &str) -> PrincipalServerConfig {
        PrincipalServerConfig {
            name: "soland".to_owned(),
            audience: audience.map(ToOwned::to_owned),
            endpoint: Url::parse(endpoint).unwrap(),
            did: None,
            session_grant_introspection_bearer: None,
            embedded_webvh_registration_bearer: None,
        }
    }

    #[test]
    fn explicit_audience_wins_and_ignores_resolved() {
        let resolved = ResolvedPrincipalAudiences::new();
        let endpoint = "https://local.host/";
        resolved.insert_for_test(
            &Url::parse(endpoint).unwrap(),
            "did:webvh:new:local.host:webvh:service",
        );
        let server = server(Some("did:webvh:pinned:local.host:webvh:service"), endpoint);
        assert_eq!(
            effective_audience(&server, &resolved).as_deref(),
            Some("did:webvh:pinned:local.host:webvh:service"),
        );
    }

    #[test]
    fn unpinned_uses_resolved_value() {
        let resolved = ResolvedPrincipalAudiences::new();
        let endpoint = "https://local.host/";
        resolved.insert_for_test(
            &Url::parse(endpoint).unwrap(),
            "did:webvh:current:local.host:webvh:service",
        );
        let server = server(None, endpoint);
        assert_eq!(
            effective_audience(&server, &resolved).as_deref(),
            Some("did:webvh:current:local.host:webvh:service"),
        );
    }

    #[test]
    fn unpinned_without_probe_is_none() {
        let resolved = ResolvedPrincipalAudiences::new();
        let server = server(None, "https://local.host/");
        assert_eq!(effective_audience(&server, &resolved), None);
    }

    #[test]
    fn endpoint_key_ignores_trailing_slash() {
        assert_eq!(
            endpoint_key(&Url::parse("https://local.host/").unwrap()),
            endpoint_key(&Url::parse("https://local.host").unwrap()),
        );
    }

    #[test]
    fn cached_audience_expires_at_maximum_trusted_age() {
        let resolved = ResolvedPrincipalAudiences::new();
        let endpoint = Url::parse("https://local.host/").unwrap();
        let resolved_at = Instant::now();
        resolved.insert_at_for_test(
            &endpoint,
            "did:webvh:current:local.host:webvh:service",
            resolved_at,
        );

        assert!(
            resolved
                .resolve_at(
                    &endpoint,
                    resolved_at + MAX_TRUSTED_AUDIENCE_AGE - Duration::from_nanos(1)
                )
                .is_some()
        );
        assert_eq!(
            resolved.resolve_at(&endpoint, resolved_at + MAX_TRUSTED_AUDIENCE_AGE),
            None
        );
    }

    #[test]
    fn refresh_failures_retain_fresh_value_then_fail_closed_after_expiry() {
        let resolved = ResolvedPrincipalAudiences::new();
        let server = server(None, "https://local.host/");
        let resolved_at = Instant::now();
        resolved.apply_refresh_result(
            &server,
            Ok("did:webvh:current:local.host:webvh:service".to_owned()),
            resolved_at,
        );

        let before_expiry = resolved_at + MAX_TRUSTED_AUDIENCE_AGE - Duration::from_secs(1);
        resolved.apply_refresh_result(
            &server,
            Err("describe unavailable".to_owned()),
            before_expiry,
        );
        assert!(
            resolved
                .resolve_at(&server.endpoint, before_expiry)
                .is_some()
        );

        let at_expiry = resolved_at + MAX_TRUSTED_AUDIENCE_AGE;
        resolved.apply_refresh_result(&server, Err("describe unavailable".to_owned()), at_expiry);
        assert_eq!(resolved.resolve_at(&server.endpoint, at_expiry), None);
    }
}
