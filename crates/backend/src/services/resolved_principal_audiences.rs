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
use std::time::Duration;

use coauth_config::{ArkretConfig, PrincipalServerConfig};
use url::Url;

use crate::outbound_http;

/// Root-relative describe path served by every Arkret Principal Server.
const DESCRIBE_PATH: &str = "/_arkret/describe";

/// Refresh-interval floor: faster than this just hammers the Principal
/// Server's describe surface.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Refresh-interval ceiling: a rotated / poisoned describe document MUST NOT
/// stay live indefinitely (mirrors `MetadataCache::MAX_REFRESH_INTERVAL`).
const MAX_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default refresh cadence used at server startup.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

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

/// Endpoint (normalized string) → current resolved `service_id` for principal
/// servers whose `audience` is not explicitly pinned. Cheap to clone (the map
/// is behind an `Arc`); all clones share the same underlying cache.
#[derive(Debug, Default, Clone)]
pub struct ResolvedPrincipalAudiences {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl ResolvedPrincipalAudiences {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current resolved `service_id` for `endpoint`, if a describe probe has
    /// succeeded at least once. Synchronous — safe to call from the
    /// request-path audience checks. Returns `None` until the first successful
    /// probe, so callers MUST fail closed on `None`.
    #[must_use]
    pub fn resolve(&self, endpoint: &Url) -> Option<String> {
        let key = endpoint_key(endpoint);
        self.inner.read().ok()?.get(&key).cloned()
    }

    /// Test/seed helper: insert a resolved value directly without a probe.
    #[cfg(test)]
    pub fn insert_for_test(&self, endpoint: &Url, service_id: impl Into<String>) {
        self.inner
            .write()
            .expect("resolved-audience lock poisoned")
            .insert(endpoint_key(endpoint), service_id.into());
    }

    /// Probe every principal server that omits an explicit `audience` once
    /// (synchronously awaited), then spawn a background task that re-probes at
    /// `interval` (clamped into `[MIN, MAX]`). Probe failures keep the last
    /// known value and log a warning — fail-open to the previously resolved
    /// audience rather than dropping it.
    pub fn warm_up_and_spawn(
        &self,
        http_client: reqwest::Client,
        arkret_config: ArkretConfig,
        interval: Duration,
    ) {
        let interval = interval.clamp(MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL);
        let this = self.clone();
        tokio::spawn(async move {
            this.refresh_all(&http_client, &arkret_config).await;
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
            if server.audience.is_some() {
                continue;
            }
            match fetch_service_id(http_client, &server.endpoint).await {
                Ok(service_id) => {
                    if let Ok(mut map) = self.inner.write() {
                        map.insert(endpoint_key(&server.endpoint), service_id);
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        endpoint = %server.endpoint,
                        name = %server.name,
                        %error,
                        "failed to resolve principal-server audience from /_arkret/describe; keeping last known value",
                    );
                }
            }
        }
    }
}

/// The audience to enforce for `server`: the explicit pin when configured,
/// else the dynamically-resolved current `service_id`. Returns `None` for an
/// unpinned server whose describe probe has not yet succeeded — callers MUST
/// fail closed (do not admit an unknown audience).
#[must_use]
pub fn effective_audience(
    server: &PrincipalServerConfig,
    resolved: &ResolvedPrincipalAudiences,
) -> Option<String> {
    match server
        .audience
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
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

async fn fetch_service_id(
    http_client: &reqwest::Client,
    endpoint: &Url,
) -> Result<String, String> {
    let describe_url = endpoint
        .join(DESCRIBE_PATH)
        .map_err(|error| format!("invalid principal-server endpoint: {error}"))?;

    let response = outbound_http::send_with_policy(
        outbound_http::soland_policy("principal_describe"),
        || http_client.get(describe_url.clone()),
    )
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

    // `/_arkret/describe` returns `ServerDescribeOutcome(ServerDescription)`,
    // a transparent newtype, so the wire body deserializes straight into
    // `ServerDescription`.
    let description: arkret_core::ServerDescription = serde_json::from_str(&text)
        .map_err(|error| format!("invalid describe body: {error}"))?;

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
        resolved.insert_for_test(&Url::parse(endpoint).unwrap(), "did:webvh:new:local.host:webvh:service");
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
        resolved.insert_for_test(&Url::parse(endpoint).unwrap(), "did:webvh:current:local.host:webvh:service");
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
}
