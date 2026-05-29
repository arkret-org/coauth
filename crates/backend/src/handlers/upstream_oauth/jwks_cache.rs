//! A small JWKS cache keyed by `jwks_uri`.
//!
//! The standard-OIDC callback ([`super::callback`]) needs the upstream
//! provider's JWKS to verify ID-token / signed-userinfo signatures. Without
//! caching, every single login performs a fresh network `GET` against the
//! provider's `jwks_uri`. The keys behind a `jwks_uri` rotate rarely (hours to
//! days), so re-fetching on every callback is pure overhead and adds an extra
//! upstream round-trip to the hot login path.
//!
//! This cache mirrors the style of [`super::cache::MetadataCache`]:
//! `Arc<RwLock<HashMap<_, _>>>` shared across requests, never evicts, does not
//! cache failures. It additionally tracks a fetched-at instant per entry and
//! honours a TTL so a rotated keyset cannot stay live indefinitely.
//!
//! ## Key rotation
//!
//! Caching JWKS introduces a staleness window: if the upstream rotates its
//! signing key, a cached keyset can lag behind for up to [`Self::TTL`]. The
//! callback verification path defends against this by calling
//! [`JwksCache::force_refresh`] and retrying verification once when the cached
//! keyset fails to verify a signature — see `super::callback`.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use coauth_jose::jwk::PublicJsonWebKeySet;
use tokio::sync::RwLock;
use url::Url;

use crate::oidc_client::error::JwksError;

/// A cached JWKS together with the instant it was fetched.
#[derive(Debug, Clone)]
struct CachedEntry {
    jwks: PublicJsonWebKeySet,
    fetched_at: Instant,
}

/// A simple JWKS cache keyed by the `jwks_uri` it was fetched from.
///
/// It never evicts entries, does not cache failures and is cheap to clone (the
/// inner map is shared behind an `Arc`). Entries older than [`Self::TTL`] are
/// treated as a miss and re-fetched on access, bounding staleness after an
/// upstream key rotation.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct JwksCache {
    cache: Arc<RwLock<HashMap<Url, CachedEntry>>>,
}

impl JwksCache {
    /// How long a cached JWKS is served before it is considered stale and
    /// re-fetched. Mirrors the lower bound of
    /// [`super::cache::MetadataCache`]'s refresh window — long enough to
    /// absorb the per-login fetch storm, short enough that an upstream key
    /// rotation heals on its own without relying solely on the
    /// verify-failure force-refresh path.
    pub const TTL: Duration = Duration::from_mins(15);

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch the JWKS over the network and store it in the cache.
    #[tracing::instrument(name = "jwks_cache.fetch", fields(%jwks_uri), skip_all)]
    async fn fetch(
        &self,
        client: &reqwest::Client,
        jwks_uri: &Url,
    ) -> Result<PublicJsonWebKeySet, JwksError> {
        let jwks = crate::oidc_client::requests::jose::fetch_jwks(client, jwks_uri).await?;

        self.cache.write().await.insert(
            jwks_uri.clone(),
            CachedEntry {
                jwks: jwks.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(jwks)
    }

    /// Get the JWKS for the given `jwks_uri`, fetching it over the network on a
    /// cache miss or when the cached entry has exceeded [`Self::TTL`].
    ///
    /// # Errors
    ///
    /// Returns an error if the JWKS could not be fetched.
    #[tracing::instrument(name = "jwks_cache.get_or_fetch", fields(%jwks_uri), skip_all)]
    pub async fn get_or_fetch(
        &self,
        client: &reqwest::Client,
        jwks_uri: &Url,
    ) -> Result<PublicJsonWebKeySet, JwksError> {
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(jwks_uri) {
                if entry.fetched_at.elapsed() < Self::TTL {
                    return Ok(entry.jwks.clone());
                }
            }
        }
        // Either a miss or a stale entry: drop the read guard and fetch.
        self.fetch(client, jwks_uri).await
    }

    /// Force a fresh fetch of the JWKS, bypassing any cached entry, and update
    /// the cache with the result.
    ///
    /// Used by the callback verification path when a cached keyset fails to
    /// verify a signature — the upstream may have rotated its signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the JWKS could not be fetched.
    #[tracing::instrument(name = "jwks_cache.force_refresh", fields(%jwks_uri), skip_all)]
    pub async fn force_refresh(
        &self,
        client: &reqwest::Client,
        jwks_uri: &Url,
    ) -> Result<PublicJsonWebKeySet, JwksError> {
        self.fetch(client, jwks_uri).await
    }
}
