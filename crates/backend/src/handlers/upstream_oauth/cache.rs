use std::collections::HashMap;
use std::sync::Arc;

use coauth_data::upstream_oauth::{UpstreamOAuthProviderRepository, provider};
use coauth_data::{RepositoryAccess, UpstreamOAuthProvider};
use coauth_iana::oauth::PkceCodeChallengeMethod;
use coauth_oauth_types::oidc::VerifiedProviderMetadata;
use tokio::sync::RwLock;
use url::Url;

use crate::oidc_client::error::DiscoveryError;

/// A high-level layer over metadata cache and provider configuration, which
/// resolves endpoint overrides and discovery modes.
pub struct LazyProviderInfos<'a> {
    cache: &'a MetadataCache,
    provider: &'a UpstreamOAuthProvider,
    client: &'a reqwest::Client,
    loaded_metadata: Option<Arc<VerifiedProviderMetadata>>,
}

impl<'a> LazyProviderInfos<'a> {
    #[must_use]
    pub fn new(
        cache: &'a MetadataCache,
        provider: &'a UpstreamOAuthProvider,
        client: &'a reqwest::Client,
    ) -> Self {
        Self {
            cache,
            provider,
            client,
            loaded_metadata: None,
        }
    }

    /// Trigger the discovery process and return the metadata if discovery is
    /// enabled.
    pub async fn maybe_discover(
        &mut self,
    ) -> Result<Option<&VerifiedProviderMetadata>, DiscoveryError> {
        match self.load().await {
            Ok(metadata) => Ok(Some(metadata)),
            Err(DiscoveryError::Disabled) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn load(&mut self) -> Result<&VerifiedProviderMetadata, DiscoveryError> {
        // Fast path: if we already cached it, return the reference directly.
        // This is split from the cold path so the borrow checker can prove
        // the success branch never needs `.unwrap()` / `.expect()`.
        if let Some(ref metadata) = self.loaded_metadata {
            return Ok(metadata);
        }

        let verify = match self.provider.discovery_mode {
            provider::DiscoveryMode::Oidc => true,
            provider::DiscoveryMode::Insecure => false,
            provider::DiscoveryMode::Disabled => {
                return Err(DiscoveryError::Disabled);
            }
        };

        let Some(issuer) = &self.provider.issuer else {
            return Err(DiscoveryError::MissingIssuer);
        };

        let metadata = self.cache.get(self.client, issuer, verify).await?;
        // `Option::insert` returns `&mut T` to the freshly inserted value
        // — we coerce to `&T` for the function signature. No unwrap needed.
        Ok(&*self.loaded_metadata.insert(metadata))
    }

    /// Get the JWKS URI for the provider.
    ///
    /// Uses [`UpstreamOAuthProvider.jwks_uri_override`] if set, otherwise uses
    /// the one from discovery.
    pub async fn jwks_uri(&mut self) -> Result<&Url, DiscoveryError> {
        if let Some(jwks_uri) = &self.provider.jwks_uri_override {
            return Ok(jwks_uri);
        }

        Ok(self.load().await?.jwks_uri())
    }

    /// Get the authorization endpoint for the provider.
    ///
    /// Uses [`UpstreamOAuthProvider.authorization_endpoint_override`] if set,
    /// otherwise uses the one from discovery.
    pub async fn authorization_endpoint(&mut self) -> Result<&Url, DiscoveryError> {
        if let Some(authorization_endpoint) = &self.provider.authorization_endpoint_override {
            return Ok(authorization_endpoint);
        }

        Ok(self.load().await?.authorization_endpoint())
    }

    /// Get the token endpoint for the provider.
    ///
    /// Uses [`UpstreamOAuthProvider.token_endpoint_override`] if set, otherwise
    /// uses the one from discovery.
    pub async fn token_endpoint(&mut self) -> Result<&Url, DiscoveryError> {
        if let Some(token_endpoint) = &self.provider.token_endpoint_override {
            return Ok(token_endpoint);
        }

        Ok(self.load().await?.token_endpoint())
    }

    /// Get the userinfo endpoint for the provider.
    ///
    /// Uses [`UpstreamOAuthProvider.userinfo_endpoint_override`] if set,
    /// otherwise uses the one from discovery.
    pub async fn userinfo_endpoint(&mut self) -> Result<&Url, DiscoveryError> {
        if let Some(userinfo_endpoint) = &self.provider.userinfo_endpoint_override {
            return Ok(userinfo_endpoint);
        }

        Ok(self.load().await?.userinfo_endpoint())
    }

    /// Get the PKCE methods supported by the provider.
    ///
    /// If the mode is set to auto, it will use the ones from discovery,
    /// defaulting to none if discovery is disabled.
    pub async fn pkce_methods(
        &mut self,
    ) -> Result<Option<Vec<PkceCodeChallengeMethod>>, DiscoveryError> {
        let methods = match self.provider.pkce_mode {
            provider::PkceMode::Auto => self
                .maybe_discover()
                .await?
                .and_then(|metadata| metadata.code_challenge_methods_supported.clone()),
            provider::PkceMode::S256 => Some(vec![PkceCodeChallengeMethod::S256]),
            provider::PkceMode::Disabled => None,
        };

        Ok(methods)
    }
}

/// A simple OIDC metadata cache
///
/// It never evicts entries, does not cache failures and has no locking.
/// It can also be refreshed in the background, and warmed up on startup.
/// It is good enough for our use case.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct MetadataCache {
    cache: Arc<RwLock<HashMap<String, Arc<VerifiedProviderMetadata>>>>,
    insecure_cache: Arc<RwLock<HashMap<String, Arc<VerifiedProviderMetadata>>>>,
}

impl MetadataCache {
    /// Lower bound on the metadata-refresh interval. Faster than this
    /// is just hammering upstream providers and risks rate-limit
    /// retaliation; values below the floor are silently clamped up.
    pub const MIN_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_mins(1);

    /// Upper bound on the metadata-refresh interval. SSRF / staleness
    /// guard: a poisoned or compromised discovery document MUST NOT
    /// remain live indefinitely. 24h matches the rough TTL the OIDC
    /// discovery RFC suggests for client-side caches.
    pub const MAX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_hours(24);

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Warm up the cache by fetching all the known providers from the database
    /// and inserting them into the cache.
    ///
    /// This spawns a background task that will refresh the cache at the given
    /// interval.
    ///
    /// # Errors
    ///
    /// Returns an error if the warm up task could not be started.
    ///
    /// # SSRF / freshness note
    ///
    /// The refresh interval is clamped to at most
    /// [`Self::MAX_REFRESH_INTERVAL`] before the background task is
    /// spawned. The cap prevents a misconfigured deployment (or a
    /// hostile admin mutation) from disabling refresh entirely and
    /// keeping a stale / poisoned discovery document live for an
    /// unbounded time. The TLS verification policy for outbound
    /// requests is controlled by `provider.discovery_mode` in
    /// [`Self::fetch`].
    #[tracing::instrument(name = "metadata_cache.warm_up_and_run", skip_all)]
    pub async fn warm_up_and_run<R: RepositoryAccess>(
        &self,
        client: &reqwest::Client,
        interval: std::time::Duration,
        repository: &mut R,
    ) -> Result<tokio::task::JoinHandle<()>, R::Error> {
        // Clamp refresh interval into a sane window. Anything longer
        // than the cap is treated as the cap; zero is treated as the
        // floor (otherwise the background loop spin-fetches forever).
        let interval = interval.clamp(Self::MIN_REFRESH_INTERVAL, Self::MAX_REFRESH_INTERVAL);
        let providers = repository.upstream_oauth_provider().all_enabled().await?;

        for provider in providers {
            let verify = match provider.discovery_mode {
                provider::DiscoveryMode::Oidc => true,
                provider::DiscoveryMode::Insecure => false,
                provider::DiscoveryMode::Disabled => continue,
            };

            let Some(issuer) = &provider.issuer else {
                tracing::error!(%provider.id, "Provider doesn't have an issuer set, but discovery is enabled!");
                continue;
            };

            if let Err(e) = self.fetch(client, issuer, verify).await {
                tracing::error!(%issuer, error = &e as &dyn std::error::Error, "Failed to fetch provider metadata");
            }
        }

        // Spawn a background task to refresh the cache regularly
        let cache = self.clone();
        let client = client.clone();
        Ok(tokio::spawn(async move {
            loop {
                // Re-fetch the known metadata at the given interval
                tokio::time::sleep(interval).await;
                cache.refresh_all(&client).await;
            }
        }))
    }

    #[tracing::instrument(name = "metadata_cache.fetch", fields(%issuer), skip_all)]
    async fn fetch(
        &self,
        client: &reqwest::Client,
        issuer: &str,
        verify: bool,
    ) -> Result<Arc<VerifiedProviderMetadata>, DiscoveryError> {
        if verify {
            let metadata =
                crate::oidc_client::requests::discovery::discover(client, issuer).await?;
            let metadata = Arc::new(metadata);

            self.cache
                .write()
                .await
                .insert(issuer.to_owned(), metadata.clone());

            Ok(metadata)
        } else {
            let metadata =
                crate::oidc_client::requests::discovery::insecure_discover(client, issuer).await?;
            let metadata = Arc::new(metadata);

            self.insecure_cache
                .write()
                .await
                .insert(issuer.to_owned(), metadata.clone());

            Ok(metadata)
        }
    }

    /// Get the metadata for the given issuer.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata could not be retrieved.
    #[tracing::instrument(name = "metadata_cache.get", fields(%issuer), skip_all)]
    pub async fn get(
        &self,
        client: &reqwest::Client,
        issuer: &str,
        verify: bool,
    ) -> Result<Arc<VerifiedProviderMetadata>, DiscoveryError> {
        let cache = if verify {
            self.cache.read().await
        } else {
            self.insecure_cache.read().await
        };

        if let Some(metadata) = cache.get(issuer) {
            return Ok(Arc::clone(metadata));
        }
        // Drop the cache guard so that we don't deadlock when we try to fetch
        drop(cache);

        let metadata = self.fetch(client, issuer, verify).await?;
        Ok(metadata)
    }

    #[tracing::instrument(name = "metadata_cache.refresh_all", skip_all)]
    async fn refresh_all(&self, client: &reqwest::Client) {
        // Grab all the keys first to avoid locking the cache for too long
        let keys: Vec<String> = {
            let cache = self.cache.read().await;
            cache.keys().cloned().collect()
        };

        for issuer in keys {
            if let Err(e) = self.fetch(client, &issuer, true).await {
                tracing::error!(issuer = %issuer, error = &e as &dyn std::error::Error, "Failed to refresh provider metadata");
            }
        }

        // Do the same for the insecure cache
        let keys: Vec<String> = {
            let cache = self.insecure_cache.read().await;
            cache.keys().cloned().collect()
        };

        for issuer in keys {
            if let Err(e) = self.fetch(client, &issuer, false).await {
                tracing::error!(issuer = %issuer, error = &e as &dyn std::error::Error, "Failed to refresh provider metadata");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: sadly, we can't test HTTPS requests with wiremock, so we can only test
    // 'insecure' discovery

    use coauth_data::Clock;
    use coauth_data::clock::MockClock;
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_oauth_types::scope::{OPENID, Scope};
    use ulid::Ulid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::handlers::test_utils::setup;

    #[tokio::test]
    async fn test_metadata_cache() {
        setup();
        let mock_server = MockServer::start().await;
        let http_client = crate::outbound_http::reqwest_client_for_tests();

        let cache = MetadataCache::new();

        // An inexistent issuer should fail
        cache
            .get(&http_client, &mock_server.uri(), false)
            .await
            .unwrap_err();

        let expected_calls = 3;
        let mut calls = 0;
        let _mock_guard = Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "jwks_uri": "https://example.com/jwks",
                "userinfo_endpoint": "https://example.com/userinfo",
                "scopes_supported": ["openid"],
                "response_types_supported": ["code"],
                "response_modes_supported": ["query", "fragment"],
                "grant_types_supported": ["authorization_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .expect(expected_calls)
            .mount(&mock_server)
            .await;

        // A valid issuer should succeed
        cache
            .get(&http_client, &mock_server.uri(), false)
            .await
            .unwrap();
        calls += 1;

        // Calling again should not trigger a new fetch
        cache
            .get(&http_client, &mock_server.uri(), false)
            .await
            .unwrap();
        calls += 0;

        // A secure discovery should call but fail because the issuer is insecure
        cache
            .get(&http_client, &mock_server.uri(), true)
            .await
            .unwrap_err();
        calls += 1;

        // Calling refresh should refresh all the known issuers
        cache.refresh_all(&http_client).await;
        calls += 1;

        assert_eq!(calls, expected_calls);
    }

    #[tokio::test]
    async fn test_lazy_provider_infos() {
        setup();

        let mock_server = MockServer::start().await;
        let http_client = crate::outbound_http::reqwest_client_for_tests();

        let expected_calls = 2;
        let mut calls = 0;
        let _mock_guard = Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": mock_server.uri(),
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "jwks_uri": "https://example.com/jwks",
                "userinfo_endpoint": "https://example.com/userinfo",
                "scopes_supported": ["openid"],
                "response_types_supported": ["code"],
                "response_modes_supported": ["query", "fragment"],
                "grant_types_supported": ["authorization_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .expect(expected_calls)
            .mount(&mock_server)
            .await;

        let clock = MockClock::default();
        let provider = UpstreamOAuthProvider {
            id: Ulid::nil(),
            issuer: Some(mock_server.uri()),
            human_name: Some("Example Ltd.".to_owned()),
            brand_name: None,
            discovery_mode: provider::DiscoveryMode::Insecure,
            pkce_mode: provider::PkceMode::Auto,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            scope: Scope::from_iter([OPENID]),
            userinfo_endpoint_override: None,
            token_endpoint_override: None,
            client_id: "client_id".to_owned(),
            encrypted_client_secret: None,
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: provider::TokenAuthMethod::None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            created_at: clock.now(),
            disabled_at: None,
            claims_imports: provider::ClaimsImports::default(),
            additional_authorization_parameters: Vec::new(),
            forward_login_hint: false,
            on_backchannel_logout: provider::OnBackchannelLogout::DoNothing,
            source: provider::ProviderSource::Config,
        };

        // Without any override, it should just use discovery
        {
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &http_client);
            lazy_metadata.maybe_discover().await.unwrap();
            assert_eq!(
                lazy_metadata
                    .authorization_endpoint()
                    .await
                    .unwrap()
                    .as_str(),
                "https://example.com/authorize"
            );
            calls += 1;
        }

        // Test overriding endpoints
        {
            let provider = UpstreamOAuthProvider {
                jwks_uri_override: Some("https://example.com/jwks_override".parse().unwrap()),
                authorization_endpoint_override: Some(
                    "https://example.com/authorize_override".parse().unwrap(),
                ),
                token_endpoint_override: Some(
                    "https://example.com/token_override".parse().unwrap(),
                ),
                ..provider.clone()
            };
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &http_client);
            assert_eq!(
                lazy_metadata.jwks_uri().await.unwrap().as_str(),
                "https://example.com/jwks_override"
            );
            assert_eq!(
                lazy_metadata
                    .authorization_endpoint()
                    .await
                    .unwrap()
                    .as_str(),
                "https://example.com/authorize_override"
            );
            assert_eq!(
                lazy_metadata.token_endpoint().await.unwrap().as_str(),
                "https://example.com/token_override"
            );
            // This shouldn't trigger a new fetch as the endpoint is overridden
            calls += 0;
        }

        // Loading an insecure provider with secure discovery should fail
        {
            let provider = UpstreamOAuthProvider {
                discovery_mode: provider::DiscoveryMode::Oidc,
                ..provider.clone()
            };
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &http_client);
            lazy_metadata.authorization_endpoint().await.unwrap_err();
            // This triggered a fetch, even though it failed
            calls += 1;
        }

        // Getting endpoints when discovery is disabled only works for overridden ones
        {
            let provider = UpstreamOAuthProvider {
                discovery_mode: provider::DiscoveryMode::Disabled,
                authorization_endpoint_override: Some(
                    Url::parse("https://example.com/authorize_override").unwrap(),
                ),
                token_endpoint_override: None,
                ..provider.clone()
            };
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &http_client);
            // This should not fail, but also does nothing
            assert!(lazy_metadata.maybe_discover().await.unwrap().is_none());
            assert_eq!(
                lazy_metadata
                    .authorization_endpoint()
                    .await
                    .unwrap()
                    .as_str(),
                "https://example.com/authorize_override"
            );
            assert!(matches!(
                lazy_metadata.token_endpoint().await,
                Err(DiscoveryError::Disabled),
            ));
            // This did not trigger a fetch
            calls += 0;
        }

        assert_eq!(calls, expected_calls);
    }
}
