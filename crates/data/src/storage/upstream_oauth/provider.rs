use std::marker::PhantomData;

use async_trait::async_trait;
use coauth_data::upstream_oauth::provider;
use coauth_data::{Clock, UpstreamOAuthProvider};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_oauth_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;

use crate::pagination::Page;
use crate::{Pagination, repository_impl};

/// Structure which holds parameters when inserting or updating an upstream
/// OAuth provider
pub struct UpstreamOAuthProviderParams {
    /// The OIDC issuer of the provider
    pub issuer: Option<String>,

    /// A human-readable name for the provider
    pub human_name: Option<String>,

    /// A brand identifier, e.g. "apple" or "google"
    pub brand_name: Option<String>,

    /// The scope to request during the authorization strand
    pub scope: Scope,

    /// The token endpoint authentication method
    pub token_endpoint_auth_method: provider::TokenAuthMethod,

    /// The JWT signing algorithm to use when then `client_secret_jwt` or
    /// `private_key_jwt` authentication methods are used
    pub token_endpoint_signing_alg: Option<JsonWebSignatureAlg>,

    /// Expected signature for the JWT payload returned by the token
    /// authentication endpoint.
    ///
    /// Defaults to `RS256`.
    pub id_token_signed_response_alg: JsonWebSignatureAlg,

    /// Whether to fetch the user profile from the userinfo endpoint,
    /// or to rely on the data returned in the `id_token` from the
    /// `token_endpoint`.
    pub fetch_userinfo: bool,

    /// Expected signature for the JWT payload returned by the userinfo
    /// endpoint.
    ///
    /// If not specified, the response is expected to be an unsigned JSON
    /// payload. Defaults to `None`.
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// The client ID to use when authenticating to the upstream
    pub client_id: String,

    /// The encrypted client secret to use when authenticating to the upstream
    pub encrypted_client_secret: Option<String>,

    /// How claims should be imported from the upstream provider
    pub claims_imports: provider::ClaimsImports,

    /// The URL to use as the authorization endpoint. If `None`, the URL will be
    /// discovered
    pub authorization_endpoint_override: Option<Url>,

    /// The URL to use as the token endpoint. If `None`, the URL will be
    /// discovered
    pub token_endpoint_override: Option<Url>,

    /// The URL to use as the userinfo endpoint. If `None`, the URL will be
    /// discovered
    pub userinfo_endpoint_override: Option<Url>,

    /// The URL to use when fetching JWKS. If `None`, the URL will be discovered
    pub jwks_uri_override: Option<Url>,

    /// How the provider metadata should be discovered
    pub discovery_mode: provider::DiscoveryMode,

    /// How should PKCE be used
    pub pkce_mode: provider::PkceMode,

    /// What response mode it should ask
    pub response_mode: Option<provider::ResponseMode>,

    /// Additional parameters to include in the authorization request
    pub additional_authorization_parameters: Vec<(String, String)>,

    /// Whether to forward the login hint to the upstream provider.
    pub forward_login_hint: bool,

    /// The position of the provider in the UI
    pub ui_order: i32,

    /// The behavior when receiving a backchannel logout notification
    pub on_backchannel_logout: provider::OnBackchannelLogout,

    /// Origin of the row (config file vs admin API)
    pub source: provider::ProviderSource,
}

/// Filter parameters for listing upstream OAuth providers
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UpstreamOAuthProviderFilter<'a> {
    /// Filter by whether the provider is enabled
    ///
    /// If `None`, all providers are returned
    enabled: Option<bool>,

    /// Filter by the row's source (config vs manual)
    source: Option<provider::ProviderSource>,

    _lifetime: PhantomData<&'a ()>,
}

impl UpstreamOAuthProviderFilter<'_> {
    /// Create a new [`UpstreamOAuthProviderFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return only enabled providers
    #[must_use]
    pub const fn enabled_only(mut self) -> Self {
        self.enabled = Some(true);
        self
    }

    /// Return only disabled providers
    #[must_use]
    pub const fn disabled_only(mut self) -> Self {
        self.enabled = Some(false);
        self
    }

    /// Restrict to a specific provider source
    #[must_use]
    pub const fn with_source(mut self, source: provider::ProviderSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Get the enabled filter
    ///
    /// Returns `None` if the filter is not set
    #[must_use]
    pub const fn enabled(&self) -> Option<bool> {
        self.enabled
    }

    /// Get the source filter
    #[must_use]
    pub const fn source(&self) -> Option<provider::ProviderSource> {
        self.source
    }
}

/// An [`UpstreamOAuthProviderRepository`] helps interacting with
/// [`UpstreamOAuthProvider`] saved in the storage backend
#[async_trait]
pub trait UpstreamOAuthProviderRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an upstream OAuth provider by its ID
    ///
    /// Returns `None` if the provider was not found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the provider to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error>;

    /// Add a new upstream OAuth provider
    ///
    /// Returns the newly created provider
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator
    /// * `clock`: The clock used to generate timestamps
    /// * `params`: The parameters of the provider to add
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: UpstreamOAuthProviderParams,
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    /// Delete an upstream OAuth provider
    ///
    /// # Parameters
    ///
    /// * `provider`: The provider to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn delete(&mut self, provider: UpstreamOAuthProvider) -> Result<(), Self::Error> {
        self.delete_by_id(provider.id).await
    }

    /// Delete an upstream OAuth provider by its ID
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the provider to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;

    /// Insert or update an upstream OAuth provider
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `id`: The ID of the provider to update
    /// * `params`: The parameters of the provider to update
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn upsert(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        params: UpstreamOAuthProviderParams,
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    /// Disable an upstream OAuth provider
    ///
    /// Returns the disabled provider
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `provider`: The provider to disable
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn disable(
        &mut self,
        clock: &dyn Clock,
        provider: UpstreamOAuthProvider,
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    /// Re-enable a previously disabled upstream OAuth provider
    ///
    /// Clears `disabled_at`. Returns the updated provider.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn enable(
        &mut self,
        provider: UpstreamOAuthProvider,
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    /// List [`UpstreamOAuthProvider`] with the given filter and pagination
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error>;

    /// Count the number of [`UpstreamOAuthProvider`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>,
    ) -> Result<usize, Self::Error>;

    /// Get all enabled upstream OAuth providers
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all_enabled(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error>;
}

repository_impl!(UpstreamOAuthProviderRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: UpstreamOAuthProviderParams
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    async fn upsert(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        params: UpstreamOAuthProviderParams
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    async fn delete(&mut self, provider: UpstreamOAuthProvider) -> Result<(), Self::Error>;

    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;

    async fn disable(
        &mut self,
        clock: &dyn Clock,
        provider: UpstreamOAuthProvider
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    async fn enable(
        &mut self,
        provider: UpstreamOAuthProvider
    ) -> Result<UpstreamOAuthProvider, Self::Error>;

    async fn list(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>,
        pagination: Pagination
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error>;

    async fn count(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>
    ) -> Result<usize, Self::Error>;

    async fn all_enabled(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error>;
);
