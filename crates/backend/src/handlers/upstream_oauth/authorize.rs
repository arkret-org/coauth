use coauth_data::{
    PostAuthAction, UpstreamOAuthProvider,
    upstream_oauth::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
};
use salvo::prelude::*;
use thiserror::Error;
use ulid::Ulid;

use super::{UpstreamSessionsCookie, cache::LazyProviderInfos};
use crate::{
    handlers::{account::DepotExt, post_auth::OptionalPostAuthAction},
    oidc_client::requests::authorization_code::AuthorizationRequestData,
    salvo_utils::{GenericError, InternalError, cookies::TimedCookie},
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("Provider not found")]
    ProviderNotFound,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(crate::oidc_client::error::DiscoveryError);
impl_from_error_for_route!(crate::oidc_client::error::AuthorizationError);
impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::account::RouteError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        match self {
            e @ Self::ProviderNotFound => {
                GenericError::new(StatusCode::NOT_FOUND, e).render(res);
            }
            Self::Internal(e) => {
                InternalError::new(e).render(res);
            }
        }
    }
}

#[handler]
#[tracing::instrument(name = "handlers.upstream_oauth.authorize.get", skip_all)]
pub async fn get(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let provider_id: Ulid = req
        .param("provider_id")
        .ok_or(RouteError::ProviderNotFound)?;
    let mut rng = crate::handlers::account::make_rng();
    let clock = crate::handlers::account::make_clock();
    let metadata_cache = depot.metadata_cache()?;
    let mut repo = depot.repo().await?;
    let url_builder = depot.url_builder()?;
    let http_client = depot.http_client()?;
    let cookie_jar = depot.cookie_jar(req)?;
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();

    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    // First, discover the provider
    // This is done lazyly according to provider.discovery_mode and the various
    // endpoint overrides
    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &http_client);
    lazy_metadata.maybe_discover().await?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    let mut data = AuthorizationRequestData::new(
        provider.client_id.clone(),
        provider.scope.clone(),
        redirect_uri,
    );

    if let Some(response_mode) = provider.response_mode {
        data = data.with_response_mode(response_mode.into());
    }

    // Forward the raw login hint upstream for the provider to handle however it
    // sees fit
    if provider.forward_login_hint
        && let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = &query.post_auth_action
        && let Some(login_hint) = repo
            .oauth_authorization_grant()
            .lookup(*id)
            .await?
            .and_then(|grant| grant.login_hint)
    {
        data = data.with_login_hint(login_hint);
    }

    let data = if let Some(methods) = lazy_metadata.pkce_methods().await? {
        data.with_code_challenge_methods_supported(methods)
    } else {
        data
    };

    // Build an authorization request for it
    let (mut url, data) =
        crate::oidc_client::requests::authorization_code::build_authorization_url(
            lazy_metadata.authorization_endpoint().await?.clone(),
            data,
            &mut rng,
        )?;

    // We do that in a block because params borrows url mutably
    {
        // Add any additional parameters to the query
        let mut params = url.query_pairs_mut();
        for (key, value) in &provider.additional_authorization_parameters {
            params.append_pair(key, value);
        }
    }

    // SECURITY (session fixation): a fresh upstream-session row is
    // minted on every `authorize` invocation with a freshly generated
    // CSPRNG `state` (via the OIDC-client builder above) and `nonce`.
    // The state is mirrored into the cookie below and re-checked on
    // callback; the nonce lands in the upstream ID token's `nonce`
    // claim. An attacker who can plant the cookie cannot fixate a
    // session because they cannot predict the freshly generated
    // `state`, and the callback handler rejects mismatches.
    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &clock,
            &provider,
            data.state.clone(),
            data.code_challenge_verifier,
            data.nonce,
        )
        .await?;

    // The cookie payload mirrors `(session_id, provider_id, state)`
    // and is signed/encrypted by the private cookie jar. The cookie
    // attributes (HttpOnly + Secure + SameSite=Lax) are applied by
    // `CookieOption::apply` — see
    // `crates/backend/src/salvo_utils/cookies.rs` for the baseline,
    // and `crates/backend/src/handlers/upstream_oauth/cookie.rs` for
    // the documented threat model.
    let cookie_jar = UpstreamSessionsCookie::load(&cookie_jar)
        .add(session.id, provider.id, data.state, query.post_auth_action)
        .save(cookie_jar, &clock);

    repo.save().await?;

    cookie_jar.finalize(res, Redirect::temporary(url.as_str()));
    Ok(())
}
