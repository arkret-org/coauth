use coauth_account_types::PostAuthAction;
use coauth_data::oauth::{
    OAuthAuthorizationGrantRepository, OAuthClientRepository, OAuthSessionFilter,
    OAuthSessionRepository,
};
use coauth_data::{
    AuthorizationCode, BoxClock, BoxRepository, BoxRng, Pkce, RepositoryAccess, SystemClock,
};
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use coauth_oauth_types::pkce;
use coauth_oauth_types::requests::{AuthorizationRequest, GrantType, Prompt, ResponseMode};
use coauth_oauth_types::response_type::ResponseType;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::prelude::*;
use serde::Deserialize;
use thiserror::Error;

use self::callback::CallbackDestination;
use crate::salvo_utils::SessionInfoExt;
use crate::salvo_utils::cookies::CookieJar;

pub(crate) mod callback;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("could not find client")]
    ClientNotFound,

    #[error("invalid response mode")]
    InvalidResponseMode,

    #[error("invalid parameters")]
    IntoCallbackDestination(#[from] self::callback::IntoCallbackDestinationError),

    #[error("invalid redirect uri")]
    UnknownRedirectUri(#[from] coauth_data::InvalidRedirectUriError),
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            Self::Internal(ref e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(e.to_string()));
            }
            Self::ClientNotFound
            | Self::InvalidResponseMode
            | Self::IntoCallbackDestination(_)
            | Self::UnknownRedirectUri(_) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain(self.to_string()));
            }
        }

        let sentry_event_id = crate::salvo_utils::sentry::SentryEventId::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(coauth_templates::TemplateError);
impl_from_error_for_route!(self::callback::CallbackDestinationError);
impl_from_error_for_route!(coauth_policy::LoadError);
impl_from_error_for_route!(coauth_policy::EvaluationError);

impl From<crate::handlers::common::RouteError> for RouteError {
    fn from(e: crate::handlers::common::RouteError) -> Self {
        Self::Internal(Box::new(e))
    }
}

#[derive(Deserialize)]
pub(crate) struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::AuthorizationRequest>,
}

fn localized_post_auth_path(
    route: &str,
    action: &PostAuthAction,
    locale: &coauth_i18n::Locale,
) -> String {
    let mut query = serde_urlencoded::to_string(action).unwrap_or_default();
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str("ui_locales=");
    query.push_str(&locale.to_string());
    format!("{route}?{query}")
}

/// Given a list of response types and an optional user-defined response mode,
/// figure out what response mode must be used, and emit an error if the
/// suggested response mode isn't allowed for the given response types.
fn resolve_response_mode(
    response_type: &ResponseType,
    suggested_response_mode: Option<ResponseMode>,
) -> Result<ResponseMode, RouteError> {
    use ResponseMode as M;

    // If the response type includes either "token" or "id_token", the default
    // response mode is "fragment" and the response mode "query" must not be
    // used
    if response_type.has_token() || response_type.has_id_token() {
        match suggested_response_mode {
            None => Ok(M::Fragment),
            Some(M::Query) => Err(RouteError::InvalidResponseMode),
            Some(mode) => Ok(mode),
        }
    } else {
        // In other cases, all response modes are allowed, defaulting to "query"
        Ok(suggested_response_mode.unwrap_or(M::Query))
    }
}

#[handler]
#[tracing::instrument(name = "handlers.oauth.authorization.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_get(req, depot).await {
        Ok((response, cookie_jar)) => {
            *res = response;
            cookie_jar.write_to_response(res);
        }
        Err(e) => e.render(res),
    }
}

async fn handle_get(req: &mut Request, depot: &Depot) -> Result<(Response, CookieJar), RouteError> {
    use crate::handlers::common::DepotExt as _;

    // Pull infrastructure off the depot via the typed extension trait so a
    // misconfigured server returns a 500 instead of panicking on the first
    // request. The `?` operator funnels the common `RouteError` into the
    // local one via the `From` impl above.
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo: BoxRepository = depot.repo().await?;
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);

    #[allow(clippy::box_default)] // Box::default() doesn't apply to dyn Clock+Send
    let clock: BoxClock = Box::new(SystemClock::default());
    let mut rng: BoxRng = Box::new(
        ChaChaRng::from_rng(rand_core::OsRng).map_err(|e| RouteError::Internal(Box::new(e)))?,
    );

    // Parse form parameters
    let params: Params = req
        .parse_queries()
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // OIDC `ui_locales` is a space-separated preference list; hand it over
    // verbatim, because the shared resolver parses that syntax directly. The
    // account tier is not consulted here: this runs before the grant is bound
    // to an authenticated user, so there is no account preference to read yet.
    // The SPA applies it once the session exists.
    let requested_locales = params.auth.ui_locales.as_ref().map(|tags| {
        tags.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    });
    let locale = crate::handlers::preferred_language_with_requested(
        req,
        depot,
        requested_locales.as_deref(),
    );

    // Get cookie jar
    let cookie_jar = CookieJar::extract_from_request(req, depot)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // First, figure out what client it is
    let client = repo
        .oauth_client()
        .find_by_client_id(&params.auth.client_id)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // And resolve the redirect_uri and response_mode
    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)?
        .clone();
    let response_type = params.auth.response_type;
    let response_mode = resolve_response_mode(&response_type, params.auth.response_mode)?;

    // Now we have a proper callback destination to go to on error
    let callback_destination = CallbackDestination::try_new(
        &response_mode,
        redirect_uri.clone(),
        params.auth.state.clone(),
    )?;

    // Get the session info from the cookie
    let (session_info, cookie_jar) = cookie_jar.session_info();

    // One day, we will have try blocks
    let inner_result: Result<salvo::http::Response, RouteError> = ({
        let templates = templates.clone();
        let callback_destination = callback_destination.clone();
        let locale = locale.clone();
        async move {
            let maybe_session = session_info.load_active_session(&mut repo).await?;
            let prompt = params.auth.prompt.as_deref().unwrap_or_default();

            // Check if the request/request_uri/registration params are used. If so, reply
            // with the right error since we don't support them.
            if params.auth.request.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RequestNotSupported),
                )?);
            }

            if params.auth.request_uri.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RequestUriNotSupported),
                )?);
            }

            // Check if the client asked for a `token` response type, and bail out if it's
            // the case, since we don't support them
            if response_type.has_token() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::UnsupportedResponseType),
                )?);
            }

            // If the client asked for a `id_token` response type, we must check if it can
            // use the `implicit` grant type
            if response_type.has_id_token() && !client.grant_types.contains(&GrantType::Implicit) {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::UnauthorizedClient),
                )?);
            }

            if params.auth.registration.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RegistrationNotSupported),
                )?);
            }

            // Fail early if prompt=none; we never let it go through
            if prompt.contains(&Prompt::None) {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::LoginRequired),
                )?);
            }

            let code: Option<AuthorizationCode> = if response_type.has_code() {
                // Check if it is allowed to use this grant type
                if !client.grant_types.contains(&GrantType::AuthorizationCode) {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::UnauthorizedClient),
                    )?);
                }
                let pkce_required = super::token_service::authorization_code_pkce_required(&client);
                match params.pkce.as_ref() {
                    None if pkce_required => {
                        return Ok(callback_destination.go(
                            &templates,
                            &locale,
                            ClientError::from(ClientErrorCode::InvalidRequest),
                        )?);
                    }
                    // SECURITY: when a challenge is present, it MUST use
                    // S256 regardless of whether PKCE is "required" for
                    // this client (see `required_pkce_method_is_allowed`
                    // for the deprecation rationale). An empty challenge
                    // is also rejected.
                    Some(pkce)
                        if pkce.code_challenge.trim().is_empty()
                            || !super::token_service::required_pkce_method_is_allowed(
                                &pkce.code_challenge_method,
                            ) =>
                    {
                        return Ok(callback_destination.go(
                            &templates,
                            &locale,
                            ClientError::from(ClientErrorCode::InvalidRequest),
                        )?);
                    }
                    _ => {}
                }

                // 32 random alphanumeric characters, about 190bit of entropy
                let code: String = {
                    const CHARSET: &[u8] =
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                    let mut buf = [0u8; 32];
                    rng.fill_bytes(&mut buf);
                    buf.iter()
                        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
                        .collect()
                };

                let pkce = params.pkce.map(|p| Pkce {
                    challenge: p.code_challenge,
                    challenge_method: p.code_challenge_method,
                });

                Some(AuthorizationCode { code, pkce })
            } else {
                // If the request had PKCE params but no code asked, it should get back with an
                // error
                if params.pkce.is_some() {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::InvalidRequest),
                    )?);
                }

                None
            };

            let grant = repo
                .oauth_authorization_grant()
                .add(
                    &mut rng,
                    &clock,
                    &client,
                    redirect_uri.clone(),
                    params.auth.scope,
                    code,
                    params.auth.state.clone(),
                    params.auth.nonce,
                    response_mode,
                    response_type.has_id_token(),
                    params.auth.login_hint,
                    Some(locale.to_string()),
                )
                .await?;
            let continue_grant = PostAuthAction::continue_grant(grant.id);

            let redirect = match maybe_session {
                None if prompt.contains(&Prompt::Create) => {
                    // Client asked for a registration, show the registration prompt
                    repo.save().await?;

                    {
                        let path = localized_post_auth_path("/register", &continue_grant, &locale);
                        salvo::writing::Redirect::other(url_builder.relative_url(&path))
                    }
                }

                None => {
                    // Other cases where we don't have a session, ask for a login
                    repo.save().await?;

                    {
                        let path = localized_post_auth_path("/login", &continue_grant, &locale);
                        salvo::writing::Redirect::other(url_builder.relative_url(&path))
                    }
                }

                Some(_) if prompt.contains(&Prompt::Create) => {
                    // Client asked for registration even though a session exists.
                    // Redirect to the registration page to create a new account.
                    repo.save().await?;

                    {
                        let path = localized_post_auth_path("/register", &continue_grant, &locale);
                        salvo::writing::Redirect::other(url_builder.relative_url(&path))
                    }
                }

                Some(_) if prompt.contains(&Prompt::Login) => {
                    // Client explicitly requested re-authentication.
                    // Redirect to the login page even though we have a session.
                    repo.save().await?;

                    {
                        let path = localized_post_auth_path("/login", &continue_grant, &locale);
                        salvo::writing::Redirect::other(url_builder.relative_url(&path))
                    }
                }

                Some(user_session) => {
                    // We have a session.  Before auto-consenting, check
                    // whether it still has active OAuth sessions.  If all
                    // sessions have been finished (user logged out), redirect
                    // to login instead of silently reusing the stale browser
                    // session.
                    let filter = OAuthSessionFilter::default().for_browser_session(&user_session);
                    let total = repo.oauth_session().count(filter).await?;
                    let active = repo.oauth_session().count(filter.active_only()).await?;

                    repo.save().await?;

                    if total > 0 && active == 0 {
                        // Every prior OAuth session was revoked/finished —
                        // the user has logged out; require fresh credentials.
                        let path = localized_post_auth_path("/login", &continue_grant, &locale);
                        salvo::writing::Redirect::other(url_builder.relative_url(&path))
                    } else {
                        activity_tracker
                            .record_browser_session(&clock, &user_session)
                            .await;
                        salvo::writing::Redirect::other(
                            url_builder.relative_url(&format!("/oauth/approval/{}", grant.id)),
                        )
                    }
                }
            };

            let mut response = Response::new();
            redirect.render(&mut response);
            Ok(response)
        }
    })
    .await;

    let response = match inner_result {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(message = &err as &dyn std::error::Error);
            callback_destination.go(
                &templates,
                &locale,
                ClientError::from(ClientErrorCode::ServerError),
            )?
        }
    };

    Ok((response, cookie_jar))
}
