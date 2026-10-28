use coauth_account_types::PostAuthAction;
use coauth_data::oauth::{
    OAuthAuthorizationGrantRepository, OAuthClientRepository, OAuthSessionFilter,
    OAuthSessionRepository,
};
use coauth_data::user::BrowserSessionRepository as _;
use coauth_data::{
    AuthorizationCode, BoxClock, BoxRepository, BoxRng, Pkce, RepositoryAccess, SystemClock,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::claims;
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
use crate::salvo_utils::cookies::{CookieJar, TimedCookie as _};

pub(crate) mod callback;
pub(crate) mod consent_cookie;

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
impl_from_error_for_route!(crate::policy::LoadError);
impl_from_error_for_route!(crate::policy::EvaluationError);

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
    let keyring = depot.keyring()?;
    let arkret_config = depot.arkret_config()?;
    let policy_factory = depot.policy_factory()?;
    let mut repo: BoxRepository = depot.repo().await?;
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);

    #[allow(clippy::box_default)] // Box::default() doesn't apply to dyn Clock+Send
    let clock: BoxClock = Box::new(SystemClock::default());
    let mut rng: BoxRng = Box::new(
        ChaChaRng::from_rng(rand_core::OsRng).map_err(|e| RouteError::Internal(Box::new(e)))?,
    );

    // Parse form parameters
    let parameters: Params = req
        .parse_queries()
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // OIDC `ui_locales` is a space-separated preference list; hand it over
    // verbatim, because the shared resolver parses that syntax directly. The
    // account tier is not consulted here: this runs before the grant is bound
    // to an authenticated user, so there is no account preference to read yet.
    // The SPA applies it once the session exists.
    let requested_locales = parameters.auth.ui_locales.as_ref().map(|tags| {
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
        .find_by_client_id(&parameters.auth.client_id)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // And resolve the redirect_uri and response_mode
    let redirect_uri = client
        .resolve_redirect_uri(&parameters.auth.redirect_uri)?
        .clone();
    let response_type = parameters.auth.response_type;
    let response_mode = resolve_response_mode(&response_type, parameters.auth.response_mode)?;

    // Now we have a proper callback destination to go to on error
    let callback_destination = CallbackDestination::try_new(
        &response_mode,
        redirect_uri.clone(),
        parameters.auth.state.clone(),
    )?;

    // Get the session info from the cookie
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let mut pending_consents = consent_cookie::PendingConsents::load(&cookie_jar);
    let consent_clock = SystemClock::default();

    // One day, we will have try blocks
    let inner_result: Result<salvo::http::Response, RouteError> = ({
        let templates = templates.clone();
        let callback_destination = callback_destination.clone();
        let locale = locale.clone();
        let pending_consents = &mut pending_consents;
        async move {
            let maybe_session = session_info.load_active_session(&mut repo).await?;
            let prompt = parameters.auth.prompt.as_deref().unwrap_or_default();
            if prompt.contains(&Prompt::None) && prompt.len() != 1 {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::InvalidRequest),
                )?);
            }

            let now = clock.now();
            let subject_hint = if let Some(hint) = parameters.auth.id_token_hint.as_deref() {
                let jwks = keyring.public_jwks();
                let algorithm = client
                    .id_token_signed_response_alg
                    .clone()
                    .unwrap_or(JsonWebSignatureAlg::Rs256);
                let issuer = url_builder.oidc_issuer().to_string();
                let verified = (|| {
                    let token = crate::oidc_client::requests::jose::verify_signed_jwt(
                        hint,
                        crate::oidc_client::requests::jose::JwtVerificationData {
                            issuer: Some(&issuer),
                            jwks: &jwks,
                            client_id: &client.client_id,
                            signing_algorithm: &algorithm,
                        },
                    )
                    .map_err(|_| ())?;
                    let mut payload = token.payload().clone();
                    // A hint may describe an expired session, but a future
                    // issuance time or malformed registered claims is invalid.
                    claims::IAT
                        .extract_required_with_options(
                            &mut payload,
                            claims::TimeOptions::new(now).leeway(chrono::Duration::zero()),
                        )
                        .map_err(|_| ())?;
                    let _: claims::Timestamp =
                        serde_json::from_value(payload.remove("exp").ok_or(())?).map_err(|_| ())?;
                    claims::SUB.extract_required(&mut payload).map_err(|_| ())
                })();
                match verified {
                    Ok(subject) if !subject.is_empty() => Some(subject),
                    _ => {
                        return Ok(callback_destination.go(
                            &templates,
                            &locale,
                            ClientError::from(ClientErrorCode::InvalidRequest),
                        )?);
                    }
                }
            } else {
                None
            };
            let requirements = consent_cookie::AuthenticationRequirements {
                required_auth_after: if prompt.contains(&Prompt::Login) {
                    Some(now)
                } else {
                    parameters
                        .auth
                        .max_age
                        .map(|seconds| now - chrono::Duration::seconds(i64::from(seconds)))
                },
                subject_hint,
            };
            if let Some(session) = maybe_session.as_ref()
                && requirements.subject_hint.as_ref().is_some_and(|hint| {
                    hint != &crate::handlers::arkret::oidc_subject_for_user(
                        &arkret_config,
                        &session.user,
                    )
                })
            {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::LoginRequired),
                )?);
            }
            let authentication_satisfied = if let Some(session) = maybe_session.as_ref() {
                let authentication = repo
                    .browser_session()
                    .get_last_authentication(session)
                    .await?;
                (!prompt.contains(&Prompt::None) || authentication.is_some())
                    && requirements.satisfied_by(
                        authentication
                            .as_ref()
                            .map(|authentication| authentication.created_at),
                        &crate::handlers::arkret::oidc_subject_for_user(
                            &arkret_config,
                            &session.user,
                        ),
                        now,
                    )
            } else {
                false
            };

            // Check if the request/request_uri/registration parameters are used. If so, reply
            // with the right error since we don't support them.
            if parameters.auth.request.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RequestNotSupported),
                )?);
            }

            if parameters.auth.request_uri.is_some() {
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

            if parameters.auth.registration.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RegistrationNotSupported),
                )?);
            }

            if prompt.contains(&Prompt::None) {
                let error = if !authentication_satisfied {
                    Some(ClientErrorCode::LoginRequired)
                } else {
                    let session = maybe_session
                        .as_ref()
                        .expect("authenticated browser session");
                    let prior = OAuthSessionFilter::default()
                        .for_browser_session(session)
                        .for_client(&client)
                        .with_scope(&parameters.auth.scope)
                        .active_only();
                    (repo.oauth_session().count(prior).await? == 0)
                        .then_some(ClientErrorCode::ConsentRequired)
                };
                if let Some(error) = error {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(error),
                    )?);
                }
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
                match parameters.pkce.as_ref() {
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

                let pkce = parameters.pkce.map(|p| Pkce {
                    challenge: p.code_challenge,
                    challenge_method: p.code_challenge_method,
                });

                Some(AuthorizationCode { code, pkce })
            } else {
                // If the request had PKCE parameters but no code asked, it should get back with an
                // error
                if parameters.pkce.is_some() {
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
                    parameters.auth.scope,
                    code,
                    parameters.auth.state.clone(),
                    parameters.auth.nonce,
                    response_mode,
                    response_type.has_id_token(),
                    parameters.auth.login_hint,
                    Some(locale.to_string()),
                )
                .await?;
            pending_consents.add(grant.id, maybe_session.as_ref(), &mut *rng);
            pending_consents.require(grant.id, requirements);
            let continue_grant = PostAuthAction::continue_grant(grant.id);

            if prompt.contains(&Prompt::None) {
                let session = maybe_session
                    .as_ref()
                    .expect("authenticated browser session");
                let decision = super::access::accept_authorization_consent(
                    repo,
                    &mut rng,
                    &clock,
                    &keyring,
                    &url_builder,
                    &arkret_config,
                    policy_factory.as_ref(),
                    session,
                    grant.id,
                    activity_tracker.ip(),
                    req.header("user-agent"),
                )
                .await;
                // The service commits on success and rolls back on error.
                // Neither outcome leaves a browser decision to continue.
                pending_consents.consume(grant.id);
                return match decision {
                    Ok(decision) => {
                        activity_tracker
                            .record_oauth_session(&clock, &decision.session)
                            .await;
                        Ok(decision.callback_destination.go(
                            &templates,
                            &locale,
                            decision.parameters,
                        )?)
                    }
                    Err(super::access::OAuthAccessError::PolicyViolation) => {
                        Ok(callback_destination.go(
                            &templates,
                            &locale,
                            ClientError::from(ClientErrorCode::AccessDenied),
                        )?)
                    }
                    Err(error) => Err(RouteError::Internal(Box::new(error))),
                };
            }

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

                Some(_) if !authentication_satisfied => {
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

    Ok((response, pending_consents.write(cookie_jar, &consent_clock)))
}
