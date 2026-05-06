use coauth_data::PostAuthAction;
use crate::salvo_utils::{
    GenericError, InternalError,
    csrf::{CsrfExt, ProtectedForm},
};
use coauth_templates::{AppContext, AppErrorState, ConsentContext, PolicyViolationContext, TemplateContext};
use salvo::{prelude::*, writing::Text};
use thiserror::Error;
use ulid::Ulid;

use crate::routing::oauth2::access::{
    OAuth2AccessError, accept_authorization_consent, load_authorization_consent,
};
use crate::routing::account::DepotExt;
use crate::routing::session::{AccountError, SessionOrFallback, load_session_or_fallback};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Csrf(#[from] crate::salvo_utils::csrf::CsrfError),

    #[error("Authorization grant not found")]
    GrantNotFound,

    #[error("Authorization grant is not pending")]
    GrantNotPending,

    #[error("Policy violation")]
    PolicyViolation,
}

impl From<OAuth2AccessError> for RouteError {
    fn from(e: OAuth2AccessError) -> Self {
        match e {
            OAuth2AccessError::NotFound => RouteError::GrantNotFound,
            OAuth2AccessError::GrantNotPending => RouteError::GrantNotPending,
            OAuth2AccessError::PolicyViolation => RouteError::PolicyViolation,
            OAuth2AccessError::Repository(e) => RouteError::Internal(Box::new(e)),
            OAuth2AccessError::Internal(e) => RouteError::Internal(e),
            OAuth2AccessError::GrantExpired => {
                RouteError::Internal(Box::new(OAuth2AccessError::GrantExpired))
            }
        }
    }
}

impl_from_error_for_route!(coauth_templates::TemplateError);
impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::routing::session::SessionLoadError);
impl_from_error_for_route!(crate::routing::account::RouteError);
impl_from_error_for_route!(super::callback::CallbackDestinationError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        match self {
            Self::Internal(e) => InternalError::new(e).render(res),
            e @ Self::GrantNotFound => GenericError::new(StatusCode::NOT_FOUND, e).render(res),
            e @ Self::GrantNotPending => GenericError::new(StatusCode::CONFLICT, e).render(res),
            e @ Self::PolicyViolation => GenericError::new(StatusCode::FORBIDDEN, e).render(res),
            e @ Self::Csrf(_) => GenericError::new(StatusCode::BAD_REQUEST, e).render(res),
        }
    }
}

#[endpoint]
#[tracing::instrument(name = "routing.oauth2.authorization.consent.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_get(req, depot, res).await {
        Ok(()) => {}
        Err(e) => e.render(res),
    }
}

async fn handle_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let mut rng = crate::routing::account::make_rng();
    let clock = crate::routing::account::make_clock();
    let locale = crate::routing::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let homeserver = depot.homeserver()?;
    let policy_factory = depot.policy_factory()?;
    let repo_factory = depot.repo_factory()?;
    let activity_tracker = crate::routing::account::extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let cookie_jar = depot.cookie_jar(req)?;
    let grant_id: Ulid = req.param("grant_id").ok_or(RouteError::GrantNotFound)?;

    let mut session_repo = repo_factory.create().await?;
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &mut session_repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::AccountError { cookie_jar, error } => {
            let err_state = crate::routing::views::app::account_error_to_state(&error);
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;
            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
    };
    session_repo.cancel().await?;

    let Some(session) = maybe_session else {
        let action = PostAuthAction::continue_grant(grant_id);
        let query_str = serde_urlencoded::to_string(&action).unwrap_or_default();
        let path = format!("/login?{query_str}");
        let redirect = salvo::writing::Redirect::other(&url_builder.relative_url(&path));
        cookie_jar.finalize(res, redirect);
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let repo = repo_factory.create().await?;
    let info = load_authorization_consent(
        repo,
        policy_factory.as_ref(),
        homeserver.as_ref(),
        &clock,
        &session,
        grant_id,
        activity_tracker.ip(),
        user_agent,
    )
    .await?;

    if info.policy_violation {
        let ctx = PolicyViolationContext::for_authorization_grant(info.grant, info.client)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        cookie_jar.finalize(res, Text::Html(content));
        return Ok(());
    }

    let ctx = ConsentContext::new(info.grant, info.client, info.matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_consent(&ctx)?;

    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}

#[endpoint]
#[tracing::instrument(name = "routing.oauth2.authorization.consent.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_post(req, depot, res).await {
        Ok(()) => {}
        Err(e) => e.render(res),
    }
}

async fn handle_post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let mut rng = crate::routing::account::make_rng();
    let clock = crate::routing::account::make_clock();
    let locale = crate::routing::preferred_language(req, depot);
    let templates = depot.templates()?;
    let key_store = depot.key_store()?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let policy_factory = depot.policy_factory()?;
    let repo_factory = depot.repo_factory()?;
    let activity_tracker = crate::routing::account::extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let cookie_jar = depot.cookie_jar(req)?;
    let grant_id: Ulid = req.param("grant_id").ok_or(RouteError::GrantNotFound)?;

    let form: ProtectedForm<()> = req
        .parse_form()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;
    cookie_jar.verify_form(&clock, form)?;

    let mut session_repo = repo_factory.create().await?;
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &mut session_repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::AccountError { cookie_jar, error } => {
            let err_state = crate::routing::views::app::account_error_to_state(&error);
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;
            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
    };
    session_repo.cancel().await?;

    let Some(browser_session) = maybe_session else {
        let next = PostAuthAction::continue_grant(grant_id);
        let query_str = serde_urlencoded::to_string(&next).unwrap_or_default();
        let path = format!("/login?{query_str}");
        let redirect = salvo::writing::Redirect::other(&url_builder.relative_url(&path));
        cookie_jar.finalize(res, redirect);
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &browser_session)
        .await;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let repo = repo_factory.create().await?;
    let decision = match accept_authorization_consent(
        repo,
        &mut rng,
        &clock,
        &key_store,
        &url_builder,
        &contrix_config,
        policy_factory.as_ref(),
        &browser_session,
        grant_id,
        activity_tracker.ip(),
        user_agent.clone(),
    )
    .await
    {
        Ok(decision) => decision,
        Err(OAuth2AccessError::PolicyViolation) => {
            // Re-load the grant and client so we can render the violation page.
            let repo = repo_factory.create().await?;
            let info = load_authorization_consent(
                repo,
                policy_factory.as_ref(),
                depot.homeserver()?.as_ref(),
                &clock,
                &browser_session,
                grant_id,
                activity_tracker.ip(),
                user_agent,
            )
            .await?;

            let ctx =
                PolicyViolationContext::for_authorization_grant(info.grant, info.client)
                    .with_session(browser_session)
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);

            let content = templates.render_policy_violation(&ctx)?;
            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    activity_tracker
        .record_oauth2_session(&clock, &decision.session)
        .await;

    let callback_response =
        decision
            .callback_destination
            .go(&templates, &locale, decision.params)?;

    *res = callback_response;
    cookie_jar.write_to_response(res);
    Ok(())
}
