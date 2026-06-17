use opentelemetry::KeyValue;
use crate::salvo_utils::{
    SessionInfoExt,
    cookies::TimedCookie,
    csrf::CsrfExt,
};
use coauth_data::{
    RepositoryAccess,
    upstream_oauth::UpstreamOAuthLinkRepository,
    user::UserRepository,
};
use coauth_templates::{
    AppContext, AppErrorState, TemplateContext, UpstreamExistingLinkContext, UpstreamRegister,
    UpstreamSuggestLink,
};
use salvo::prelude::*;
use ulid::Ulid;

use super::{LOGIN_COUNTER, PROVIDER, REGISTRATION_COUNTER, RouteError, UpstreamSessionsCookie};
use crate::handlers::{
    common::DepotExt,
    upstream_oauth::link_workflow::{
        LoadUpstreamLinkOutcome, UpstreamLinkWorkflowError, load_upstream_link_context,
        load_upstream_link_state,
    },
    account::registration_cookie::UserRegistrationSessions as UserRegistrationSessionsCookie,
};

#[handler]
#[tracing::instrument(name = "handlers.upstream_oauth.link.get", skip_all)]
pub async fn get(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let link_id: Ulid = req.param("link_id").ok_or(RouteError::LinkNotFound)?;
    let mut rng = crate::handlers::account::make_rng();
    let clock = crate::handlers::account::make_clock();
    let mut repo = depot.repo().await?;
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let principal_server = depot.principal_server()?;
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    let policy_factory = depot.policy_factory()?;
    let mut policy = policy_factory.instantiate().await?;
    let site_config = depot.site_config()?;
    let ip_address = crate::handlers::account::extract_bound_activity_tracker(req, depot).ip();

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let context = load_upstream_link_context(&mut repo, &session_info, &sessions_cookie, link_id)
        .await?;

    // We need to stash the browser session before it's consumed by
    // load_upstream_link_state, so we can use it for template rendering.
    let browser_session_for_template = context.browser_session.clone();

    let outcome = match load_upstream_link_state(
        &mut repo,
        &mut *rng,
        &*clock,
        &url_builder,
        &*principal_server,
        &mut policy,
        &site_config,
        user_agent,
        ip_address,
        context,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(
            UpstreamLinkWorkflowError::ConflictFail { handle: ref username }
            | UpstreamLinkWorkflowError::ConflictSetBlocked { handle: ref username },
        ) => {
            let err_state = AppErrorState {
                kind: "generic".to_owned(),
                handle: None,
                description: Some(format!(
                    "Upstream account provider returned {username:?} as username, \
                     which could not be linked automatically."
                )),
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.write_to_response(&mut *res);
            res.render(Text::Html(content));
            return Ok(());
        }
        Err(UpstreamLinkWorkflowError::PolicyDeniedHandle {
            handle: ref username,
            ref detail,
        }) => {
            let err_state = AppErrorState {
                kind: "generic".to_owned(),
                handle: None,
                description: Some(format!(
                    "Upstream account provider returned {username:?} as username, \
                     which does not pass the policy check: {detail}"
                )),
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.write_to_response(&mut *res);
            res.render(Text::Html(content));
            return Ok(());
        }
        Err(UpstreamLinkWorkflowError::HandleUnavailable { handle: ref username }) => {
            let err_state = AppErrorState {
                kind: "generic".to_owned(),
                handle: None,
                description: Some(format!(
                    "Username {username:?} is not available on this PrincipalServer"
                )),
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.write_to_response(&mut *res);
            res.render(Text::Html(content));
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    match outcome {
        LoadUpstreamLinkOutcome::Authenticated {
            session,
            redirect_url,
        } => {
            let cookie_jar = cookie_jar.set_session(&session);
            repo.save().await?;

            cookie_jar.finalize(res, Redirect::other(&redirect_url));
        }

        LoadUpstreamLinkOutcome::LoggedIn {
            session,
            redirect_url,
            provider_id,
        } => {
            let cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock)
                .set_session(&session);

            repo.save().await?;

            LOGIN_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider_id.to_string())]);

            cookie_jar.finalize(res, Redirect::other(&redirect_url));
        }

        LoadUpstreamLinkOutcome::LinkMismatch { existing_handle: existing_username } => {
            // Look up the user again for the template context (needs the full User object)
            let user = repo
                .user()
                .find_by_handle(&existing_username)
                .await?
                .ok_or_else(|| {
                    RouteError::Internal(
                        format!("User {existing_username:?} not found for link mismatch template")
                            .into(),
                    )
                })?;

            // LinkMismatch only occurs when there's a logged-in user session
            let user_session = browser_session_for_template.ok_or_else(|| {
                RouteError::Internal("LinkMismatch without a browser session".into())
            })?;

            let ctx = UpstreamExistingLinkContext::new(user)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_upstream_oauth_link_mismatch(&ctx)?),
            );
        }

        LoadUpstreamLinkOutcome::SuggestLink {
            provider_name: _,
            upstream_subject: _,
        } => {
            // Re-load the link to construct the template context.
            let link = repo
                .upstream_oauth_link()
                .lookup(link_id)
                .await?
                .ok_or(RouteError::LinkNotFound)?;

            // SuggestLink only occurs when there's a logged-in user session
            let user_session = browser_session_for_template.ok_or_else(|| {
                RouteError::Internal("SuggestLink without a browser session".into())
            })?;

            let ctx = UpstreamSuggestLink::new(&link)
                .with_session(user_session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_upstream_oauth_suggest_link(&ctx)?),
            );
        }

        LoadUpstreamLinkOutcome::Register { screen } => {
            let mut ctx = UpstreamRegister::new(screen.link, screen.provider);

            if let Some(username) = screen.suggested_handle {
                ctx = ctx.with_handle(username, screen.handle_forced);
            }

            if let Some(display_name) = screen.suggested_display_name {
                ctx = ctx.with_display_name(display_name, screen.display_name_forced);
            }

            if let Some(email) = screen.suggested_email {
                ctx = ctx.with_email(email, screen.email_forced);
            }

            let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

            cookie_jar.finalize(
                res,
                Text::Html(templates.render_upstream_oauth_do_register(&ctx)?),
            );
        }

        LoadUpstreamLinkOutcome::Registered {
            registration,
            redirect_url: _,
            provider_id,
        } => {
            let registrations = UserRegistrationSessionsCookie::load(&cookie_jar);
            let cookie_jar = sessions_cookie
                .consume_link(link_id)?
                .save(cookie_jar, &clock);
            let cookie_jar = registrations.add(&registration).save(cookie_jar, &clock);

            repo.save().await?;

            REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider_id.to_string())]);

            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(
                    &url_builder.relative_url(&format!("/register/steps/{}/finish", registration.id)),
                ),
            );
        }

        LoadUpstreamLinkOutcome::AccountDeactivated { handle: username } => {
            let err_state = AppErrorState {
                kind: "account_deactivated".to_owned(),
                handle: Some(username),
                description: None,
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.finalize(res, Text::Html(content));
        }

        LoadUpstreamLinkOutcome::AccountLocked { handle: username } => {
            let err_state = AppErrorState {
                kind: "account_locked".to_owned(),
                handle: Some(username),
                description: None,
            };
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;

            cookie_jar.finalize(res, Text::Html(content));
        }
    }

    Ok(())
}
