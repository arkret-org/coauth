//! `POST /login` handler.

use opentelemetry::KeyValue;
use coauth_templates::{
    AppContext, FieldError, FormError, LoginFormField, TemplateContext, Templates, ToFormState,
};
use salvo::{prelude::*, writing::Text};
use zeroize::Zeroizing;

use super::form::LoginForm;
use super::render::render;
use super::{PASSWORD_LOGIN_COUNTER, RESULT};
use crate::handlers::RequesterFingerprint;
use crate::handlers::account::DepotExt;
use crate::handlers::account::service::access::{
    PasswordLoginOutcome, PasswordLoginRequest, login_with_password,
};
use crate::handlers::session::AccountError;
use crate::handlers::views::shared::OptionalPostAuthAction;
use crate::salvo_utils::{
    InternalError, SessionInfoExt,
    csrf::{CsrfExt, ProtectedForm},
};

#[handler]
pub async fn post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = common::make_rng();
    let clock = common::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let password_manager = depot.password_manager()?;
    let site_config = depot.site_config()?;
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let limiter = depot.limiter()?;
    let principal_server = depot.principal_server()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let form: ProtectedForm<LoginForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    if !site_config.password_login_enabled {
        // Password login globally disabled — return 405 without a body. The
        // GET handler already falls through to the upstream SSO template, so
        // users reaching this POST with a hand-crafted form is the only way
        // to hit it; a plain status code is sufficient.
        res.status_code(StatusCode::METHOD_NOT_ALLOWED);
        return Ok(());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    // Validate the form
    let mut form_state = form.to_form_state();

    if form.username.is_empty() {
        form_state.add_error_on_field(LoginFormField::Username, FieldError::Required);
    }

    if form.password.is_empty() {
        form_state.add_error_on_field(LoginFormField::Password, FieldError::Required);
    }

    if !form_state.is_valid() {
        tracing::warn!("Invalid login form: {form_state:?}");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &principal_server,
            &site_config,
            res,
        )
        .await;
    }

    match login_with_password(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        &limiter,
        principal_server.as_ref(),
        &url_builder,
        &contrix_config,
        &site_config,
        PasswordLoginRequest {
            username_or_email: form.username,
            password: Zeroizing::new(form.password),
            user_agent,
            requester,
        },
    )
    .await
    .map_err(|error| InternalError::from_anyhow(error.into()))?
    {
        PasswordLoginOutcome::Disabled => {
            res.status_code(StatusCode::METHOD_NOT_ALLOWED);
            Ok(())
        }
        PasswordLoginOutcome::InvalidCredentials => {
            let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            let mut render_repo = depot.repo().await?;
            render(
                locale,
                cookie_jar,
                form_state,
                query,
                &mut render_repo,
                &clock,
                &mut rng,
                &templates,
                &principal_server,
                &site_config,
                res,
            )
            .await
        }
        PasswordLoginOutcome::RateLimited => {
            let form_state = form_state.with_error_on_form(FormError::RateLimitExceeded);
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            let mut render_repo = depot.repo().await?;
            render(
                locale,
                cookie_jar,
                form_state,
                query,
                &mut render_repo,
                &clock,
                &mut rng,
                &templates,
                &principal_server,
                &site_config,
                res,
            )
            .await
        }
        PasswordLoginOutcome::AccountDeactivated { user } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            let err = AccountError::Deactivated { username: user.handle.clone() };
            let err_state = crate::handlers::views::app::account_error_to_state(&err);
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;
            cookie_jar.finalize(res, Text::Html(content));
            Ok(())
        }
        PasswordLoginOutcome::AccountLocked { user } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            let err = AccountError::Locked { username: user.handle.clone() };
            let err_state = crate::handlers::views::app::account_error_to_state(&err);
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;
            cookie_jar.finalize(res, Text::Html(content));
            Ok(())
        }
        PasswordLoginOutcome::Authenticated { user_session, .. } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

            activity_tracker
                .record_browser_session(&clock, &user_session)
                .await;

            let cookie_jar = cookie_jar.set_session(&user_session);
            let reply = query.go_next(&url_builder);
            cookie_jar.finalize(res, reply);
            Ok(())
        }
    }
}
