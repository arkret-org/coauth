use crate::salvo_utils::{InternalError, SessionInfoExt, csrf::CsrfExt as _};
use coauth_templates::{RegisterContext, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};

use super::shared::OptionalPostAuthAction;
use crate::handlers::account::service::access::load_enabled_upstream_providers;
use crate::handlers::views::context::ViewContext;

mod cookie;
pub mod password;
pub mod steps;

pub use self::cookie::UserRegistrationSessions as UserRegistrationSessionsCookie;

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let ViewContext {
        mut rng,
        clock,
        locale,
        site_config,
        templates,
        url_builder,
        mut repo,
        cookie_jar,
    } = ViewContext::extract(req, depot).await?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        cookie_jar.finalize(res, reply);
        return Ok(());
    }

    let providers = load_enabled_upstream_providers(&mut repo).await?;

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization strand
    if !site_config.password_registration_enabled && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let base_path = format!("/upstream/authorize/{}", provider.id);
        let path = if let Some(action) = &query.post_auth_action {
            let query_str = serde_urlencoded::to_string(action).unwrap_or_default();
            if query_str.is_empty() {
                base_path
            } else {
                format!("{base_path}?{query_str}")
            }
        } else {
            base_path
        };

        cookie_jar.finalize(
            res,
            salvo::writing::Redirect::other(&url_builder.relative_url(&path)),
        );
        return Ok(());
    }

    // If password-based registration is enabled and there are no upstream
    // providers, we redirect to the password registration page
    if site_config.password_registration_enabled && providers.is_empty() {
        let base_path = "/register/password";
        let path = if let Some(action) = &query.post_auth_action {
            let query_str = serde_urlencoded::to_string(action).unwrap_or_default();
            if query_str.is_empty() {
                base_path.to_owned()
            } else {
                format!("{base_path}?{query_str}")
            }
        } else {
            base_path.to_owned()
        };

        cookie_jar.finalize(
            res,
            salvo::writing::Redirect::other(&url_builder.relative_url(&path)),
        );
        return Ok(());
    }

    let mut ctx = RegisterContext::new(providers);
    let post_action = query
        .load_context(&mut repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    if let Some(action) = post_action {
        ctx = ctx.with_post_action(action);
    }

    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_register(&ctx)?;

    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}
