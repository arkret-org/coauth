//! `GET /login` handler.

use coauth_templates::{AppContext, FormState, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};

use super::render::render;
use crate::handlers::account::DepotExt;
use crate::handlers::account::service::access::load_enabled_upstream_providers;
use crate::handlers::session::{SessionOrFallback, load_session_or_fallback};
use crate::handlers::views::shared::OptionalPostAuthAction;
use crate::salvo_utils::InternalError;

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = common::make_rng();
    let clock = common::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let site_config = depot.site_config()?;
    let principal_server = depot.principal_server()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::AccountError { cookie_jar, error } => {
            let err_state = crate::handlers::views::app::account_error_to_state(&error);
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;
            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
    };

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
    if !site_config.password_login_enabled && providers.len() == 1 {
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

    render(
        locale,
        cookie_jar,
        FormState::default(),
        query,
        &mut repo,
        &clock,
        &mut rng,
        &templates,
        &principal_server,
        &site_config,
        res,
    )
    .await
}
