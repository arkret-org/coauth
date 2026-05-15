use coauth_data::{AccountAction, PostAuthAction};
use crate::salvo_utils::InternalError;
use coauth_templates::{AppContext, AppErrorState, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};
use serde::Deserialize;

use crate::handlers::account::DepotExt;
use crate::handlers::session::{AccountError, SessionOrFallback, load_session_or_fallback};
use crate::handlers::views::context::ViewContext;

#[derive(Deserialize, Default)]
pub struct Params {
    #[serde(default, flatten)]
    action: Option<AccountAction>,
}

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let ViewContext {
        rng: _,
        clock,
        locale,
        site_config: _,
        templates,
        url_builder,
        mut repo,
        cookie_jar,
    } = ViewContext::extract(req, depot).await?;
    let script_src = depot.frontend_script_src()?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let Params { action } = req.parse_queries().unwrap_or_default();

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
            // Render the SPA shell with the error injected so the
            // Dioxus frontend shows the appropriate error page.
            let err_state = account_error_to_state(&error);
            let ctx = AppContext::new(&url_builder, &script_src)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;
            cookie_jar.finalize(res, Text::Html(content));
            return Ok(());
        }
    };

    let Some(session) = maybe_session else {
        let post_action = PostAuthAction::manage_account(action);
        let query = serde_urlencoded::to_string(&post_action).unwrap_or_default();
        let path = if query.is_empty() {
            "/login".to_owned()
        } else {
            format!("/login?{query}")
        };
        cookie_jar.finalize(
            res,
            salvo::writing::Redirect::other(&url_builder.relative_url(&path)),
        );
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = AppContext::new(&url_builder, &script_src).with_language(locale);
    let content = templates.render_app(&ctx)?;

    cookie_jar.finalize(res, Text::Html(content));
    Ok(())
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[handler]
pub async fn get_anonymous(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let script_src = depot.frontend_script_src()?;

    let ctx = AppContext::new(&url_builder, &script_src).with_language(locale);
    let content = templates.render_app(&ctx)?;

    res.render(Text::Html(content));
    Ok(())
}

/// Convert an [`AccountError`] into an [`AppErrorState`] for injection
/// into the SPA configuration.
pub(crate) fn account_error_to_state(err: &AccountError) -> AppErrorState {
    match err {
        AccountError::Deactivated { handle } => AppErrorState {
            kind: "account_deactivated".to_owned(),
            handle: Some(handle.clone()),
            description: None,
        },
        AccountError::Locked { handle } => AppErrorState {
            kind: "account_locked".to_owned(),
            handle: Some(handle.clone()),
            description: None,
        },
        AccountError::SessionEnded => AppErrorState {
            kind: "session_ended".to_owned(),
            handle: None,
            description: None,
        },
    }
}
