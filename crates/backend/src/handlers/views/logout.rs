use coauth_data::PostAuthAction;
use crate::handlers::post_auth::post_auth_action_redirect;
use crate::salvo_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use salvo::prelude::*;

use crate::handlers::account::service::access::logout_browser_session;
use crate::handlers::account;
use crate::handlers::account::DepotExt;

#[handler]
pub async fn post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let clock = common::make_clock();
    let repo = depot.repo().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let url_builder = depot.url_builder()?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let form: ProtectedForm<Option<PostAuthAction>> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    let form = cookie_jar.verify_form(&clock, form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    if let Some(session) =
        logout_browser_session(repo, &clock, session_info.current_session_id()).await?
    {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;
    }

    // We always want to clear out the session cookie, even if the session was
    // invalid
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    let destination = if let Some(action) = form {
        post_auth_action_redirect(&action, &url_builder)
    } else {
        salvo::writing::Redirect::other(&url_builder.relative_url("/login"))
    };

    cookie_jar.finalize(res, destination);
    Ok(())
}
