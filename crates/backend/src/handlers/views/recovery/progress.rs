use crate::salvo_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use coauth_templates::{EmptyContext, RecoveryProgressContext, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};
use ulid::Ulid;

use crate::handlers::account::DepotExt;
use crate::handlers::views::context::ViewContext;
use crate::handlers::views::shared::OptionalPostAuthAction;
use crate::handlers::{
    RequesterFingerprint,
    account::service::recovery::{
        LoadAccountRecoverySessionError, ResendAccountRecoveryError, load_account_recovery_session,
        resend_account_recovery,
    },
    rest,
};

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
    let id: Ulid = req.param("id").unwrap_or_default();
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();

    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        cookie_jar.finalize(res, Text::Html(rendered));
        return Ok(());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_active_session(&mut repo).await?;
    if maybe_session.is_some() {
        // Already signed in — skip recovery and continue the original post-auth
        // strand if any.
        let reply = query.go_next(&url_builder);
        cookie_jar.finalize(res, reply);
        return Ok(());
    }

    let recovery_session = match load_account_recovery_session(&mut repo, id).await {
        Ok(session) => session,
        Err(LoadAccountRecoverySessionError::NotFound) => {
            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(&url_builder.relative_url("/recover")),
            );
            return Ok(());
        }
        Err(LoadAccountRecoverySessionError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    if recovery_session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        cookie_jar.finalize(res, Text::Html(rendered));
        return Ok(());
    }

    let context = RecoveryProgressContext::new(recovery_session, false)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates.render_recovery_progress(&context)?;

    cookie_jar.finalize(res, Text::Html(rendered));
    Ok(())
}

#[handler]
pub async fn post(
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
    let limiter = depot.limiter()?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let id: Ulid = req.param("id").unwrap_or_default();
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();
    let form: ProtectedForm<()> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        cookie_jar.finalize(res, Text::Html(rendered));
        return Ok(());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_active_session(&mut repo).await?;
    if maybe_session.is_some() {
        // Already signed in — skip recovery and continue the original post-auth
        // strand if any.
        let reply = query.go_next(&url_builder);
        cookie_jar.finalize(res, reply);
        return Ok(());
    }

    let recovery_session = match load_account_recovery_session(&mut repo, id).await {
        Ok(session) => session,
        Err(LoadAccountRecoverySessionError::NotFound) => {
            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(&url_builder.relative_url("/recover")),
            );
            return Ok(());
        }
        Err(LoadAccountRecoverySessionError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    if recovery_session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        cookie_jar.finalize(res, Text::Html(rendered));
        return Ok(());
    }

    // Verify the CSRF token
    let () = cookie_jar.verify_form(&clock, form)?;

    let recovery_session = match resend_account_recovery(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester,
        recovery_session.id,
    )
    .await
    {
        Ok(session) => session,
        Err(ResendAccountRecoveryError::AlreadyConsumed) => {
            let context = EmptyContext.with_language(locale);
            let rendered = templates.render_recovery_consumed(&context)?;
            cookie_jar.finalize(res, Text::Html(rendered));
            return Ok(());
        }
        Err(ResendAccountRecoveryError::RateLimited) => {
            let context = RecoveryProgressContext::new(recovery_session, true)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);
            let rendered = templates.render_recovery_progress(&context)?;

            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            cookie_jar.finalize(res, Text::Html(rendered));
            return Ok(());
        }
        Err(ResendAccountRecoveryError::NotFound) => {
            cookie_jar.finalize(
                res,
                salvo::writing::Redirect::other(&url_builder.relative_url("/recover")),
            );
            return Ok(());
        }
        Err(ResendAccountRecoveryError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    let context = RecoveryProgressContext::new(recovery_session, false)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates.render_recovery_progress(&context)?;

    cookie_jar.finalize(res, Text::Html(rendered));
    Ok(())
}
