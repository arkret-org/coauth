use std::time::Duration;

use anyhow::Context;
use coauth_data::{Clock, PrincipalUser};
use coauth_policy::Policy;
use crate::salvo_utils::{
    InternalError,
    csrf::{CsrfExt, ProtectedForm},
};
use coauth_templates::{AppContext, AppErrorState, DeviceConsentContext, PolicyViolationContext, TemplateContext};
use salvo::{prelude::*, writing::Text};
use serde::Deserialize;
use tracing::warn;
use ulid::Ulid;

use crate::handlers::account::DepotExt;
use crate::handlers::session::{
    AccountError, SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback,
};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Action {
    Consent,
    Reject,
}

#[derive(Deserialize, Debug)]
pub struct ConsentForm {
    action: Action,
}

#[handler]
#[tracing::instrument(name = "handlers.oauth.device.consent.get", skip_all)]
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
) -> Result<(), InternalError> {
    let mut rng = crate::handlers::account::make_rng();
    let clock = crate::handlers::account::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let principal_server = depot.principal_server()?;
    let mut repo = depot.repo().await?;
    let policy_factory = depot.policy_factory()?;
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| InternalError::new(Box::new(e)))?;
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let cookie_jar = depot.cookie_jar(req)?;
    let grant_id: Ulid = req.param("device_code_id").ok_or_else(|| {
        InternalError::from_anyhow(anyhow::anyhow!("Missing device_code_id path parameter"))
    })?;

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

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let Some(session) = maybe_session else {
        let action = coauth_data::PostAuthAction::continue_device_code_grant(grant_id);
        let query_str = serde_urlencoded::to_string(&action).unwrap_or_default();
        let path = format!("/login?{query_str}");
        let redirect = salvo::writing::Redirect::other(&url_builder.relative_url(&path));
        cookie_jar.finalize(res, redirect);
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // TODO: better error handling
    let grant = repo
        .oauth_device_code_grant()
        .lookup(grant_id)
        .await?
        .context("Device grant not found")
        .map_err(InternalError::from_anyhow)?;

    if grant.expires_at < clock.now() {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Grant is expired"
        )));
    }

    let client = repo
        .oauth_client()
        .lookup(grant.client_id)
        .await?
        .context("Client not found")
        .map_err(InternalError::from_anyhow)?;

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    // Evaluate the policy
    let res_policy = policy
        .evaluate_authorization_grant(coauth_policy::AuthorizationGrantInput {
            grant_type: coauth_policy::GrantType::DeviceCode,
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            user: Some(&session.user),
            requester: coauth_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
                ..Default::default()
            },
        })
        .await?;
    if !res_policy.valid() {
        warn!(violation = ?res_policy, "Device code grant for client {} denied by policy", client.id);

        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = PolicyViolationContext::for_device_code_grant(grant, client)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        cookie_jar.finalize(res, Text::Html(content));
        return Ok(());
    }

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let username = &session.user.handle;
    let display_name = match tokio::time::timeout(
        Duration::from_secs(1),
        principal_server.query_user(username),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                username,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(username, "Timed out while querying user");
            None
        }
    };

    let principal_user = PrincipalUser {
        principal_id: principal_server.principal_id(username),
        display_name,
    };

    let ctx = DeviceConsentContext::new(grant, client, principal_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates
        .render_device_consent(&ctx)
        .context("Failed to render template")
        .map_err(InternalError::from_anyhow)?;

    cookie_jar.finalize(res, Text::Html(rendered));
    Ok(())
}

#[handler]
#[tracing::instrument(name = "handlers.oauth.device.consent.post", skip_all)]
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
) -> Result<(), InternalError> {
    let mut rng = crate::handlers::account::make_rng();
    let clock = crate::handlers::account::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let principal_server = depot.principal_server()?;
    let mut repo = depot.repo().await?;
    let policy_factory = depot.policy_factory()?;
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| InternalError::new(Box::new(e)))?;
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let cookie_jar = depot.cookie_jar(req)?;
    let grant_id: Ulid = req.param("device_code_id").ok_or_else(|| {
        InternalError::from_anyhow(anyhow::anyhow!("Missing device_code_id path parameter"))
    })?;

    let form: ProtectedForm<ConsentForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::new(Box::new(e)))?;
    let form = cookie_jar
        .verify_form(&clock, form)
        .map_err(|e| InternalError::new(Box::new(e)))?;

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
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let Some(session) = maybe_session else {
        let action = coauth_data::PostAuthAction::continue_device_code_grant(grant_id);
        let query_str = serde_urlencoded::to_string(&action).unwrap_or_default();
        let path = format!("/login?{query_str}");
        let redirect = salvo::writing::Redirect::other(&url_builder.relative_url(&path));
        cookie_jar.finalize(res, redirect);
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // TODO: better error handling
    let grant = repo
        .oauth_device_code_grant()
        .lookup(grant_id)
        .await?
        .context("Device grant not found")
        .map_err(InternalError::from_anyhow)?;

    if grant.expires_at < clock.now() {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Grant is expired"
        )));
    }

    let client = repo
        .oauth_client()
        .lookup(grant.client_id)
        .await?
        .context("Client not found")
        .map_err(InternalError::from_anyhow)?;

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    // Evaluate the policy
    let res_policy = policy
        .evaluate_authorization_grant(coauth_policy::AuthorizationGrantInput {
            grant_type: coauth_policy::GrantType::DeviceCode,
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            user: Some(&session.user),
            requester: coauth_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
                ..Default::default()
            },
        })
        .await?;
    if !res_policy.valid() {
        warn!(violation = ?res_policy, "Device code grant for client {} denied by policy", client.id);

        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = PolicyViolationContext::for_device_code_grant(grant, client)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        cookie_jar.finalize(res, Text::Html(content));
        return Ok(());
    }

    let grant = if grant.is_pending() {
        match form.action {
            Action::Consent => {
                repo.oauth_device_code_grant()
                    .fulfill(&clock, grant, &session)
                    .await?
            }
            Action::Reject => {
                repo.oauth_device_code_grant()
                    .reject(&clock, grant, &session)
                    .await?
            }
        }
    } else {
        // XXX: In case we're not pending, let's just return the grant as-is
        // since it might just be a form resubmission, and feedback is nice enough
        warn!(
            oauth_device_code.id = %grant.id,
            browser_session.id = %session.id,
            user.id = %session.user.id,
            "Grant is not pending",
        );
        grant
    };

    repo.save().await?;

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let username = &session.user.handle;
    let display_name = match tokio::time::timeout(
        Duration::from_secs(1),
        principal_server.query_user(username),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                username,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(username, "Timed out while querying user");
            None
        }
    };

    let principal_user = PrincipalUser {
        principal_id: principal_server.principal_id(username),
        display_name,
    };

    let ctx = DeviceConsentContext::new(grant, client, principal_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates
        .render_device_consent(&ctx)
        .context("Failed to render template")
        .map_err(InternalError::from_anyhow)?;

    cookie_jar.finalize(res, Text::Html(rendered));
    Ok(())
}
