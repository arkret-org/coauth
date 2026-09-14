//! REST API endpoints for upstream OAuth link flow.
//!
//! These endpoints replace the server-rendered HTML handlers in
//! `upstream_oauth::link`, providing JSON responses for the Dioxus SPA.

use std::sync::LazyLock;

use coauth_account_types::{UpstreamLinkActionOutcome, UpstreamLinkState as LinkState};
use opentelemetry::metrics::Counter;
use opentelemetry::{Key, KeyValue};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::handlers::METER;
use crate::handlers::account::registration_cookie::UserRegistrationSessions;
use crate::handlers::upstream_oauth::UpstreamSessionsCookie;
use crate::handlers::upstream_oauth::link_workflow::{
    LoadUpstreamLinkOutcome, SubmitUpstreamLinkError, SubmitUpstreamLinkOutcome,
    UpstreamLinkAction, UpstreamLinkRegistrationAction, UpstreamLinkWorkflowError,
    load_upstream_link_context, load_upstream_link_state, submit_upstream_link_action,
};
use crate::salvo_utils::SessionInfoExt;
use crate::salvo_utils::cookies::{CookieJar, TimedCookie};

static LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.rest.upstream_oauth.login")
        .with_description("Successful upstream OAuth login via REST API")
        .with_unit("{login}")
        .build()
});
static REGISTRATION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.rest.upstream_oauth.registration")
        .with_description("Successful upstream OAuth registration via REST API")
        .with_unit("{registration}")
        .build()
});
const PROVIDER: Key = Key::from_static_str("provider");

#[derive(Serialize, ToSchema)]
pub struct LinkOutcome {
    #[serde(flatten)]
    pub state: LinkState,
}

#[derive(Deserialize, ToSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum LinkAction {
    Link,
    Register {
        #[serde(default)]
        handle: Option<String>,
        #[serde(default)]
        import_email: Option<bool>,
        #[serde(default)]
        import_display_name: Option<bool>,
        #[serde(default)]
        accept_terms: Option<bool>,
    },
}

/// Return the current state of an upstream OAuth link as JSON.
#[endpoint]
pub async fn get_link(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let link_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing link id".into()))?;
    let mut rng = make_rng();
    let clock = make_clock();
    let mut repo = depot.repo().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned);
    let url_builder = depot.url_builder()?;
    let site_config = depot.site_config()?;
    let ip_address = extract_bound_activity_tracker(req, depot).ip();
    let station = depot.station()?;
    let mut policy = depot
        .policy_factory()?
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let context = load_upstream_link_context(&mut repo, &session_info, &sessions_cookie, link_id)
        .await
        .map_err(map_upstream_link_workflow_error)?;
    let outcome = load_upstream_link_state(
        &mut repo,
        &mut *rng,
        &*clock,
        &url_builder,
        &*station,
        &mut policy,
        &site_config,
        user_agent,
        ip_address,
        context,
    )
    .await
    .map_err(map_upstream_link_workflow_error)?;

    if matches!(
        &outcome,
        LoadUpstreamLinkOutcome::Authenticated { .. }
            | LoadUpstreamLinkOutcome::LoggedIn { .. }
            | LoadUpstreamLinkOutcome::Registered { .. }
    ) {
        repo.save().await?;
    }

    render_get_link_outcome(res, cookie_jar, sessions_cookie, &clock, link_id, outcome)
}

/// Process a user's choice for an upstream OAuth link.
#[endpoint]
pub async fn post_link(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let link_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing link id".into()))?;
    let mut rng = make_rng();
    let clock = make_clock();
    let mut repo = depot.repo().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned);
    let mut policy = depot
        .policy_factory()?
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;
    let station = depot.station()?;
    let url_builder = depot.url_builder()?;
    let site_config = depot.site_config()?;
    let ip_address = extract_bound_activity_tracker(req, depot).ip();

    let input: LinkAction = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let context = load_upstream_link_context(&mut repo, &session_info, &sessions_cookie, link_id)
        .await
        .map_err(map_upstream_link_workflow_error)?;

    let action = match input {
        LinkAction::Link => UpstreamLinkAction::LinkCurrentSession,
        LinkAction::Register {
            handle,
            import_email,
            import_display_name,
            accept_terms,
        } => UpstreamLinkAction::Register(UpstreamLinkRegistrationAction {
            handle,
            import_email: import_email.unwrap_or(false),
            import_display_name: import_display_name.unwrap_or(false),
            accept_terms: accept_terms.unwrap_or(false),
        }),
    };

    let outcome = submit_upstream_link_action(
        &mut repo,
        &mut *rng,
        &*clock,
        &url_builder,
        &*station,
        &mut policy,
        &site_config,
        user_agent,
        ip_address,
        context,
        action,
    )
    .await;

    match outcome {
        Ok(outcome) => {
            if matches!(
                &outcome,
                SubmitUpstreamLinkOutcome::Linked { .. }
                    | SubmitUpstreamLinkOutcome::Registered { .. }
            ) {
                repo.save().await?;
            }
            render_post_link_outcome(res, cookie_jar, sessions_cookie, &clock, link_id, outcome)
        }
        Err(SubmitUpstreamLinkError::InvalidAction) => {
            cookie_jar.finalize(
                res,
                Json(UpstreamLinkActionOutcome::Error {
                    error: "invalid_action".to_owned(),
                    field_errors: None,
                }),
            );
            Ok(())
        }
        Err(SubmitUpstreamLinkError::Validation { field_errors }) => {
            cookie_jar.finalize(
                res,
                Json(UpstreamLinkActionOutcome::Error {
                    error: "validation_failed".to_owned(),
                    field_errors: Some(field_errors),
                }),
            );
            Ok(())
        }
        Err(SubmitUpstreamLinkError::Workflow(error)) => {
            Err(map_upstream_link_workflow_error(error))
        }
    }
}

fn render_get_link_outcome(
    res: &mut Response,
    cookie_jar: CookieJar,
    sessions_cookie: UpstreamSessionsCookie,
    clock: &coauth_data::BoxClock,
    link_id: Ulid,
    outcome: LoadUpstreamLinkOutcome,
) -> Result<(), RouteError> {
    match outcome {
        LoadUpstreamLinkOutcome::Authenticated {
            session,
            redirect_url,
        } => {
            let cookie_jar = cookie_jar.set_session(&session);
            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::Redirect { redirect_url },
                }),
            );
        }
        LoadUpstreamLinkOutcome::LoggedIn {
            session,
            redirect_url,
            provider_id,
        } => {
            let cookie_jar = sessions_cookie
                .consume_link(link_id)
                .map_err(|e| RouteError::Internal(e.into()))?
                .save(cookie_jar, clock)
                .set_session(&session);

            LOGIN_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider_id.to_string())]);

            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::Redirect { redirect_url },
                }),
            );
        }
        LoadUpstreamLinkOutcome::LinkMismatch { existing_handle } => {
            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::LinkMismatch { existing_handle },
                }),
            );
        }
        LoadUpstreamLinkOutcome::SuggestLink {
            provider_name,
            upstream_subject,
        } => {
            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::SuggestLink {
                        provider_name,
                        upstream_subject,
                    },
                }),
            );
        }
        LoadUpstreamLinkOutcome::Register { screen } => {
            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::Register {
                        suggested_handle: screen.suggested_handle,
                        handle_forced: screen.handle_forced,
                        suggested_display_name: screen.suggested_display_name,
                        display_name_forced: screen.display_name_forced,
                        suggested_email: screen.suggested_email,
                        email_forced: screen.email_forced,
                        provider_name: screen.provider_name,
                        has_tos: screen.has_tos,
                    },
                }),
            );
        }
        LoadUpstreamLinkOutcome::Registered {
            registration,
            redirect_url,
            provider_id,
        } => {
            let registrations = UserRegistrationSessions::load(&cookie_jar);
            let cookie_jar = sessions_cookie
                .consume_link(link_id)
                .map_err(|e| RouteError::Internal(e.into()))?
                .save(cookie_jar, clock);
            let cookie_jar = registrations.add(&registration).save(cookie_jar, clock);

            REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider_id.to_string())]);

            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::Redirect { redirect_url },
                }),
            );
        }
        LoadUpstreamLinkOutcome::AccountDeactivated { handle } => {
            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::AccountDeactivated { handle },
                }),
            );
        }
        LoadUpstreamLinkOutcome::AccountLocked { handle } => {
            cookie_jar.finalize(
                res,
                Json(LinkOutcome {
                    state: LinkState::AccountLocked { handle },
                }),
            );
        }
    }

    Ok(())
}

fn render_post_link_outcome(
    res: &mut Response,
    cookie_jar: CookieJar,
    sessions_cookie: UpstreamSessionsCookie,
    clock: &coauth_data::BoxClock,
    link_id: Ulid,
    outcome: SubmitUpstreamLinkOutcome,
) -> Result<(), RouteError> {
    match outcome {
        SubmitUpstreamLinkOutcome::Linked {
            session,
            redirect_url,
        } => {
            let cookie_jar = sessions_cookie
                .consume_link(link_id)
                .map_err(|e| RouteError::Internal(e.into()))?
                .save(cookie_jar, clock)
                .set_session(&session);

            cookie_jar.finalize(
                res,
                Json(UpstreamLinkActionOutcome::Success { redirect_url }),
            );
        }
        SubmitUpstreamLinkOutcome::Registered {
            registration,
            redirect_url,
            provider_id,
        } => {
            let registrations = UserRegistrationSessions::load(&cookie_jar);
            let cookie_jar = sessions_cookie
                .consume_link(link_id)
                .map_err(|e| RouteError::Internal(e.into()))?
                .save(cookie_jar, clock);
            let cookie_jar = registrations.add(&registration).save(cookie_jar, clock);

            REGISTRATION_COUNTER.add(1, &[KeyValue::new(PROVIDER, provider_id.to_string())]);

            cookie_jar.finalize(
                res,
                Json(UpstreamLinkActionOutcome::Success { redirect_url }),
            );
        }
    }

    Ok(())
}

fn map_upstream_link_workflow_error(error: UpstreamLinkWorkflowError) -> RouteError {
    match error {
        UpstreamLinkWorkflowError::MissingCookie => {
            RouteError::BadRequest("missing upstream session cookie".into())
        }
        UpstreamLinkWorkflowError::LinkNotFound | UpstreamLinkWorkflowError::SessionNotFound => {
            RouteError::NotFound
        }
        UpstreamLinkWorkflowError::SessionConsumed => {
            RouteError::BadRequest("session already consumed".into())
        }
        UpstreamLinkWorkflowError::UserNotFound | UpstreamLinkWorkflowError::ProviderNotFound => {
            RouteError::LoadFailed
        }
        UpstreamLinkWorkflowError::ConflictFail { .. }
        | UpstreamLinkWorkflowError::ConflictSetBlocked { .. }
        | UpstreamLinkWorkflowError::PolicyDeniedHandle { .. }
        | UpstreamLinkWorkflowError::HandleUnavailable { .. } => {
            RouteError::BadRequest(error.to_string())
        }
        UpstreamLinkWorkflowError::RequiredAttributeEmpty { .. }
        | UpstreamLinkWorkflowError::RequiredAttributeRender { .. }
        | UpstreamLinkWorkflowError::ConnectorAdmin(_)
        | UpstreamLinkWorkflowError::Repository(_)
        | UpstreamLinkWorkflowError::Internal(_) => RouteError::Internal(Box::new(error)),
    }
}
