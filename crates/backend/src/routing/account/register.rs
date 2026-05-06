//! REST API endpoints for user registration.
//!
//! These endpoints serve as thin HTTP adapters over the business logic in
//! [`crate::routing::account::service::registration`]. They parse requests,
//! check config/policy constraints, delegate to service functions, and map
//! results to JSON responses.

use chrono::Utc;
use coauth_data::{
    flow::{FlowSession, FlowSessionStatus},
    new_id,
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::{
    routing::{
        RequesterFingerprint,
        account::service::registration::{
            BeginPasswordRegistrationError, BeginPasswordRegistrationRequest,
            BeginPasswordRegistrationResult, EmailAvailabilityCheck, HomeserverCheckMode,
            LoadRegistrationProgressError, RegistrationDisplayNameOutcome,
            RegistrationDisplayNameWorkflowError, RegistrationEmailChangeError,
            RegistrationEmailChangeOutcome, RegistrationFinishError, RegistrationFinishOutcome,
            RegistrationResendError, RegistrationResendOutcome, RegistrationVerificationError,
            RegistrationVerificationOutcome, begin_password_registration,
            change_registration_email, finish_registration, load_registration_status,
            next_registration_step, resend_registration_verification,
            submit_registration_display_name, submit_registration_email_code,
            submit_registration_phone_code,
        },
        flow::{FlowExecutor, defaults::default_registration_flow, flow_session_store_write},
    },
    salvo_utils::SessionInfoExt,
};

// ── POST /api/v1/auth/register ─────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct RegisterInput {
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the flow engine is enabled, the frontend should use this ID
    /// with the flow session API (`/api/v1/flow/session/:id`) instead of
    /// the legacy registration step endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_session_id: Option<String>,
}

#[endpoint]
pub async fn post_register(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegisterResponse>, RouteError> {
    let input: RegisterInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let site_config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let homeserver = depot.homeserver()?;
    let policy_factory = depot.policy_factory()?;
    let limiter = depot.limiter()?;
    let repo_factory = depot.repo_factory()?;
    let notification_language = crate::routing::notification_language(req, depot, None);

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let ip_address = activity_tracker.ip();

    let repo = repo_factory.create().await?;

    let started = match begin_password_registration(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        homeserver.as_ref(),
        policy_factory.as_ref(),
        &limiter,
        BeginPasswordRegistrationRequest {
            username: input.username,
            email: input.email,
            phone: if site_config.phone_verification_enabled {
                input.phone
            } else {
                None
            },
            password: input.password,
            password_confirm: input.password_confirm,
            user_agent,
            ip_address,
            requester,
            notification_language,
            post_auth_action: None,
            password_registration_enabled: site_config.password_registration_enabled,
            password_registration_contact_required: site_config
                .password_registration_contact_required,
            terms_url: site_config.tos_uri.clone(),
            email_availability: EmailAvailabilityCheck::Precheck,
        },
    )
    .await
    .map_err(|error| {
        tracing::error!(
            error = &error as &dyn std::error::Error,
            "Registration failed"
        );
        match error {
            BeginPasswordRegistrationError::Repository(error) => RouteError::from(error),
            BeginPasswordRegistrationError::Internal(error) => RouteError::Internal(error.into()),
        }
    })? {
        BeginPasswordRegistrationResult::Started(started) => started,
        BeginPasswordRegistrationResult::Rejected { issues } => {
            return Ok(Json(RegisterResponse {
                status: "error",
                id: None,
                next_step: None,
                error: Some(
                    issues
                        .into_iter()
                        .map(|issue| issue.as_api_error())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                flow_session_id: None,
            }));
        }
    };

    let registration = started.registration;
    let email_verified = started.email_verified;
    let phone_verified = started.phone_verified;

    let step = next_registration_step(&registration, email_verified, phone_verified);

    // If the flow engine is enabled, start a flow session alongside the
    // legacy registration so the frontend can choose the flow-based path.
    let flow_session_id = if site_config.flow_engine_enabled {
        let mut rng = make_rng();
        let (flow_def, bindings) = default_registration_flow(&mut *rng);
        let plan = FlowExecutor::plan(flow_def, bindings);

        let now = Utc::now();
        let session_id = new_id(now, &mut *rng);

        let session = FlowSession {
            id: session_id,
            flow_id: plan.flow.id,
            current_stage_index: 0,
            status: FlowSessionStatus::InProgress,
            context: Value::Object(serde_json::Map::new()),
            ip_address: None,
            user_agent: None,
            created_at: now,
            updated_at: now,
            expires_at: now + chrono::Duration::hours(1),
            completed_at: None,
        };

        flow_session_store_write()
            .await
            .insert(session_id, (plan, session));

        Some(session_id.to_string())
    } else {
        None
    };

    Ok(Json(RegisterResponse {
        status: "success",
        id: Some(registration.id.to_string()),
        next_step: Some(step),
        error: None,
        flow_session_id,
    }))
}

// ── GET /api/v1/auth/register/:id ──────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct RegistrationStatusResponse {
    pub id: String,
    pub username: String,
    pub email_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_email: Option<String>,
    pub phone_pending: bool,
    pub steps_completed: Vec<&'static str>,
    pub next_step: &'static str,
}

#[endpoint]
pub async fn get_registration(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegistrationStatusResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let repo_factory = depot.repo_factory()?;
    let mut repo = repo_factory.create().await?;

    let status = load_registration_status(&mut repo, id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => RouteError::NotFound,
            LoadRegistrationProgressError::Repository(error) => RouteError::from(error),
        })?;

    repo.cancel().await?;

    Ok(Json(RegistrationStatusResponse {
        id: status.registration.id.to_string(),
        username: status.registration.username,
        email_pending: status.email_pending,
        pending_email: status.pending_email,
        phone_pending: status.phone_pending,
        steps_completed: status.steps_completed,
        next_step: status.next_step,
    }))
}

// ── POST /api/v1/auth/register/:id/verify-email ────────────────

#[derive(Deserialize, ToSchema)]
pub struct VerifyEmailInput {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyEmailResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_verify_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<VerifyEmailResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let input: VerifyEmailInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let repo = repo_factory.create().await?;

    let outcome =
        match submit_registration_email_code(repo, &limiter, &clock, id, &input.code).await {
            Ok(outcome) => outcome,
            Err(RegistrationVerificationError::NotFound) => return Err(RouteError::NotFound),
            Err(RegistrationVerificationError::NotAvailable) => {
                return Err(RouteError::BadRequest(
                    "no email authentication for this registration".into(),
                ));
            }
            Err(RegistrationVerificationError::Repository(error)) => return Err(error.into()),
        };

    let (status, next_step, error) = match outcome {
        RegistrationVerificationOutcome::Advanced { next_step } => {
            ("success", Some(next_step), None)
        }
        RegistrationVerificationOutcome::RegistrationCompleted => {
            ("error", None, Some("registration_already_completed".into()))
        }
        RegistrationVerificationOutcome::AlreadyVerified => {
            ("error", None, Some("email_already_verified".into()))
        }
        RegistrationVerificationOutcome::InvalidCode => {
            ("error", None, Some("invalid_code".into()))
        }
        RegistrationVerificationOutcome::RateLimited => {
            ("error", None, Some("rate_limited".into()))
        }
    };

    Ok(Json(VerifyEmailResponse {
        status,
        next_step,
        error,
    }))
}

// ── POST /api/v1/auth/register/:id/resend-verification ────────

#[derive(Serialize, ToSchema)]
pub struct ResendVerificationResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Resend the next pending verification code for a registration.
///
/// Unlike the authenticated `/email-auth/:id/resend` endpoint, this one works
/// during registration when the user does not yet have a browser session.
#[endpoint]
pub async fn post_resend_verification(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendVerificationResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language = crate::routing::notification_language(req, depot, None);

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);

    let repo = repo_factory.create().await?;

    let outcome = match resend_registration_verification(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester,
        id,
        notification_language,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(RegistrationResendError::NotFound) => return Err(RouteError::NotFound),
        Err(RegistrationResendError::Repository(error)) => return Err(error.into()),
    };

    let (status, error) = match outcome {
        RegistrationResendOutcome::RegistrationCompleted => {
            ("error", Some("registration_already_completed".into()))
        }
        RegistrationResendOutcome::Resent => ("resent", None),
        RegistrationResendOutcome::AlreadyVerified => ("already_verified", None),
        RegistrationResendOutcome::RateLimited => ("rate_limited", None),
    };

    Ok(Json(ResendVerificationResponse { status, error }))
}

// ── POST /api/v1/auth/register/:id/change-email ──────────────

#[derive(Deserialize, ToSchema)]
pub struct ChangeRegistrationEmailInput {
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct ChangeRegistrationEmailResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_change_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ChangeRegistrationEmailResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let input: ChangeRegistrationEmailInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language = crate::routing::notification_language(req, depot, None);

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);

    let repo = repo_factory.create().await?;

    let outcome = match change_registration_email(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester,
        id,
        &input.email,
        notification_language,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(RegistrationEmailChangeError::NotFound) => return Err(RouteError::NotFound),
        Err(RegistrationEmailChangeError::NotAvailable) => {
            return Err(RouteError::BadRequest(
                "no email authentication for this registration".into(),
            ));
        }
        Err(RegistrationEmailChangeError::Repository(error)) => return Err(error.into()),
    };

    let (status, error) = match outcome {
        RegistrationEmailChangeOutcome::Updated => ("updated", None),
        RegistrationEmailChangeOutcome::RegistrationCompleted => {
            ("error", Some("registration_already_completed".into()))
        }
        RegistrationEmailChangeOutcome::AlreadyVerified => {
            ("error", Some("email_already_verified".into()))
        }
        RegistrationEmailChangeOutcome::InvalidEmail => ("error", Some("email_invalid".into())),
        RegistrationEmailChangeOutcome::EmailInUse => ("error", Some("email_in_use".into())),
        RegistrationEmailChangeOutcome::RateLimited => ("error", Some("rate_limited".into())),
    };

    Ok(Json(ChangeRegistrationEmailResponse { status, error }))
}

// ── POST /api/v1/auth/register/:id/verify-phone ────────────────

#[derive(Deserialize, ToSchema)]
pub struct VerifyPhoneInput {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyPhoneResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_verify_phone(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<VerifyPhoneResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let input: VerifyPhoneInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let repo = repo_factory.create().await?;

    let outcome =
        match submit_registration_phone_code(repo, &limiter, &clock, id, &input.code).await {
            Ok(outcome) => outcome,
            Err(RegistrationVerificationError::NotFound) => return Err(RouteError::NotFound),
            Err(RegistrationVerificationError::NotAvailable) => {
                return Err(RouteError::BadRequest(
                    "no phone authentication for this registration".into(),
                ));
            }
            Err(RegistrationVerificationError::Repository(error)) => return Err(error.into()),
        };

    let (status, next_step, error) = match outcome {
        RegistrationVerificationOutcome::Advanced { next_step } => {
            ("success", Some(next_step), None)
        }
        RegistrationVerificationOutcome::RegistrationCompleted => {
            ("error", None, Some("registration_already_completed".into()))
        }
        RegistrationVerificationOutcome::AlreadyVerified => {
            ("error", None, Some("phone_already_verified".into()))
        }
        RegistrationVerificationOutcome::InvalidCode => {
            ("error", None, Some("invalid_code".into()))
        }
        RegistrationVerificationOutcome::RateLimited => {
            ("error", None, Some("rate_limited".into()))
        }
    };

    Ok(Json(VerifyPhoneResponse {
        status,
        next_step,
        error,
    }))
}

// ── POST /api/v1/auth/register/:id/display-name ────────────────

#[derive(Deserialize, ToSchema)]
pub struct DisplayNameInput {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub skip: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct DisplayNameResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_display_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DisplayNameResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let input: DisplayNameInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let repo = repo_factory.create().await?;

    let outcome = match submit_registration_display_name(
        repo,
        id,
        input.display_name,
        input.skip.unwrap_or(false),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(RegistrationDisplayNameWorkflowError::NotFound) => return Err(RouteError::NotFound),
        Err(RegistrationDisplayNameWorkflowError::Repository(error)) => return Err(error.into()),
    };

    let (status, next_step, error) = match outcome {
        RegistrationDisplayNameOutcome::Advanced { next_step } => {
            ("success", Some(next_step), None)
        }
        RegistrationDisplayNameOutcome::RegistrationCompleted => {
            ("error", None, Some("registration_already_completed".into()))
        }
        RegistrationDisplayNameOutcome::InvalidDisplayName => {
            ("error", None, Some("invalid_display_name".into()))
        }
    };

    Ok(Json(DisplayNameResponse {
        status,
        next_step,
        error,
    }))
}

// ── POST /api/v1/auth/register/:id/finish ──────────────────────

#[derive(Serialize, ToSchema)]
pub struct FinishRegistrationResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// If the registration was started as part of another flow (e.g. an
    /// OAuth2 authorization grant continuation), the frontend uses this to
    /// resume that flow after the account is created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_auth_action: Option<serde_json::Value>,
}

#[derive(Default, Deserialize, ToSchema)]
pub struct FinishRegistrationInput {
    #[serde(default)]
    pub bootstrap_admin_token: Option<String>,
}

#[endpoint]
pub async fn post_finish(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<Json<FinishRegistrationResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = depot.site_config()?;
    let homeserver = depot.homeserver()?;
    let repo_factory = depot.repo_factory()?;
    let input = if req
        .payload()
        .await
        .map_err(|error| RouteError::Internal(error.into()))?
        .is_empty()
    {
        FinishRegistrationInput::default()
    } else {
        req.parse_json()
            .await
            .map_err(|_| RouteError::BadRequest("invalid request body".into()))?
    };

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let cookie_jar = depot.cookie_jar(req)?;

    let repo = repo_factory.create().await?;

    let outcome = match finish_registration(
        repo,
        &mut rng,
        &clock,
        homeserver.as_ref(),
        id,
        None,
        HomeserverCheckMode::BestEffort,
        site_config.registration_token_required,
        site_config.bootstrap_admin_token.as_deref(),
        input.bootstrap_admin_token,
        user_agent,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(RegistrationFinishError::NotFound) => return Err(RouteError::NotFound),
        Err(RegistrationFinishError::Repository(error)) => return Err(error.into()),
        Err(RegistrationFinishError::Internal(error)) => {
            return Err(RouteError::Internal(error.into()));
        }
    };

    let completed = match outcome {
        RegistrationFinishOutcome::Completed(completed) => completed,
        RegistrationFinishOutcome::Rejected { error } => {
            return Ok(Json(FinishRegistrationResponse {
                status: "error",
                error: Some(error.into()),
                post_auth_action: None,
            }));
        }
    };

    // Record the browser session activity
    activity_tracker
        .record_browser_session(&clock, &completed.user_session)
        .await;

    // Set the session cookie to log the user in
    let cookie_jar = cookie_jar.set_session(&completed.user_session);
    cookie_jar.write_to_response(res);

    let post_auth_action = completed.registration.post_auth_action.clone();

    Ok(Json(FinishRegistrationResponse {
        status: "success",
        error: None,
        post_auth_action,
    }))
}
