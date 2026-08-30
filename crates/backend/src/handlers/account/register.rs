//! REST API endpoints for user registration.
//!
//! These endpoints serve as thin HTTP adapters over the business logic in
//! [`crate::handlers::account::service::registration`]. They parse requests,
//! check config/policy constraints, delegate to service functions, and map
//! results to JSON responses.

use coauth_account_types::{ChangeRegistrationEmailOutcome, RegisterInput, RegisterOutcome};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::handlers::RequesterFingerprint;
use crate::handlers::account::service::registration::{
    BeginPasswordRegistrationError, BeginPasswordRegistrationRequestBody,
    BeginPasswordRegistrationResult, EmailAvailabilityCheck, LoadRegistrationProgressError,
    RegistrationDisplayNameOutcome, RegistrationDisplayNameWorkflowError,
    RegistrationEmailChangeError, RegistrationEmailChangeOutcome, RegistrationFinishError,
    RegistrationFinishOutcome, RegistrationResendError, RegistrationResendOutcome,
    RegistrationVerificationError, RegistrationVerificationOutcome, begin_password_registration,
    change_registration_email, finish_registration, load_registration_status,
    next_registration_step, resend_registration_verification, submit_registration_display_name,
    submit_registration_email_code, submit_registration_phone_code,
};
use crate::salvo_utils::SessionInfoExt;

// ── POST /_coauth/account/auth/register ─────────────────────────────────

#[endpoint]
pub async fn post_register(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegisterOutcome>, RouteError> {
    let input: RegisterInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    // Account-first onboarding (account-lifecycle.md 2.1.1): the account record
    // is created without a principal DID. The client completes cold-root custody
    // and its client-signed DID inception after sign-in, then binds the resulting
    // principal_id. An unbound account can sign in but cannot issue a session
    // grant (principal_unknown) and therefore cannot make any persistent write.
    let site_config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let station = depot.station()?;
    let policy_factory = depot.policy_factory()?;
    let limiter = depot.limiter()?;
    let repo_factory = depot.repo_factory()?;
    let url_builder = depot.url_builder()?;
    let notification_language = crate::handlers::notification_language(
        req, depot,
        // No account tier: this runs before any user is identified, so the
        // request headers are the only preference available.
        None, None,
    );

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(std::borrow::ToOwned::to_owned);
    let ip_address = activity_tracker.ip();

    if site_config.captcha.is_some() {
        let http_client = depot.http_client()?;
        if let Err(error) = crate::handlers::captcha::verify_token(
            activity_tracker.ip(),
            &http_client,
            url_builder.public_hostname(),
            site_config.captcha.as_ref(),
            input.captcha_token.as_deref(),
        )
        .await
        {
            tracing::warn!(error = %error, "CAPTCHA verification failed on registration");
            return Ok(Json(RegisterOutcome {
                status: "error".to_owned(),
                id: None,
                next_step: None,
                error: Some("captcha_failed".into()),
            }));
        }
    }

    let repo = repo_factory.create().await?;

    let started = match begin_password_registration(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        station.as_ref(),
        policy_factory.as_ref(),
        &limiter,
        BeginPasswordRegistrationRequestBody {
            handle: input.handle,
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
            post_auth_action: input.post_auth_action,
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
            return Ok(Json(RegisterOutcome {
                status: "error".to_owned(),
                id: None,
                next_step: None,
                error: Some(
                    issues
                        .into_iter()
                        .map(|issue| issue.as_api_error())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            }));
        }
    };

    let registration = started.registration;
    let email_verified = started.email_verified;
    let phone_verified = started.phone_verified;

    let step = next_registration_step(&registration, email_verified, phone_verified);

    Ok(Json(RegisterOutcome {
        status: "success".to_owned(),
        id: Some(registration.id.to_string()),
        next_step: Some(step.to_owned()),
        error: None,
    }))
}

// ── GET /_coauth/account/auth/register/:id ──────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct RegistrationStatusOutcome {
    pub id: String,
    pub handle: String,
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
) -> Result<Json<RegistrationStatusOutcome>, RouteError> {
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

    Ok(Json(RegistrationStatusOutcome {
        id: status.registration.id.to_string(),
        handle: status.registration.localpart,
        email_pending: status.email_pending,
        pending_email: status.pending_email,
        phone_pending: status.phone_pending,
        steps_completed: status.steps_completed,
        next_step: status.next_step,
    }))
}

// ── POST /_coauth/account/auth/register/:id/verify-email ────────────────

#[derive(Deserialize, ToSchema)]
pub struct VerifyEmailInput {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyEmailOutcome {
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
) -> Result<Json<VerifyEmailOutcome>, RouteError> {
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

    Ok(Json(VerifyEmailOutcome {
        status,
        next_step,
        error,
    }))
}

// ── POST /_coauth/account/auth/register/:id/resend-verification ────────

#[derive(Serialize, ToSchema)]
pub struct ResendVerificationOutcome {
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
) -> Result<Json<ResendVerificationOutcome>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language = crate::handlers::notification_language(
        req, depot,
        // No account tier: this runs before any user is identified, so the
        // request headers are the only preference available.
        None, None,
    );

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);

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

    Ok(Json(ResendVerificationOutcome { status, error }))
}

// ── POST /_coauth/account/auth/register/:id/change-email ──────────────

#[derive(Deserialize, ToSchema)]
pub struct ChangeRegistrationEmailInput {
    pub email: String,
}

#[endpoint]
pub async fn post_change_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ChangeRegistrationEmailOutcome>, RouteError> {
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
    let notification_language = crate::handlers::notification_language(
        req, depot,
        // No account tier: this runs before any user is identified, so the
        // request headers are the only preference available.
        None, None,
    );

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);

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

    Ok(Json(ChangeRegistrationEmailOutcome {
        status: status.to_owned(),
        error,
    }))
}

// ── POST /_coauth/account/auth/register/:id/verify-phone ────────────────

#[derive(Deserialize, ToSchema)]
pub struct VerifyPhoneInput {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyPhoneOutcome {
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
) -> Result<Json<VerifyPhoneOutcome>, RouteError> {
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

    Ok(Json(VerifyPhoneOutcome {
        status,
        next_step,
        error,
    }))
}

// ── POST /_coauth/account/auth/register/:id/display-name ────────────────

#[derive(Deserialize, ToSchema)]
pub struct DisplayNameInput {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub skip: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct DisplayNameOutcome {
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
) -> Result<Json<DisplayNameOutcome>, RouteError> {
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

    Ok(Json(DisplayNameOutcome {
        status,
        next_step,
        error,
    }))
}

// ── POST /_coauth/account/auth/register/:id/finish ──────────────────────

#[derive(Serialize, ToSchema)]
pub struct FinishRegistrationOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// If the registration was started as part of another strand (e.g. an
    /// OAuth authorization grant continuation), the frontend uses this to
    /// resume that strand after the account is created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_auth_action: Option<coauth_account_types::PostAuthAction>,
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
) -> Result<Json<FinishRegistrationOutcome>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = depot.site_config()?;
    let station = depot.station()?;
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
        .map(std::borrow::ToOwned::to_owned);
    let cookie_jar = depot.cookie_jar(req)?;

    let repo = repo_factory.create().await?;

    let outcome = match finish_registration(
        repo,
        &mut rng,
        &clock,
        station.as_ref(),
        id,
        None,
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
            return Ok(Json(FinishRegistrationOutcome {
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
    Ok(Json(FinishRegistrationOutcome {
        status: "success",
        error: None,
        post_auth_action,
    }))
}
