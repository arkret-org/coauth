//! REST API endpoints for user registration.
//!
//! These endpoints serve as thin HTTP adapters over the business logic in
//! [`crate::handlers::account::service::registration`]. They parse requests,
//! check config/policy constraints, delegate to service functions, and map
//! results to JSON responses.

use std::{str::FromStr, time::Duration as StdDuration};

use chrono::{Duration, Utc};
use coauth_data::{
    RepositoryAccess as _,
    flow::{FlowSession, FlowSessionStatus},
    new_id,
    user::{UserEmailRepository as _, UserRegistrationRepository as _, UserRepository as _},
};
use lettre::Address;
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ulid::Ulid;
use url::Url;
use zeroize::Zeroizing;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::{
    handlers::{
        RequesterFingerprint,
        account::service::registration::{
            BeginPasswordRegistrationError, BeginPasswordRegistrationRequest,
            BeginPasswordRegistrationResult, EmailAvailabilityCheck, LoadRegistrationProgressError,
            PrincipalServerCheckMode, RegistrationDisplayNameOutcome,
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
        notification_dispatch::{NotificationIntent, schedule_notification},
    },
    salvo_utils::SessionInfoExt,
};

// ── POST /api/v1/auth/register ─────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct RegisterInput {
    pub handle: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    pub password: String,
    pub password_confirm: String,
    /// Solved CAPTCHA token, supplied when the deployment has a CAPTCHA
    /// provider configured (`site.captcha`). Verified before the
    /// registration policy / availability checks run.
    #[serde(default)]
    pub captcha_token: Option<String>,
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
    let principal_server = depot.principal_server()?;
    let policy_factory = depot.policy_factory()?;
    let limiter = depot.limiter()?;
    let repo_factory = depot.repo_factory()?;
    let url_builder = depot.url_builder()?;
    let notification_language = crate::handlers::notification_language(req, depot, None);

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
            return Ok(Json(RegisterResponse {
                status: "error",
                id: None,
                next_step: None,
                error: Some("captcha_failed".into()),
                flow_session_id: None,
            }));
        }
    }

    let repo = repo_factory.create().await?;

    let started = match begin_password_registration(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        principal_server.as_ref(),
        policy_factory.as_ref(),
        &limiter,
        BeginPasswordRegistrationRequest {
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

// ── POST /api/v1/auth/register/webvh/start ────────────────────

#[derive(Deserialize, ToSchema)]
pub struct WebvhRegistrationStartInput {
    pub handle: String,
    #[serde(default)]
    pub principal_server_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct WebvhRegistrationStartResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<&'static str>,
    pub email_verification_bypass_allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_webvh_start(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<WebvhRegistrationStartResponse>, RouteError> {
    let input: WebvhRegistrationStartInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let site_config = depot.site_config()?;
    if !site_config.password_registration_enabled {
        return Ok(Json(WebvhRegistrationStartResponse {
            status: "error",
            registration_id: None,
            next_step: None,
            provider_id: None,
            email_verification_bypass_allowed: site_config
                .registration_email_delivery_bypass_allowed,
            error: Some("registration_disabled".into()),
        }));
    }

    let username = input.handle.trim().to_owned();
    if username.is_empty() {
        return Ok(Json(WebvhRegistrationStartResponse {
            status: "error",
            registration_id: None,
            next_step: None,
            provider_id: None,
            email_verification_bypass_allowed: site_config
                .registration_email_delivery_bypass_allowed,
            error: Some("username_required".into()),
        }));
    }

    let principal_server = depot.principal_server()?;
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(std::borrow::ToOwned::to_owned);
    let ip_address = activity_tracker.ip();
    let mut repo = repo_factory.create().await?;

    if repo.user().exists(&username).await? {
        return Ok(Json(WebvhRegistrationStartResponse {
            status: "error",
            registration_id: None,
            next_step: None,
            provider_id: None,
            email_verification_bypass_allowed: site_config
                .registration_email_delivery_bypass_allowed,
            error: Some("handle_exists".into()),
        }));
    }
    if matches!(
        principal_server.is_handle_available(&username).await,
        Ok(false)
    ) {
        return Ok(Json(WebvhRegistrationStartResponse {
            status: "error",
            registration_id: None,
            next_step: None,
            provider_id: None,
            email_verification_bypass_allowed: site_config
                .registration_email_delivery_bypass_allowed,
            error: Some("handle_exists".into()),
        }));
    }

    let mut registration = repo
        .user_registration()
        .add(
            &mut *rng,
            &clock,
            username.clone(),
            ip_address,
            user_agent,
            Some(json!({
                "kind": "coauth.webvh_registration.v1",
                "principal_server_url": input.principal_server_url,
            })),
        )
        .await?;
    registration = repo
        .user_registration()
        .set_display_name(registration, username)
        .await?;
    if let Some(tos_uri) = site_config.tos_uri.clone() {
        registration = repo
            .user_registration()
            .set_terms_url(registration, tos_uri)
            .await?;
    }
    repo.save().await?;

    Ok(Json(WebvhRegistrationStartResponse {
        status: "success",
        registration_id: Some(registration.id.to_string()),
        next_step: Some("email"),
        provider_id: Some("soland.embedded"),
        email_verification_bypass_allowed: site_config.registration_email_delivery_bypass_allowed,
        error: None,
    }))
}

// ── POST /api/v1/auth/register/webvh/:id/email ────────────────

#[derive(Deserialize, ToSchema)]
pub struct WebvhRegistrationEmailInput {
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct WebvhRegistrationEmailResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_webvh_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<WebvhRegistrationEmailResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;
    let input: WebvhRegistrationEmailInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;
    let site_config = depot.site_config()?;
    let email = input.email.trim();
    if Address::from_str(email).is_err() {
        return Ok(Json(WebvhRegistrationEmailResponse {
            status: "error",
            next_step: None,
            delivery: None,
            dev_code: None,
            error: Some("email_invalid".into()),
        }));
    }
    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language = crate::handlers::notification_language(req, depot, None);
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
    let mut repo = repo_factory.create().await?;

    let Some(registration) = repo.user_registration().lookup(id).await? else {
        return Err(RouteError::NotFound);
    };
    if registration.completed_at.is_some() {
        return Ok(Json(WebvhRegistrationEmailResponse {
            status: "error",
            next_step: None,
            delivery: None,
            dev_code: None,
            error: Some("registration_already_completed".into()),
        }));
    }
    if repo.user_email().find_by_email(email).await?.is_some() {
        return Ok(Json(WebvhRegistrationEmailResponse {
            status: "error",
            next_step: None,
            delivery: None,
            dev_code: None,
            error: Some("email_in_use".into()),
        }));
    }
    if limiter
        .check_email_authentication_email(requester, email)
        .await
        .is_err()
    {
        return Ok(Json(WebvhRegistrationEmailResponse {
            status: "error",
            next_step: None,
            delivery: None,
            dev_code: None,
            error: Some("rate_limited".into()),
        }));
    }

    let authentication = repo
        .user_email()
        .add_authentication_for_registration(&mut *rng, &clock, email.to_owned(), &registration)
        .await?;
    let _registration = repo
        .user_registration()
        .set_email_authentication(registration, &authentication)
        .await?;

    let (delivery, dev_code) = if site_config.registration_email_delivery_bypass_allowed {
        let code = "123456".to_owned();
        let _ = repo
            .user_email()
            .add_authentication_code(
                &mut *rng,
                &clock,
                Duration::minutes(15),
                &authentication,
                code.clone(),
            )
            .await?;
        ("skipped", Some(code))
    } else {
        schedule_notification(
            &mut repo,
            &mut *rng,
            &clock,
            NotificationIntent::verify_email(&authentication, notification_language),
        )
        .await?;
        ("email", None)
    };
    repo.save().await?;

    Ok(Json(WebvhRegistrationEmailResponse {
        status: "sent",
        next_step: Some("verify_email"),
        delivery: Some(delivery),
        dev_code,
        error: None,
    }))
}

// ── POST /api/v1/auth/register/webvh/:id/verify-email ─────────

#[endpoint]
pub async fn post_webvh_verify_email(
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

// ── POST /api/v1/auth/register/webvh/:id/finish ───────────────

#[derive(Deserialize, ToSchema)]
pub struct WebvhRegistrationFinishInput {
    pub did_public_key_multibase: String,
    pub update_public_key_multibase: String,
    #[serde(default)]
    pub did_key_id: Option<String>,
    #[serde(default)]
    pub update_key_id: Option<String>,
    #[serde(default)]
    pub webvh_version_time: Option<String>,
    #[serde(default)]
    pub webvh_proof: Option<Value>,
    #[serde(default)]
    pub device_id: Option<String>,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Serialize, ToSchema)]
pub struct WebvhRegistrationFinishResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_public_key_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_public_key_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub did_document: Value,
    #[serde(default)]
    pub did_log: Vec<Value>,
}

#[endpoint]
pub async fn post_webvh_finish(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<WebvhRegistrationFinishResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;
    let input: WebvhRegistrationFinishInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;
    if input.password != input.password_confirm {
        return Ok(Json(webvh_finish_error("password_mismatch")));
    }
    if input.did_public_key_multibase.trim().is_empty() {
        return Ok(Json(webvh_finish_error("did_public_key_required")));
    }
    if input.update_public_key_multibase.trim().is_empty() {
        return Ok(Json(webvh_finish_error("update_public_key_required")));
    }
    if input.did_public_key_multibase.trim() == input.update_public_key_multibase.trim() {
        return Ok(Json(webvh_finish_error("webvh_keys_must_be_separate")));
    }
    let Some(webvh_version_time) = input
        .webvh_version_time
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(Json(webvh_finish_error("webvh_version_time_required")));
    };
    let Some(webvh_proof) = input.webvh_proof.clone() else {
        return Ok(Json(webvh_finish_error("webvh_proof_required")));
    };

    let site_config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    if !site_config.password_registration_enabled || !site_config.password_login_enabled {
        return Ok(Json(webvh_finish_error("registration_disabled")));
    }
    if !password_manager
        .is_password_complex_enough(&input.password)
        .map_err(|error| RouteError::Internal(error.into()))?
    {
        return Ok(Json(webvh_finish_error("password_too_weak")));
    }

    let repo_factory = depot.repo_factory()?;
    let principal_server = depot.principal_server()?;
    let contrix_config = depot.contrix_config()?;
    let http_client = depot.http_client()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(std::borrow::ToOwned::to_owned);

    let mut repo = repo_factory.create().await?;
    let Some(registration) = repo.user_registration().lookup(id).await? else {
        return Err(RouteError::NotFound);
    };
    let principal_url = registration_webvh_principal_url(&registration.post_auth_action);
    let target = resolve_webvh_target(&contrix_config, principal_url.as_deref())
        .map_err(RouteError::BadRequest)?;
    let (version, password_hash) = password_manager
        .hash(&mut *rng, Zeroizing::new(input.password))
        .await
        .map_err(|error| RouteError::Internal(error.into()))?;
    let registration = repo
        .user_registration()
        .set_password(registration, password_hash, version)
        .await?;
    repo.save().await?;

    let webvh = register_soland_webvh(
        http_client,
        &target,
        registration.handle.as_str(),
        input.did_public_key_multibase.trim(),
        input.update_public_key_multibase.trim(),
        input.did_key_id.as_deref().unwrap_or("did-key-1"),
        input.update_key_id.as_deref().unwrap_or("update-key-1"),
        webvh_version_time,
        webvh_proof,
    )
    .await
    .map_err(RouteError::BadRequest)?;

    let repo = repo_factory.create().await?;
    let outcome = finish_registration(
        repo,
        &mut rng,
        &clock,
        principal_server.as_ref(),
        id,
        None,
        PrincipalServerCheckMode::BestEffort,
        site_config.registration_token_required,
        site_config.bootstrap_admin_token.as_deref(),
        None,
        user_agent,
    )
    .await
    .map_err(|error| match error {
        RegistrationFinishError::NotFound => RouteError::NotFound,
        RegistrationFinishError::Repository(error) => RouteError::from(error),
        RegistrationFinishError::Internal(error) => RouteError::Internal(error.into()),
    })?;

    let completed = match outcome {
        RegistrationFinishOutcome::Completed(completed) => completed,
        RegistrationFinishOutcome::Rejected { error } => {
            return Ok(Json(webvh_finish_error(error)));
        }
    };

    Ok(Json(WebvhRegistrationFinishResponse {
        status: "success",
        error: None,
        handle: Some(completed.user.handle),
        did: webvh.did,
        did_key_id: webvh.did_key_id,
        update_key_id: webvh.update_key_id,
        did_public_key_multibase: webvh.did_public_key_multibase,
        update_public_key_multibase: webvh.update_public_key_multibase,
        key_log_head: webvh.key_log_head,
        document_url: webvh.document_url,
        log_url: webvh.log_url,
        provider_id: webvh.provider_id,
        did_document: webvh.did_document,
        did_log: webvh.did_log,
    }))
}

// ── POST /api/v1/auth/register/did/start ──────────────────────

#[derive(Deserialize, ToSchema)]
pub struct ExistingDidRegistrationInput {
    pub did: String,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ExistingDidRegistrationResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
}

#[endpoint]
pub async fn post_existing_did_start(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ExistingDidRegistrationResponse>, RouteError> {
    let input: ExistingDidRegistrationInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;
    let did = input.did.trim();
    if !did.starts_with("did:") {
        return Ok(Json(ExistingDidRegistrationResponse {
            status: "error",
            error: Some("invalid_did".into()),
            did: None,
            proof_url: None,
            next_step: None,
        }));
    }
    let proof_url = depot
        .url_builder()?
        .absolute_url("/register/did/proof")
        .to_string();
    Ok(Json(ExistingDidRegistrationResponse {
        status: "proof_required",
        error: None,
        did: Some(did.to_owned()),
        proof_url: Some(proof_url),
        next_step: Some("did_proof"),
    }))
}

fn webvh_finish_error(error: impl Into<String>) -> WebvhRegistrationFinishResponse {
    WebvhRegistrationFinishResponse {
        status: "error",
        error: Some(error.into()),
        handle: None,
        did: String::new(),
        did_key_id: None,
        update_key_id: None,
        did_public_key_multibase: None,
        update_public_key_multibase: None,
        key_log_head: None,
        document_url: None,
        log_url: None,
        provider_id: None,
        did_document: Value::Null,
        did_log: Vec::new(),
    }
}

fn registration_webvh_principal_url(post_auth_action: &Option<Value>) -> Option<String> {
    post_auth_action
        .as_ref()
        .and_then(|value| value.get("principal_server_url"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[derive(Clone)]
struct WebvhTarget {
    endpoint: Url,
    bearer: String,
}

fn resolve_webvh_target(
    config: &coauth_config::ContrixConfig,
    requested: Option<&str>,
) -> Result<WebvhTarget, String> {
    let requested = requested.and_then(|value| Url::parse(value).ok());
    let candidate = config
        .principal_servers
        .iter()
        .filter(|server| {
            server
                .embedded_webvh_registration_bearer
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty())
        })
        .find(|server| {
            requested
                .as_ref()
                .is_none_or(|requested| urls_match(requested, &server.endpoint))
        });
    let Some(server) = candidate else {
        return Err("embedded_webvh_provider_not_configured".to_owned());
    };
    let endpoint = server
        .endpoint
        .join("api/v1/identity/webvh/register")
        .map_err(|_| "embedded_webvh_provider_url_invalid".to_owned())?;
    let bearer = server
        .embedded_webvh_registration_bearer
        .clone()
        .unwrap_or_default();
    Ok(WebvhTarget { endpoint, bearer })
}

fn urls_match(left: &Url, right: &Url) -> bool {
    left.as_str().trim_end_matches('/') == right.as_str().trim_end_matches('/')
}

#[derive(Deserialize)]
struct SolandEmbeddedWebvhResponse {
    pub did: String,
    #[serde(default)]
    pub did_key_id: Option<String>,
    #[serde(default)]
    pub update_key_id: Option<String>,
    #[serde(default)]
    pub did_public_key_multibase: Option<String>,
    #[serde(default)]
    pub update_public_key_multibase: Option<String>,
    #[serde(default)]
    pub key_log_head: Option<String>,
    #[serde(default)]
    pub document_url: Option<String>,
    #[serde(default)]
    pub log_url: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub did_document: Value,
    #[serde(default)]
    pub did_log: Vec<Value>,
}

async fn register_soland_webvh(
    http_client: reqwest::Client,
    target: &WebvhTarget,
    username: &str,
    did_public_key_multibase: &str,
    update_public_key_multibase: &str,
    did_key_id: &str,
    update_key_id: &str,
    webvh_version_time: &str,
    webvh_proof: Value,
) -> Result<SolandEmbeddedWebvhResponse, String> {
    let local_id = normalize_webvh_local_id(username).unwrap_or_else(|| username.to_owned());
    let response = http_client
        .post(target.endpoint.clone())
        .bearer_auth(target.bearer.as_str())
        .timeout(StdDuration::from_secs(10))
        .json(&json!({
            "local_id": local_id,
            "did_public_key_multibase": did_public_key_multibase,
            "update_public_key_multibase": update_public_key_multibase,
            "did_key_id": did_key_id,
            "update_key_id": update_key_id,
            "also_known_as": [format!("acct:{local_id}")],
            "version_time": webvh_version_time,
            "proof": webvh_proof,
        }))
        .send()
        .await
        .map_err(|error| format!("embedded_webvh_provider_unreachable:{error}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("embedded_webvh_provider_body:{error}"))?;
    if !status.is_success() {
        return Err(format!(
            "embedded_webvh_provider_error:{status}:{}",
            body.chars().take(256).collect::<String>()
        ));
    }
    serde_json::from_str(&body).map_err(|error| format!("embedded_webvh_provider_json:{error}"))
}

fn normalize_webvh_local_id(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    let valid = !normalized.is_empty()
        && normalized.len() <= 64
        && !normalized.contains("..")
        && normalized
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then_some(normalized)
}

// ── GET /api/v1/auth/register/:id ──────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct RegistrationStatusResponse {
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
        handle: status.registration.handle,
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
    let notification_language = crate::handlers::notification_language(req, depot, None);

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
    let notification_language = crate::handlers::notification_language(req, depot, None);

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
    /// OAuth authorization grant continuation), the frontend uses this to
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
    let principal_server = depot.principal_server()?;
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
        principal_server.as_ref(),
        id,
        None,
        PrincipalServerCheckMode::BestEffort,
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
