//! REST API endpoints for user registration.
//!
//! These endpoints serve as thin HTTP adapters over the business logic in
//! [`crate::handlers::account::service::registration`]. They parse requests,
//! check config/policy constraints, delegate to service functions, and map
//! results to JSON responses.

use std::str::FromStr;

use chrono::Duration;
use coauth_data::RepositoryAccess as _;
use coauth_data::user::{
    UserEmailRepository as _, UserRegistrationRepository as _, UserRepository as _,
};
use lettre::Address;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ulid::Ulid;
use url::Url;
use zeroize::Zeroizing;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::handlers::account::service::registration::{
    BeginPasswordRegistrationError, BeginPasswordRegistrationRequestBody,
    BeginPasswordRegistrationResult, CheckRegistrationFinishEligibilityError,
    EmailAvailabilityCheck, LoadRegistrationProgressError, PrincipalServerCheckMode,
    RegistrationDisplayNameOutcome, RegistrationDisplayNameWorkflowError,
    RegistrationEmailChangeError, RegistrationEmailChangeOutcome, RegistrationFinishError,
    RegistrationFinishOutcome, RegistrationResendError, RegistrationResendOutcome,
    RegistrationVerificationError, RegistrationVerificationOutcome, begin_password_registration,
    change_registration_email, check_registration_finish_eligibility, finish_registration,
    load_registration_status, next_registration_step, resend_registration_verification,
    submit_registration_display_name, submit_registration_email_code,
    submit_registration_phone_code,
};
use crate::handlers::notification_dispatch::{NotificationIntent, schedule_notification};
use crate::handlers::{RequesterFingerprint, arkret};
use crate::salvo_utils::SessionInfoExt;
use crate::services::soland_webvh::{self, SuppliedInceptionInput};

// ── POST /_coauth/account/auth/register ─────────────────────────────────

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
pub struct RegisterOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_register(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegisterOutcome>, RouteError> {
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
            return Ok(Json(RegisterOutcome {
                status: "error",
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
        principal_server.as_ref(),
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
            return Ok(Json(RegisterOutcome {
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
            }));
        }
    };

    let registration = started.registration;
    let email_verified = started.email_verified;
    let phone_verified = started.phone_verified;

    let step = next_registration_step(&registration, email_verified, phone_verified);

    Ok(Json(RegisterOutcome {
        status: "success",
        id: Some(registration.id.to_string()),
        next_step: Some(step),
        error: None,
    }))
}

// ── POST /_coauth/account/auth/register/webvh/start ────────────────────

#[derive(Deserialize, ToSchema)]
pub struct WebvhRegistrationStartInput {
    pub handle: String,
    #[serde(default)]
    pub principal_server_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct WebvhRegistrationStartOutcome {
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
) -> Result<Json<WebvhRegistrationStartOutcome>, RouteError> {
    let input: WebvhRegistrationStartInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let site_config = depot.site_config()?;
    if !site_config.password_registration_enabled {
        return Ok(Json(WebvhRegistrationStartOutcome {
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
        return Ok(Json(WebvhRegistrationStartOutcome {
            status: "error",
            registration_id: None,
            next_step: None,
            provider_id: None,
            email_verification_bypass_allowed: site_config
                .registration_email_delivery_bypass_allowed,
            error: Some("username_required".into()),
        }));
    }
    // HDL-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) —
    // wire-level handle normalize / homograph check via the SDK helper.
    // MUST run before any storage lookup so confusable handles never
    // hit `repo.user().exists(...)` or the principal server.
    if cokret_core::normalize_handle_localpart(&username).is_err() {
        return Ok(Json(WebvhRegistrationStartOutcome {
            status: "error",
            registration_id: None,
            next_step: None,
            provider_id: None,
            email_verification_bypass_allowed: site_config
                .registration_email_delivery_bypass_allowed,
            error: Some("handle_homograph_forbidden".into()),
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
        return Ok(Json(WebvhRegistrationStartOutcome {
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
        return Ok(Json(WebvhRegistrationStartOutcome {
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

    Ok(Json(WebvhRegistrationStartOutcome {
        status: "success",
        registration_id: Some(registration.id.to_string()),
        next_step: Some("email"),
        provider_id: Some("soland.embedded"),
        email_verification_bypass_allowed: site_config.registration_email_delivery_bypass_allowed,
        error: None,
    }))
}

// ── POST /_coauth/account/auth/register/webvh/:id/email ────────────────

#[derive(Deserialize, ToSchema)]
pub struct WebvhRegistrationEmailInput {
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct WebvhRegistrationEmailOutcome {
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
) -> Result<Json<WebvhRegistrationEmailOutcome>, RouteError> {
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
        return Ok(Json(WebvhRegistrationEmailOutcome {
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
        return Ok(Json(WebvhRegistrationEmailOutcome {
            status: "error",
            next_step: None,
            delivery: None,
            dev_code: None,
            error: Some("registration_already_completed".into()),
        }));
    }
    if repo.user_email().find_by_email(email).await?.is_some() {
        return Ok(Json(WebvhRegistrationEmailOutcome {
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
        return Ok(Json(WebvhRegistrationEmailOutcome {
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
        // Dev/test bypass only (guarded above by the config flag, which the
        // configuration layer refuses to enable in production). Generate a
        // random code rather than a predictable constant so a leaked
        // bypass-enabled deployment cannot be trivially registered against with
        // a known code. The code is returned in-band via `dev_code` for the
        // e2e harness, which is acceptable because this branch never runs in
        // production.
        use rand_core::RngCore as _;
        let code = format!("{:06}", rng.next_u32() % 1_000_000);
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

    Ok(Json(WebvhRegistrationEmailOutcome {
        status: "sent",
        next_step: Some("verify_email"),
        delivery: Some(delivery),
        dev_code,
        error: None,
    }))
}

// ── POST /_coauth/account/auth/register/webvh/:id/verify-email ─────────

#[endpoint]
pub async fn post_webvh_verify_email(
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

// ── POST /_coauth/account/auth/register/webvh/:id/finish ───────────────

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
pub struct WebvhRegistrationFinishOutcome {
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
) -> Result<Json<WebvhRegistrationFinishOutcome>, RouteError> {
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
    let cokret_config = depot.cokret_config()?;
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
    let target = resolve_webvh_provider(&cokret_config, principal_url.as_deref())
        .map_err(RouteError::BadRequest)?;

    // Pre-flight the registration-finish eligibility *before* writing the
    // password and submitting the (non-reversible) DID operation. This moves
    // the common rejection cases (handle already taken, registration expired)
    // ahead of the irreversible side effects so a doomed finish does not leave
    // an orphaned password row and a submitted DID with no backing user.
    match check_registration_finish_eligibility(
        &mut repo,
        &clock,
        principal_server.as_ref(),
        &registration,
        None,
        PrincipalServerCheckMode::BestEffort,
    )
    .await
    {
        Ok(()) => {}
        Err(CheckRegistrationFinishEligibilityError::RegistrationExpired) => {
            return Ok(Json(webvh_finish_error("registration_expired")));
        }
        Err(CheckRegistrationFinishEligibilityError::HandleTaken) => {
            return Ok(Json(webvh_finish_error("handle_taken")));
        }
        Err(CheckRegistrationFinishEligibilityError::HandleNotAvailable) => {
            return Ok(Json(webvh_finish_error("handle_not_available")));
        }
        // BestEffort mode never surfaces these, but fail closed regardless.
        Err(CheckRegistrationFinishEligibilityError::BrowserSessionMissing) => {
            return Ok(Json(webvh_finish_error("browser_session_required")));
        }
        Err(CheckRegistrationFinishEligibilityError::PrincipalServerUnavailable(error)) => {
            return Err(RouteError::Internal(error.into()));
        }
        Err(CheckRegistrationFinishEligibilityError::Repository(error)) => {
            return Err(error.into());
        }
    }

    let (version, password_hash) = password_manager
        .hash(&mut *rng, Zeroizing::new(input.password))
        .await
        .map_err(|error| RouteError::Internal(error.into()))?;
    let registration = repo
        .user_registration()
        .set_password(registration, password_hash, version)
        .await?;
    repo.save().await?;

    let local_id = registration
        .localpart
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    let also_known_as = [format!("acct:{local_id}")];
    // The minted principal DID document MUST designate coauth as the
    // CokretDeviceEnrollmentAuthority; without it soland rejects every device
    // authorization event with `device_enrollment_authority_not_designated`, so
    // the account can never enroll a device or publish an MLS KeyPackage. The
    // OIDC login path already injects this (auth/oidc_bridge.rs); the password
    // registration path previously hardcoded `None`, silently minting accounts
    // that could authenticate but never participate in MLS. Mirror the OIDC path.
    let enrollment_authority_did =
        crate::services::device_enrollment_authority::enrollment_authority()
            .did()
            .to_owned();
    let webvh = soland_webvh::prepare_supplied_inception(&SuppliedInceptionInput {
        principal_endpoint: &target.endpoint,
        local_id: registration.localpart.as_str(),
        also_known_as: &also_known_as,
        version_time: webvh_version_time,
        did_public_key_multibase: input.did_public_key_multibase.trim(),
        update_public_key_multibase: input.update_public_key_multibase.trim(),
        did_key_fragment: input.did_key_id.as_deref(),
        update_key_fragment: input.update_key_id.as_deref(),
        proof: webvh_proof,
        enrollment_authority_did: Some(enrollment_authority_did.as_str()),
    })
    .map_err(|error| RouteError::BadRequest(format!("embedded_webvh_provider_invalid:{error}")))?;
    soland_webvh::submit_did_operation(
        &http_client,
        &target.endpoint,
        target.bearer.as_deref(),
        &webvh.submit_body,
    )
    .await
    .map_err(|error| RouteError::BadRequest(format!("embedded_webvh_provider_error:{error}")))?;

    // At this point the password has been persisted and the (irreversible) DID
    // operation has been submitted to the webvh provider. If the final finish
    // step fails we have an orphaned password row + submitted DID with no
    // backing user. We cannot transactionally roll back the remote DID
    // submission, so emit a structured error with enough context for an
    // operator (or a retry) to reconcile. The whole `finish` endpoint is
    // idempotent — `set_password` overwrites, the webvh submission is
    // idempotent on the provider side, and a second `finish_registration` for
    // an already-created user returns `Rejected{registration_already_completed}`
    // — so the client may safely retry this request.
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
    .map_err(|error| {
        tracing::error!(
            registration.id = %id,
            did = %webvh.did,
            localpart = %local_id,
            error = %error,
            "webvh registration finish failed AFTER DID submission; password and DID are \
             orphaned without a backing user. The finish endpoint is idempotent and can be \
             retried to reconcile."
        );
        match error {
            RegistrationFinishError::NotFound => RouteError::NotFound,
            RegistrationFinishError::Repository(error) => RouteError::from(error),
            RegistrationFinishError::Internal(error) => RouteError::Internal(error.into()),
        }
    })?;

    let completed = match outcome {
        RegistrationFinishOutcome::Completed(completed) => completed,
        RegistrationFinishOutcome::Rejected { error } => {
            return Ok(Json(webvh_finish_error(error)));
        }
    };

    Ok(Json(WebvhRegistrationFinishOutcome {
        status: "success",
        error: None,
        handle: Some(completed.user.localpart),
        did: webvh.did,
        did_key_id: Some(webvh.did_key_id),
        update_key_id: Some(webvh.update_key_id),
        did_public_key_multibase: Some(webvh.did_public_key_multibase),
        update_public_key_multibase: Some(webvh.update_public_key_multibase),
        key_log_head: Some(webvh.key_log_head),
        document_url: Some(webvh.document_url),
        log_url: Some(webvh.log_url),
        provider_id: Some(webvh.provider_id),
        did_document: webvh.did_document,
        did_log: webvh.did_log,
    }))
}

// ── POST /_coauth/account/auth/register/did/start ──────────────────────

#[derive(Deserialize, ToSchema)]
pub struct ExistingDidRegistrationInput {
    pub did: String,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ExistingDidRegistrationOutcome {
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
) -> Result<Json<ExistingDidRegistrationOutcome>, RouteError> {
    let input: ExistingDidRegistrationInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;
    let did = input.did.trim();
    if !did.starts_with("did:") {
        return Ok(Json(ExistingDidRegistrationOutcome {
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
    Ok(Json(ExistingDidRegistrationOutcome {
        status: "proof_required",
        error: None,
        did: Some(did.to_owned()),
        proof_url: Some(proof_url),
        next_step: Some("did_proof"),
    }))
}

fn webvh_finish_error(error: impl Into<String>) -> WebvhRegistrationFinishOutcome {
    WebvhRegistrationFinishOutcome {
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
struct WebvhProviderTarget {
    endpoint: Url,
    bearer: Option<String>,
}

fn resolve_webvh_provider(
    config: &coauth_config::CokretConfig,
    requested: Option<&str>,
) -> Result<WebvhProviderTarget, String> {
    let requested = requested.and_then(|value| Url::parse(value).ok());
    let candidate = config.principal_servers.iter().find(|server| {
        requested
            .as_ref()
            .is_none_or(|requested| urls_match(requested, &server.endpoint))
    });
    let Some(server) = candidate else {
        return Err("embedded_webvh_provider_not_configured".to_owned());
    };
    let bearer = server
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(WebvhProviderTarget {
        endpoint: server.endpoint.clone(),
        bearer,
    })
}

fn urls_match(left: &Url, right: &Url) -> bool {
    left.as_str().trim_end_matches('/') == right.as_str().trim_end_matches('/')
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

    Ok(Json(ResendVerificationOutcome { status, error }))
}

// ── POST /_coauth/account/auth/register/:id/change-email ──────────────

#[derive(Deserialize, ToSchema)]
pub struct ChangeRegistrationEmailInput {
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct ChangeRegistrationEmailOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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

    Ok(Json(ChangeRegistrationEmailOutcome { status, error }))
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
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// If the registration was started as part of another strand (e.g. an
    /// OAuth authorization grant continuation), the frontend uses this to
    /// resume that strand after the account is created.
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
) -> Result<Json<FinishRegistrationOutcome>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = depot.site_config()?;
    let principal_server = depot.principal_server()?;
    let repo_factory = depot.repo_factory()?;
    let cokret_config = depot.cokret_config()?;
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
            return Ok(Json(FinishRegistrationOutcome {
                status: "error",
                did: None,
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
    let did = arkret::user_did_for(&cokret_config, &completed.user);

    Ok(Json(FinishRegistrationOutcome {
        status: "success",
        did: Some(did),
        error: None,
        post_auth_action,
    }))
}
