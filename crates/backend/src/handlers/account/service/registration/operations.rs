use std::str::FromStr;

use anyhow::Error as AnyhowError;
use coauth_data::user::{
    UserEmailFilter, UserEmailRepository, UserPhoneRepository, UserRepository,
};
use coauth_data::{BoxRepository, Clock, RepositoryAccess, UserRegistration};
use coauth_policy::PolicyFactory;
use coauth_principal::ConnectorAdmin;
use lettre::Address;
use rand_chacha::rand_core::CryptoRngCore;
use ulid::Ulid;
use zeroize::Zeroizing;

use super::*;
use crate::handlers::notification_dispatch::{NotificationIntent, schedule_notification};
use crate::handlers::passwords::PasswordManager;
use crate::handlers::{Limiter, RequesterFingerprint};

pub async fn start_password_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    request: StartPasswordRegistrationRequestBody,
) -> Result<StartedPasswordRegistration, StartPasswordRegistrationError> {
    let mut registration = repo
        .user_registration()
        .add(
            rng,
            clock,
            request.handle,
            request.ip_address,
            request.user_agent,
            request.post_auth_action,
        )
        .await?;

    if let Some(terms_url) = request.terms_url {
        registration = repo
            .user_registration()
            .set_terms_url(registration, terms_url)
            .await?;
    }

    let email_verified = if let Some(email) = request.email {
        let user_email_authentication = repo
            .user_email()
            .add_authentication_for_registration(rng, clock, email, &registration)
            .await?;

        schedule_notification(
            &mut repo,
            rng,
            clock,
            NotificationIntent::verify_email(
                &user_email_authentication,
                request.notification_language.clone(),
            ),
        )
        .await?;

        registration = repo
            .user_registration()
            .set_email_authentication(registration, &user_email_authentication)
            .await?;

        false
    } else {
        true
    };

    let phone_verified = if let Some(phone) = request.phone {
        let user_phone_authentication = repo
            .user_phone()
            .add_authentication_for_registration(rng, clock, phone, &registration)
            .await?;

        schedule_notification(
            &mut repo,
            rng,
            clock,
            NotificationIntent::verify_phone(
                &user_phone_authentication,
                request.notification_language,
            ),
        )
        .await?;

        registration = repo
            .user_registration()
            .set_phone_authentication(registration, &user_phone_authentication)
            .await?;

        false
    } else {
        true
    };

    let (version, hashed_password) = password_manager.hash(rng, request.password).await?;

    registration = repo
        .user_registration()
        .set_password(registration, hashed_password, version)
        .await?;

    repo.save().await?;

    Ok(StartedPasswordRegistration {
        registration,
        email_verified,
        phone_verified,
    })
}

pub async fn begin_password_registration(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    principal_server: &dyn ConnectorAdmin,
    policy_factory: &PolicyFactory,
    limiter: &Limiter,
    request: BeginPasswordRegistrationRequestBody,
) -> Result<BeginPasswordRegistrationResult, BeginPasswordRegistrationError> {
    if !request.password_registration_enabled {
        return Ok(BeginPasswordRegistrationResult::Rejected {
            issues: vec![BeginPasswordRegistrationIssue::RegistrationDisabled],
        });
    }

    let mut issues: Vec<BeginPasswordRegistrationIssue> = Vec::new();

    if request.handle.is_empty() {
        issues.push(BeginPasswordRegistrationIssue::HandleRequired);
    } else if cokret_core::normalize_handle_localpart(&request.handle).is_err() {
        // HDL-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) —
        // wire-level NFC + UTS#39 confusable skeleton + script-mixed
        // reject. MUST run before any storage / availability lookup so
        // confusable handles can never reach the user table or the
        // upstream principal server. The SDK helper is the single
        // source of truth for the rejection set.
        issues.push(BeginPasswordRegistrationIssue::HandleHomographForbidden);
    } else if repo.user().exists(&request.handle).await? {
        issues.push(BeginPasswordRegistrationIssue::HandleExists);
    } else {
        match principal_server.is_handle_available(&request.handle).await {
            Ok(false) => issues.push(BeginPasswordRegistrationIssue::HandleExists),
            Ok(true) => {}
            Err(error) => {
                tracing::warn!(
                    error = &*error as &dyn std::error::Error,
                    "Failed to check username availability, skipping PrincipalServer check"
                );
            }
        }
    }

    let email_str = request.email.unwrap_or_default();
    let phone_str = request.phone.unwrap_or_default();

    if request.password_registration_contact_required
        && email_str.is_empty()
        && phone_str.is_empty()
    {
        issues.push(BeginPasswordRegistrationIssue::EmailOrPhoneRequired);
    }

    let email = if !email_str.is_empty() {
        if Address::from_str(&email_str).is_err() {
            issues.push(BeginPasswordRegistrationIssue::EmailInvalid);
            None
        } else if matches!(request.email_availability, EmailAvailabilityCheck::Precheck)
            && repo
                .user_email()
                .count(UserEmailFilter::new().for_email(&email_str))
                .await?
                > 0
        {
            issues.push(BeginPasswordRegistrationIssue::EmailInUse);
            None
        } else {
            Some(email_str)
        }
    } else {
        None
    };

    let phone = if !phone_str.is_empty() {
        if repo.user_phone().find_by_phone(&phone_str).await?.is_some() {
            issues.push(BeginPasswordRegistrationIssue::PhoneInUse);
            None
        } else {
            Some(phone_str)
        }
    } else {
        None
    };

    if request.password.is_empty() {
        issues.push(BeginPasswordRegistrationIssue::PasswordRequired);
    }

    if request.password_confirm.is_empty() {
        issues.push(BeginPasswordRegistrationIssue::PasswordConfirmRequired);
    }

    if request.password != request.password_confirm {
        issues.push(BeginPasswordRegistrationIssue::PasswordMismatch);
    }

    if issues.is_empty()
        && !password_manager
            .is_password_complex_enough(&request.password)
            .map_err(AnyhowError::from)?
    {
        issues.push(BeginPasswordRegistrationIssue::PasswordTooWeak);
    }

    if issues.is_empty() {
        let mut policy = policy_factory
            .instantiate()
            .await
            .map_err(AnyhowError::from)?;
        let result = policy
            .evaluate_register(coauth_policy::RegisterInput {
                registration_method: coauth_policy::RegistrationMethod::Password,
                handle: &request.handle,
                email: email.as_deref(),
                requester: coauth_policy::Requester {
                    ip_address: request.ip_address,
                    user_agent: request.user_agent.clone(),
                    ..Default::default()
                },
            })
            .await
            .map_err(AnyhowError::from)?;

        for violation in result.violations {
            issues.push(BeginPasswordRegistrationIssue::Policy {
                field: violation.field,
                code: violation.code.map(|code| code.as_str()),
                message: violation.msg,
            });
        }
    }

    if issues.is_empty() {
        let mut rate_limited = false;

        if let Err(error) = limiter.check_registration(request.requester).await {
            tracing::warn!(error = &error as &dyn std::error::Error);
            rate_limited = true;
        }

        if let Some(email) = &email
            && let Err(error) = limiter
                .check_email_authentication_email(request.requester, email)
                .await
        {
            tracing::warn!(error = &error as &dyn std::error::Error);
            rate_limited = true;
        }

        if let Some(phone) = &phone
            && let Err(error) = limiter
                .check_phone_authentication_phone(request.requester, phone)
                .await
        {
            tracing::warn!(error = &error as &dyn std::error::Error);
            rate_limited = true;
        }

        if rate_limited {
            issues.push(BeginPasswordRegistrationIssue::RateLimited);
        }
    }

    if !issues.is_empty() {
        return Ok(BeginPasswordRegistrationResult::Rejected { issues });
    }

    let started = start_password_registration(
        repo,
        rng,
        clock,
        password_manager,
        StartPasswordRegistrationRequestBody {
            handle: request.handle,
            email,
            phone,
            password: Zeroizing::new(request.password),
            user_agent: request.user_agent,
            ip_address: request.ip_address,
            post_auth_action: request.post_auth_action,
            terms_url: request.terms_url,
            notification_language: request.notification_language,
        },
    )
    .await
    .map_err(|error| match error {
        StartPasswordRegistrationError::Repository(error) => {
            BeginPasswordRegistrationError::Repository(error)
        }
        StartPasswordRegistrationError::Password(error) => {
            BeginPasswordRegistrationError::Internal(error)
        }
    })?;

    Ok(BeginPasswordRegistrationResult::Started(started))
}

pub async fn resend_pending_registration_verification(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    registration_id: Ulid,
    notification_language: String,
) -> Result<ResendRegistrationVerificationStatus, ResendRegistrationVerificationError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(ResendRegistrationVerificationError::NotFound)?;

    if registration.completed_at.is_some() {
        return Ok(ResendRegistrationVerificationStatus::RegistrationCompleted);
    }

    if let Some(email_authentication_id) = registration.email_authentication_id {
        let auth = repo
            .user_email()
            .lookup_authentication(email_authentication_id)
            .await?
            .ok_or(ResendRegistrationVerificationError::NotFound)?;

        if auth.completed_at.is_none() {
            if let Err(error) = limiter
                .check_email_authentication_send_code(requester, &auth)
                .await
            {
                tracing::warn!(error = &error as &dyn std::error::Error);
                return Err(ResendRegistrationVerificationError::RateLimited);
            }

            schedule_notification(
                &mut repo,
                rng,
                clock,
                NotificationIntent::verify_email(&auth, notification_language),
            )
            .await?;
            repo.save().await?;

            return Ok(ResendRegistrationVerificationStatus::Resent);
        }
    }

    if let Some(phone_authentication_id) = registration.phone_authentication_id {
        let auth = repo
            .user_phone()
            .lookup_authentication(phone_authentication_id)
            .await?
            .ok_or(ResendRegistrationVerificationError::NotFound)?;

        if auth.completed_at.is_none() {
            if let Err(error) = limiter
                .check_phone_authentication_send_code(requester, &auth)
                .await
            {
                tracing::warn!(error = &error as &dyn std::error::Error);
                return Err(ResendRegistrationVerificationError::RateLimited);
            }

            schedule_notification(
                &mut repo,
                rng,
                clock,
                NotificationIntent::verify_phone(&auth, notification_language),
            )
            .await?;
            repo.save().await?;

            return Ok(ResendRegistrationVerificationStatus::Resent);
        }
    }

    Ok(ResendRegistrationVerificationStatus::AlreadyVerified)
}

pub async fn verify_registration_email_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationProgress, VerifyRegistrationEmailCodeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => VerifyRegistrationEmailCodeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                VerifyRegistrationEmailCodeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Err(VerifyRegistrationEmailCodeError::RegistrationCompleted);
    }

    let email_authentication = if progress.registration.email_authentication_id.is_none() {
        return Err(VerifyRegistrationEmailCodeError::NoEmailAuthentication);
    } else {
        progress
            .email_authentication
            .ok_or(VerifyRegistrationEmailCodeError::EmailAuthenticationMissing)?
    };

    if email_authentication.completed_at.is_some() {
        return Err(VerifyRegistrationEmailCodeError::EmailAlreadyVerified);
    }

    if let Err(error) = limiter
        .check_email_authentication_attempt(&email_authentication)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(VerifyRegistrationEmailCodeError::RateLimited);
    }

    let code = repo
        .user_email()
        .find_authentication_code(&email_authentication, code)
        .await?
        .ok_or(VerifyRegistrationEmailCodeError::InvalidCode)?;

    let email_authentication = repo
        .user_email()
        .complete_authentication_with_code(clock, email_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(RegistrationProgress {
        registration: progress.registration,
        email_authentication: Some(email_authentication),
        phone_authentication: progress.phone_authentication,
    })
}

pub async fn verify_registration_phone_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationProgress, VerifyRegistrationPhoneCodeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => VerifyRegistrationPhoneCodeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                VerifyRegistrationPhoneCodeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Err(VerifyRegistrationPhoneCodeError::RegistrationCompleted);
    }

    let phone_authentication = if progress.registration.phone_authentication_id.is_none() {
        return Err(VerifyRegistrationPhoneCodeError::NoPhoneAuthentication);
    } else {
        progress
            .phone_authentication
            .ok_or(VerifyRegistrationPhoneCodeError::PhoneAuthenticationMissing)?
    };

    if phone_authentication.completed_at.is_some() {
        return Err(VerifyRegistrationPhoneCodeError::PhoneAlreadyVerified);
    }

    if let Err(error) = limiter
        .check_phone_authentication_attempt(&phone_authentication)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(VerifyRegistrationPhoneCodeError::RateLimited);
    }

    let code = repo
        .user_phone()
        .find_authentication_code(&phone_authentication, code)
        .await?
        .ok_or(VerifyRegistrationPhoneCodeError::InvalidCode)?;

    let phone_authentication = repo
        .user_phone()
        .complete_authentication_with_code(clock, phone_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(RegistrationProgress {
        registration: progress.registration,
        email_authentication: progress.email_authentication,
        phone_authentication: Some(phone_authentication),
    })
}

pub async fn set_registration_display_name(
    mut repo: BoxRepository,
    registration_id: Ulid,
    display_name: Option<String>,
    skip: bool,
) -> Result<UserRegistration, SetRegistrationDisplayNameError> {
    let registration = repo
        .user_registration()
        .lookup(registration_id)
        .await?
        .ok_or(SetRegistrationDisplayNameError::NotFound)?;

    if registration.completed_at.is_some() {
        return Err(SetRegistrationDisplayNameError::RegistrationCompleted);
    }

    let display_name = if skip {
        registration.localpart.clone()
    } else {
        let display_name = display_name.as_deref().unwrap_or("").trim().to_owned();

        if display_name.is_empty() || display_name.len() > 255 {
            return Err(SetRegistrationDisplayNameError::InvalidDisplayName);
        }

        display_name
    };

    let registration = repo
        .user_registration()
        .set_display_name(registration, display_name)
        .await?;

    repo.save().await?;

    Ok(registration)
}

pub async fn resend_registration_verification(
    repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    registration_id: Ulid,
    notification_language: String,
) -> Result<RegistrationResendOutcome, RegistrationResendError> {
    match resend_pending_registration_verification(
        repo,
        limiter,
        rng,
        clock,
        requester,
        registration_id,
        notification_language,
    )
    .await
    {
        Ok(ResendRegistrationVerificationStatus::Resent) => Ok(RegistrationResendOutcome::Resent),
        Ok(ResendRegistrationVerificationStatus::AlreadyVerified) => {
            Ok(RegistrationResendOutcome::AlreadyVerified)
        }
        Ok(ResendRegistrationVerificationStatus::RegistrationCompleted) => {
            Ok(RegistrationResendOutcome::RegistrationCompleted)
        }
        Err(ResendRegistrationVerificationError::NotFound) => {
            Err(RegistrationResendError::NotFound)
        }
        Err(ResendRegistrationVerificationError::RateLimited) => {
            Ok(RegistrationResendOutcome::RateLimited)
        }
        Err(ResendRegistrationVerificationError::Repository(error)) => {
            Err(RegistrationResendError::Repository(error))
        }
    }
}

pub async fn change_registration_email(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    registration_id: Ulid,
    email: &str,
    notification_language: String,
) -> Result<RegistrationEmailChangeOutcome, RegistrationEmailChangeError> {
    let progress = load_registration_progress(&mut repo, registration_id)
        .await
        .map_err(|error| match error {
            LoadRegistrationProgressError::NotFound => RegistrationEmailChangeError::NotFound,
            LoadRegistrationProgressError::Repository(error) => {
                RegistrationEmailChangeError::Repository(error)
            }
        })?;

    if progress.registration.completed_at.is_some() {
        return Ok(RegistrationEmailChangeOutcome::RegistrationCompleted);
    }

    if progress.registration.email_authentication_id.is_none() {
        return Err(RegistrationEmailChangeError::NotAvailable);
    }

    let current_auth = progress
        .email_authentication
        .ok_or(RegistrationEmailChangeError::NotFound)?;

    if current_auth.completed_at.is_some() {
        return Ok(RegistrationEmailChangeOutcome::AlreadyVerified);
    }

    let email = email.trim();
    if Address::from_str(email).is_err() {
        return Ok(RegistrationEmailChangeOutcome::InvalidEmail);
    }

    if repo.user_email().find_by_email(email).await?.is_some() {
        return Ok(RegistrationEmailChangeOutcome::EmailInUse);
    }

    if let Err(error) = limiter
        .check_email_authentication_email(requester, email)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Ok(RegistrationEmailChangeOutcome::RateLimited);
    }

    let updated_auth = repo
        .user_email()
        .add_authentication_for_registration(rng, clock, email.to_owned(), &progress.registration)
        .await?;

    schedule_notification(
        &mut repo,
        rng,
        clock,
        NotificationIntent::verify_email(&updated_auth, notification_language),
    )
    .await?;

    let _ = repo
        .user_registration()
        .set_email_authentication(progress.registration, &updated_auth)
        .await?;

    repo.save().await?;

    Ok(RegistrationEmailChangeOutcome::Updated)
}

pub async fn submit_registration_email_code(
    repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationVerificationOutcome, RegistrationVerificationError> {
    match verify_registration_email_code(repo, limiter, clock, registration_id, code).await {
        Ok(progress) => Ok(RegistrationVerificationOutcome::Advanced {
            next_step: progress.next_step(),
        }),
        Err(
            VerifyRegistrationEmailCodeError::NotFound
            | VerifyRegistrationEmailCodeError::EmailAuthenticationMissing,
        ) => Err(RegistrationVerificationError::NotFound),
        Err(VerifyRegistrationEmailCodeError::NoEmailAuthentication) => {
            Err(RegistrationVerificationError::NotAvailable)
        }
        Err(VerifyRegistrationEmailCodeError::RegistrationCompleted) => {
            Ok(RegistrationVerificationOutcome::RegistrationCompleted)
        }
        Err(VerifyRegistrationEmailCodeError::EmailAlreadyVerified) => {
            Ok(RegistrationVerificationOutcome::AlreadyVerified)
        }
        Err(VerifyRegistrationEmailCodeError::RateLimited) => {
            Ok(RegistrationVerificationOutcome::RateLimited)
        }
        Err(VerifyRegistrationEmailCodeError::InvalidCode) => {
            Ok(RegistrationVerificationOutcome::InvalidCode)
        }
        Err(VerifyRegistrationEmailCodeError::Repository(error)) => {
            Err(RegistrationVerificationError::Repository(error))
        }
    }
}

pub async fn submit_registration_phone_code(
    repo: BoxRepository,
    limiter: &Limiter,
    clock: &dyn Clock,
    registration_id: Ulid,
    code: &str,
) -> Result<RegistrationVerificationOutcome, RegistrationVerificationError> {
    match verify_registration_phone_code(repo, limiter, clock, registration_id, code).await {
        Ok(progress) => Ok(RegistrationVerificationOutcome::Advanced {
            next_step: progress.next_step(),
        }),
        Err(
            VerifyRegistrationPhoneCodeError::NotFound
            | VerifyRegistrationPhoneCodeError::PhoneAuthenticationMissing,
        ) => Err(RegistrationVerificationError::NotFound),
        Err(VerifyRegistrationPhoneCodeError::NoPhoneAuthentication) => {
            Err(RegistrationVerificationError::NotAvailable)
        }
        Err(VerifyRegistrationPhoneCodeError::RegistrationCompleted) => {
            Ok(RegistrationVerificationOutcome::RegistrationCompleted)
        }
        Err(VerifyRegistrationPhoneCodeError::PhoneAlreadyVerified) => {
            Ok(RegistrationVerificationOutcome::AlreadyVerified)
        }
        Err(VerifyRegistrationPhoneCodeError::RateLimited) => {
            Ok(RegistrationVerificationOutcome::RateLimited)
        }
        Err(VerifyRegistrationPhoneCodeError::InvalidCode) => {
            Ok(RegistrationVerificationOutcome::InvalidCode)
        }
        Err(VerifyRegistrationPhoneCodeError::Repository(error)) => {
            Err(RegistrationVerificationError::Repository(error))
        }
    }
}

pub async fn submit_registration_display_name(
    repo: BoxRepository,
    registration_id: Ulid,
    display_name: Option<String>,
    skip: bool,
) -> Result<RegistrationDisplayNameOutcome, RegistrationDisplayNameWorkflowError> {
    match set_registration_display_name(repo, registration_id, display_name, skip).await {
        Ok(_) => Ok(RegistrationDisplayNameOutcome::Advanced {
            next_step: "finish",
        }),
        Err(SetRegistrationDisplayNameError::NotFound) => {
            Err(RegistrationDisplayNameWorkflowError::NotFound)
        }
        Err(SetRegistrationDisplayNameError::RegistrationCompleted) => {
            Ok(RegistrationDisplayNameOutcome::RegistrationCompleted)
        }
        Err(SetRegistrationDisplayNameError::InvalidDisplayName) => {
            Ok(RegistrationDisplayNameOutcome::InvalidDisplayName)
        }
        Err(SetRegistrationDisplayNameError::Repository(error)) => {
            Err(RegistrationDisplayNameWorkflowError::Repository(error))
        }
    }
}
