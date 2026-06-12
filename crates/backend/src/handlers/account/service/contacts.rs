//! Service functions for user contact (email/phone) verification and
//! management.
//!
//! These functions encapsulate the business logic for adding, verifying, and
//! removing contact information on an existing user account. They are consumed
//! by the REST handlers in [`crate::handlers::account::emails`].
//!
//! # Migration path
//!
//! The contact verification workflow currently uses direct repository calls for
//! state tracking. It will be progressively migrated to use
//! `WorkflowRepository` for unified workflow state management. The flow engine
//! (`crate::handlers::flow`) can already orchestrate contact verification as a
//! workflow.

use anyhow::Error as AnyhowError;
use coauth_data::queue::{ProvisionUserJob, QueueJobRepositoryExt as _};
use coauth_data::user::{UserEmailRepository, UserRepository};
use coauth_data::{
    BoxRepository, BrowserSession, Clock, RepositoryAccess, RepositoryError,
    UserEmailAuthentication,
};
use rand_core::RngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::account::service::password::{
    VerifyPasswordIfNeededError, verify_password_if_needed as verify_contact_password_if_needed,
};
use crate::handlers::notification_dispatch::{NotificationIntent, schedule_notification};
use crate::handlers::passwords::PasswordManager;
use crate::handlers::{Limiter, RequesterFingerprint};

// ── Start email verification ──────────────────────────────────

#[derive(Debug, Error)]
pub enum StartEmailVerificationError {
    #[error("browser session required")]
    Unauthorized,

    #[error("email changes are not allowed")]
    Disabled,

    #[error("invalid email address")]
    InvalidEmail,

    #[error("incorrect password")]
    IncorrectPassword,

    #[error("email verification is rate limited")]
    RateLimited,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub struct StartedEmailVerification {
    pub authentication: UserEmailAuthentication,
}

/// Begin an email verification flow for an existing user session.
///
/// Creates a [`UserEmailAuthentication`] record and schedules a verification
/// code notification.
pub async fn start_email_verification(
    mut repo: BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    limiter: &Limiter,
    password_manager: &PasswordManager,
    email_change_allowed: bool,
    password_login_enabled: bool,
    requester_is_admin: bool,
    requester: RequesterFingerprint,
    browser_session: Option<&BrowserSession>,
    email: String,
    password: Option<String>,
    notification_language: String,
) -> Result<StartedEmailVerification, StartEmailVerificationError> {
    let Some(browser_session) = browser_session else {
        return Err(StartEmailVerificationError::Unauthorized);
    };

    if !email_change_allowed {
        return Err(StartEmailVerificationError::Disabled);
    }

    if !email.contains('@') {
        return Err(StartEmailVerificationError::InvalidEmail);
    }

    if !verify_contact_password_if_needed(
        requester_is_admin,
        password_login_enabled,
        password_manager,
        password,
        &browser_session.user,
        &mut repo,
    )
    .await
    .map_err(|error| match error {
        VerifyPasswordIfNeededError::Password(error) => {
            StartEmailVerificationError::Password(error)
        }
        VerifyPasswordIfNeededError::Repository(error) => {
            StartEmailVerificationError::Repository(error)
        }
    })? {
        return Err(StartEmailVerificationError::IncorrectPassword);
    }

    if let Err(error) = limiter
        .check_email_authentication_email(requester, &email)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(StartEmailVerificationError::RateLimited);
    }

    let auth = repo
        .user_email()
        .add_authentication_for_session(rng, clock, email, browser_session)
        .await?;

    schedule_notification(
        &mut repo,
        rng,
        clock,
        NotificationIntent::verify_email(&auth, notification_language),
    )
    .await?;

    repo.save().await?;

    Ok(StartedEmailVerification {
        authentication: auth,
    })
}

// ── Complete email verification ───────────────────────────────

#[derive(Debug, Error)]
pub enum CompleteEmailVerificationError {
    #[error("browser session required")]
    Unauthorized,

    #[error("email authentication not found")]
    NotFound,

    #[error("email authentication does not belong to this session")]
    NotOwned,

    #[error("email authentication already completed")]
    AlreadyCompleted,

    #[error("email verification is rate limited")]
    RateLimited,

    #[error("invalid verification code")]
    InvalidCode,

    #[error("verification code has expired")]
    CodeExpired,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Verify an email authentication code and, if successful, add the email to
/// the user's account.
pub async fn complete_email_verification(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    authentication_id: Ulid,
    browser_session: Option<&BrowserSession>,
    code: &str,
) -> Result<(), CompleteEmailVerificationError> {
    let Some(browser_session) = browser_session else {
        return Err(CompleteEmailVerificationError::Unauthorized);
    };

    let auth = repo
        .user_email()
        .lookup_authentication(authentication_id)
        .await?
        .ok_or(CompleteEmailVerificationError::NotFound)?;

    if auth.user_session_id != Some(browser_session.id) {
        return Err(CompleteEmailVerificationError::NotOwned);
    }

    if auth.completed_at.is_some() {
        return Err(CompleteEmailVerificationError::AlreadyCompleted);
    }

    if let Err(error) = limiter.check_email_authentication_attempt(&auth).await {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(CompleteEmailVerificationError::RateLimited);
    }

    let found_code = repo
        .user_email()
        .find_authentication_code(&auth, code)
        .await?
        .ok_or(CompleteEmailVerificationError::InvalidCode)?;

    if found_code.expires_at < clock.now() {
        return Err(CompleteEmailVerificationError::CodeExpired);
    }

    repo.user_email()
        .complete_authentication_with_code(clock, auth.clone(), &found_code)
        .await?;

    // Add email to user if not already present
    let existing = repo
        .user_email()
        .find(&browser_session.user, &auth.email)
        .await?;
    if existing.is_none() {
        repo.user_email()
            .add(rng, clock, &browser_session.user, auth.email.clone())
            .await?;
    }

    repo.save().await?;

    Ok(())
}

// ── Resend email verification code ────────────────────────────

#[derive(Debug, Error)]
pub enum ResendEmailVerificationError {
    #[error("browser session required")]
    Unauthorized,

    #[error("email authentication not found")]
    NotFound,

    #[error("email authentication does not belong to this session")]
    NotOwned,

    #[error("email authentication already completed")]
    AlreadyCompleted,

    #[error("email verification resend is rate limited")]
    RateLimited,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Resend the verification code for an in-progress email authentication.
pub async fn resend_email_verification_code(
    mut repo: BoxRepository,
    limiter: &Limiter,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    requester: RequesterFingerprint,
    authentication_id: Ulid,
    browser_session: Option<&BrowserSession>,
    notification_language: String,
) -> Result<(), ResendEmailVerificationError> {
    let Some(browser_session) = browser_session else {
        return Err(ResendEmailVerificationError::Unauthorized);
    };

    let auth = repo
        .user_email()
        .lookup_authentication(authentication_id)
        .await?
        .ok_or(ResendEmailVerificationError::NotFound)?;

    if auth.user_session_id != Some(browser_session.id) {
        return Err(ResendEmailVerificationError::NotOwned);
    }

    if auth.completed_at.is_some() {
        return Err(ResendEmailVerificationError::AlreadyCompleted);
    }

    if let Err(error) = limiter
        .check_email_authentication_send_code(requester, &auth)
        .await
    {
        tracing::warn!(error = &error as &dyn std::error::Error);
        return Err(ResendEmailVerificationError::RateLimited);
    }

    schedule_notification(
        &mut repo,
        rng,
        clock,
        NotificationIntent::verify_email(&auth, notification_language),
    )
    .await?;

    repo.save().await?;

    Ok(())
}

// ── Remove user email ─────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RemoveUserEmailError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("user email not found")]
    NotFound,

    #[error("user owning email not found")]
    UserNotFound,

    #[error("incorrect password")]
    IncorrectPassword,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Remove an email address from a user's account.
pub async fn remove_user_email(
    mut repo: BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    requester_user_id: Option<Ulid>,
    requester_is_admin: bool,
    password_login_enabled: bool,
    password: Option<String>,
    email_id: Ulid,
) -> Result<(), RemoveUserEmailError> {
    let email = repo
        .user_email()
        .lookup(email_id)
        .await?
        .ok_or(RemoveUserEmailError::NotFound)?;

    if !requester_is_admin && requester_user_id != Some(email.user_id) {
        return Err(RemoveUserEmailError::Unauthorized);
    }

    let user = repo
        .user()
        .lookup(email.user_id)
        .await?
        .ok_or(RemoveUserEmailError::UserNotFound)?;

    if !verify_contact_password_if_needed(
        requester_is_admin,
        password_login_enabled,
        password_manager,
        password,
        &user,
        &mut repo,
    )
    .await
    .map_err(|error| match error {
        VerifyPasswordIfNeededError::Password(error) => RemoveUserEmailError::Password(error),
        VerifyPasswordIfNeededError::Repository(error) => RemoveUserEmailError::Repository(error),
    })? {
        return Err(RemoveUserEmailError::IncorrectPassword);
    }

    repo.user_email().remove(email).await?;

    repo.queue_job()
        .schedule_job(rng, clock, ProvisionUserJob::new(&user))
        .await?;

    repo.save().await?;

    Ok(())
}

// ── Load email verification status ────────────────────────────

#[derive(Debug, Error)]
pub enum LoadEmailVerificationStatusError {
    #[error("email authentication not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn load_email_verification_status(
    repo: &mut BoxRepository,
    authentication_id: Ulid,
) -> Result<UserEmailAuthentication, LoadEmailVerificationStatusError> {
    repo.user_email()
        .lookup_authentication(authentication_id)
        .await?
        .ok_or(LoadEmailVerificationStatusError::NotFound)
}
