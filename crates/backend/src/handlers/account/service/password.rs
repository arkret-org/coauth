//! Service functions for password management.
//!
//! These functions encapsulate the business logic for changing a user's
//! password while already authenticated. Recovery-session orchestration lives
//! in [`crate::handlers::account::service::recovery`].

use anyhow::Error as AnyhowError;
use coauth_data::user::{UserPasswordRepository, UserRepository};
use coauth_data::{BoxRepository, Clock, RepositoryAccess, RepositoryError, User};
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::handlers::passwords::PasswordManager;
use crate::handlers::{Limiter, RequesterFingerprint, make_rng_from};

// ── Change password ───────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ChangePasswordError {
    #[error("password manager is disabled")]
    PasswordDisabled,

    #[error("new password is too weak")]
    PasswordTooWeak,

    #[error("user not found")]
    UserNotFound,

    #[error("password changes are not allowed")]
    PasswordChangesDisabled,

    #[error("no current password set")]
    NoCurrentPassword,

    #[error("current password is required")]
    CurrentPasswordRequired,

    #[error("current password is incorrect")]
    WrongPassword,

    #[error("too many password attempts")]
    RateLimited,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum VerifyPasswordIfNeededError {
    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Change the password for an existing user.
///
/// When `is_admin` is `false`, the `current_password` must be provided and
/// verified against the stored hash. Admins can set a new password without
/// knowing the current one.
///
/// The caller is responsible for verifying ownership (`is_owner_or_admin`)
/// before calling this function.
pub async fn change_password(
    mut repo: BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    password_manager: &PasswordManager,
    limiter: &Limiter,
    requester: RequesterFingerprint,
    user_id: ulid::Ulid,
    current_password: Option<Zeroizing<String>>,
    new_password: Zeroizing<String>,
    is_admin: bool,
    password_change_allowed: bool,
    keep_browser_session_id: Option<ulid::Ulid>,
    keep_oauth_session_id: Option<ulid::Ulid>,
) -> Result<(), ChangePasswordError> {
    if new_password.is_empty() {
        return Err(ChangePasswordError::PasswordTooWeak);
    }

    if !password_manager.is_enabled() {
        return Err(ChangePasswordError::PasswordDisabled);
    }

    if !password_manager
        .is_password_complex_enough(&new_password)
        .map_err(|e| ChangePasswordError::Password(e.into()))?
    {
        return Err(ChangePasswordError::PasswordTooWeak);
    }

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(ChangePasswordError::UserNotFound)?;

    if !is_admin {
        if !password_change_allowed {
            return Err(ChangePasswordError::PasswordChangesDisabled);
        }

        // Rate limit the current-password verification path (per requester IP
        // and per target user), mirroring the login limiter, so the
        // authenticated change-password endpoint cannot be abused to brute
        // force the current password.
        if let Err(error) = limiter.check_password(requester, &user).await {
            tracing::warn!(error = &error as &dyn std::error::Error);
            return Err(ChangePasswordError::RateLimited);
        }

        let active_password = repo
            .user_password()
            .active(&user)
            .await?
            .ok_or(ChangePasswordError::NoCurrentPassword)?;

        let current = current_password.ok_or(ChangePasswordError::CurrentPasswordRequired)?;

        if !password_manager
            .verify(
                active_password.version,
                current,
                active_password.hashed_password,
            )
            .await
            .map_err(ChangePasswordError::Password)?
            .is_success()
        {
            return Err(ChangePasswordError::WrongPassword);
        }
    }

    let (version, hash) = password_manager
        .hash(make_rng_from(rng), new_password)
        .await
        .map_err(ChangePasswordError::Password)?;

    repo.user_password()
        .add(rng, clock, &user, version, hash, None)
        .await?;

    // Revoke all existing sessions established with the previous password,
    // preserving the session performing this request so the user is not logged
    // out of the device they just used to change their password.
    crate::handlers::account::service::sessions::revoke_user_sessions(
        &mut repo,
        rng,
        clock,
        &user,
        keep_browser_session_id,
        keep_oauth_session_id,
    )
    .await?;

    repo.save().await?;

    Ok(())
}

pub async fn verify_password_if_needed(
    is_admin: bool,
    password_login_enabled: bool,
    password_manager: &PasswordManager,
    password: Option<String>,
    user: &User,
    repo: &mut BoxRepository,
) -> Result<bool, VerifyPasswordIfNeededError> {
    if is_admin {
        return Ok(true);
    }

    if !password_login_enabled {
        return Ok(true);
    }

    let user_password = repo.user_password().active(user).await?;

    let Some(user_password) = user_password else {
        return Ok(true);
    };

    let Some(password) = password else {
        return Ok(false);
    };

    let password = Zeroizing::new(password);

    let res = password_manager
        .verify(
            user_password.version,
            password,
            user_password.hashed_password,
        )
        .await
        .map_err(VerifyPasswordIfNeededError::Password)?;

    Ok(res.is_success())
}
