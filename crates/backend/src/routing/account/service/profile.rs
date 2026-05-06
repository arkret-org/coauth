use anyhow::{Context as _, Error as AnyhowError};
use coauth_data::{
    BoxRepository, Clock, RepositoryAccess, RepositoryError, SiteConfig, User,
    queue::{DeactivateUserJob, QueueJobRepositoryExt as _},
    user::UserRepository,
};
use coauth_matrix::HomeserverAdmin;
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::routing::{common::Requester, passwords::PasswordManager};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeactivateAccountOutcome {
    IncorrectPassword,
    Deactivated,
}

#[derive(Debug, Error)]
pub enum AccountProfileError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("browser session required")]
    BrowserSessionRequired,

    #[error("account deactivation is disabled")]
    DeactivationDisabled,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Homeserver(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn allow_cross_signing_reset(
    mut repo: BoxRepository,
    requester: &Requester,
    homeserver: &dyn HomeserverAdmin,
    user_id: Ulid,
) -> Result<User, AccountProfileError> {
    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(AccountProfileError::Unauthorized);
    }

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(AccountProfileError::NotFound)?;

    repo.cancel().await?;

    homeserver
        .allow_cross_signing_reset(&user.username)
        .await
        .context("failed to allow cross-signing reset")
        .map_err(AccountProfileError::Homeserver)?;

    Ok(user)
}

pub async fn deactivate_current_account(
    mut repo: BoxRepository,
    requester: &Requester,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    config: &SiteConfig,
    password_manager: &PasswordManager,
    password: Option<String>,
    hs_erase: bool,
) -> Result<DeactivateAccountOutcome, AccountProfileError> {
    let Some(browser_session) = requester.browser_session() else {
        return Err(AccountProfileError::BrowserSessionRequired);
    };

    if !config.account_deactivation_allowed {
        return Err(AccountProfileError::DeactivationDisabled);
    }

    let password_ok = crate::routing::account::service::password::verify_password_if_needed(
        requester.is_admin(),
        config.password_login_enabled,
        password_manager,
        password,
        &browser_session.user,
        &mut repo,
    )
    .await
    .map_err(|error| match error {
        crate::routing::account::service::password::VerifyPasswordIfNeededError::Password(
            error,
        ) => AccountProfileError::Password(error),
        crate::routing::account::service::password::VerifyPasswordIfNeededError::Repository(
            error,
        ) => AccountProfileError::Repository(error),
    })?;

    if !password_ok {
        repo.cancel().await?;
        return Ok(DeactivateAccountOutcome::IncorrectPassword);
    }

    let user = repo
        .user()
        .deactivate(clock, browser_session.user.clone())
        .await?;

    repo.queue_job()
        .schedule_job(rng, clock, DeactivateUserJob::new(&user, hs_erase))
        .await?;

    repo.save().await?;

    Ok(DeactivateAccountOutcome::Deactivated)
}
