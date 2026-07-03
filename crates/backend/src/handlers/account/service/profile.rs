use anyhow::Error as AnyhowError;
use coauth_data::queue::{
    AccountProjectionRewriteJob, DeactivateUserJob, QueueJobRepositoryExt as _,
};
use coauth_data::user::UserRepository;
use coauth_data::{BoxRepository, Clock, RepositoryAccess, RepositoryError, SiteConfig};
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;

use crate::handlers::common::Requester;
use crate::handlers::passwords::PasswordManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeactivateAccountOutcome {
    IncorrectPassword,
    Deactivated,
}

#[derive(Debug, Error)]
pub enum AccountProfileError {
    #[error("browser session required")]
    BrowserSessionRequired,

    #[error("account deactivation is disabled")]
    DeactivationDisabled,

    #[error(transparent)]
    Password(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn deactivate_current_account(
    mut repo: BoxRepository,
    requester: &Requester,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    config: &SiteConfig,
    password_manager: &PasswordManager,
    password: Option<String>,
    principal_erase: bool,
) -> Result<DeactivateAccountOutcome, AccountProfileError> {
    let Some(browser_session) = requester.browser_session() else {
        return Err(AccountProfileError::BrowserSessionRequired);
    };

    if !config.account_deactivation_allowed {
        return Err(AccountProfileError::DeactivationDisabled);
    }

    let password_ok = crate::handlers::account::service::password::verify_password_if_needed(
        requester.is_admin(),
        config.password_login_enabled,
        password_manager,
        password,
        &browser_session.user,
        &mut repo,
    )
    .await
    .map_err(|error| match error {
        crate::handlers::account::service::password::VerifyPasswordIfNeededError::Password(
            error,
        ) => AccountProfileError::Password(error),
        crate::handlers::account::service::password::VerifyPasswordIfNeededError::Repository(
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
        .schedule_job(rng, clock, DeactivateUserJob::new(&user, principal_erase))
        .await?;
    if principal_erase {
        repo.queue_job()
            .schedule_job(
                rng,
                clock,
                AccountProjectionRewriteJob::new(&user, principal_erase),
            )
            .await?;
    }

    repo.save().await?;

    Ok(DeactivateAccountOutcome::Deactivated)
}
