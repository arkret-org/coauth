use anyhow::Error as AnyhowError;
use coauth_data::queue::{
    AccountProjectionRewriteJob, DeactivateUserJob, QueueJobRepositoryExt as _,
};
use coauth_data::user::UserRepository;
use coauth_data::{BoxRepository, Clock, RepositoryAccess, RepositoryError, SiteConfig};
use coauth_keyring::Keyring;
use coauth_principal::ConnectorAdmin;
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

    #[error("account status publication failed: {0}")]
    AccountStatusPublication(String),
}

pub async fn deactivate_current_account(
    mut repo: BoxRepository,
    requester: &Requester,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    config: &SiteConfig,
    password_manager: &PasswordManager,
    station: &dyn ConnectorAdmin,
    keyring: &Keyring,
    service_id: &str,
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

    let original_user = browser_session.user.clone();
    let (_destination_name, audience) = station
        .account_status_destination()
        .map_err(|error| AccountProfileError::AccountStatusPublication(error.to_string()))?;
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(&original_user, audience.as_str())
        .await?
        .ok_or_else(|| {
            AccountProfileError::AccountStatusPublication(
                "durable principal/PCR authority binding is missing".to_owned(),
            )
        })?;
    let publication = crate::services::account_status_publication::author_transition_plan(
        &mut repo,
        station,
        keyring,
        service_id,
        &original_user,
        &binding,
        arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated,
        None,
        clock.now(),
        rng,
    )
    .await
    .map_err(|error| AccountProfileError::AccountStatusPublication(error.to_string()))?;

    let user = repo.user().deactivate(clock, original_user).await?;

    crate::services::account_status_publication::enqueue_exact_publication(
        &mut repo,
        rng,
        clock,
        &publication.destination_name,
        publication.local_account_id,
        &publication.idempotency_key,
        publication.body,
    )
    .await
    .map_err(|error| AccountProfileError::AccountStatusPublication(error.to_string()))?;

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
