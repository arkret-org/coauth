use coauth_data::{
    Authentication, BoxRepository, BrowserSession, Client, Clock, RepositoryError, Session,
    oauth2::{OAuth2ClientRepository, OAuth2SessionRepository},
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::{BrowserSessionRepository, UserRepository},
};
use coauth_principal::PrincipalServerAdmin;
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::account::Requester;

pub struct BrowserSessionDetailData {
    pub session: BrowserSession,
    pub last_authentication: Option<Authentication>,
}

pub struct OAuth2SessionDetailData {
    pub session: Session,
    pub client: Option<Client>,
}

#[derive(Debug, Error)]
pub enum AccountSessionError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn load_browser_session_detail(
    mut repo: BoxRepository,
    requester: &Requester,
    session_id: Ulid,
) -> Result<BrowserSessionDetailData, AccountSessionError> {
    let session = repo
        .browser_session()
        .lookup(session_id)
        .await?
        .ok_or(AccountSessionError::NotFound)?;

    if !requester.is_owner_or_admin(Some(session.user.id)) {
        return Err(AccountSessionError::Unauthorized);
    }

    let last_authentication = repo
        .browser_session()
        .get_last_authentication(&session)
        .await?;

    repo.cancel().await?;

    Ok(BrowserSessionDetailData {
        session,
        last_authentication,
    })
}

pub async fn load_oauth2_session_detail(
    mut repo: BoxRepository,
    requester: &Requester,
    session_id: Ulid,
) -> Result<OAuth2SessionDetailData, AccountSessionError> {
    let session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(AccountSessionError::NotFound)?;

    if !requester.is_owner_or_admin(session.user_id) {
        return Err(AccountSessionError::Unauthorized);
    }

    let client = repo.oauth2_client().lookup(session.client_id).await?;

    repo.cancel().await?;

    Ok(OAuth2SessionDetailData { session, client })
}

pub async fn end_browser_session(
    mut repo: BoxRepository,
    requester: &Requester,
    clock: &dyn Clock,
    session_id: Ulid,
) -> Result<(), AccountSessionError> {
    let session = repo
        .browser_session()
        .lookup(session_id)
        .await?
        .ok_or(AccountSessionError::NotFound)?;

    if !requester.is_owner_or_admin(Some(session.user.id)) {
        return Err(AccountSessionError::Unauthorized);
    }

    repo.browser_session().finish(clock, session).await?;
    repo.save().await?;

    Ok(())
}

pub async fn end_oauth2_session(
    mut repo: BoxRepository,
    requester: &Requester,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    session_id: Ulid,
) -> Result<(), AccountSessionError> {
    let session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(AccountSessionError::NotFound)?;

    if !requester.is_owner_or_admin(session.user_id) {
        return Err(AccountSessionError::Unauthorized);
    }

    let sync_user = if let Some(user_id) = session.user_id {
        repo.user().lookup(user_id).await?
    } else {
        None
    };

    if let Some(user) = sync_user.as_ref() {
        repo.queue_job()
            .schedule_job(rng, clock, SyncDevicesJob::new(user))
            .await?;
    }

    repo.oauth2_session().finish(clock, session).await?;
    repo.save().await?;

    Ok(())
}

pub async fn set_oauth2_session_human_name(
    mut repo: BoxRepository,
    requester: &Requester,
    _clock: &dyn Clock,
    principal_server: &dyn PrincipalServerAdmin,
    session_id: Ulid,
    human_name: Option<String>,
) -> Result<(), AccountSessionError> {
    let session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(AccountSessionError::NotFound)?;

    if !requester.is_owner_or_admin(session.user_id) {
        return Err(AccountSessionError::Unauthorized);
    }

    let session_user = if let Some(user_id) = session.user_id {
        repo.user().lookup(user_id).await?
    } else {
        None
    };

    let session = repo
        .oauth2_session()
        .set_human_name(session, human_name.clone())
        .await?;

    if let (Some(name), Some(user)) = (&human_name, session_user.as_ref()) {
        for token in session.scope.iter() {
            if let Some(device_id) = token.strip_prefix("urn:contrix:client:device:") {
                let _ = principal_server
                    .update_device_display_name(&user.handle, device_id, name)
                    .await;
            }
        }
    }

    repo.save().await?;

    Ok(())
}
