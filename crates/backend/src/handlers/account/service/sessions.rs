use coauth_data::oauth::{OAuthClientRepository, OAuthSessionFilter, OAuthSessionRepository};
use coauth_data::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use coauth_data::user::{BrowserSessionFilter, BrowserSessionRepository, UserRepository};
use coauth_data::{
    Authentication, BoxRepository, BrowserSession, Client, Clock, Pagination, RepositoryError,
    Session, User,
};
use coauth_principal::ConnectorAdmin;
use rand_chacha::rand_core::CryptoRngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::account::Requester;

pub struct BrowserSessionDetailData {
    pub session: BrowserSession,
    pub last_authentication: Option<Authentication>,
}

pub struct OAuthSessionDetailData {
    pub session: Session,
    pub client: Option<Client>,
}

pub struct OAuthSessionListData {
    pub sessions: Vec<OAuthSessionDetailData>,
    pub next_cursor: Option<Ulid>,
    pub has_more: bool,
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

pub async fn load_oauth_session_detail(
    mut repo: BoxRepository,
    requester: &Requester,
    session_id: Ulid,
) -> Result<OAuthSessionDetailData, AccountSessionError> {
    let session = repo
        .oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(AccountSessionError::NotFound)?;

    if !requester.is_owner_or_admin(session.user_id) {
        return Err(AccountSessionError::Unauthorized);
    }

    let client = repo.oauth_client().lookup(session.client_id).await?;

    repo.cancel().await?;

    Ok(OAuthSessionDetailData { session, client })
}

/// List the requesting user's active OAuth sessions with their client rows
/// resolved for display. Self surface for the settings "signed-in apps"
/// card — strictly scoped to the requester's own user; admins reading other
/// users' sessions go through the admin v1 resource tree instead.
pub async fn list_active_oauth_sessions_for_requester(
    mut repo: BoxRepository,
    requester: &Requester,
    pagination: Pagination,
) -> Result<OAuthSessionListData, AccountSessionError> {
    let Some(user) = requester.user() else {
        return Err(AccountSessionError::Unauthorized);
    };
    let page = repo
        .oauth_session()
        .list(
            OAuthSessionFilter::new().for_user(user).active_only(),
            pagination,
        )
        .await?;
    let mut sessions = Vec::with_capacity(page.edges.len());
    let mut next_cursor = None;
    for edge in page.edges {
        next_cursor = Some(edge.cursor);
        let session = edge.node;
        let client = repo.oauth_client().lookup(session.client_id).await?;
        sessions.push(OAuthSessionDetailData { session, client });
    }
    repo.cancel().await?;
    Ok(OAuthSessionListData {
        sessions,
        next_cursor: page.has_next_page.then_some(next_cursor).flatten(),
        has_more: page.has_next_page,
    })
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

pub async fn end_oauth_session(
    mut repo: BoxRepository,
    requester: &Requester,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    session_id: Ulid,
) -> Result<(), AccountSessionError> {
    let session = repo
        .oauth_session()
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

    repo.oauth_session().finish(clock, session).await?;
    repo.save().await?;

    Ok(())
}

/// Revoke every active browser and OAuth session belonging to `user`,
/// optionally preserving the session that is performing the current request.
///
/// This is invoked after a credential change (password change or account
/// recovery) so that any session established with the *old* password is
/// terminated. For password recovery there is no trusted current session, so
/// callers pass `None` for both `keep_*` arguments to revoke everything.
///
/// A [`SyncDevicesJob`] is scheduled so downstream device state is reconciled.
/// The caller is responsible for `repo.save()`.
pub async fn revoke_user_sessions(
    repo: &mut BoxRepository,
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    user: &User,
    keep_browser_session_id: Option<Ulid>,
    keep_oauth_session_id: Option<Ulid>,
) -> Result<(), RepositoryError> {
    // Finish active browser sessions, skipping the caller's own session.
    let mut cursor = Pagination::first(1000);
    loop {
        let page = repo
            .browser_session()
            .list(
                BrowserSessionFilter::new().for_user(user).active_only(),
                cursor,
            )
            .await?;

        for edge in page.edges {
            cursor = cursor.after(edge.cursor);
            if Some(edge.node.id) == keep_browser_session_id {
                continue;
            }
            repo.browser_session().finish(clock, edge.node).await?;
        }

        if !page.has_next_page {
            break;
        }
    }

    // Finish active OAuth sessions, skipping the caller's own session.
    let mut cursor = Pagination::first(1000);
    loop {
        let page = repo
            .oauth_session()
            .list(
                OAuthSessionFilter::new().for_user(user).active_only(),
                cursor,
            )
            .await?;

        for edge in page.edges {
            cursor = cursor.after(edge.cursor);
            if Some(edge.node.id) == keep_oauth_session_id {
                continue;
            }
            repo.oauth_session().finish(clock, edge.node).await?;
        }

        if !page.has_next_page {
            break;
        }
    }

    repo.queue_job()
        .schedule_job(rng, clock, SyncDevicesJob::new(user))
        .await?;

    Ok(())
}

pub async fn set_oauth_session_human_name(
    mut repo: BoxRepository,
    requester: &Requester,
    _clock: &dyn Clock,
    station: &dyn ConnectorAdmin,
    session_id: Ulid,
    human_name: Option<String>,
) -> Result<(), AccountSessionError> {
    let session = repo
        .oauth_session()
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
        .oauth_session()
        .set_human_name(session, human_name.clone())
        .await?;

    if let (Some(name), Some(user)) = (&human_name, session_user.as_ref()) {
        for token in session.scope.iter() {
            if let Some(device_id) = token.strip_prefix("urn:arkret:client:device:") {
                let _ = station
                    .update_device_display_name(&user.localpart, device_id, name)
                    .await;
            }
        }
    }

    repo.save().await?;

    Ok(())
}
