use coauth_data::oauth::{OAuthClientRepository, OAuthSessionFilter, OAuthSessionRepository};
use coauth_data::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use coauth_data::user::{BrowserSessionFilter, BrowserSessionRepository, UserRepository};
use coauth_data::{
    Authentication, BoxRepository, BrowserSession, Client, Clock, Edge, Page, Pagination,
    RepositoryError, Session, User,
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

/// Which slice of each session connection `/self/viewer` should return.
///
/// The two settings pages both fetch the viewer and each paginates exactly one
/// connection, so the cursors are named per connection rather than shared: a
/// cursor is a node id, and a `BrowserSession` id applied to the OAuth list
/// would silently slice it by an unrelated ULID.
pub struct ViewerSessionPage {
    pub browser: Pagination,
    pub app: Pagination,
    /// Include sessions that have already ended. Default is active only.
    pub include_ended: bool,
    /// Narrow the app connection to the sessions whose scope carries this
    /// device. The device redirect resolves a device id to its session this
    /// way; it used to take whichever session happened to be first on the
    /// page, which is not the device the user asked for.
    pub app_device: Option<String>,
}

/// Both session connections of the viewer payload, with their unpaginated
/// totals.
pub struct ViewerSessionConnections {
    pub browser: Page<BrowserSession>,
    pub browser_total: usize,
    pub app: Page<OAuthSessionDetailData>,
    pub app_total: usize,
}

/// Load the browser- and app-session connections for the viewer payload.
///
/// Until 2026-09-05 the viewer hard-coded both to `None`. The frontend reads
/// them through `map_or(0, …)` / `unwrap_or_default()`, so `None` and "zero
/// sessions" were indistinguishable: the session pages rendered as empty and
/// the device redirect never found its target, with nothing failing.
///
/// `last_authentication` is deliberately not resolved per row -- it would be
/// one query per session and no list card reads it; the viewer's own session
/// carries it, which is where the UI shows it.
pub async fn load_viewer_session_connections(
    repo: &mut BoxRepository,
    user: &User,
    page: &ViewerSessionPage,
) -> Result<ViewerSessionConnections, RepositoryError> {
    let browser_filter = BrowserSessionFilter::new().for_user(user);
    let browser_filter = if page.include_ended {
        browser_filter
    } else {
        browser_filter.active_only()
    };
    // Count first, from the same filter the page is drawn with: the total the
    // UI shows must describe the set being paged, not a wider one.
    let browser_total = repo.browser_session().count(browser_filter).await?;
    let browser = repo
        .browser_session()
        .list(browser_filter, page.browser)
        .await?;

    let app_filter = OAuthSessionFilter::new().for_user(user);
    let app_filter = if page.include_ended {
        app_filter
    } else {
        app_filter.active_only()
    };
    let app_filter = match page.app_device.as_deref() {
        Some(device) => app_filter.for_device(device),
        None => app_filter,
    };
    let app_total = repo.oauth_session().count(app_filter).await?;
    let app_page = repo.oauth_session().list(app_filter, page.app).await?;

    // Resolve each session's client for display. `Page::try_map` cannot be used
    // because the lookup is async.
    let mut edges = Vec::with_capacity(app_page.edges.len());
    for edge in app_page.edges {
        let client = repo.oauth_client().lookup(edge.node.client_id).await?;
        edges.push(Edge {
            cursor: edge.cursor,
            node: OAuthSessionDetailData {
                session: edge.node,
                client,
            },
        });
    }
    let app = Page {
        has_next_page: app_page.has_next_page,
        has_previous_page: app_page.has_previous_page,
        edges,
    };

    Ok(ViewerSessionConnections {
        browser,
        browser_total,
        app,
        app_total,
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
