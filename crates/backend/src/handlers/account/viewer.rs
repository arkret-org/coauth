use coauth_account_types::{
    AnonymousViewer as AnonymousData, AppSession as AppSessionData, AppSessionConnection,
    AppSessionEdge, AuthenticationInfo, BrowserSession as BrowserSessionData,
    BrowserSessionConnection, BrowserSessionEdge, EmailConnection as EmailListData,
    EmailEdge as EmailEdgeData, LinkedAccount, OAuthClient as OAuthClientData,
    OAuthSession as OAuthSessionData, PageInfo, PrincipalUser as PrincipalUserData,
    SecuritySummaryOutcome as SecuritySummaryData, UserEmail as EmailData, Viewer as ViewerData,
    ViewerOutcome, ViewerSession as ViewerSessionData, ViewerUser,
    ViewerUserProfile as UserProfileData,
};
use coauth_data::account::AccountSecuritySummary;
use coauth_data::user::BrowserSessionRepository;
use coauth_data::{Page, Pagination, RepositoryAccess, Ulid};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::Serialize;

use super::site_config::from_site_config;
use super::{DepotExt, NodeType, RouteError, make_clock, parse_user_agent};
use crate::handlers::account::service::connections::load_linked_accounts;
use crate::handlers::account::service::sessions::{
    OAuthSessionDetailData, ViewerSessionPage, load_viewer_session_connections,
};
use crate::handlers::arkret;
use crate::services::user_profile::load_viewer_profile;

/// Rows per session connection when the caller names no `session_limit`.
/// Matches the settings pages' own `PaginationState::new(6)`.
const SESSION_PAGE_SIZE_DEFAULT: usize = 6;
const SESSION_PAGE_SIZE_MAX: usize = 100;

/// Read the session pagination the settings pages send.
///
/// No cursor means the newest page (`Pagination::last`), which is what both
/// pages open on; the frontend reverses the edges for display.
fn session_page(req: &Request) -> Result<ViewerSessionPage, RouteError> {
    let size = req
        .query::<usize>("session_limit")
        .unwrap_or(SESSION_PAGE_SIZE_DEFAULT)
        .clamp(1, SESSION_PAGE_SIZE_MAX);
    Ok(ViewerSessionPage {
        browser: cursor_pagination(
            req,
            size,
            NodeType::BrowserSession,
            "browser_after",
            "browser_before",
        )?,
        app: cursor_pagination(req, size, NodeType::OAuthSession, "app_after", "app_before")?,
        include_ended: req.query::<bool>("include_ended").unwrap_or(false),
        app_device: req
            .query::<String>("app_device")
            .filter(|device| !device.trim().is_empty()),
    })
}

fn cursor_pagination(
    req: &Request,
    size: usize,
    expected: NodeType,
    after: &str,
    before: &str,
) -> Result<Pagination, RouteError> {
    if let Some(cursor) = req.query::<String>(after) {
        return Ok(Pagination::first(size).after(session_cursor(&cursor, expected)?));
    }
    if let Some(cursor) = req.query::<String>(before) {
        return Ok(Pagination::last(size).before(session_cursor(&cursor, expected)?));
    }
    Ok(Pagination::last(size))
}

/// A cursor is the node id of a row in the connection it pages. Rejecting a
/// cursor of the wrong kind keeps a browser-session id from silently slicing
/// the OAuth list by an unrelated ULID.
fn session_cursor(cursor: &str, expected: NodeType) -> Result<Ulid, RouteError> {
    let (node_type, ulid) = NodeType::deserialize(cursor)?;
    if node_type != expected {
        return Err(RouteError::BadRequest(
            "session cursor names the wrong node type".to_owned(),
        ));
    }
    Ok(ulid)
}

fn connection_page_info<T>(page: &Page<T>, node_type: NodeType) -> PageInfo {
    PageInfo {
        has_next_page: page.has_next_page,
        has_previous_page: page.has_previous_page,
        start_cursor: page
            .edges
            .first()
            .map(|edge| node_type.serialize(edge.cursor)),
        end_cursor: page
            .edges
            .last()
            .map(|edge| node_type.serialize(edge.cursor)),
    }
}

/// A count that has to cross into the wire type's `i32`. Saturating is the
/// honest choice: a viewer with more than `i32::MAX` sessions does not exist,
/// and a wrapped negative count would render as a nonsense total.
fn connection_total(total: usize) -> i32 {
    i32::try_from(total).unwrap_or(i32::MAX)
}

/// Map a stored browser session to its wire node.
///
/// `user` is left out for the same reason the viewer's own session leaves it
/// out: the user is already the viewer. `display_name` is `None` because
/// `coauth_data::BrowserSession` carries no human-assigned name -- only OAuth
/// sessions do (`Session::human_name`) -- and the card falls back to the user
/// agent. `last_authentication` is not resolved per row; see
/// `load_viewer_session_connections`.
fn browser_session_node(session: &coauth_data::BrowserSession) -> BrowserSessionData {
    BrowserSessionData {
        id: NodeType::BrowserSession.serialize(session.id),
        user: None,
        user_agent: session.user_agent.as_deref().map(parse_user_agent),
        last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
        last_active_at: session
            .last_active_at
            .map(arkret_canonical::format_timestamp_canonical),
        created_at: Some(arkret_canonical::format_timestamp_canonical(
            session.created_at,
        )),
        last_authentication: None,
        display_name: None,
    }
}

fn app_session_node(detail: &OAuthSessionDetailData) -> AppSessionData {
    let session = &detail.session;
    AppSessionData::OAuthSession(OAuthSessionData {
        id: NodeType::OAuthSession.serialize(session.id),
        scope: Some(session.scope.to_string()),
        client: detail.client.as_ref().map(|client| OAuthClientData {
            id: NodeType::OAuthClient.serialize(client.id),
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            client_uri: client.client_uri.as_ref().map(ToString::to_string),
            logo_uri: client.logo_uri.as_ref().map(ToString::to_string),
        }),
        user_agent: session.user_agent.as_deref().map(parse_user_agent),
        last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
        last_active_at: session
            .last_active_at
            .map(arkret_canonical::format_timestamp_canonical),
        created_at: Some(arkret_canonical::format_timestamp_canonical(
            session.created_at,
        )),
        display_name: session.human_name.clone(),
    })
}

// ── GET /_coauth/self/viewer ─────────────────────────────────────────

/// Returns the current viewer (user or anonymous), viewer session, and site
/// config in a single response.
#[endpoint]
pub async fn get_viewer(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ViewerOutcome>, RouteError> {
    let config = depot.site_config()?;
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let station = depot.station()?;
    let clock = make_clock();

    let (requester, mut repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

    let (viewer, viewer_session) = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => {
            let user = &session.user;

            // Load viewer profile from service
            let profile = load_viewer_profile(&mut repo, station.as_ref(), user)
                .await
                .map_err(super::map_user_profile_error)?;

            let principal = Some(PrincipalUserData {
                principal_address: profile.principal_address,
                display_name: profile.principal_display_name,
            });

            let email_edges: Vec<EmailEdgeData> = profile
                .emails
                .into_iter()
                .map(|e| EmailEdgeData {
                    cursor: NodeType::UserEmail.serialize(e.id),
                    node: EmailData {
                        id: NodeType::UserEmail.serialize(e.id),
                        email: e.email,
                        confirmed_at: e
                            .confirmed_at
                            .map(arkret_canonical::format_timestamp_canonical),
                        is_primary: e.is_primary,
                    },
                })
                .collect();
            let total = email_edges.len() as i32;

            let has_password = profile.has_password;
            let principal_id =
                arkret::published_principal_id_for_user(&mut repo, &arkret_config, user)
                    .await?
                    .ok_or_else(|| {
                        RouteError::Internal(Box::new(std::io::Error::other(format!(
                            "missing principal DID for user {}",
                            user.id
                        ))))
                    })?;

            let sessions =
                load_viewer_session_connections(&mut repo, user, &session_page(req)?).await?;

            // Fetch linked upstream OAuth accounts
            let linked_accounts: Vec<LinkedAccount> = load_linked_accounts(&mut repo, user, 100)
                .await?
                .into_iter()
                .map(|link| LinkedAccount {
                    id: link.id.to_string(),
                    provider_id: link.provider_id.to_string(),
                    provider_name: link.provider_name,
                    provider_brand: link.provider_brand,
                    subject: link.subject,
                    human_account_name: link.human_account_name,
                    created_at: arkret_canonical::format_timestamp_canonical(link.created_at),
                })
                .collect();

            let viewer_user = ViewerUser {
                id: NodeType::User.serialize(user.id),
                username: user.localpart.clone(),
                principal_id: principal_id.to_string(),
                handle: arkret::user_handle(&url_builder, user),
                can_request_admin: user.can_request_admin,
                has_password,
                profile: UserProfileData {
                    display_name: profile.profile.display_name,
                    avatar_url: profile.profile.avatar_url,
                    preferred_locale: profile
                        .profile
                        .preferred_locale
                        .map(|locale| locale.code().to_owned()),
                    updated_at: arkret_canonical::format_timestamp_canonical(
                        profile.profile.updated_at,
                    ),
                },
                principal,
                emails: Some(EmailListData {
                    total_count: total,
                    edges: email_edges,
                }),
                linked_accounts: Some(linked_accounts),
                browser_sessions: Some(BrowserSessionConnection {
                    total_count: connection_total(sessions.browser_total),
                    page_info: connection_page_info(&sessions.browser, NodeType::BrowserSession),
                    edges: sessions
                        .browser
                        .edges
                        .iter()
                        .map(|edge| BrowserSessionEdge {
                            cursor: NodeType::BrowserSession.serialize(edge.cursor),
                            node: browser_session_node(&edge.node),
                        })
                        .collect(),
                }),
                app_sessions: Some(AppSessionConnection {
                    total_count: connection_total(sessions.app_total),
                    page_info: connection_page_info(&sessions.app, NodeType::OAuthSession),
                    edges: sessions
                        .app
                        .edges
                        .iter()
                        .map(|edge| AppSessionEdge {
                            cursor: NodeType::OAuthSession.serialize(edge.cursor),
                            node: app_session_node(&edge.node),
                        })
                        .collect(),
                }),
            };

            // The viewer's own session is the one place the UI shows when the
            // browser last authenticated, so it is worth the extra query here
            // and not per row of the list.
            let last_authentication = repo
                .browser_session()
                .get_last_authentication(session)
                .await?
                .map(|authentication| AuthenticationInfo {
                    id: NodeType::Authentication.serialize(authentication.id),
                    created_at: arkret_canonical::format_timestamp_canonical(
                        authentication.created_at,
                    ),
                });
            let browser_session_data = BrowserSessionData {
                last_authentication,
                ..browser_session_node(session)
            };

            (
                ViewerData::User(viewer_user),
                ViewerSessionData::BrowserSession(browser_session_data),
            )
        }
        _ => (
            ViewerData::Anonymous(AnonymousData {
                id: "anonymous".to_owned(),
            }),
            ViewerSessionData::Anonymous(AnonymousData {
                id: "anonymous".to_owned(),
            }),
        ),
    };

    repo.cancel().await?;

    Ok(Json(ViewerOutcome {
        viewer,
        viewer_session,
        site_config: from_site_config(&config),
    }))
}

// ── GET /_coauth/self/viewer/security ───────────────────────────────

/// Returns a lightweight security summary for the current user, including
/// password status, active session count, linked provider count, and
/// verified email/phone counts.
///
/// Reuses [`SecuritySummaryData`] (also embedded in the overview response).
#[endpoint]
pub async fn get_security_summary(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SecuritySummaryData>, RouteError> {
    let clock = make_clock();

    let (requester, mut repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

    let user = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => &session.user,
        _ => return Err(RouteError::Unauthorized),
    };

    let summary = repo.account().security_summary(user.id).await?;

    repo.cancel().await?;

    Ok(Json(security_summary_data(&summary)))
}

// ── Response types for viewer overview ─────────────────────

/// Summary of the user for the overview dashboard.
#[derive(Serialize, ToSchema)]
pub struct ViewerUserSummary {
    pub id: String,
    pub has_password: bool,
}

/// Summary of contact points for the overview.
#[derive(Serialize, ToSchema)]
pub struct ContactsSummary {
    pub total: usize,
    pub verified: usize,
}

/// Summary of identity bindings for the overview.
#[derive(Serialize, ToSchema)]
pub struct IdentitiesSummary {
    pub total: usize,
}

/// Summary of pending workflows for the overview.
#[derive(Serialize, ToSchema)]
pub struct WorkflowsSummary {
    pub pending_count: usize,
}

/// Unified overview response combining security, contacts, identities, and
/// workflow summaries into a single payload for the account dashboard.
#[derive(Serialize, ToSchema)]
pub struct ViewerOverviewOutcome {
    pub user: ViewerUserSummary,
    pub security: SecuritySummaryData,
    pub contacts: ContactsSummary,
    pub identities: IdentitiesSummary,
    pub workflows: WorkflowsSummary,
}

fn security_summary_data(summary: &AccountSecuritySummary) -> SecuritySummaryData {
    SecuritySummaryData {
        has_password: summary.has_password,
        active_sessions_count: summary.active_sessions_count,
        linked_providers_count: summary.linked_providers_count,
        verified_emails_count: summary.verified_emails_count,
        verified_phones_count: summary.verified_phones_count,
    }
}

// ── GET /_coauth/self/viewer/overview ────────────────────────────

/// Returns a unified account overview for the dashboard, combining the
/// security summary, contact-point counts, identity-binding counts, and
/// pending workflow counts into a single response.
#[endpoint]
pub async fn get_viewer_overview(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ViewerOverviewOutcome>, RouteError> {
    let clock = make_clock();

    let (requester, mut repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

    let user = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => &session.user,
        _ => return Err(RouteError::Unauthorized),
    };

    let user_id = user.id;

    // Fetch all three aggregates from the account repository.
    let security = repo.account().security_summary(user_id).await?;
    let contacts = repo.account().list_contact_points(user_id).await?;
    let identities = repo.account().list_identity_bindings(user_id).await?;

    repo.cancel().await?;

    let verified_contacts = contacts.iter().filter(|c| c.verified).count();

    // Workflow sessions are in-memory and not user-associated yet, so
    // pending count is always zero for now.
    let pending_workflow_count: usize = 0;

    Ok(Json(ViewerOverviewOutcome {
        user: ViewerUserSummary {
            id: NodeType::User.serialize(user_id),
            has_password: security.has_password,
        },
        security: security_summary_data(&security),
        contacts: ContactsSummary {
            total: contacts.len(),
            verified: verified_contacts,
        },
        identities: IdentitiesSummary {
            total: identities.len(),
        },
        workflows: WorkflowsSummary {
            pending_count: pending_workflow_count,
        },
    }))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::user::{BrowserSessionRepository as _, UserRepository as _};
    use hyper::{Request, StatusCode};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;

    use crate::handlers::test_utils::{
        CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };
    use crate::salvo_utils::SessionInfoExt;

    /// Three sessions have to come back as three, and a smaller page as fewer
    /// edges with the same total.
    ///
    /// Until 2026-09-05 `browser_sessions` and `app_sessions` were hard-coded
    /// `None`. The frontend reads them through `map_or(0, …)`, so an unwired
    /// connection and an empty one rendered identically and no test could tell
    /// them apart -- which is how the gap survived. Asserting a non-zero count
    /// is what closes that.
    #[tokio::test]
    async fn viewer_returns_every_browser_session_and_pages_them() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        // The viewer resolves the user's published principal DID, which needs the
        // owning Station configured.
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let username = format!("viewer{}", Ulid::generate().to_string().to_lowercase());
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();

        let mut sessions = Vec::new();
        for _ in 0..3 {
            sessions.push(
                repo.browser_session()
                    .add(&mut rng, &state.clock, &user, None)
                    .await
                    .unwrap(),
            );
        }
        repo.save().await.unwrap();
        state.seed_principal_binding(&user, "viewersessions").await;

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&sessions[0]));

        let response = state
            .request(cookies.with_cookies(Request::get("/_coauth/self/viewer").empty()))
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let connection = &body["viewer"]["browser_sessions"];
        assert_eq!(connection["total_count"], 3, "body: {body}");
        assert_eq!(connection["edges"].as_array().unwrap().len(), 3);

        let paged = state
            .request(
                cookies.with_cookies(Request::get("/_coauth/self/viewer?session_limit=2").empty()),
            )
            .await;
        paged.assert_status(StatusCode::OK);
        let paged_body: serde_json::Value = paged.json();
        let paged_connection = &paged_body["viewer"]["browser_sessions"];
        assert_eq!(
            paged_connection["total_count"], 3,
            "the total describes the filtered set, not the page"
        );
        assert_eq!(paged_connection["edges"].as_array().unwrap().len(), 2);
        assert_eq!(paged_connection["page_info"]["has_previous_page"], true);
    }

    /// A cursor from one connection must not page the other.
    #[tokio::test]
    async fn viewer_rejects_a_cursor_of_the_wrong_node_type() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        // The viewer resolves the user's published principal DID, which needs the
        // owning Station configured.
        let state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let username = format!("viewer{}", Ulid::generate().to_string().to_lowercase());
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        state.seed_principal_binding(&user, "viewercursor").await;

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&session));

        let browser_cursor = format!("browser_session:{}", session.id);
        let response = state
            .request(cookies.with_cookies(
                Request::get(format!("/_coauth/self/viewer?app_after={browser_cursor}")).empty(),
            ))
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
