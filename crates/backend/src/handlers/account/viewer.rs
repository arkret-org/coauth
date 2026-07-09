use coauth_data::RepositoryAccess;
use coauth_data::account::AccountSecuritySummary;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::Serialize;

use super::linked_accounts::LinkedAccount;
use super::site_config::{SiteConfigOutcome, from_site_config};
use super::{
    DepotExt, NodeType, RouteError, UserAgentInfo, extract_bound_activity_tracker,
    extract_session_info, get_requester, make_clock, parse_user_agent,
};
use crate::handlers::account::service::connections::load_linked_accounts;
use crate::handlers::arkret;
use crate::services::user_profile::{UserProfileServiceError, load_viewer_profile};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct ViewerOutcome {
    viewer: ViewerData,
    viewer_session: ViewerSessionData,
    site_config: SiteConfigOutcome,
}

#[derive(Serialize, ToSchema)]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
enum ViewerData {
    User(ViewerUser),
    Anonymous(AnonymousData),
}

#[derive(Serialize, ToSchema)]
struct ViewerUser {
    id: String,
    username: String,
    did: String,
    handle: String,
    can_request_admin: bool,
    has_password: bool,
    profile: UserProfileData,
    principal: Option<PrincipalUserData>,
    emails: Option<EmailListData>,
    linked_accounts: Option<Vec<LinkedAccount>>,
}

#[derive(Serialize, ToSchema)]
struct AnonymousData {
    id: String,
}

#[derive(Serialize, ToSchema)]
#[serde(tag = "__typename")]
#[allow(clippy::large_enum_variant)]
enum ViewerSessionData {
    BrowserSession(BrowserSessionData),
    Anonymous(AnonymousData),
}

#[derive(Serialize, ToSchema)]
struct BrowserSessionData {
    id: String,
    user: Option<ViewerUser>,
    user_agent: Option<UserAgentInfo>,
    last_active_ip: Option<String>,
    last_active_at: Option<String>,
    created_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct PrincipalUserData {
    principal_id: String,
    display_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct UserProfileData {
    display_name: Option<String>,
    avatar_url: Option<String>,
    preferred_locale: Option<String>,
    updated_at: String,
}

#[derive(Serialize, ToSchema)]
struct EmailListData {
    total_count: i64,
    edges: Vec<EmailEdgeData>,
}

#[derive(Serialize, ToSchema)]
struct EmailEdgeData {
    cursor: String,
    node: EmailData,
}

#[derive(Serialize, ToSchema)]
struct EmailData {
    id: String,
    email: String,
    confirmed_at: Option<String>,
    is_primary: bool,
}

// ── GET /_coauth/self/viewer ─────────────────────────────────────────

/// Returns the current viewer (user or anonymous), viewer session, and site
/// config in a single response.
#[endpoint]
pub async fn get_viewer(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ViewerOutcome>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let principal_server = depot.principal_server()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let (viewer, viewer_session) = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => {
            let user = &session.user;

            // Load viewer profile from service
            let profile = load_viewer_profile(&mut repo, principal_server.as_ref(), user)
                .await
                .map_err(map_user_profile_error)?;

            let principal = Some(PrincipalUserData {
                principal_id: profile.principal_id,
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
                        confirmed_at: e.confirmed_at.map(|confirmed_at| confirmed_at.to_rfc3339()),
                        is_primary: e.is_primary,
                    },
                })
                .collect();
            let total = email_edges.len() as i64;

            let has_password = profile.has_password;
            let did = arkret::published_principal_did_for_user(&mut repo, &arkret_config, user)
                .await?
                .ok_or_else(|| {
                    RouteError::Internal(Box::new(std::io::Error::other(format!(
                        "missing principal DID for user {}",
                        user.id
                    ))))
                })?;

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
                    created_at: link.created_at.to_rfc3339(),
                })
                .collect();

            let viewer_user = ViewerUser {
                id: NodeType::User.serialize(user.id),
                username: user.localpart.clone(),
                did,
                handle: arkret::user_handle(&url_builder, user),
                can_request_admin: user.can_request_admin,
                has_password,
                profile: UserProfileData {
                    display_name: profile.profile.display_name,
                    avatar_url: profile.profile.avatar_url,
                    preferred_locale: profile.profile.preferred_locale,
                    updated_at: profile.profile.updated_at.to_rfc3339(),
                },
                principal,
                emails: Some(EmailListData {
                    total_count: total,
                    edges: email_edges,
                }),
                linked_accounts: Some(linked_accounts),
            };

            let browser_session_data = BrowserSessionData {
                id: NodeType::BrowserSession.serialize(session.id),
                user: None, // avoid duplication, user is in viewer
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session.last_active_at.map(|t| t.to_rfc3339()),
                created_at: Some(session.created_at.to_rfc3339()),
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

fn map_user_profile_error(error: UserProfileServiceError) -> RouteError {
    match error {
        UserProfileServiceError::NotFound => RouteError::NotFound,
        UserProfileServiceError::Unauthorized => RouteError::Unauthorized,
        UserProfileServiceError::InvalidDisplayName => {
            RouteError::BadRequest("Invalid display name".into())
        }
        UserProfileServiceError::UnsupportedNotificationChannel(channel) => {
            RouteError::BadRequest(format!("Unsupported notification channel: {channel}"))
        }
        UserProfileServiceError::DuplicateNotificationChannel(channel) => {
            RouteError::BadRequest(format!("Duplicate notification channel: {channel}"))
        }
        UserProfileServiceError::PrincipalServer(error) => RouteError::Internal(error.into()),
        UserProfileServiceError::Repository(error) => RouteError::from(error),
    }
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
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => &session.user,
        _ => return Err(RouteError::Unauthorized),
    };

    let summary = repo.account().security_summary(user.id).await?;

    repo.cancel().await?;

    Ok(Json(SecuritySummaryData::from(&summary)))
}

// ── Response types for workflow inbox ────────────────────────

/// A single pending workflow item in the inbox.
#[derive(Serialize, ToSchema)]
pub struct WorkflowInboxItem {
    pub session_id: String,
    pub strand_slug: String,
    pub strand_title: String,
    pub current_stage: String,
    pub started_at: String,
}

/// Response for `GET /_coauth/self/viewer/workflow-inbox`.
#[derive(Serialize, ToSchema)]
pub struct WorkflowInboxOutcome {
    pub pending: Vec<WorkflowInboxItem>,
    pub total: usize,
}

// ── GET /_coauth/self/viewer/workflow-inbox ────────────────────────

/// Returns the list of pending strand sessions for the current user.
///
/// Strand sessions are currently in-memory and do not have a user-id
/// association, so this endpoint always returns an empty list. Once
/// persistent strand sessions with user ownership are implemented, this
/// will return actual pending items.
#[endpoint]
pub async fn get_workflow_inbox(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<WorkflowInboxOutcome>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    // Require an authenticated user.
    match &requester.entity {
        super::RequestingEntity::BrowserSession(_) => {}
        _ => return Err(RouteError::Unauthorized),
    }

    repo.cancel().await?;

    // Placeholder: strand sessions are in-memory and not user-associated yet.
    let pending: Vec<WorkflowInboxItem> = Vec::new();
    let total = pending.len();

    Ok(Json(WorkflowInboxOutcome { pending, total }))
}

// ── Response types for viewer overview ─────────────────────

/// Summary of the user for the overview dashboard.
#[derive(Serialize, ToSchema)]
pub struct ViewerUserSummary {
    pub id: String,
    pub has_password: bool,
}

/// Security summary data exposed in the overview.
#[derive(Serialize, ToSchema)]
pub struct SecuritySummaryData {
    pub has_password: bool,
    pub active_sessions_count: usize,
    pub linked_providers_count: usize,
    pub verified_emails_count: usize,
    pub verified_phones_count: usize,
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

impl From<&AccountSecuritySummary> for SecuritySummaryData {
    fn from(s: &AccountSecuritySummary) -> Self {
        Self {
            has_password: s.has_password,
            active_sessions_count: s.active_sessions_count,
            linked_providers_count: s.linked_providers_count,
            verified_emails_count: s.verified_emails_count,
            verified_phones_count: s.verified_phones_count,
        }
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
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

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
        security: SecuritySummaryData::from(&security),
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
