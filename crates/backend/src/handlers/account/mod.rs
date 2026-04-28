//! Account management API endpoints consumed by the frontend SPA.
//!
//! These endpoints let users manage their sessions, emails, passwords, and
//! profile. All responses use JSON and authentication is via browser session
//! cookies or OAuth 2.0 bearer tokens.

#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Utc};
use coauth_data::{BoxRepository, Clock, SiteConfig, User};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

// Re-export shared types so that existing `crate::handlers::account::X` paths
// continue to work until all call-sites are migrated.
pub use crate::handlers::common::{
    DepotExt, Requester, RequestingEntity, RouteError, UserAgentInfo,
    extract_bound_activity_tracker, extract_session_info, make_clock, make_rng, parse_user_agent,
};
use crate::{
    handlers::{BoundActivityTracker, passwords::PasswordManager},
    salvo_utils::SessionInfo,
};

pub mod auth;
pub mod avatar;
pub mod bootstrap_admin_status;
pub mod consent;
pub mod emails;
pub mod flow;
pub mod linked_accounts;
pub mod notification_prefs;
pub mod oauth2_clients;
pub mod openapi;
pub mod password;
pub mod recovery;
pub mod register;
pub mod sessions;
pub mod site_config;
pub mod upstream_oauth2;
pub mod users;
pub mod viewer;

// ── Helper: extract requester from session cookie ──────────────

pub async fn get_requester(
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    mut repo: BoxRepository,
    session_info: &SessionInfo,
) -> Result<(Requester, BoxRepository), RouteError> {
    use crate::salvo_utils::SessionInfoExt as _;

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session.as_ref() {
        activity_tracker
            .record_browser_session(clock, session)
            .await;
    }

    let entity = RequestingEntity::from(maybe_session);

    let requester = Requester {
        entity,
        ip_address: activity_tracker.ip(),
        user_agent: None,
    };

    Ok((requester, repo))
}

// ── Helper: verify password if needed ──────────────────────────

pub async fn verify_password_if_needed(
    requester: &Requester,
    config: &SiteConfig,
    password_manager: &PasswordManager,
    password: Option<String>,
    user: &User,
    repo: &mut BoxRepository,
) -> Result<bool, RouteError> {
    crate::handlers::account::service::password::verify_password_if_needed(
        requester.is_admin(),
        config.password_login_enabled,
        password_manager,
        password,
        user,
        repo,
    )
    .await
    .map_err(|error| RouteError::Internal(Box::new(error)))
}

// ── Node ID helpers ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Authentication,
    BrowserSession,
    OAuth2Client,
    OAuth2Session,
    UpstreamOAuth2Provider,
    UpstreamOAuth2Link,
    User,
    UserEmail,
    UserEmailAuthentication,
    UserRecoveryTicket,
}

impl NodeType {
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::BrowserSession => "browser_session",
            Self::OAuth2Client => "oauth2_client",
            Self::OAuth2Session => "oauth2_session",
            Self::UpstreamOAuth2Provider => "upstream_oauth2_provider",
            Self::UpstreamOAuth2Link => "upstream_oauth2_link",
            Self::User => "user",
            Self::UserEmail => "user_email",
            Self::UserEmailAuthentication => "user_email_authentication",
            Self::UserRecoveryTicket => "user_recovery_ticket",
        }
    }

    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "authentication" => Some(Self::Authentication),
            "browser_session" => Some(Self::BrowserSession),
            "oauth2_client" => Some(Self::OAuth2Client),
            "oauth2_session" => Some(Self::OAuth2Session),
            "upstream_oauth2_provider" => Some(Self::UpstreamOAuth2Provider),
            "upstream_oauth2_link" => Some(Self::UpstreamOAuth2Link),
            "user" => Some(Self::User),
            "user_email" => Some(Self::UserEmail),
            "user_email_authentication" => Some(Self::UserEmailAuthentication),
            "user_recovery_ticket" => Some(Self::UserRecoveryTicket),
            _ => None,
        }
    }

    pub fn serialize(self, id: Ulid) -> String {
        format!("{}:{}", self.prefix(), id)
    }

    pub fn deserialize(s: &str) -> Result<(Self, Ulid), RouteError> {
        let (prefix, id) = s
            .split_once(':')
            .ok_or_else(|| RouteError::BadRequest("invalid id format".into()))?;
        let node_type = Self::from_prefix(prefix)
            .ok_or_else(|| RouteError::BadRequest("unknown id prefix".into()))?;
        let ulid: Ulid = id
            .parse()
            .map_err(|_| RouteError::BadRequest("invalid ulid".into()))?;
        Ok((node_type, ulid))
    }

    pub fn extract_ulid(self, id: &str) -> Result<Ulid, RouteError> {
        let (node_type, ulid) = Self::deserialize(id)?;
        if node_type == self {
            Ok(ulid)
        } else {
            Err(RouteError::BadRequest(format!(
                "expected {} id, got {}",
                self.prefix(),
                node_type.prefix()
            )))
        }
    }
}

// ── Pagination helpers ─────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct PaginationParams {
    pub first: Option<i64>,
    pub after: Option<String>,
    pub last: Option<i64>,
    pub before: Option<String>,
}

#[derive(Serialize)]
pub struct PageInfo {
    pub has_next_page: bool,
    pub has_previous_page: bool,
    pub start_cursor: Option<String>,
    pub end_cursor: Option<String>,
}

#[derive(Serialize)]
pub struct Edge<T: Serialize> {
    pub cursor: String,
    pub node: T,
}

#[derive(Serialize)]
pub struct Connection<T: Serialize> {
    pub total_count: i64,
    pub edges: Vec<Edge<T>>,
    pub page_info: PageInfo,
}

// ── Date filter ────────────────────────────────────────────────

#[derive(Deserialize, Default, Clone, Copy)]
pub struct DateFilter {
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
}

/// Cookie management for user registration sessions.
pub mod registration_cookie;
pub(crate) mod service;
