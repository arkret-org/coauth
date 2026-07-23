use coauth_data::Pagination;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, NodeType, RouteError, UserAgentInfo, extract_bound_activity_tracker,
    extract_session_info, get_requester, make_clock, make_rng, parse_user_agent,
};
use crate::handlers::account::service::sessions::{
    AccountSessionError, OAuthSessionDetailData,
    end_browser_session as end_browser_session_service,
    end_oauth_session as end_oauth_session_service, list_active_oauth_sessions_for_requester,
    load_browser_session_detail, load_oauth_session_detail, set_oauth_session_human_name,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
#[serde(tag = "__typename")]
pub enum SessionDetailOutcome {
    BrowserSession(BrowserSessionDetail),
    #[serde(rename = "OauthSession")]
    OAuthSession(OAuthSessionDetail),
}

#[derive(Serialize, ToSchema)]
pub struct BrowserSessionDetail {
    pub id: String,
    pub display_name: Option<String>,
    pub user_agent: Option<UserAgentInfo>,
    pub last_active_ip: Option<String>,
    pub last_active_at: Option<String>,
    pub created_at: Option<String>,
    pub last_authentication: Option<AuthenticationData>,
}

#[derive(Serialize, ToSchema)]
pub struct AuthenticationData {
    pub id: String,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct OAuthSessionDetail {
    pub id: String,
    pub scope: Option<String>,
    pub display_name: Option<String>,
    pub client: Option<OAuthClientBrief>,
    pub user_agent: Option<UserAgentInfo>,
    pub last_active_ip: Option<String>,
    pub last_active_at: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct OAuthClientBrief {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
}

fn oauth_session_detail_response(detail: OAuthSessionDetailData) -> OAuthSessionDetail {
    let session = detail.session;
    OAuthSessionDetail {
        id: NodeType::OAuthSession.serialize(session.id),
        scope: Some(session.scope.to_string()),
        display_name: session.human_name.clone(),
        client: detail.client.map(|c| OAuthClientBrief {
            id: NodeType::OAuthClient.serialize(c.id),
            client_id: c.client_id.clone(),
            client_name: c.client_name.clone(),
            client_uri: c.client_uri.as_ref().map(std::string::ToString::to_string),
            logo_uri: c.logo_uri.as_ref().map(std::string::ToString::to_string),
        }),
        user_agent: session.user_agent.as_deref().map(parse_user_agent),
        last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
        last_active_at: session
            .last_active_at
            .map(arkret_canonical::format_timestamp_canonical),
        created_at: Some(arkret_canonical::format_timestamp_canonical(
            session.created_at,
        )),
    }
}

// ── GET /_coauth/self/oauth-sessions ─────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct OAuthSessionList {
    pub sessions: Vec<OAuthSessionDetail>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// List the requesting user's active OAuth sessions (settings "signed-in
/// apps" card). Query params: `limit` (default 50, cap 100) and `after`
/// (an `OAuthSession` node id from a previous page's `next_cursor`).
#[endpoint]
pub async fn list_oauth_sessions(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<OAuthSessionList>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);
    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let limit = req.query::<usize>("limit").unwrap_or(50).clamp(1, 100);
    let mut pagination = Pagination::first(limit);
    if let Some(after) = req.query::<String>("after") {
        let (node_type, ulid) = NodeType::deserialize(&after)?;
        if node_type != NodeType::OAuthSession {
            return Err(RouteError::BadRequest("not an oauth session cursor".into()));
        }
        pagination = pagination.after(ulid);
    }

    let data = list_active_oauth_sessions_for_requester(repo, &requester, pagination)
        .await
        .map_err(map_account_session_error)?;
    Ok(Json(OAuthSessionList {
        sessions: data
            .sessions
            .into_iter()
            .map(oauth_session_detail_response)
            .collect(),
        next_cursor: data
            .next_cursor
            .map(|id| NodeType::OAuthSession.serialize(id)),
        has_more: data.has_more,
    }))
}

// ── GET /_coauth/self/sessions/:id ───────────────────────────────────

#[endpoint]
pub async fn get_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionDetailOutcome>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;

    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let (node_type, ulid) = NodeType::deserialize(&id)?;

    let response = match node_type {
        NodeType::BrowserSession => {
            let detail = load_browser_session_detail(repo, &requester, ulid)
                .await
                .map_err(map_account_session_error)?;
            let session = detail.session;

            SessionDetailOutcome::BrowserSession(BrowserSessionDetail {
                id: NodeType::BrowserSession.serialize(session.id),
                display_name: None,
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session
                    .last_active_at
                    .map(arkret_canonical::format_timestamp_canonical),
                created_at: Some(arkret_canonical::format_timestamp_canonical(
                    session.created_at,
                )),
                last_authentication: detail.last_authentication.map(|a| AuthenticationData {
                    id: NodeType::Authentication.serialize(a.id),
                    created_at: arkret_canonical::format_timestamp_canonical(a.created_at),
                }),
            })
        }
        NodeType::OAuthSession => {
            let detail = load_oauth_session_detail(repo, &requester, ulid)
                .await
                .map_err(map_account_session_error)?;
            let session = detail.session;

            SessionDetailOutcome::OAuthSession(OAuthSessionDetail {
                id: NodeType::OAuthSession.serialize(session.id),
                scope: Some(session.scope.to_string()),
                display_name: None,
                client: detail.client.map(|c| OAuthClientBrief {
                    id: NodeType::OAuthClient.serialize(c.id),
                    client_id: c.client_id.clone(),
                    client_name: c.client_name.clone(),
                    client_uri: c.client_uri.as_ref().map(std::string::ToString::to_string),
                    logo_uri: c.logo_uri.as_ref().map(std::string::ToString::to_string),
                }),
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session
                    .last_active_at
                    .map(arkret_canonical::format_timestamp_canonical),
                created_at: Some(arkret_canonical::format_timestamp_canonical(
                    session.created_at,
                )),
            })
        }
        _ => return Err(RouteError::BadRequest("not a session id".into())),
    };

    Ok(Json(response))
}

// ── DELETE /_coauth/self/browser-sessions/:id ────────────────────────

#[derive(Serialize, ToSchema)]
pub struct EndSessionOutcome {
    pub status: &'static str,
}

#[endpoint]
pub async fn end_browser_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EndSessionOutcome>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::BrowserSession.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    end_browser_session_service(repo, &requester, &clock, ulid)
        .await
        .map_err(map_account_session_error)?;

    Ok(Json(EndSessionOutcome { status: "ENDED" }))
}

// ── DELETE /_coauth/self/oauth-sessions/:id ─────────────────────────

#[endpoint]
pub async fn end_oauth_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EndSessionOutcome>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuthSession.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    end_oauth_session_service(repo, &requester, &mut rng, &clock, ulid)
        .await
        .map_err(map_account_session_error)?;

    Ok(Json(EndSessionOutcome { status: "ENDED" }))
}

// ── PUT /_coauth/self/oauth-sessions/:id/name ───────────────────────

#[derive(Deserialize, ToSchema)]
pub struct SetSessionNameInput {
    pub human_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SetSessionNameOutcome {
    pub status: &'static str,
}

#[endpoint]
pub async fn set_oauth_session_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetSessionNameOutcome>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuthSession.extract_ulid(&id)?;

    let input: SetSessionNameInput = req
        .parse_json::<SetSessionNameInput>()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let principal_server = depot.principal_server()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    set_oauth_session_human_name(
        repo,
        &requester,
        &clock,
        principal_server.as_ref(),
        ulid,
        input.human_name,
    )
    .await
    .map_err(map_account_session_error)?;

    Ok(Json(SetSessionNameOutcome { status: "UPDATED" }))
}

fn map_account_session_error(error: AccountSessionError) -> RouteError {
    match error {
        AccountSessionError::NotFound => RouteError::NotFound,
        AccountSessionError::Unauthorized => RouteError::Unauthorized,
        AccountSessionError::Repository(error) => RouteError::from(error),
    }
}
