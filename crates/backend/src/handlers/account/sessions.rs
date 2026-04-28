use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, NodeType, RouteError, UserAgentInfo, extract_bound_activity_tracker,
    extract_session_info, get_requester, make_clock, make_rng, parse_user_agent,
};
use crate::handlers::account::service::sessions::{
    AccountSessionError, end_browser_session as end_browser_session_service,
    end_oauth2_session as end_oauth2_session_service, load_browser_session_detail,
    load_oauth2_session_detail, set_oauth2_session_human_name,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
#[serde(tag = "__typename")]
pub enum SessionDetailResponse {
    BrowserSession(BrowserSessionDetail),
    Oauth2Session(Oauth2SessionDetail),
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
pub struct Oauth2SessionDetail {
    pub id: String,
    pub scope: Option<String>,
    pub display_name: Option<String>,
    pub client: Option<Oauth2ClientBrief>,
    pub user_agent: Option<UserAgentInfo>,
    pub last_active_ip: Option<String>,
    pub last_active_at: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Oauth2ClientBrief {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
}

// ── GET /api/v1/sessions/:id ───────────────────────────────────

#[endpoint]
pub async fn get_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionDetailResponse>, RouteError> {
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

            SessionDetailResponse::BrowserSession(BrowserSessionDetail {
                id: NodeType::BrowserSession.serialize(session.id),
                display_name: None,
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session.last_active_at.map(|t| t.to_rfc3339()),
                created_at: Some(session.created_at.to_rfc3339()),
                last_authentication: detail.last_authentication.map(|a| AuthenticationData {
                    id: NodeType::Authentication.serialize(a.id),
                    created_at: a.created_at.to_rfc3339(),
                }),
            })
        }
        NodeType::OAuth2Session => {
            let detail = load_oauth2_session_detail(repo, &requester, ulid)
                .await
                .map_err(map_account_session_error)?;
            let session = detail.session;

            SessionDetailResponse::Oauth2Session(Oauth2SessionDetail {
                id: NodeType::OAuth2Session.serialize(session.id),
                scope: Some(session.scope.to_string()),
                display_name: None,
                client: detail.client.map(|c| Oauth2ClientBrief {
                    id: NodeType::OAuth2Client.serialize(c.id),
                    client_id: c.client_id.to_string(),
                    client_name: c.client_name.clone(),
                    client_uri: c.client_uri.as_ref().map(|u| u.to_string()),
                    logo_uri: c.logo_uri.as_ref().map(|u| u.to_string()),
                }),
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session.last_active_at.map(|t| t.to_rfc3339()),
                created_at: Some(session.created_at.to_rfc3339()),
            })
        }
        _ => return Err(RouteError::BadRequest("not a session id".into())),
    };

    Ok(Json(response))
}

// ── DELETE /api/v1/browser-sessions/:id ────────────────────────

#[derive(Serialize, ToSchema)]
pub struct EndSessionResponse {
    pub status: &'static str,
}

#[endpoint]
pub async fn end_browser_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EndSessionResponse>, RouteError> {
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

    Ok(Json(EndSessionResponse { status: "ENDED" }))
}

// ── DELETE /api/v1/oauth2-sessions/:id ─────────────────────────

#[endpoint]
pub async fn end_oauth2_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EndSessionResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuth2Session.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    end_oauth2_session_service(repo, &requester, &mut rng, &clock, ulid)
        .await
        .map_err(map_account_session_error)?;

    Ok(Json(EndSessionResponse { status: "ENDED" }))
}

// ── PUT /api/v1/oauth2-sessions/:id/name ───────────────────────

#[derive(Deserialize, ToSchema)]
pub struct SetSessionNameInput {
    pub human_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SetSessionNameResponse {
    pub status: &'static str,
}

#[endpoint]
pub async fn set_oauth2_session_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetSessionNameResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuth2Session.extract_ulid(&id)?;

    let input: SetSessionNameInput = req
        .parse_json::<SetSessionNameInput>()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let homeserver = depot.homeserver()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    set_oauth2_session_human_name(
        repo,
        &requester,
        &clock,
        homeserver.as_ref(),
        ulid,
        input.human_name,
    )
    .await
    .map_err(map_account_session_error)?;

    Ok(Json(SetSessionNameResponse { status: "UPDATED" }))
}

fn map_account_session_error(error: AccountSessionError) -> RouteError {
    match error {
        AccountSessionError::NotFound => RouteError::NotFound,
        AccountSessionError::Unauthorized => RouteError::Unauthorized,
        AccountSessionError::Repository(error) => RouteError::from(error),
    }
}
