//! REST API endpoints for OAuth2 consent and device-code flows.
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. They replace the server-rendered HTML consent pages.

use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, make_clock,
    make_rng,
};
use crate::routing::oauth2::access::{
    ConsentScreen, DeviceConsentAction, DeviceConsentStatus, OAuth2AccessError,
    accept_authorization_consent, load_authorization_consent, load_device_consent,
    lookup_device_link, submit_device_consent,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ClientInfo {
    pub id: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct UserInfo {
    pub mxid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ConsentGetResponse {
    pub grant_id: String,
    pub client: ClientInfo,
    pub scope: String,
    pub user: UserInfo,
    pub policy_violation: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct ConsentPostRequest {
    pub action: String,
}

#[derive(Serialize, ToSchema)]
pub struct ConsentPostResponse {
    pub status: &'static str,
    pub redirect_url: String,
}

#[derive(Serialize, ToSchema)]
pub struct DeviceLinkResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct DeviceLinkQuery {
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct DeviceConsentPostRequest {
    pub action: String,
}

#[derive(Serialize, ToSchema)]
pub struct DeviceConsentPostResponse {
    pub status: &'static str,
}

fn client_info(client: &coauth_data::Client) -> ClientInfo {
    ClientInfo {
        id: client.id.to_string(),
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        client_uri: client.client_uri.as_ref().map(|u| u.to_string()),
        logo_uri: client.logo_uri.as_ref().map(|u| u.to_string()),
    }
}

fn consent_get_response(screen: ConsentScreen) -> ConsentGetResponse {
    ConsentGetResponse {
        grant_id: screen.grant_id.to_string(),
        client: client_info(&screen.client),
        scope: screen.scope,
        user: UserInfo {
            mxid: screen.user_mxid,
            display_name: screen.user_display_name,
        },
        policy_violation: screen.policy_violation,
    }
}

fn map_oauth2_access_error(error: OAuth2AccessError) -> RouteError {
    match error {
        OAuth2AccessError::NotFound => RouteError::NotFound,
        OAuth2AccessError::GrantNotPending => RouteError::BadRequest("grant is not pending".into()),
        OAuth2AccessError::GrantExpired => RouteError::BadRequest("grant is expired".into()),
        OAuth2AccessError::PolicyViolation => RouteError::BadRequest("policy_violation".into()),
        OAuth2AccessError::Repository(error) => RouteError::from(error),
        OAuth2AccessError::Internal(error) => RouteError::Internal(error),
    }
}

/// Load the browser session from cookies, record activity, and render a 401
/// JSON error if the user is not authenticated. Returns `None` when the
/// unauthenticated response has already been written to `res`.
async fn require_authenticated_session(
    session_info: &crate::salvo_utils::SessionInfo,
    repo: &mut coauth_data::BoxRepository,
    activity_tracker: &crate::routing::BoundActivityTracker,
    clock: &dyn coauth_data::Clock,
    res: &mut Response,
) -> Result<Option<coauth_data::BrowserSession>, RouteError> {
    let maybe_session = session_info.load_active_session(repo).await?;

    let Some(session) = maybe_session else {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(serde_json::json!({
            "status": "error",
            "error": "not_authenticated"
        })));
        return Ok(None);
    };

    activity_tracker
        .record_browser_session(clock, &session)
        .await;

    Ok(Some(session))
}

// ── GET /api/v1/oauth2/consent/:grant_id ───────────────────────

/// Return the data needed to render a consent page for an OAuth2 authorization
/// grant.
#[endpoint]
#[tracing::instrument(name = "routing.rest.consent.oauth2_get", skip_all)]
pub async fn oauth2_consent_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let homeserver = depot.homeserver()?;
    let policy_factory = depot.policy_factory()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("grant_id")
        .ok_or_else(|| RouteError::BadRequest("missing grant_id".into()))?;

    let Some(session) =
        require_authenticated_session(&session_info, &mut repo, &activity_tracker, &clock, res)
            .await?
    else {
        return Ok(());
    };

    let info = load_authorization_consent(
        repo,
        policy_factory.as_ref(),
        homeserver.as_ref(),
        &clock,
        &session,
        grant_id,
        activity_tracker.ip(),
        user_agent,
    )
    .await
    .map_err(map_oauth2_access_error)?;

    res.render(Json(consent_get_response(info.into())));
    Ok(())
}

// ── POST /api/v1/oauth2/consent/:grant_id ──────────────────────

/// Accept the OAuth2 authorization consent: create an OAuth2 session, fulfill
/// the grant, and return the callback redirect URL.
#[endpoint]
#[tracing::instrument(name = "routing.rest.consent.oauth2_post", skip_all, err)]
pub async fn oauth2_consent_post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let mut rng = make_rng();
    let clock = make_clock();
    let key_store = depot.key_store()?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let policy_factory = depot.policy_factory()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("grant_id")
        .ok_or_else(|| RouteError::BadRequest("missing grant_id".into()))?;

    let input: ConsentPostRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    if input.action != "consent" {
        return Err(RouteError::BadRequest("invalid action".into()));
    }

    let Some(browser_session) =
        require_authenticated_session(&session_info, &mut repo, &activity_tracker, &clock, res)
            .await?
    else {
        return Ok(());
    };

    let decision = accept_authorization_consent(
        repo,
        &mut rng,
        &clock,
        &key_store,
        &url_builder,
        &contrix_config,
        policy_factory.as_ref(),
        &browser_session,
        grant_id,
        activity_tracker.ip(),
        user_agent,
    )
    .await
    .map_err(map_oauth2_access_error)?;

    activity_tracker
        .record_oauth2_session(&clock, &decision.session)
        .await;

    let redirect_url = decision.redirect_url().map_err(map_oauth2_access_error)?;

    res.render(Json(ConsentPostResponse {
        status: "success",
        redirect_url,
    }));
    Ok(())
}

// ── GET /api/v1/device-link ────────────────────────────────────

/// Validate a device user code and return the grant ID if valid.
#[endpoint]
#[tracing::instrument(name = "routing.rest.consent.device_link_get", skip_all)]
pub async fn device_link_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let repo = depot.repo().await?;

    let query: DeviceLinkQuery = req
        .parse_queries()
        .unwrap_or(DeviceLinkQuery { code: None });

    let Some(code) = query.code else {
        res.render(Json(DeviceLinkResponse {
            status: "invalid",
            grant_id: None,
        }));
        return Ok(());
    };

    let code = code.to_uppercase();
    if let Some(grant_id) = lookup_device_link(repo, &clock, &code)
        .await
        .map_err(map_oauth2_access_error)?
    {
        res.render(Json(DeviceLinkResponse {
            status: "valid",
            grant_id: Some(grant_id.to_string()),
        }));
    } else {
        res.render(Json(DeviceLinkResponse {
            status: "invalid",
            grant_id: None,
        }));
    }
    Ok(())
}

// ── GET /api/v1/device-consent/:id ─────────────────────────────

/// Return the data needed to render a consent page for a device code grant.
#[endpoint]
#[tracing::instrument(name = "routing.rest.consent.device_consent_get", skip_all)]
pub async fn device_consent_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let homeserver = depot.homeserver()?;
    let policy_factory = depot.policy_factory()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing id".into()))?;

    let Some(session) =
        require_authenticated_session(&session_info, &mut repo, &activity_tracker, &clock, res)
            .await?
    else {
        return Ok(());
    };

    let screen = load_device_consent(
        repo,
        policy_factory.as_ref(),
        homeserver.as_ref(),
        &clock,
        &session,
        grant_id,
        activity_tracker.ip(),
        user_agent,
    )
    .await
    .map_err(map_oauth2_access_error)?;

    res.render(Json(consent_get_response(screen)));
    Ok(())
}

// ── POST /api/v1/device-consent/:id ────────────────────────────

/// Accept or reject a device code grant.
#[endpoint]
#[tracing::instrument(name = "routing.rest.consent.device_consent_post", skip_all)]
pub async fn device_consent_post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let policy_factory = depot.policy_factory()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing id".into()))?;

    let input: DeviceConsentPostRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let action = match input.action.as_str() {
        "consent" => DeviceConsentAction::Consent,
        "reject" => DeviceConsentAction::Reject,
        _ => return Err(RouteError::BadRequest("invalid action".into())),
    };

    let Some(session) =
        require_authenticated_session(&session_info, &mut repo, &activity_tracker, &clock, res)
            .await?
    else {
        return Ok(());
    };

    let result_status = match submit_device_consent(
        repo,
        policy_factory.as_ref(),
        &clock,
        &session,
        grant_id,
        action,
        activity_tracker.ip(),
        user_agent,
    )
    .await
    .map_err(map_oauth2_access_error)?
    {
        DeviceConsentStatus::Fulfilled => "fulfilled",
        DeviceConsentStatus::Rejected => "rejected",
    };

    res.render(Json(DeviceConsentPostResponse {
        status: result_status,
    }));
    Ok(())
}
