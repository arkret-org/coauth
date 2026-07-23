use arkret_models_collaboration::session_grant_bodies::{
    AuthSessionLogoutOutcome, AuthSessionLogoutRequestBody,
};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use super::*;
use crate::handlers::arkret::*;

/// `POST /_arkret/gate/account/auth-sessions/logout` — Auth-side S2S logout
/// sub-operation used by the Account Authority after it has validated the
/// client-visible `ak.gate.account.command.logout` request.
#[handler]
pub async fn logout_auth_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AuthSessionLogoutOutcome>, ArkretRouteError> {
    require_auth_session_logout_service_caller(req, depot)?;

    let body: AuthSessionLogoutRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    if body.grant_jwt.trim().is_empty() {
        return Err(ArkretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    // Reject malformed bodies, but do not require the row to still exist. The
    // operation is idempotent once a valid grant-shaped identifier is presented
    // by an authenticated service caller.
    let _jwt: Jwt<'_, SignedSessionGrantClaims> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| ArkretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;

    Ok(Json(
        terminate_auth_side_session_by_grant_jwt(depot, &body.grant_jwt).await?,
    ))
}

fn require_auth_session_logout_service_caller(
    req: &Request,
    depot: &Depot,
) -> Result<(), ArkretRouteError> {
    let header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| ArkretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let value = header
        .to_str()
        .map_err(|_| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?
        .trim();
    if token.is_empty() {
        return Err(ArkretRouteError::Unauthorized(
            "empty service bearer".to_owned(),
        ));
    }

    let arkret_config = depot.arkret_config()?;
    if super::super::principal_server_static_session_grant_bearer_matches(&arkret_config, token) {
        return Ok(());
    }

    Err(ArkretRouteError::Unauthorized(
        "invalid service bearer".to_owned(),
    ))
}

async fn terminate_auth_side_session_by_grant_jwt(
    depot: &Depot,
    grant_jwt: &str,
) -> Result<AuthSessionLogoutOutcome, ArkretRouteError> {
    let clock = crate::handlers::make_clock();
    let mut repo = depot.repo().await?;

    let Some(grant) = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(grant_jwt)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
    else {
        repo.cancel()
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        return Ok(success_outcome());
    };

    if grant.revoked_at.is_none() {
        repo.oauth_session_grant()
            .revoke(&*clock, grant.clone())
            .await
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    }

    if let Some(browser_session_id) = grant.browser_session_id {
        let unfinished_session = {
            repo.browser_session()
                .lookup(browser_session_id)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
                .filter(|session| session.finished_at.is_none())
        };
        if let Some(session) = unfinished_session {
            repo.browser_session()
                .finish(&*clock, session)
                .await
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        }
    }

    repo.save()
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;

    Ok(success_outcome())
}

fn success_outcome() -> AuthSessionLogoutOutcome {
    AuthSessionLogoutOutcome {
        ok: true,
        grant_chain_terminated: true,
        auth_session_logged_out: true,
    }
}
