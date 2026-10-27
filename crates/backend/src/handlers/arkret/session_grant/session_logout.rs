use arkret_models_collaboration::session_grants::{
    AuthenticationSessionTerminationInput, AuthenticationSessionTerminationResponseBody,
};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use super::*;
use crate::handlers::arkret::*;

/// Deployment-private Auth-side hard-logout adapter.
/// sub-operation used by the Account Authority after it has validated the
/// client-visible `ak.gate.account.command.logout.v1` request.
#[handler]
pub async fn logout_auth_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AuthenticationSessionTerminationResponseBody>, ArkretRouteError> {
    let caller_service_id = require_auth_session_logout_service_caller(req, depot)?;

    let body: AuthenticationSessionTerminationInput = req
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
        crate::services::station_authority::session_termination::terminate_auth_side_session_by_grant_jwt(
                &crate::services::station_authority::Context::from_depot(depot)?, &caller_service_id, &body.grant_jwt)
            .await?,
    ))
}

fn require_auth_session_logout_service_caller(
    req: &Request,
    depot: &Depot,
) -> Result<String, ArkretRouteError> {
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
    if let Some(caller) = super::super::station_internal_channel_caller(&arkret_config, token) {
        return Ok(caller);
    }

    Err(ArkretRouteError::Unauthorized(
        "invalid service bearer".to_owned(),
    ))
}
