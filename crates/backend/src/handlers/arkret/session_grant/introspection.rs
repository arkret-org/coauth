//! Deployment adapter for the shared authoritative issuer service.
use arkret_models_collaboration::session_grants::{
    SessionGrantValidationInput, SessionGrantValidationResponseBody,
};
use salvo::prelude::*;

use crate::handlers::arkret::*;
#[cfg(test)]
pub(crate) use crate::services::station_authority::introspection::{
    introspection_status, session_grant_jwt_digest,
};

#[handler]
pub async fn introspect_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantValidationResponseBody>, ArkretRouteError> {
    // `json_invalid` (400) means the bytes are not JSON; a body that parses but
    // breaks the request contract — such as carrying both selectors, or
    // neither — is `schema_violation` (422). Deserializing straight into the
    // typed body would collapse both onto `json_invalid`.
    let raw_body: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".into()))?;
    let body: SessionGrantValidationInput = serde_json::from_value(raw_body).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            error.to_string(),
        )
    })?;

    let caller = require_session_grant_caller(req, depot, true).await?;
    let context = crate::services::station_authority::Context::from_depot(depot)?;
    crate::services::station_authority::introspection::validate_session_grant(
        &context,
        body,
        caller.allowed_audiences.as_deref(),
    )
    .await
    .map(Json)
}
