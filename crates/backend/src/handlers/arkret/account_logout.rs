//! Expose the registered Account Authority ingress for the existing native coordinator.
use arkret_models_identity::{AccountLogoutRequestBody, AccountLogoutResponseBody};
use coauth_data::RepositoryAccess;
use salvo::http::HeaderValue;
use salvo::prelude::*;

use crate::handlers::arkret::ArkretRouteError;
use crate::handlers::common::DepotExt;
use crate::services::station_trust;

fn unavailable() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "native account logout is temporarily unavailable",
    )
}

#[handler]
pub async fn logout_account(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), ArkretRouteError> {
    // The Account Authority remains the sole client-visible origin. Its
    // configured native coordinator validates the original holder proof and
    // owns the existing ordered issuer-termination/private-cleanup journal.
    let token = crate::services::dpop::dpop_authorization_token(req)
        .ok_or_else(|| {
            ArkretRouteError::Unauthorized("Authorization: DPoP <session_grant> is required".into())
        })?
        .to_owned();
    let proof = req
        .headers()
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ArkretRouteError::Unauthorized("holder DPoP proof is required".into()))?
        .to_owned();
    let body: AccountLogoutRequestBody = req.parse_json().await.map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("invalid account logout body: {error}"),
        )
    })?;
    let config = depot.arkret_config()?;
    let station = config.owning_station().ok_or_else(unavailable)?;
    let pinned = station_trust::effective_audience_shared(station).ok_or_else(unavailable)?;
    if pinned != station_trust::owning_station_id_for(&config) {
        return Err(unavailable());
    }
    // An ended grant must remain addressable: the coordinator's immutable
    // holder journal, not an active-only facade check, authorizes exact retry.
    let mut repo = depot.repo().await?;
    let original = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&token)
        .await?;
    repo.cancel().await?;
    if original
        .as_ref()
        .is_some_and(|grant| grant.audience_id != pinned)
    {
        return Err(ArkretRouteError::Unauthorized(
            "session grant has another Station audience".into(),
        ));
    }
    // A pruned issuer row cannot erase the native coordinator's independently
    // durable holder journal. Unknown credentials still fail at that boundary.
    let mut target = station.endpoint.clone();
    let prefix = target.path().trim_end_matches('/').to_owned();
    target.set_path(&format!("{prefix}/_arkret/gate/account/logout"));
    target.set_query(None);
    target.set_fragment(None);
    let client = depot.http_client()?;
    let payload = arkret_canonical::canonical_json_bytes(&body)?;
    // One attempt only: a transport retry cannot reuse a consumed DPoP JTI.
    // A client retry reaches this ingress again with a fresh holder proof.
    let mut response = crate::outbound_http::send_with_policy(
        crate::outbound_http::OutboundRequestPolicy::new("coland", "account_logout"),
        || {
            client
                .post(target.clone())
                .header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT_V1,
                )
                .header("Authorization", format!("DPoP {token}"))
                .header("DPoP", &proof)
                .header("Content-Type", "application/json")
                .body(payload.clone())
        },
    )
    .await
    .map_err(|_| unavailable())?;
    let status = response.status();
    let retry_after = response.headers().get("retry-after").cloned();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len().saturating_add(chunk.len()) > 64 * 1024 {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    if status == reqwest::StatusCode::OK {
        let _: AccountLogoutResponseBody =
            serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        res.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
    } else if status.is_client_error() || status.is_server_error() {
        let problem: arkret_wire::Problem =
            serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        if problem.status != status.as_u16() {
            return Err(unavailable());
        }
        res.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/problem+json"),
        );
    } else {
        return Err(unavailable());
    }
    res.status_code(StatusCode::from_u16(status.as_u16()).map_err(|_| unavailable())?);
    res.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    if let Some(value) = retry_after {
        res.headers_mut().insert("retry-after", value);
    }
    res.write_body(bytes).map_err(|_| unavailable())?;
    Ok(())
}
