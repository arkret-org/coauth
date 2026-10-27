//! Deployment adapter for actual Account Authority gate issuance.
use arkret_models_identity::agent_signer_evidence::ControllerAccountGateIssuanceInput;
use salvo::prelude::*;

use crate::handlers::arkret::ArkretRouteError;
use crate::handlers::common::DepotExt;

pub struct ControllerGateCanonicalJson(Vec<u8>);

impl Scribe for ControllerGateCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("canonical controller gate outcome is writable");
    }
}

#[handler]
pub async fn issue_controller_gate_attestation(
    req: &mut Request,
    depot: &Depot,
) -> Result<ControllerGateCanonicalJson, ArkretRouteError> {
    let canonical_body = req
        .payload()
        .await
        .map_err(|_| schema_violation("invalid controller gate request"))?
        .to_vec();
    let request: ControllerAccountGateIssuanceInput = serde_json::from_slice(&canonical_body)
        .map_err(|_| schema_violation("invalid controller gate request"))?;
    authenticate_internal_channel_caller(req, depot, &request)?;
    let context = crate::services::station_authority::Context::from_depot(depot)?;
    crate::services::station_authority::controller_gate::issue_controller_gate(
        &context,
        &request,
        request.agent_authority_id.as_str(),
    )
    .await
    .map(ControllerGateCanonicalJson)
}

/// Authenticate the caller on the registered deployment-internal channel
/// (`sync/service-http-binding.md` §2.2.3).
///
/// The internal identity comes only from verifying the credential configured
/// for this exact Account Authority / Station edge. Request identity headers,
/// path fields and body fields do not decide that identity. The fixed route and
/// matched peer configuration provide the remaining binding. The channel is the complete
/// authentication contract for this operation and replaces the RFC 9421 request signature, so the
/// request body no longer carries a service-resolution carrier.
///
/// The verified caller MUST equal `agent_authority_id`; the caller's verbatim
/// equality with the principal's current `AcceptedAtServiceBinding.service_id`
/// is enforced by the binding lookup in the handler, which resolves the
/// principal only under that exact accepted service id.
///
/// The *response* attestation keeps its signature, its verification method's
/// public DID assertion authorization, its TTL and its exact replay: it leaves
/// this relationship and enters the external Agent evidence chain.
fn authenticate_internal_channel_caller(
    req: &Request,
    depot: &Depot,
    request: &ControllerAccountGateIssuanceInput,
) -> Result<(), ArkretRouteError> {
    let config = depot.arkret_config()?;
    let credential = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(not_found)?;
    let authenticated_caller =
        crate::handlers::arkret::station_internal_channel_caller(&config, credential)
            .ok_or_else(not_found)?;
    if authenticated_caller != request.agent_authority_id.as_str() {
        return Err(not_found());
    }
    Ok(())
}

fn not_found() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
        "controller gate unavailable",
    )
}
fn schema_violation(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        message,
    )
}
