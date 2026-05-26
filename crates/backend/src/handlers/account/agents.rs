//! CXP-0008 personal-agent controller-approval endpoints.
//!
//! Phase P2 (B-A / `_before_todos.md` §1.4): when a controller approves
//! provisioning of a native Personal Agent, coauth (as the controller's
//! accountability domain) issues a typed `accountability_grant` credential
//! to soland referencing the agent's principal id and the capability set
//! covered by the grant. soland's reducer is the persistence authority;
//! coauth is only the signed-grant issuer.
//!
//! Authentication: this endpoint accepts the soland / sodmin static
//! bearer token configured under
//! `contrix.principal_servers[].session_grant_introspection_bearer` —
//! the same trust anchor used elsewhere for server-to-server flows.
//! Browser sessions and end-user OAuth tokens are NOT accepted.
//!
//! Persistence: this is currently a thin stub. The grant payload is
//! built deterministically (typed id + agent principal id + capability
//! list) and returned to the caller. Actual persistence (audit log row +
//! revocation index + soland fan-out) is tracked at TODO(P2-impl) below.
//!
//! Wire shape: see [`AccountabilityGrantRequest`] and
//! [`AccountabilityGrantResponse`].

use chrono::{DateTime, Utc};
use coauth_config::ContrixConfig;
use contrix_core::identifiers::{AccountabilityGrantId, AgentPrincipalId, new_prefixed_uuid7};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::DepotExt;
use crate::{
    AppError, CreatedJsonResult, handlers::admin::CreatedJson,
    services::did_binding_proof::normalize_did_for_binding,
};

/// Request body for `POST /api/v1/agents/{id}/accountability-grant`.
#[derive(Deserialize, JsonSchema, ToSchema)]
pub struct AccountabilityGrantRequest {
    /// DID of the controller (account holder) issuing the grant. MUST
    /// round-trip through the SDK `Did::new` validator (Round-4 regex
    /// `^did:[a-z0-9]+:[^\s]+$`).
    pub controller_did: String,

    /// Capability actions covered by the grant. Each entry is a
    /// `cx.agent.*` action name from the 14-action registry; the typed
    /// id below references the union as a single accountability grant.
    pub capabilities: Vec<String>,

    /// Optional human-readable reason recorded with the grant for the
    /// audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response payload for `POST /api/v1/agents/{id}/accountability-grant`.
///
/// CXP-0008 (`id-kind-registry.json`): the wire shape carries the
/// freshly minted `cx:accountability_grant:<uuid7>` typed id, the
/// `agent_principal_id`, the canonical capability list, and the issuer
/// controller DID. soland MUST verify each capability action is in the
/// registered 14-action set before accepting the grant.
///
/// `accountability_grant_id` and `agent_principal_id` are emitted as
/// raw strings in the OpenAPI surface — the SDK `AccountabilityGrantId`
/// / `AgentPrincipalId` newtypes are construction-validated by the
/// handler before the payload is built, so the wire shape is canonical
/// without dragging the SDK's `salvo` feature into coauth's dep graph.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountabilityGrantResponse {
    /// Typed id of the issued grant. Wire form: `cx:accountability_grant:<uuid7>`.
    pub accountability_grant_id: String,

    /// Agent principal id this grant authorizes capability actions on.
    /// Wire form: `cx:agent_principal:<uuid7>` typed id. The {id} URL
    /// segment is canonicalized into this field.
    pub agent_principal_id: String,

    /// Controller DID this grant attributes accountability to.
    pub controller_did: String,

    /// Capability actions covered by this grant.
    pub capabilities: Vec<String>,

    /// Optional human-readable reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Grant issuance timestamp.
    pub issued_at: DateTime<Utc>,
}

/// `POST /api/v1/agents/{id}/accountability-grant`
///
/// Internal CXP-0008 grant-issuance endpoint. Accepts only the soland /
/// sodmin static bearer token (matched against any
/// `contrix.principal_servers[].session_grant_introspection_bearer`
/// configured for the deployment); browser sessions and end-user
/// bearers are rejected with 401.
///
/// On success returns a freshly minted `accountability_grant` payload
/// referencing the agent principal id + capability set. Persistence is
/// a stub (TODO(P2-impl) below); the returned payload is canonical and
/// soland can accept it once the persistence cut-over lands.
#[endpoint]
#[tracing::instrument(name = "handler.account.agents.accountability_grant", skip_all)]
pub async fn post_accountability_grant(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<AccountabilityGrantResponse> {
    let agent_principal_raw = req
        .param::<String>("id")
        .ok_or_else(|| AppError::bad_request("missing agent principal id"))?;
    let agent_principal_raw = agent_principal_raw.trim().to_owned();
    // Validate that the path {id} is a canonical `cx:agent_principal:<uuid7>`
    // typed id BEFORE doing any further work. The SDK's strict typed-id
    // check rejects non-canonical payloads at the edge.
    let agent_principal_id = AgentPrincipalId::new(agent_principal_raw)
        .map_err(|err| AppError::bad_request(format!("agent principal id invalid: {err}")))?;

    // soland / sodmin only — reject browser sessions and end-user bearers.
    let contrix_config = depot.contrix_config()?;
    authn_internal_caller(req, &contrix_config)?;

    let body: AccountabilityGrantRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let controller_did = normalize_did_for_binding(&body.controller_did)
        .map_err(|error| AppError::bad_request(format!("controller_did invalid: {error}")))?;

    if body.capabilities.is_empty() {
        return Err(AppError::bad_request(
            "capabilities must list at least one cx.agent.* action",
        ));
    }
    // Minimal wire-shape check: all entries MUST be in the cx.agent.*
    // namespace per `capability-action-registry.json` (14-action set).
    if let Some(bad) = body
        .capabilities
        .iter()
        .find(|c| !c.starts_with("cx.agent."))
    {
        return Err(AppError::bad_request(format!(
            "capability {bad:?} is not in the cx.agent.* action namespace"
        )));
    }

    let issued_at = Utc::now();
    let accountability_grant_id =
        AccountabilityGrantId::new(new_prefixed_uuid7("cx:accountability_grant:"))
            .map_err(|err| AppError::internal_box(Box::new(err)))?;

    // TODO(P2-impl): persist the grant.
    //
    //   - append an admin-operation audit-log row (resource_type:
    //     "agent", resource_id: <agent_principal_id>, operation:
    //     "accountability_grant_issued") whose `details` JSON is the
    //     canonical wire form of the response below;
    //   - fan-out to soland over the existing principal-server HTTP
    //     binding so soland's reducer can stamp `cx.capability.grant`
    //     events with the agent_principal_id target;
    //   - maintain a revocation index so a controller-side pause /
    //     deactivate event automatically revokes the grant.
    //
    // For Phase P2 the wire response is canonical and soland can begin
    // testing against it; persistence lands in the follow-up CL.

    Ok(CreatedJson(AccountabilityGrantResponse {
        accountability_grant_id: accountability_grant_id.into_string(),
        agent_principal_id: agent_principal_id.into_string(),
        controller_did,
        capabilities: body.capabilities,
        reason: body.reason,
        issued_at,
    }))
}

/// Reject any caller that isn't soland / sodmin (no browser session, no
/// end-user bearer). The single accepted credential is the static
/// bearer configured under
/// `contrix.principal_servers[].session_grant_introspection_bearer` —
/// shared with the existing session-grant introspection path.
fn authn_internal_caller(req: &Request, contrix_config: &ContrixConfig) -> Result<(), AppError> {
    let authorization = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let token = authorization
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            AppError::unauthorized(
                "accountability_grant requires a soland/sodmin Bearer credential",
            )
        })?;

    let accepted = contrix_config.principal_servers.iter().any(|server| {
        server
            .session_grant_introspection_bearer
            .as_deref()
            .is_some_and(|configured| configured == token)
    });
    if !accepted {
        return Err(AppError::forbidden(
            "accountability_grant: caller is not a configured soland/sodmin principal",
        ));
    }

    Ok(())
}
