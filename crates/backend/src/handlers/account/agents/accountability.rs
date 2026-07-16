//! AKP-0008 accountability-grant issuance endpoint and grant revocation
//! helpers.
//!
//! When a controller approves provisioning of a native Personal Agent, coauth
//! issues a typed `accountability_grant` credential to soland referencing the
//! agent's principal id and the capability set covered by the grant. soland's
//! reducer is the persistence authority; coauth is only the signed-grant
//! issuer.
//!
//! Wire shape: see [`AccountabilityGrantRequestBody`] and
//! [`AccountabilityGrantOutcome`].

use std::collections::BTreeSet;

use arkret_core::CapabilityActionId;
use arkret_core::identifiers::{GrantId, new_prefixed_uuid7};
use chrono::{DateTime, Utc};
use coauth_config::ArkretConfig;
use coauth_data::RepositoryAccess;
use coauth_data::accountability::{
    AccountabilityGrantFanoutState, AccountabilitySubjectKind, NewAccountabilityGrant,
};
use coauth_data::audit::AdminOperation;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::proof::canonical_digest;
use crate::handlers::account::{DepotExt, make_clock, make_rng};
use crate::handlers::admin::CreatedJson;
use crate::handlers::admin::audit_helper::record_service_admin_operation_signed;
use crate::handlers::arkret::service_id_for;
use crate::services::did_binding_proof::normalize_did_for_binding;
use crate::{AppError, CreatedJsonResult};

const ACCOUNTABILITY_GRANT_FANOUT_QUEUE: &str = "soland-accountability-grant-fanout";

fn is_registered_agent_capability(action: &str) -> bool {
    matches!(
        CapabilityActionId::from_wire(action),
        Some(
            CapabilityActionId::AgentKeyAuthorize
                | CapabilityActionId::AgentKeyRevoke
                | CapabilityActionId::SelfAgentCommandProvision
                | CapabilityActionId::SelfAgentCommandPause
                | CapabilityActionId::SelfAgentCommandResume
                | CapabilityActionId::SelfAgentCommandDeactivate
                | CapabilityActionId::AgentDraftPropose
                | CapabilityActionId::AgentActionRequest
                | CapabilityActionId::AgentActionApprove
                | CapabilityActionId::AgentActionReject
                | CapabilityActionId::SelfAgentSidecarThreadCommandEnsure
                | CapabilityActionId::AgentSidecarThreadWrite
                | CapabilityActionId::AgentSidecarThreadPublish
        )
    )
}

/// Request body for `POST /_coauth/self/agents/{id}/accountability-grant`.
#[derive(Deserialize, JsonSchema, ToSchema)]
pub struct AccountabilityGrantRequestBody {
    /// DID of the controller (account holder) issuing the grant. MUST
    /// round-trip through the SDK `Did::new` validator (Round-4 regex
    /// `^did:[a-z0-9]+:[^\s]+$`).
    pub controller_id: String,

    /// Capability actions covered by the grant. Each entry must be a
    /// registered `ak.agent.*` action from `capability-action-registry.json`;
    /// the agent principal below references the union as a single
    /// accountability grant.
    pub capabilities: Vec<String>,

    /// Optional human-readable reason recorded with the grant for the
    /// audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response payload for `POST /_coauth/self/agents/{id}/accountability-grant`.
///
/// AKP-0008 (`id-kind-registry.json`): the wire shape carries the
/// freshly minted `ak:grant:<uuid7>` typed id, the
/// `agent_id`, the canonical capability list, and the issuer
/// controller DID. coauth rejects actions outside the registered
/// `ak.agent.*` set before issuing the response; soland still verifies
/// the grant on ingest.
///
/// `accountability_grant_id` and `agent_id` are emitted as
/// raw strings in the OpenAPI surface — the grant id is construction-validated
/// by the SDK typed id helper, while `agent_id` is a DID-as-id per
/// `arkret-spec` common-fields §4.2.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountabilityGrantOutcome {
    /// Typed id of the issued grant. Wire form:
    /// `ak:grant:<uuid7>`.
    pub accountability_grant_id: String,

    /// Agent principal DID this grant authorizes capability actions on.
    /// The {id} URL segment is percent-decoded by the router and canonicalized
    /// into this DID-as-id field.
    pub agent_id: String,

    /// Controller DID this grant attributes accountability to.
    pub controller_id: String,

    /// Capability actions covered by this grant.
    pub capabilities: Vec<String>,

    /// Optional human-readable reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Grant issuance timestamp.
    pub issued_at: DateTime<Utc>,
}

/// `POST /_coauth/self/agents/{id}/accountability-grant`
///
/// Internal AKP-0008 grant-issuance endpoint. Accepts only the soland /
/// sodmin static bearer token (matched against any
/// `arkret.principal_servers[].session_grant_introspection_bearer`
/// configured for the deployment); browser sessions and end-user
/// bearers are rejected with 401.
///
/// On success stores and returns a freshly minted `accountability_grant`
/// payload referencing the agent principal id + capability set. The
/// returned payload is canonical and a soland fan-out job is queued for
/// reducer ingestion.
#[endpoint]
#[tracing::instrument(name = "handler.account.agents.accountability_grant", skip_all)]
pub async fn post_accountability_grant(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<AccountabilityGrantOutcome> {
    let agent_principal_raw = req
        .param::<String>("id")
        .ok_or_else(|| AppError::bad_request("missing agent principal id"))?;
    let agent_id = normalize_did_for_binding(agent_principal_raw.trim())
        .map_err(|error| AppError::bad_request(format!("agent_id invalid: {error}")))?;

    // soland / sodmin only — reject browser sessions and end-user bearers.
    let arkret_config = depot.arkret_config()?;
    authn_internal_caller(req, &arkret_config)?;

    let body: AccountabilityGrantRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let controller_id = normalize_did_for_binding(&body.controller_id)
        .map_err(|error| AppError::bad_request(format!("controller_id invalid: {error}")))?;

    let capabilities = normalize_capabilities(body.capabilities)?;

    let clock = make_clock();
    let mut rng = make_rng();
    let issued_at = clock.now();
    let accountability_grant_id = GrantId::new(new_prefixed_uuid7("ak:grant:"))
        .map_err(|err| AppError::internal_box(Box::new(err)))?;
    let accountability_grant_id = accountability_grant_id.into_string();
    let response = AccountabilityGrantOutcome {
        accountability_grant_id: accountability_grant_id.clone(),
        agent_id: agent_id.clone(),
        controller_id: controller_id.clone(),
        capabilities: capabilities.clone(),
        reason: body.reason.clone(),
        issued_at,
    };

    let raw_payload_digest = canonical_digest(&response)?;
    let capabilities_digest =
        accountability_capabilities_digest(&agent_id, &controller_id, &capabilities)?;
    let idempotency_key = accountability_grant_idempotency_key(&accountability_grant_id);
    let service_id = service_id_for(&arkret_config);
    let fanout_payload = build_soland_fanout_payload(
        &response,
        &raw_payload_digest,
        service_id.as_str(),
        &arkret_config,
    )?;

    let mut repo = depot.repo().await?;
    if repo
        .accountability_grant()
        .subject_revoked(AccountabilitySubjectKind::ControllerId, &controller_id)
        .await?
    {
        return Err(AppError::forbidden(
            "controller DID is revoked for accountability grants",
        ));
    }
    if repo
        .accountability_grant()
        .subject_revoked(AccountabilitySubjectKind::AgentId, &agent_id)
        .await?
    {
        return Err(AppError::forbidden(
            "agent principal is revoked for accountability grants",
        ));
    }
    if repo
        .accountability_grant()
        .find_active_by_fingerprint(&agent_id, &controller_id, &capabilities_digest)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "active accountability grant already exists for this controller, agent, and capability set",
        ));
    }

    let grant = repo
        .accountability_grant()
        .add(
            &mut *rng,
            &*clock,
            NewAccountabilityGrant {
                accountability_grant_id: accountability_grant_id.clone(),
                agent_id: agent_id.clone(),
                controller_id: controller_id.clone(),
                capabilities: capabilities.clone(),
                capabilities_digest,
                reason: body.reason.clone(),
                issued_at,
                raw_payload_digest: raw_payload_digest.clone(),
                soland_fanout_state: AccountabilityGrantFanoutState::Queued,
                soland_fanout_idempotency_key: idempotency_key.clone(),
                soland_fanout_payload: fanout_payload.clone(),
                soland_fanout_attempt: 0,
                soland_fanout_next_retry_at: Some(issued_at),
                soland_fanout_dead_letter_reason: None,
            },
        )
        .await?;

    let audit_details = serde_json::json!({
        "actor": {
            "kind": "service",
            "service_id": &service_id,
        },
        "operation": "accountability_grant_issued",
        "accountability_grant_id": &grant.accountability_grant_id,
        "agent_id": &grant.agent_id,
        "controller_id": &controller_id,
        "capabilities": &capabilities,
        "reason": &grant.reason,
        "issued_at": issued_at,
        "raw_payload_digest": &raw_payload_digest,
        "soland_fanout": {
            "state": grant.soland_fanout_state,
            "idempotency_key": &idempotency_key,
            "queue": ACCOUNTABILITY_GRANT_FANOUT_QUEUE,
            "next_retry_at": issued_at,
        }
    });
    let key_store = depot.key_store()?;
    record_service_admin_operation_signed(
        &mut repo,
        &mut *rng,
        &*clock,
        &key_store,
        service_id.as_str(),
        arkret_config.audit_signature_fail_closed,
        AdminOperation::Other("accountability_grant_issued".to_owned()),
        "agent",
        None,
        audit_details,
    )
    .await?;

    repo.queue_job()
        .schedule(
            &mut *rng,
            &*clock,
            ACCOUNTABILITY_GRANT_FANOUT_QUEUE,
            fanout_payload,
            serde_json::json!({
                "idempotency_key": grant.soland_fanout_idempotency_key,
                "accountability_grant_id": grant.accountability_grant_id,
                "raw_payload_digest": grant.raw_payload_digest,
                "next_retry_at": issued_at,
                "attempt": 0,
            }),
        )
        .await?;
    repo.save().await?;

    Ok(CreatedJson(response))
}

pub(super) fn normalize_capabilities(capabilities: Vec<String>) -> Result<Vec<String>, AppError> {
    if capabilities.is_empty() {
        return Err(AppError::bad_request(
            "capabilities must list at least one ak.agent.* action",
        ));
    }

    let mut unique = BTreeSet::new();
    for raw in capabilities {
        let capability = raw.trim();
        if capability.is_empty() {
            return Err(AppError::bad_request(
                "capabilities must not contain empty actions",
            ));
        }
        if !is_registered_agent_capability(capability) {
            return Err(AppError::bad_request(format!(
                "capability {capability:?} is not a registered ak.agent.* action"
            )));
        }
        unique.insert(capability.to_owned());
    }

    Ok(unique.into_iter().collect())
}

#[derive(Serialize)]
struct CapabilityDigestInput<'a> {
    kind: &'a str,
    agent_id: &'a str,
    controller_id: &'a str,
    capabilities: &'a [String],
}

pub(super) fn accountability_capabilities_digest(
    agent_id: &str,
    controller_id: &str,
    capabilities: &[String],
) -> Result<String, AppError> {
    canonical_digest(&CapabilityDigestInput {
        kind: "org.arkret.coauth.accountability_grant.capabilities.v1",
        agent_id,
        controller_id,
        capabilities,
    })
}

fn accountability_grant_idempotency_key(accountability_grant_id: &str) -> String {
    format!("coauth:accountability_grant:{accountability_grant_id}")
}

fn build_soland_fanout_payload(
    response: &AccountabilityGrantOutcome,
    raw_payload_digest: &str,
    service_id: &str,
    arkret_config: &ArkretConfig,
) -> Result<serde_json::Value, AppError> {
    let principal_servers: Vec<_> = arkret_config
        .principal_servers
        .iter()
        .map(|server| {
            let service_id =
                crate::services::resolved_principal_audiences::effective_audience_shared(server);
            serde_json::json!({
                "name": server.name.as_str(),
                "audience": service_id.clone(),
                "endpoint": server.endpoint.as_str(),
                "did": service_id,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "kind": "org.arkret.coauth.accountability_grant.fanout.v1",
        "issuer_service_id": service_id,
        "raw_payload_digest": raw_payload_digest,
        "grant": response,
        "principal_servers": principal_servers,
    }))
}

/// Revoke all active accountability grants for a controller DID and mark the
/// subject as blocked for future grant issuance.
pub async fn revoke_accountability_grants_for_controller(
    repo: &mut coauth_data::BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    controller_id: &str,
    reason: &str,
) -> Result<usize, coauth_data::RepositoryError> {
    repo.accountability_grant()
        .mark_subject_revoked(
            rng,
            clock,
            AccountabilitySubjectKind::ControllerId,
            controller_id,
            reason,
        )
        .await?;
    repo.accountability_grant()
        .revoke_for_subject(
            clock,
            AccountabilitySubjectKind::ControllerId,
            controller_id,
            reason,
        )
        .await
}

/// Revoke all active accountability grants for an agent principal and mark the
/// subject as blocked for future grant issuance.
pub async fn revoke_accountability_grants_for_agent(
    repo: &mut coauth_data::BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    agent_id: &str,
    reason: &str,
) -> Result<usize, coauth_data::RepositoryError> {
    repo.accountability_grant()
        .mark_subject_revoked(
            rng,
            clock,
            AccountabilitySubjectKind::AgentId,
            agent_id,
            reason,
        )
        .await?;
    repo.accountability_grant()
        .revoke_for_subject(clock, AccountabilitySubjectKind::AgentId, agent_id, reason)
        .await
}

/// Revoke one accountability grant by its wire typed id.
pub async fn revoke_accountability_grant_by_id(
    repo: &mut coauth_data::BoxRepository,
    clock: &dyn coauth_data::Clock,
    accountability_grant_id: &str,
    reason: &str,
) -> Result<Option<coauth_data::AccountabilityGrant>, coauth_data::RepositoryError> {
    repo.accountability_grant()
        .revoke_by_grant_id(clock, accountability_grant_id, reason)
        .await
}

/// Reject any caller that isn't soland / sodmin (no browser session, no
/// end-user bearer). The single accepted credential is the static
/// bearer configured under
/// `arkret.principal_servers[].session_grant_introspection_bearer` —
/// shared with the existing session-grant introspection path.
fn authn_internal_caller(req: &Request, arkret_config: &ArkretConfig) -> Result<(), AppError> {
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

    let accepted = arkret_config.principal_servers.iter().any(|server| {
        server
            .session_grant_introspection_bearer
            .as_deref()
            .is_some_and(|configured| crate::util::constant_time_token_eq(configured, token))
    });
    if !accepted {
        return Err(AppError::forbidden(
            "accountability_grant: caller is not a configured soland/sodmin principal",
        ));
    }

    Ok(())
}
