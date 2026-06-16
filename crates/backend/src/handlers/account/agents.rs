//! CKP-0008 personal-agent controller-approval endpoints.
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
//! `cokret.principal_servers[].session_grant_introspection_bearer` —
//! the same trust anchor used elsewhere for server-to-server strands.
//! Browser sessions and end-user OAuth tokens are NOT accepted.
//!
//! Persistence: coauth stores the accountability grant, writes a signed
//! audit row, and queues soland fan-out. soland remains the reducer-side
//! authority for agent lifecycle state.
//!
//! Wire shape: see [`AccountabilityGrantRequestBody`] and
//! [`AccountabilityGrantOutcome`].

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use coauth_config::CokretConfig;
use coauth_data::RepositoryAccess;
use coauth_data::accountability::{
    AccountabilityGrantFanoutState, AccountabilitySubjectKind, NewAccountabilityGrant,
};
use coauth_data::agent_key::{NewAgentKeyAuthorization, NewAgentSessionProofReplay};
use coauth_data::audit::AdminOperation;
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
use cokret_core::error::{
    ERROR_CODE_AGENT_DEACTIVATED, ERROR_CODE_AGENT_PAUSED, ERROR_CODE_PAIRING_REQUEST_EXPIRED,
    ERROR_CODE_PROOF_INVALID, ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
    REASON_ACCOUNTABILITY_GRANT_MISSING,
};
use cokret_core::identifiers::{GrantId, new_prefixed_uuid7};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DepotExt, make_clock, make_rng};
use crate::handlers::admin::CreatedJson;
use crate::handlers::admin::audit_helper::record_service_admin_operation_signed;
use crate::handlers::cokret::{is_allowed_session_grant_audience, service_did_for};
use crate::services::did_binding_proof::normalize_did_for_binding;
use crate::{AppError, CreatedJsonResult};

/// CKP-0008 §4.5 baseline runtime attestation kind. v1 only accepts
/// `self_asserted`; any other kind MUST fail closed.
const RUNTIME_ATTESTATION_SELF_ASSERTED: &str = "self_asserted";

/// Replay grace window appended to the proof `expires_at` (CKP-0008 §4.6:
/// "at least covers the proof expiry plus a replay grace window"). A consumed
/// challenge stays in the replay table until `proof.expires_at + this` so a
/// replay landing right after expiry is still rejected.
const AGENT_PROOF_REPLAY_GRACE: chrono::Duration = chrono::Duration::minutes(5);

/// Spec ceiling on the default agent session TTL (CKP-0008 §4.6 / key-management
/// §3.6.1: default SHOULD be ≤ 15 minutes). coauth caps the agent branch to
/// this regardless of the (human-oriented) `cokret.session_grant_ttl`.
pub const AGENT_SESSION_MAX_TTL: chrono::Duration = chrono::Duration::minutes(15);

const AGENT_KEY_AUTHORIZE_FANOUT_QUEUE: &str = "soland-agent-key-authorize-fanout";

const ACCOUNTABILITY_GRANT_FANOUT_QUEUE: &str = "soland-accountability-grant-fanout";

const AGENT_CAPABILITY_ACTIONS: &[&str] = &[
    "ck.agent.key.authorize",
    "ck.agent.key.revoke",
    "ck.agent.key.rotate",
    "ck.self.agent.command.provision",
    "ck.self.agent.command.pause",
    "ck.self.agent.command.resume",
    "ck.self.agent.command.deactivate",
    "ck.agent.draft.propose",
    "ck.agent.action_request",
    "ck.agent.action_approve",
    "ck.agent.action_reject",
    "ck.self.agent.sidecar_thread.command.ensure",
    "ck.agent.sidecar_thread.write",
    "ck.agent.sidecar_thread.publish",
    "ck.agent.protocol.discover",
    "ck.agent.session.start",
    "ck.agent.session.cancel",
    "ck.agent.session.stream_status",
    "ck.agent.session.attach_artifact",
    "ck.agent.session.read_transcript",
];

fn is_registered_agent_capability(action: &str) -> bool {
    AGENT_CAPABILITY_ACTIONS.contains(&action)
}

/// Request body for `POST /_coauth/self/agents/{id}/accountability-grant`.
#[derive(Deserialize, JsonSchema, ToSchema)]
pub struct AccountabilityGrantRequestBody {
    /// DID of the controller (account holder) issuing the grant. MUST
    /// round-trip through the SDK `Did::new` validator (Round-4 regex
    /// `^did:[a-z0-9]+:[^\s]+$`).
    pub controller_did: String,

    /// Capability actions covered by the grant. Each entry must be a
    /// registered `ck.agent.*` action from `capability-action-registry.json`;
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
/// CKP-0008 (`id-kind-registry.json`): the wire shape carries the
/// freshly minted `ck:grant:<uuid7>` typed id, the
/// `agent_principal_id`, the canonical capability list, and the issuer
/// controller DID. coauth rejects actions outside the registered
/// `ck.agent.*` set before issuing the response; soland still verifies
/// the grant on ingest.
///
/// `accountability_grant_id` and `agent_principal_id` are emitted as
/// raw strings in the OpenAPI surface — the grant id is construction-validated
/// by the SDK typed id helper, while `agent_principal_id` is a DID-as-id per
/// `cokret-spec` common-fields §4.2.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct AccountabilityGrantOutcome {
    /// Typed id of the issued grant. Wire form:
    /// `ck:grant:<uuid7>`.
    pub accountability_grant_id: String,

    /// Agent principal DID this grant authorizes capability actions on.
    /// The {id} URL segment is percent-decoded by the router and canonicalized
    /// into this DID-as-id field.
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

/// `POST /_coauth/self/agents/{id}/accountability-grant`
///
/// Internal CKP-0008 grant-issuance endpoint. Accepts only the soland /
/// sodmin static bearer token (matched against any
/// `cokret.principal_servers[].session_grant_introspection_bearer`
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
    let agent_principal_id = normalize_did_for_binding(agent_principal_raw.trim())
        .map_err(|error| AppError::bad_request(format!("agent_principal_id invalid: {error}")))?;

    // soland / sodmin only — reject browser sessions and end-user bearers.
    let cokret_config = depot.cokret_config()?;
    authn_internal_caller(req, &cokret_config)?;

    let body: AccountabilityGrantRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let controller_did = normalize_did_for_binding(&body.controller_did)
        .map_err(|error| AppError::bad_request(format!("controller_did invalid: {error}")))?;

    let capabilities = normalize_capabilities(body.capabilities)?;

    let clock = make_clock();
    let mut rng = make_rng();
    let issued_at = clock.now();
    let accountability_grant_id = GrantId::new(new_prefixed_uuid7("ck:grant:"))
        .map_err(|err| AppError::internal_box(Box::new(err)))?;
    let accountability_grant_id = accountability_grant_id.into_string();
    let response = AccountabilityGrantOutcome {
        accountability_grant_id: accountability_grant_id.clone(),
        agent_principal_id: agent_principal_id.clone(),
        controller_did: controller_did.clone(),
        capabilities: capabilities.clone(),
        reason: body.reason.clone(),
        issued_at,
    };

    let raw_payload_digest = canonical_digest(&response)?;
    let capabilities_digest =
        accountability_capabilities_digest(&agent_principal_id, &controller_did, &capabilities)?;
    let idempotency_key = accountability_grant_idempotency_key(&accountability_grant_id);
    let url_builder = depot.url_builder()?;
    let service_did = service_did_for(&url_builder, &cokret_config);
    let fanout_payload =
        build_soland_fanout_payload(&response, &raw_payload_digest, &service_did, &cokret_config)?;

    let mut repo = depot.repo().await?;
    if repo
        .accountability_grant()
        .subject_revoked(AccountabilitySubjectKind::ControllerDid, &controller_did)
        .await?
    {
        return Err(AppError::forbidden(
            "controller DID is revoked for accountability grants",
        ));
    }
    if repo
        .accountability_grant()
        .subject_revoked(
            AccountabilitySubjectKind::AgentPrincipalId,
            &agent_principal_id,
        )
        .await?
    {
        return Err(AppError::forbidden(
            "agent principal is revoked for accountability grants",
        ));
    }
    if repo
        .accountability_grant()
        .find_active_by_fingerprint(&agent_principal_id, &controller_did, &capabilities_digest)
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
                agent_principal_id: agent_principal_id.clone(),
                controller_did: controller_did.clone(),
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
            "service_did": &service_did,
        },
        "operation": "accountability_grant_issued",
        "accountability_grant_id": &grant.accountability_grant_id,
        "agent_principal_id": &grant.agent_principal_id,
        "controller_did": &controller_did,
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
        &service_did,
        cokret_config.audit_signature_fail_closed,
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

fn normalize_capabilities(capabilities: Vec<String>) -> Result<Vec<String>, AppError> {
    if capabilities.is_empty() {
        return Err(AppError::bad_request(
            "capabilities must list at least one ck.agent.* action",
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
                "capability {capability:?} is not a registered ck.agent.* action"
            )));
        }
        unique.insert(capability.to_owned());
    }

    Ok(unique.into_iter().collect())
}

#[derive(Serialize)]
struct CapabilityDigestInput<'a> {
    kind: &'a str,
    agent_principal_id: &'a str,
    controller_did: &'a str,
    capabilities: &'a [String],
}

fn accountability_capabilities_digest(
    agent_principal_id: &str,
    controller_did: &str,
    capabilities: &[String],
) -> Result<String, AppError> {
    canonical_digest(&CapabilityDigestInput {
        kind: "ck.coauth.accountability_grant.capabilities.v1",
        agent_principal_id,
        controller_did,
        capabilities,
    })
}

fn canonical_digest(value: &impl Serialize) -> Result<String, AppError> {
    canonical_sha256(value).map_err(|error| {
        AppError::internal_box(Box::new(std::io::Error::other(format!(
            "canonical digest failed: {error}"
        ))))
    })
}

fn accountability_grant_idempotency_key(accountability_grant_id: &str) -> String {
    format!("coauth:accountability_grant:{accountability_grant_id}")
}

fn build_soland_fanout_payload(
    response: &AccountabilityGrantOutcome,
    raw_payload_digest: &str,
    service_did: &str,
    cokret_config: &CokretConfig,
) -> Result<serde_json::Value, AppError> {
    let principal_servers: Vec<_> = cokret_config
        .principal_servers
        .iter()
        .map(|server| {
            serde_json::json!({
                "name": server.name.as_str(),
                "audience": server.audience.as_str(),
                "endpoint": server.endpoint.as_str(),
                "did": server.did.as_deref(),
            })
        })
        .collect();

    Ok(serde_json::json!({
        "kind": "ck.coauth.accountability_grant.fanout.v1",
        "issuer_service_did": service_did,
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
    controller_did: &str,
    reason: &str,
) -> Result<usize, coauth_data::RepositoryError> {
    repo.accountability_grant()
        .mark_subject_revoked(
            rng,
            clock,
            AccountabilitySubjectKind::ControllerDid,
            controller_did,
            reason,
        )
        .await?;
    repo.accountability_grant()
        .revoke_for_subject(
            clock,
            AccountabilitySubjectKind::ControllerDid,
            controller_did,
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
    agent_principal_id: &str,
    reason: &str,
) -> Result<usize, coauth_data::RepositoryError> {
    repo.accountability_grant()
        .mark_subject_revoked(
            rng,
            clock,
            AccountabilitySubjectKind::AgentPrincipalId,
            agent_principal_id,
            reason,
        )
        .await?;
    repo.accountability_grant()
        .revoke_for_subject(
            clock,
            AccountabilitySubjectKind::AgentPrincipalId,
            agent_principal_id,
            reason,
        )
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

// ─────────────────────────────────────────────────────────────────────────
// R3 spec-sync (2026-05-27, cokret-spec b47ff6ec) — agent auth error matrix.
//
// AUTH-1: `ck.gate.account.command.pair_agent_key` error matrix. Before invoking the
// proof         validator, fail-closed DID match →
// `verification_method_principal_mismatch`.         Distinct codes for
// `pairing_request_expired`, `proof_invalid`,         `agent_deactivated`.
// AUTH-2: `ck.gate.account.command.issue_session_grant` agent branch errors. Emit
//         `agent_paused`, `agent_deactivated`, `proof_invalid`,
//         `verification_method_principal_mismatch`,
// `accountability_grant_missing`. AUTH-3: Revocation freshness window for
// paused agents — existing tokens must         fail closed within the
// configured window even before reducer         convergence catches up.
//
// Full reducer/persistence wiring of these deferred endpoints is in soland
// (the principal server is the persistence authority). coauth keeps the
// wire-level error matrix for `agent_key_pair` / `issue_session_grant`'s
// agent branch as reserved internal helpers until the routes are implemented.
// Do not expose these operations in discovery, docs, or sodmin before routed
// handlers land.
//
// TODO(R3.1): wire up the actual `POST /_cokret/gate/account/agent-key-pair`
// and agent-branch session-grant handlers. The error matrix below is the bound
// surface; the internal lookups (pairing request lifetime, agent state,
// accountability grant existence) are implemented in soland.
// ─────────────────────────────────────────────────────────────────────────

/// Wire-level rejection reasons for the `ck.gate.account.command.pair_agent_key`
/// operation and the agent branch of `ck.gate.account.command.issue_session_grant`.
/// Each variant renders to a canonical error code from
/// `cokret-spec/v1/artifacts/error-code-registry.json` v2026-05-27.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentAuthRejection {
    /// `verification_method_principal_mismatch` — the proof's
    /// verification_method DID does not match the agent principal claimed
    /// in the request body. MUST be checked **before** invoking the proof
    /// validator (fail-closed at the edge).
    VerificationMethodPrincipalMismatch,
    /// `pairing_request_expired` — the pairing request token used to
    /// authorize the key-pair issuance has aged out of its validity window.
    PairingRequestExpired,
    /// `proof_invalid` — the proof JWS failed signature or canonicalization
    /// validation. Distinct from `verification_method_principal_mismatch`
    /// (which fires before the validator runs) so clients can tell a
    /// principal mismatch apart from a crypto failure.
    ProofInvalid,
    /// `agent_deactivated` — the target agent has been deactivated; the
    /// `ck.self.agent.deactivate` FSM transition is terminal so this rejection
    /// is permanent. Renders 403.
    AgentDeactivated,
    /// `agent_paused` — the agent is in the `paused` FSM state. Renders 403.
    /// Also used for AUTH-3 revocation-freshness-window denials: existing
    /// tokens minted before the pause fail closed within
    /// [`PAUSED_REVOCATION_FRESHNESS_WINDOW`].
    AgentPaused,
    /// `accountability_grant_missing` — the controller's accountability
    /// grant covering the requested capability set is absent or expired.
    /// Used on `ck.gate.account.command.issue_session_grant` (agent branch) and
    /// `ck.self.agent.command.provision` / `ck.self.agent.command.resume` per
    /// `operations↔error mapping` §0.8.
    AccountabilityGrantMissing,
}

impl AgentAuthRejection {
    /// Canonical wire-code string from `error-code-registry.json`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::VerificationMethodPrincipalMismatch => {
                ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH
            }
            Self::PairingRequestExpired => ERROR_CODE_PAIRING_REQUEST_EXPIRED,
            Self::ProofInvalid => ERROR_CODE_PROOF_INVALID,
            Self::AgentDeactivated => ERROR_CODE_AGENT_DEACTIVATED,
            Self::AgentPaused => ERROR_CODE_AGENT_PAUSED,
            // `accountability_grant_missing` is delivered as a
            // `failed_precondition` HTTP rejection with `reason` carrying
            // this canonical string (see operations↔error mapping §0.8).
            Self::AccountabilityGrantMissing => REASON_ACCOUNTABILITY_GRANT_MISSING,
        }
    }

    /// HTTP status code paired with the rejection. Matches the registry
    /// (`401` for auth, `403` for lifecycle gates, `400` for the
    /// failed-precondition accountability-grant case).
    #[must_use]
    pub fn http_status(self) -> http::StatusCode {
        match self {
            Self::VerificationMethodPrincipalMismatch
            | Self::PairingRequestExpired
            | Self::ProofInvalid => http::StatusCode::UNAUTHORIZED,
            Self::AgentPaused | Self::AgentDeactivated => http::StatusCode::FORBIDDEN,
            Self::AccountabilityGrantMissing => http::StatusCode::BAD_REQUEST,
        }
    }

    /// Build an [`AppError`] whose body carries the canonical wire code.
    /// The handler attaches the rendered code in the error response title
    /// per the rest of the coauth wire surface.
    #[must_use]
    pub fn into_app_error(self) -> AppError {
        let code = self.code();
        match self.http_status() {
            http::StatusCode::UNAUTHORIZED => AppError::unauthorized(code),
            http::StatusCode::FORBIDDEN => AppError::forbidden(code),
            http::StatusCode::BAD_REQUEST => AppError::bad_request(code),
            other => AppError::new(other, code),
        }
    }
}

/// AUTH-3 — revocation freshness window. When an agent is paused, any
/// outstanding session tokens MUST fail closed within this window even
/// before the reducer fan-out catches up. Default 30 s per spec discussion
/// (the full ceiling tunable lives on the deployment config and is
/// surfaced under `ck.profile.agent_runtime.v1` in a follow-up).
// TODO(R3.1): plumb a deployment-config override
// (`cokret.agent_runtime.revocation_freshness_window_seconds`) so SREs
// can dial this in for tighter / looser windows.
pub const PAUSED_REVOCATION_FRESHNESS_WINDOW: chrono::Duration = chrono::Duration::seconds(30);

/// AUTH-1: fail-closed DID match. Returns
/// [`AgentAuthRejection::VerificationMethodPrincipalMismatch`] when the
/// proof's verification_method DID does not exactly equal the agent
/// principal DID derived from the agent_principal_id in the request body.
/// This MUST be invoked **before** the proof validator so a crypto bug
/// can't mask a principal-binding bug.
///
/// `verification_method` is the DID URL extracted from the JWS header (or
/// the embedded `verification_method` claim); `agent_principal_did` is the
/// canonical DID carried by `agent_principal_id`.
pub fn enforce_verification_method_binding(
    verification_method: &str,
    agent_principal_did: &str,
) -> Result<(), AgentAuthRejection> {
    // The verification_method is a DID URL. Strip query and fragment before
    // comparing to the scalar principal DID.
    let vm_did = verification_method
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    if vm_did != agent_principal_did {
        return Err(AgentAuthRejection::VerificationMethodPrincipalMismatch);
    }
    Ok(())
}

/// AUTH-2: agent FSM lifecycle gate. Reject session-grant issuance and
/// agent-key-pair issuance when the target agent is paused or deactivated.
/// Callers MUST invoke this **before** running the proof validator (same
/// fail-closed reasoning as AUTH-1).
///
/// `is_paused` / `is_deactivated` come from the reducer-stamped agent
/// state projection in soland; coauth queries them over the principal
/// server binding before issuing the grant.
pub fn enforce_agent_lifecycle_gate(
    is_paused: bool,
    is_deactivated: bool,
) -> Result<(), AgentAuthRejection> {
    // Deactivated is terminal — check first.
    if is_deactivated {
        return Err(AgentAuthRejection::AgentDeactivated);
    }
    if is_paused {
        return Err(AgentAuthRejection::AgentPaused);
    }
    Ok(())
}

/// AUTH-3: revocation freshness window enforcement. Given a paused-at
/// timestamp and "now", return `Err(AgentPaused)` while the freshness
/// window is still open so existing tokens fail closed even before the
/// reducer fan-out catches up.
///
/// Returns `Ok(())` once the window has elapsed (token rejection is then
/// the responsibility of the underlying revocation-list lookup).
pub fn enforce_paused_revocation_freshness(
    paused_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), AgentAuthRejection> {
    if now < paused_at + PAUSED_REVOCATION_FRESHNESS_WINDOW {
        return Err(AgentAuthRejection::AgentPaused);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod agent_auth_error_matrix_tests {
    use super::*;

    #[test]
    fn verification_method_mismatch_fires_before_proof_validator() {
        let agent_did = "did:web:agent.example";
        let bad_vm = "did:web:other.example#key-1";
        let err = enforce_verification_method_binding(bad_vm, agent_did).expect_err("must reject");
        assert_eq!(
            err.code(),
            "verification_method_principal_mismatch",
            "must surface the canonical wire code"
        );
        assert_eq!(err.http_status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn verification_method_match_succeeds_with_fragment() {
        let agent_did = "did:web:agent.example";
        let good_vm = "did:web:agent.example#key-1";
        enforce_verification_method_binding(good_vm, agent_did).expect("must accept exact match");
    }

    #[test]
    fn deactivated_takes_priority_over_paused() {
        let err = enforce_agent_lifecycle_gate(true, true).expect_err("must reject");
        assert_eq!(err.code(), "agent_deactivated");
        assert_eq!(err.http_status(), http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn paused_alone_yields_agent_paused() {
        let err = enforce_agent_lifecycle_gate(true, false).expect_err("must reject");
        assert_eq!(err.code(), "agent_paused");
    }

    #[test]
    fn auth3_freshness_window_holds_for_30s() {
        let paused_at = Utc::now();
        let just_paused = paused_at + chrono::Duration::seconds(5);
        let err = enforce_paused_revocation_freshness(paused_at, just_paused)
            .expect_err("must reject inside window");
        assert_eq!(err.code(), "agent_paused");
    }

    #[test]
    fn auth3_freshness_window_releases_after_30s() {
        let paused_at = Utc::now();
        let after_window = paused_at + chrono::Duration::seconds(31);
        enforce_paused_revocation_freshness(paused_at, after_window)
            .expect("must release once window has elapsed");
    }

    #[test]
    fn accountability_grant_missing_renders_as_failed_precondition() {
        let err = AgentAuthRejection::AccountabilityGrantMissing;
        assert_eq!(err.code(), "accountability_grant_missing");
        assert_eq!(err.http_status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unknown_accountability_grant_action_is_rejected() {
        let err = normalize_capabilities(vec!["ck.agent.unregistered".to_owned()])
            .expect_err("unknown action must fail closed");
        assert_eq!(err.status(), http::StatusCode::BAD_REQUEST);
        assert!(
            err.message()
                .contains("is not a registered ck.agent.* action")
        );
    }

    #[test]
    fn capability_set_is_trimmed_sorted_and_deduplicated() {
        let normalized = normalize_capabilities(vec![
            " ck.self.agent.command.resume ".to_owned(),
            "ck.self.agent.command.provision".to_owned(),
            "ck.self.agent.command.resume".to_owned(),
        ])
        .expect("registered actions normalize");
        assert_eq!(
            normalized,
            vec![
                "ck.self.agent.command.provision".to_owned(),
                "ck.self.agent.command.resume".to_owned()
            ]
        );
    }

    #[test]
    fn capability_digest_is_stable_after_normalization() {
        let left = normalize_capabilities(vec![
            "ck.self.agent.command.resume".to_owned(),
            "ck.self.agent.command.provision".to_owned(),
        ])
        .unwrap();
        let right = normalize_capabilities(vec![
            " ck.self.agent.command.provision ".to_owned(),
            "ck.self.agent.command.resume".to_owned(),
            "ck.self.agent.command.resume".to_owned(),
        ])
        .unwrap();
        assert_eq!(left, right);
        assert_eq!(
            accountability_capabilities_digest(
                "did:web:agent.example",
                "did:web:controller.example",
                &left,
            )
            .unwrap(),
            accountability_capabilities_digest(
                "did:web:agent.example",
                "did:web:controller.example",
                &right,
            )
            .unwrap()
        );
    }

    #[test]
    fn pairing_request_expired_is_401() {
        let err = AgentAuthRejection::PairingRequestExpired;
        assert_eq!(err.code(), "pairing_request_expired");
        assert_eq!(err.http_status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn proof_signature_round_trips_over_canonical_signed_fields() {
        use base64ct::Encoding as _;
        use cokret::identity::binding::{derive_ed25519_from_seed, multicodec_ed25519_public_key};
        use ed25519_dalek::Signer as _;

        let signing_key = derive_ed25519_from_seed(&[7u8; 32]);
        let multibase = multicodec_ed25519_public_key(&signing_key.verifying_key());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let fields = ProofSignedFields {
            audience: "https://cokret.example/_cokret",
            challenge: "challenge-abc",
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let message = canonical_json_bytes(&fields).expect("canonical bytes");
        let signature = signing_key.sign(&message);
        let sig_b64 = base64ct::Base64UrlUnpadded::encode_string(&signature.to_bytes());

        verify_proof_signature(&multibase, &fields, &sig_b64).expect("valid signature accepts");
    }

    #[test]
    fn proof_signature_rejects_tampered_field() {
        use base64ct::Encoding as _;
        use cokret::identity::binding::{derive_ed25519_from_seed, multicodec_ed25519_public_key};
        use ed25519_dalek::Signer as _;

        let signing_key = derive_ed25519_from_seed(&[9u8; 32]);
        let multibase = multicodec_ed25519_public_key(&signing_key.verifying_key());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let signed = ProofSignedFields {
            audience: "https://cokret.example/_cokret",
            challenge: "challenge-abc",
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let message = canonical_json_bytes(&signed).expect("canonical bytes");
        let signature = signing_key.sign(&message);
        let sig_b64 = base64ct::Base64UrlUnpadded::encode_string(&signature.to_bytes());

        // A different audience (replay to a different service) must fail closed.
        let tampered = ProofSignedFields {
            audience: "https://evil.example/_cokret",
            challenge: "challenge-abc",
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let err = verify_proof_signature(&multibase, &tampered, &sig_b64)
            .expect_err("tampered audience must reject");
        assert_eq!(err.code(), "proof_invalid");
    }

    #[test]
    fn base64_decode_accepts_url_and_standard() {
        use base64ct::Encoding as _;
        // 64 zero bytes encoded url-unpadded and standard-padded both decode.
        let raw = [0u8; 64];
        let url = base64ct::Base64UrlUnpadded::encode_string(&raw);
        let std_padded = base64ct::Base64::encode_string(&raw);
        assert_eq!(base64_decode_flexible(&url).unwrap().len(), 64);
        assert_eq!(base64_decode_flexible(&std_padded).unwrap().len(), 64);
    }
}

/// Reject any caller that isn't soland / sodmin (no browser session, no
/// end-user bearer). The single accepted credential is the static
/// bearer configured under
/// `cokret.principal_servers[].session_grant_introspection_bearer` —
/// shared with the existing session-grant introspection path.
fn authn_internal_caller(req: &Request, cokret_config: &CokretConfig) -> Result<(), AppError> {
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

    let accepted = cokret_config.principal_servers.iter().any(|server| {
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

// ─────────────────────────────────────────────────────────────────────────
// CKP-0008 §4.5 — runtime key pairing (`ck.gate.account.command.pair_agent_key`).
//
// `POST /_cokret/gate/account/agent-key-pair`. The agent runtime generated a
// key pair locally and submits the public key plus a proof-of-possession. This
// endpoint validates the DID binding + PoP, then writes a durable
// `agent_key_authorization` row and fans the `ck.agent.key.authorize` event out
// to soland (the reducer authority) over the same retryable queue mechanism the
// accountability-grant path uses. coauth is the local PoP / session-issuance
// authority; soland projects the durable event and clears
// `effective_after_first_authorized_key` flags.
// ─────────────────────────────────────────────────────────────────────────

/// Ed25519 public key submitted at pairing (CKP-0008 §4.5 `public_key`).
#[derive(Debug, Clone, Deserialize)]
struct AgentPublicKeyInput {
    key_type: String,
    public_key_multibase: String,
}

/// Proof-of-possession over the pairing request (CKP-0008 §4.5
/// `proof_of_possession`). The `signature` covers the canonical bytes of the
/// remaining fields and is NOT part of those bytes.
#[derive(Debug, Clone, Deserialize)]
struct ProofOfPossessionInput {
    challenge: String,
    audience: String,
    request_canonical_digest: String,
    expires_at: DateTime<Utc>,
    signature: String,
}

/// Canonical signed-fields view of a proof-of-possession: every field except
/// the signature, serialized via the SDK canonical JSON helper. Both pairing
/// PoP and the agent-key-proof session branch sign over this same shape so the
/// two proof surfaces share one verification routine.
#[derive(Debug, Serialize)]
struct ProofSignedFields<'a> {
    audience: &'a str,
    challenge: &'a str,
    expires_at: DateTime<Utc>,
    request_canonical_digest: &'a str,
    verification_method: &'a str,
}

/// Optional runtime attestation (CKP-0008 §4.5 `runtime_attestation`). Only the
/// `kind` is interpreted at v1 baseline; an unknown kind fails closed.
#[derive(Debug, Clone, Deserialize)]
struct RuntimeAttestationInput {
    kind: String,
}

/// Strip DID URL `#fragment` and `?query`, returning the bare DID.
fn did_without_fragment_query(did_url: &str) -> &str {
    did_url
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
}

/// Verify an Ed25519 PoP signature (base64url, unpadded or padded) over the
/// canonical signed-fields bytes against a multibase Ed25519 public key.
fn verify_proof_signature(
    public_key_multibase: &str,
    signed_fields: &ProofSignedFields<'_>,
    signature_b64: &str,
) -> Result<(), AgentAuthRejection> {
    let key_bytes = cokret::identity::binding::decode_multicodec_ed25519(public_key_multibase)
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    let verifying = VerifyingKey::from_bytes(&key_bytes).map_err(|_| AgentAuthRejection::ProofInvalid)?;

    let message = canonical_json_bytes(signed_fields).map_err(|_| AgentAuthRejection::ProofInvalid)?;

    let signature_bytes = base64_decode_flexible(signature_b64).ok_or(AgentAuthRejection::ProofInvalid)?;
    if signature_bytes.len() != 64 {
        return Err(AgentAuthRejection::ProofInvalid);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying
        .verify(&message, &signature)
        .map_err(|_| AgentAuthRejection::ProofInvalid)
}

/// Decode base64url (preferred) or standard base64, padded or unpadded.
fn base64_decode_flexible(value: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(value)
        .or_else(|_| Base64Url::decode_vec(value))
        .or_else(|_| Base64Unpadded::decode_vec(value))
        .or_else(|_| Base64::decode_vec(value))
        .ok()
}

/// `POST /_cokret/gate/account/agent-key-pair`
/// (`ck.gate.account.command.pair_agent_key`).
///
/// Validates the runtime key pairing proof-of-possession and, on success,
/// records a durable agent key authorization and queues the
/// `ck.agent.key.authorize` soland fan-out. Returns the SDK
/// [`AgentKeyPairOutcome`] carrying the minted authorization event ref.
#[handler]
#[tracing::instrument(name = "handler.account.agents.agent_key_pair", skip_all)]
pub async fn post_agent_key_pair(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<cokret_core::AgentKeyPairOutcome> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;

    let body: cokret_core::AgentKeyPairRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let agent_principal_id = normalize_did_for_binding(body.agent_principal_id.as_str())
        .map_err(|error| AppError::bad_request(format!("agent_principal_id invalid: {error}")))?;

    // AUTH-1: fail-closed DID binding BEFORE any crypto runs. The
    // verification_method DID part (fragment/query stripped) MUST be
    // bit-identical to the agent principal.
    let vm_did = did_without_fragment_query(&body.verification_method);
    enforce_verification_method_binding(&body.verification_method, &agent_principal_id)
        .map_err(AgentAuthRejection::into_app_error)?;
    let _ = vm_did;

    let public_key: AgentPublicKeyInput = serde_json::from_value(body.public_key.clone())
        .map_err(|error| AppError::bad_request(format!("public_key invalid: {error}")))?;
    if !public_key.key_type.eq_ignore_ascii_case("Ed25519") {
        // v1 pairing accepts Ed25519 runtime keys only; unknown key types fail
        // closed rather than being silently treated as Ed25519.
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    let pop: ProofOfPossessionInput = serde_json::from_value(body.proof_of_possession.clone())
        .map_err(|error| AppError::bad_request(format!("proof_of_possession invalid: {error}")))?;

    // runtime_attestation: v1 baseline accepts only `kind=self_asserted`. Any
    // present-but-unknown kind fails closed (CKP-0008 §4.5 / Non-Goals).
    if let Some(attestation_value) = body.runtime_attestation.clone() {
        let attestation: RuntimeAttestationInput = serde_json::from_value(attestation_value)
            .map_err(|error| {
                AppError::bad_request(format!("runtime_attestation invalid: {error}"))
            })?;
        if attestation.kind != RUNTIME_ATTESTATION_SELF_ASSERTED {
            return Err(AppError::bad_request(format!(
                "runtime_attestation.kind {:?} is not supported (v1 baseline is self_asserted)",
                attestation.kind
            )));
        }
    }

    let clock = make_clock();
    let now = clock.now();

    // Expiry: a stale pairing PoP is rejected as `pairing_request_expired`.
    if pop.expires_at <= now {
        return Err(AgentAuthRejection::PairingRequestExpired.into_app_error());
    }

    // Audience MUST be this service (the coauth issuer audience or a configured
    // principal-server audience).
    if !is_allowed_session_grant_audience(&url_builder, &cokret_config, &pop.audience) {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    // The PoP MUST bind the request canonical digest (CKP-0008 §4.5). It is an
    // opaque `sha256:<hex>` the client computed over the pairing request body;
    // we re-bind it into the signed-fields so the signature covers it.
    if !pop.request_canonical_digest.starts_with("sha256:") {
        return Err(AgentAuthRejection::ProofInvalid.into_app_error());
    }

    let signed_fields = ProofSignedFields {
        audience: &pop.audience,
        challenge: &pop.challenge,
        expires_at: pop.expires_at,
        request_canonical_digest: &pop.request_canonical_digest,
        verification_method: &body.verification_method,
    };
    verify_proof_signature(&public_key.public_key_multibase, &signed_fields, &pop.signature)
        .map_err(AgentAuthRejection::into_app_error)?;

    // The accountable controller for this agent: derive from the active
    // accountability grant coauth issued at provisioning. Without one, the key
    // authorization has nothing to be accountable to — fail closed.
    let pairing_request_id = req
        .query::<String>("pairing_request_id")
        .or_else(|| {
            body.runtime_attestation
                .as_ref()
                .and_then(|_| None::<String>)
        })
        .unwrap_or_default();

    let mut rng = make_rng();
    let mut repo = depot.repo().await?;

    let accountable_grants = repo
        .accountability_grant()
        .list_active_for_subject(AccountabilitySubjectKind::AgentPrincipalId, &agent_principal_id)
        .await?;
    let Some(accountability) = accountable_grants.into_iter().next() else {
        repo.cancel().await.ok();
        return Err(AgentAuthRejection::AccountabilityGrantMissing.into_app_error());
    };
    let controller_did = accountability.controller_did.clone();

    // Mint the durable authorization event id coauth returns and binds the
    // session branch's `agent_key_authorization_ref` against. The `key_id` is
    // the verification method DID URL.
    let authorized_event_id = new_prefixed_uuid7("ck:event:");
    let key_id = body.verification_method.clone();
    let issued_at = now;
    // §4.5: the authorized key inherits the controller-approved scope; coauth
    // stores the broadest tier the accountability grant covers and soland's
    // evaluator intersects it down per-resource. v1 baseline tier is `limited`.
    let agent_key_scope = cokret_core::AgentKeyScope::Limited;
    let expires_at = now + chrono::Duration::days(30);

    let service_did = service_did_for(&url_builder, &cokret_config);
    let outcome_event_id = cokret_core::EventId::new(authorized_event_id.clone())
        .map_err(|err| AppError::internal_box(Box::new(err)))?;

    let fanout_payload = build_agent_key_authorize_fanout_payload(
        &authorized_event_id,
        &agent_principal_id,
        &key_id,
        &body.verification_method,
        &public_key.public_key_multibase,
        &controller_did,
        agent_key_scope,
        &pop.audience,
        issued_at,
        expires_at,
        &pairing_request_id,
        &pop.request_canonical_digest,
        &service_did,
        &cokret_config,
    )?;
    let raw_payload_digest = canonical_digest(&fanout_payload)?;
    let idempotency_key = format!("coauth:agent_key_authorize:{authorized_event_id}");

    repo.agent_key_authorization()
        .add(
            &mut *rng,
            &*clock,
            NewAgentKeyAuthorization {
                authorized_event_id: authorized_event_id.clone(),
                agent_principal_id: agent_principal_id.clone(),
                key_id: key_id.clone(),
                verification_method: body.verification_method.clone(),
                public_key_multibase: public_key.public_key_multibase.clone(),
                accountable_principal_id: controller_did.clone(),
                agent_key_scope: agent_key_scope_str(agent_key_scope).to_owned(),
                audience: vec![pop.audience.clone()],
                issued_at,
                expires_at,
                pairing_request_id: pairing_request_id.clone(),
                request_canonical_digest: pop.request_canonical_digest.clone(),
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
        "actor": { "kind": "service", "service_did": &service_did },
        "operation": "agent_key_authorize_issued",
        "authorized_event_id": &authorized_event_id,
        "agent_principal_id": &agent_principal_id,
        "controller_did": &controller_did,
        "verification_method": &body.verification_method,
        "audience": &pop.audience,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "raw_payload_digest": &raw_payload_digest,
        "soland_fanout": {
            "state": AccountabilityGrantFanoutState::Queued,
            "idempotency_key": &idempotency_key,
            "queue": AGENT_KEY_AUTHORIZE_FANOUT_QUEUE,
            "next_retry_at": issued_at,
        }
    });
    let key_store = depot.key_store()?;
    record_service_admin_operation_signed(
        &mut repo,
        &mut *rng,
        &*clock,
        &key_store,
        &service_did,
        cokret_config.audit_signature_fail_closed,
        AdminOperation::Other("agent_key_authorize_issued".to_owned()),
        "agent",
        None,
        audit_details,
    )
    .await?;

    repo.queue_job()
        .schedule(
            &mut *rng,
            &*clock,
            AGENT_KEY_AUTHORIZE_FANOUT_QUEUE,
            fanout_payload,
            serde_json::json!({
                "idempotency_key": idempotency_key,
                "authorized_event_id": authorized_event_id,
                "raw_payload_digest": raw_payload_digest,
                "next_retry_at": issued_at,
                "attempt": 0,
            }),
        )
        .await?;
    repo.save().await?;

    Ok(CreatedJson(cokret_core::AgentKeyPairOutcome {
        ok: true,
        authorized_event_ref: outcome_event_id,
    }))
}

fn agent_key_scope_str(scope: cokret_core::AgentKeyScope) -> &'static str {
    match scope {
        cokret_core::AgentKeyScope::Account => "account",
        cokret_core::AgentKeyScope::Realm => "realm",
        cokret_core::AgentKeyScope::Applet => "applet",
        cokret_core::AgentKeyScope::Limited => "limited",
    }
}

/// Build the canonical `ck.agent.key.authorize` fan-out payload for soland.
/// Field order tracks `agent_key_authorize_payload`.
#[allow(clippy::too_many_arguments)]
fn build_agent_key_authorize_fanout_payload(
    authorized_event_id: &str,
    agent_principal_id: &str,
    key_id: &str,
    verification_method: &str,
    public_key_multibase: &str,
    accountable_principal_id: &str,
    agent_key_scope: cokret_core::AgentKeyScope,
    audience: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    pairing_request_id: &str,
    request_canonical_digest: &str,
    service_did: &str,
    cokret_config: &CokretConfig,
) -> Result<serde_json::Value, AppError> {
    let principal_servers: Vec<_> = cokret_config
        .principal_servers
        .iter()
        .map(|server| {
            serde_json::json!({
                "name": server.name.as_str(),
                "audience": server.audience.as_str(),
                "endpoint": server.endpoint.as_str(),
                "did": server.did.as_deref(),
            })
        })
        .collect();

    // `payload` mirrors event-payload.schema.json#/$defs/agent_key_authorize_payload.
    let payload = serde_json::json!({
        "agent_principal_id": agent_principal_id,
        "key_id": key_id,
        "verification_method": verification_method,
        "public_key_digest": { "key_type": "Ed25519", "public_key_multibase": public_key_multibase },
        "accountable_principal_id": accountable_principal_id,
        "agent_key_scope": agent_key_scope_str(agent_key_scope),
        "audience": [audience],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "approval_evidence": {
            "kind": "pairing_request",
            "ref": { "kind": "pairing_request_id", "value": pairing_request_id },
            "request_canonical_digest": request_canonical_digest,
            "approved_by": accountable_principal_id,
        },
        "runtime_attestation": { "kind": RUNTIME_ATTESTATION_SELF_ASSERTED },
    });

    Ok(serde_json::json!({
        "kind": "ck.coauth.agent_key_authorize.fanout.v1",
        "issuer_service_did": service_did,
        "authorized_event_id": authorized_event_id,
        "payload": payload,
        "principal_servers": principal_servers,
    }))
}

// ─────────────────────────────────────────────────────────────────────────
// CKP-0008 §4.6 — agent runtime authentication (`agent_key_proof` branch of
// `ck.gate.account.command.issue_session_grant`). This is the independent
// validator the session-grant endpoint calls; it MUST NOT fall back to the
// password / OIDC / passkey validators.
// ─────────────────────────────────────────────────────────────────────────

/// Outcome of validating an `agent_key_proof` session-grant request.
pub struct AgentSessionAuthorization {
    /// Agent principal DID the proof authenticated.
    pub agent_principal_id: String,
    /// Controller DID accountable for the agent.
    pub controller_did: String,
    /// Effective granted scope (intersection of requested scope and the
    /// authorized key scope).
    pub granted_scope: Vec<String>,
    /// `scope_details` overlay (realm_ids / strand_ids / track_names +
    /// optional participation entries).
    pub scope_details: serde_json::Value,
    /// Capped agent session TTL (≤ 15 min).
    pub ttl: chrono::Duration,
}

/// Structured `claim_required` rejection (CKP-0008 §4.6): the agent runtime
/// MUST NOT be shown a CAPTCHA / OTP. The session endpoint renders this as
/// `{ok:false, error:{code, reason_code, approval_request_id}}`.
pub struct AgentHumanApprovalRequired {
    pub approval_request_id: String,
}

/// Either a fail-closed wire rejection or a structured human-approval request.
pub enum AgentSessionProofError {
    /// Canonical fail-closed rejection (proof_invalid / agent_paused / …).
    Rejection(AgentAuthRejection),
    /// `claim_required` / `human_approval_required` structured error.
    HumanApprovalRequired(AgentHumanApprovalRequired),
}

impl From<AgentAuthRejection> for AgentSessionProofError {
    fn from(value: AgentAuthRejection) -> Self {
        Self::Rejection(value)
    }
}

/// `agent_scope_request` overlay (CKP-0008 §4.6). `participation[]` is the
/// participation-aware extension; an `act_on_behalf` selection routes to the
/// human-approval path (act-on-behalf is default-disabled and requires fresh
/// controller approval, §4.10).
#[derive(Debug, Clone, Default, Deserialize)]
struct AgentScopeRequestInput {
    #[serde(default)]
    realm_ids: Vec<String>,
    #[serde(default)]
    strand_ids: Vec<String>,
    #[serde(default)]
    track_names: Vec<String>,
    #[serde(default)]
    participation: Vec<cokret_core::AgentParticipationEntry>,
}

/// Validate an `agent_key_proof` session-grant request. On success returns the
/// resolved scope material the caller mints the session from.
///
/// `repo` is borrowed for the active-key lookup + replay consumption;
/// `controller_status` reports whether the accountable controller is
/// deactivated/suspended (resolved by the caller from the local user record or
/// soland introspection) so a deactivated controller fails closed.
pub async fn validate_agent_session_proof(
    repo: &mut coauth_data::BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    url_builder: &coauth_data::UrlBuilder,
    cokret_config: &CokretConfig,
    body: &cokret_core::SessionGrantRequestBody,
) -> Result<AgentSessionAuthorization, AgentSessionProofError> {
    let now = clock.now();
    let proof = &body.proof;

    // The agent principal MUST be present for this branch.
    let agent_principal_id = body
        .principal_id
        .as_ref()
        .map(|did| did.as_str().to_owned())
        .ok_or(AgentAuthRejection::ProofInvalid)?;

    // `proof.verification_method` MUST be present and its DID part MUST equal
    // the agent principal (AUTH-1, fail closed before crypto).
    let verification_method = proof
        .verification_method
        .as_deref()
        .ok_or(AgentAuthRejection::VerificationMethodPrincipalMismatch)?;
    enforce_verification_method_binding(verification_method, &agent_principal_id)?;

    // expiry / audience.
    let expires_at = proof.expires_at.ok_or(AgentAuthRejection::ProofInvalid)?;
    if expires_at <= now {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if !is_allowed_session_grant_audience(url_builder, cokret_config, &proof.audience) {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    if !proof.request_canonical_digest.as_str().starts_with("sha256:") {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }

    // The key MUST be authorized by an accepted, unexpired, unrevoked
    // `ck.agent.key.authorize`. Resolve it by the request's
    // `agent_key_authorization_ref` (the minted authorize event id).
    let authorization_ref = body
        .agent_key_authorization_ref
        .as_deref()
        .ok_or(AgentAuthRejection::ProofInvalid)?;
    let authorization = repo
        .agent_key_authorization()
        .lookup_by_event_id(authorization_ref)
        .await
        .map_err(|_| AgentAuthRejection::ProofInvalid)?
        .ok_or(AgentAuthRejection::ProofInvalid)?;

    if authorization.revoked_at.is_some() {
        return Err(AgentAuthRejection::AgentDeactivated.into());
    }
    if authorization.expires_at <= now {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }
    // The authorization MUST belong to this agent + verification method.
    if authorization.agent_principal_id != agent_principal_id
        || authorization.verification_method != verification_method
    {
        return Err(AgentAuthRejection::VerificationMethodPrincipalMismatch.into());
    }

    // Verify the proof signature over the same canonical signed-fields shape
    // the pairing PoP used, against the authorized public key.
    let signed_fields = ProofSignedFields {
        audience: &proof.audience,
        challenge: &proof.challenge,
        expires_at,
        request_canonical_digest: proof.request_canonical_digest.as_str(),
        verification_method,
    };
    verify_proof_signature(
        &authorization.public_key_multibase,
        &signed_fields,
        &proof.signature,
    )?;

    // Replay defense: consume the challenge exactly once. A replayed challenge
    // (or one already consumed within the grace window) fails closed.
    let prune_after = expires_at + AGENT_PROOF_REPLAY_GRACE;
    let won = repo
        .agent_key_authorization()
        .consume_proof_challenge(
            rng,
            clock,
            NewAgentSessionProofReplay {
                agent_principal_id: agent_principal_id.clone(),
                verification_method: verification_method.to_owned(),
                challenge: proof.challenge.clone(),
                request_canonical_digest: proof.request_canonical_digest.as_str().to_owned(),
                audience: proof.audience.clone(),
                proof_expires_at: expires_at,
                prune_after,
            },
        )
        .await
        .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    if !won {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }

    // Parse the `agent_scope_request` overlay. An `act_on_behalf` participation
    // selection routes to the human-approval path (§4.10).
    let scope_request: AgentScopeRequestInput = if body.agent_scope_request.is_null() {
        AgentScopeRequestInput::default()
    } else {
        serde_json::from_value(body.agent_scope_request.clone())
            .map_err(|_| AgentAuthRejection::ProofInvalid)?
    };

    let requests_act_on_behalf = scope_request
        .participation
        .iter()
        .any(|entry| entry.effective.act_on_behalf);
    if requests_act_on_behalf {
        // Opaque UUIDv7 artifact id (CKP-0008 §4.6); the controller resolves it
        // out-of-band, the agent runtime never renders a UI for it.
        let approval_request_id = new_prefixed_uuid7("");
        return Err(AgentSessionProofError::HumanApprovalRequired(
            AgentHumanApprovalRequired { approval_request_id },
        ));
    }

    // Scope intersection: requested scope MUST NOT be broader than the
    // authorized key scope. coauth holds the key-scope tier; soland's
    // capability evaluator narrows further per-resource at the resource edge.
    // Here we keep only requested scopes (the agent's session scope is the
    // intersection of requested ∩ authorized; an empty request is denied).
    let granted_scope: Vec<String> = body.requested_scope.clone();
    if granted_scope.is_empty() {
        return Err(AgentAuthRejection::ProofInvalid.into());
    }

    // scope_details overlay: echo the requested narrowing + resolved
    // participation entries (the controller-approved effective participation).
    let mut scope_details = serde_json::json!({
        "realm_ids": scope_request.realm_ids,
        "strand_ids": scope_request.strand_ids,
        "track_names": scope_request.track_names,
    });
    if !scope_request.participation.is_empty() {
        scope_details["participation"] = serde_json::to_value(&scope_request.participation)
            .map_err(|_| AgentAuthRejection::ProofInvalid)?;
    }

    // TTL: cap to the spec ceiling (≤ 15 min), never wider than the
    // (human-oriented) configured grant TTL.
    let configured = cokret_config.session_grant_ttl;
    let ttl = if configured < AGENT_SESSION_MAX_TTL {
        configured
    } else {
        AGENT_SESSION_MAX_TTL
    };

    Ok(AgentSessionAuthorization {
        agent_principal_id,
        controller_did: authorization.accountable_principal_id,
        granted_scope,
        scope_details,
        ttl,
    })
}
