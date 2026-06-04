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
//! the same trust anchor used elsewhere for server-to-server flows.
//! Browser sessions and end-user OAuth tokens are NOT accepted.
//!
//! Persistence: coauth stores the accountability grant, writes a signed
//! audit row, and queues soland fan-out. soland remains the reducer-side
//! authority for agent lifecycle state.
//!
//! Wire shape: see [`AccountabilityGrantRequest`] and
//! [`AccountabilityGrantResponse`].

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use coauth_config::CokretConfig;
use coauth_data::{
    RepositoryAccess,
    accountability::{
        AccountabilityGrantFanoutState, AccountabilitySubjectKind, NewAccountabilityGrant,
    },
    audit::AdminOperation,
};
use cokret_core::{
    canonical::canonical_sha256,
    error::{
        ERROR_CODE_AGENT_DEACTIVATED, ERROR_CODE_AGENT_PAUSED, ERROR_CODE_PAIRING_REQUEST_EXPIRED,
        ERROR_CODE_PROOF_INVALID, ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        REASON_ACCOUNTABILITY_GRANT_MISSING,
    },
    identifiers::{AccountabilityGrantId, new_prefixed_uuid7},
};
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{DepotExt, make_clock, make_rng};
use crate::{
    AppError, CreatedJsonResult,
    handlers::{
        admin::{CreatedJson, audit_helper::record_service_admin_operation_signed},
        cokret::service_did_for,
    },
    services::did_binding_proof::normalize_did_for_binding,
};

const ACCOUNTABILITY_GRANT_FANOUT_QUEUE: &str = "soland-accountability-grant-fanout";

const AGENT_CAPABILITY_ACTIONS: &[&str] = &[
    "ck.agent.key.authorize",
    "ck.agent.key.revoke",
    "ck.agent.key.rotate",
    "ck.agent.provision",
    "ck.agent.pause",
    "ck.agent.resume",
    "ck.agent.deactivate",
    "ck.agent.draft.propose",
    "ck.agent.action_request",
    "ck.agent.action_approve",
    "ck.agent.action_reject",
    "ck.agent.sidecar_thread.ensure",
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

/// Request body for `POST /_cokret/self/agents/{id}/accountability-grant`.
#[derive(Deserialize, JsonSchema, ToSchema)]
pub struct AccountabilityGrantRequest {
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

/// Response payload for `POST /_cokret/self/agents/{id}/accountability-grant`.
///
/// CKP-0008 (`id-kind-registry.json`): the wire shape carries the
/// freshly minted `ck:accountability_grant:<uuid7>` typed id, the
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
pub struct AccountabilityGrantResponse {
    /// Typed id of the issued grant. Wire form:
    /// `ck:accountability_grant:<uuid7>`.
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

/// `POST /_cokret/self/agents/{id}/accountability-grant`
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
) -> CreatedJsonResult<AccountabilityGrantResponse> {
    let agent_principal_raw = req
        .param::<String>("id")
        .ok_or_else(|| AppError::bad_request("missing agent principal id"))?;
    let agent_principal_id = normalize_did_for_binding(agent_principal_raw.trim())
        .map_err(|error| AppError::bad_request(format!("agent_principal_id invalid: {error}")))?;

    // soland / sodmin only — reject browser sessions and end-user bearers.
    let cokret_config = depot.cokret_config()?;
    authn_internal_caller(req, &cokret_config)?;

    let body: AccountabilityGrantRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let controller_did = normalize_did_for_binding(&body.controller_did)
        .map_err(|error| AppError::bad_request(format!("controller_did invalid: {error}")))?;

    let capabilities = normalize_capabilities(body.capabilities)?;

    let clock = make_clock();
    let mut rng = make_rng();
    let issued_at = clock.now();
    let accountability_grant_id =
        AccountabilityGrantId::new(new_prefixed_uuid7("ck:accountability_grant:"))
            .map_err(|err| AppError::internal_box(Box::new(err)))?;
    let accountability_grant_id = accountability_grant_id.into_string();
    let response = AccountabilityGrantResponse {
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
    response: &AccountabilityGrantResponse,
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
// AUTH-1: `ck.account.agent_key_pair` error matrix. Before invoking the proof
//         validator, fail-closed DID match →
// `verification_method_principal_mismatch`.         Distinct codes for
// `pairing_request_expired`, `proof_invalid`,         `agent_deactivated`.
// AUTH-2: `ck.account.issue_session_grant` agent branch errors. Emit
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

/// Wire-level rejection reasons for the `ck.account.agent_key_pair` operation
/// and the agent branch of `ck.account.issue_session_grant`. Each variant
/// renders to a canonical error code from
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
    /// `ck.agent.deactivate` FSM transition is terminal so this rejection
    /// is permanent. Renders 403.
    AgentDeactivated,
    /// `agent_paused` — the agent is in the `paused` FSM state. Renders 403.
    /// Also used for AUTH-3 revocation-freshness-window denials: existing
    /// tokens minted before the pause fail closed within
    /// [`PAUSED_REVOCATION_FRESHNESS_WINDOW`].
    AgentPaused,
    /// `accountability_grant_missing` — the controller's accountability
    /// grant covering the requested capability set is absent or expired.
    /// Used on `ck.account.issue_session_grant` (agent branch) and
    /// `ck.agent.provision` / `ck.agent.resume` per
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
            " ck.agent.resume ".to_owned(),
            "ck.agent.provision".to_owned(),
            "ck.agent.resume".to_owned(),
        ])
        .expect("registered actions normalize");
        assert_eq!(
            normalized,
            vec![
                "ck.agent.provision".to_owned(),
                "ck.agent.resume".to_owned()
            ]
        );
    }

    #[test]
    fn capability_digest_is_stable_after_normalization() {
        let left = normalize_capabilities(vec![
            "ck.agent.resume".to_owned(),
            "ck.agent.provision".to_owned(),
        ])
        .unwrap();
        let right = normalize_capabilities(vec![
            " ck.agent.provision ".to_owned(),
            "ck.agent.resume".to_owned(),
            "ck.agent.resume".to_owned(),
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
            .is_some_and(|configured| configured == token)
    });
    if !accepted {
        return Err(AppError::forbidden(
            "accountability_grant: caller is not a configured soland/sodmin principal",
        ));
    }

    Ok(())
}
