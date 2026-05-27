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
use contrix_core::{
    error::{
        ERROR_CODE_AGENT_DEACTIVATED, ERROR_CODE_AGENT_PAUSED, ERROR_CODE_PAIRING_REQUEST_EXPIRED,
        ERROR_CODE_PROOF_INVALID, ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        REASON_ACCOUNTABILITY_GRANT_MISSING,
    },
    identifiers::{AccountabilityGrantId, AgentPrincipalId, new_prefixed_uuid7},
};
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

// ─────────────────────────────────────────────────────────────────────────
// R3 spec-sync (2026-05-27, contrix-spec b47ff6ec) — agent auth error matrix.
//
// AUTH-1: `cx.account.agent_key_pair` error matrix. Before invoking the proof
//         validator, fail-closed DID match → `verification_method_principal_mismatch`.
//         Distinct codes for `pairing_request_expired`, `proof_invalid`,
//         `agent_deactivated`.
// AUTH-2: `cx.account.issue_session_grant` agent branch errors. Emit
//         `agent_paused`, `agent_deactivated`, `proof_invalid`,
//         `verification_method_principal_mismatch`, `accountability_grant_missing`.
// AUTH-3: Revocation freshness window for paused agents — existing tokens must
//         fail closed within the configured window even before reducer
//         convergence catches up.
//
// Full reducer/persistence wiring of these endpoints is in soland (the
// principal server is the persistence authority). coauth owns the wire-level
// error matrix exposed by `agent_key_pair` / `issue_session_grant`'s agent
// branch when they front through the OIDC bridge. We expose the canonical
// rejection helpers here so the (future) handler module — landing in R3.1
// alongside the rest of the agent_runtime surface — has a single source of
// truth for the wire codes.
//
// TODO(R3.1): wire up the actual `POST /api/v1/account/agent-key-pair` and
// agent-branch session-grant handlers. The error matrix below is the bound
// surface; the internal lookups (pairing request lifetime, agent state,
// accountability grant existence) are implemented in soland.
// ─────────────────────────────────────────────────────────────────────────

/// Wire-level rejection reasons for the `cx.account.agent_key_pair` operation
/// and the agent branch of `cx.account.issue_session_grant`. Each variant
/// renders to a canonical error code from
/// `contrix-spec/v1/artifacts/error-code-registry.json` v2026-05-27.
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
    /// `cx.agent.deactivate` FSM transition is terminal so this rejection
    /// is permanent. Renders 403.
    AgentDeactivated,
    /// `agent_paused` — the agent is in the `paused` FSM state. Renders 403.
    /// Also used for AUTH-3 revocation-freshness-window denials: existing
    /// tokens minted before the pause fail closed within
    /// [`PAUSED_REVOCATION_FRESHNESS_WINDOW`].
    AgentPaused,
    /// `accountability_grant_missing` — the controller's accountability
    /// grant covering the requested capability set is absent or expired.
    /// Used on `cx.account.issue_session_grant` (agent branch) and
    /// `cx.agent.provision` / `cx.agent.resume` per
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
/// surfaced under `cx.profile.agent_runtime.v1` in a follow-up).
///
// TODO(R3.1): plumb a deployment-config override
// (`contrix.agent_runtime.revocation_freshness_window_seconds`) so SREs
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
/// canonical DID resolved from the agent_principal_id newtype.
pub fn enforce_verification_method_binding(
    verification_method: &str,
    agent_principal_did: &str,
) -> Result<(), AgentAuthRejection> {
    // The verification_method is a DID URL of the form `<did>#<fragment>`.
    // Strip the fragment before comparing to the principal DID.
    let vm_did = verification_method.split('#').next().unwrap_or("");
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
mod agent_auth_error_matrix_tests {
    use super::*;

    #[test]
    fn verification_method_mismatch_fires_before_proof_validator() {
        let agent_did = "did:web:agent.example";
        let bad_vm = "did:web:other.example#key-1";
        let err =
            enforce_verification_method_binding(bad_vm, agent_did).expect_err("must reject");
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
    fn pairing_request_expired_is_401() {
        let err = AgentAuthRejection::PairingRequestExpired;
        assert_eq!(err.code(), "pairing_request_expired");
        assert_eq!(err.http_status(), http::StatusCode::UNAUTHORIZED);
    }
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
