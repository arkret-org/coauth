//! R3 spec-sync agent auth error matrix and fail-closed enforcement helpers.
//!
//! The wire-level rejection codes and the fail-closed enforcement guards for
//! the `ck.gate.account.command.pair_agent_key` operation and the agent branch
//! of `ck.gate.account.command.issue_session_grant`.

use chrono::{DateTime, Utc};
use cokret_core::error::{
    ERROR_CODE_AGENT_DEACTIVATED, ERROR_CODE_AGENT_PAUSED, ERROR_CODE_PAIRING_REQUEST_EXPIRED,
    ERROR_CODE_PROOF_INVALID, ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
    REASON_ACCOUNTABILITY_GRANT_MISSING,
};

use crate::AppError;

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
