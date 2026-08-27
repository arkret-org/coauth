//! R3 spec-sync agent auth error matrix and fail-closed enforcement helpers.
//!
//! The wire-level rejection codes and the fail-closed enforcement guards for
//! the `ak.gate.account.command.pair_agent_key.v1` operation and the agent branch
//! of `ak.gate.account.command.issue_session_grant.v1`.
use chrono::{DateTime, Utc};

use crate::AppError;

// ─────────────────────────────────────────────────────────────────────────
// R3 spec-sync (2026-05-27, arkret-spec b47ff6ec) — agent auth error matrix.
//
// AUTH-1: `ak.gate.account.command.pair_agent_key.v1` error matrix. Before invoking the
// proof         validator, fail-closed DID match →
// `verification_method_principal_mismatch`.         Distinct codes for
// `pairing_request_expired`, `proof_invalid`,         `agent_deactivated`.
// AUTH-2: `ak.gate.account.command.issue_session_grant.v1` agent branch errors. Emit
//         `agent_paused`, `agent_deactivated`, `proof_invalid`,
//         `verification_method_principal_mismatch`,
// `accountability_grant_missing`. AUTH-3: Revocation freshness window for
// paused agents — existing tokens must         fail closed within the
// configured window even before reducer         convergence catches up.
//
// Full reducer/persistence wiring is in soland (the principal server is the
// persistence authority). coauth owns the gate endpoints and the wire-level
// error matrix for `agent_key_pair` / the `agent_key_proof` session-grant
// branch, then relies on soland projection state for pairing lifetime, agent
// lifecycle, accepted runtime keys, and accountability-grant coverage.
//
// Session revocation strategy: agent runtime grants are stateless, short-lived
// signed JWTs rather than durable browser-session rows. coauth caps the grant
// TTL to 15 minutes; soland rechecks lifecycle/revocation state at the resource
// edge during the freshness window, and normal projection gates reject after
// convergence. Do not introduce a second coauth-local revocation table without
// changing this strategy explicitly.
// ─────────────────────────────────────────────────────────────────────────

/// Wire-level rejection reasons for the `ak.gate.account.command.pair_agent_key.v1`
/// operation and the agent branch of `ak.gate.account.command.issue_session_grant.v1`.
/// Each variant renders to a canonical error code from
/// `arkret-spec/v1/artifacts/error-code-registry.json` v2026-05-27.
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
    /// `agent_key_authorization_expired` — the referenced
    /// `ak.agent.key.authorize` declared an `expires_at` that has elapsed
    /// (key-management §3.6.1). Strictly distinct from `proof_invalid`: the
    /// proof itself was well-formed and the runtime must prompt the
    /// controller for a same-key re-authorization instead of rebuilding the
    /// proof. Never emitted for non-expiring (absent `expires_at`)
    /// authorizations.
    AgentKeyAuthorizationExpired,
    /// `agent_deactivated` — the target agent has been deactivated; the
    /// `ak.self.agent.deactivate` FSM transition is terminal so this rejection
    /// is permanent. Renders 403.
    AgentDeactivated,
    /// `agent_paused` — the agent is in the `paused` FSM state. Renders 403.
    /// Also used for AUTH-3 revocation-freshness-window denials: existing
    /// tokens minted before the pause fail closed within
    /// [`PAUSED_REVOCATION_FRESHNESS_WINDOW`].
    AgentPaused,
    /// `accountability_grant_missing` — the controller's accountability
    /// relation for this Agent is absent, revoked, or expired.
    /// Used on `ak.gate.account.command.issue_session_grant.v1` (agent branch) and
    /// `ak.self.agent.command.provision.v1` / `ak.self.agent.command.resume.v1` per
    /// `operations↔error mapping` §0.8. It is deliberately not a
    /// `ak.gate.account.command.pair_agent_key.v1` rejection: provisioning already
    /// established the durable accountability event before issuing a pairing
    /// handle.
    AccountabilityGrantMissing,
    /// `agent_requested_scope_commitment_invalid` — verifier-private scope
    /// evidence no longer matches the accepted-at Agent DID commitment.
    AgentRequestedScopeCommitmentInvalid,
    /// Immutable provision ceiling omits a mandatory runtime operation.
    AgentProvisionScopeMigrationRequired,
    /// Accepted Agent key authorization omits a mandatory runtime operation.
    AgentKeyScopeReauthorizationRequired,
    /// Requested/current session omits a mandatory runtime operation.
    AgentSessionScopeRefreshRequired,
    /// `capability_denied` — an active Realm capability grant did not cover
    /// the requested agent session content action or resource selector.
    CapabilityDenied,
    /// `policy_violation` — Realm policy rejected the requested agent session
    /// scope or narrowed it to an empty effective set.
    PolicyViolation,
    /// `policy_unavailable` — coauth could not obtain an authoritative Realm
    /// policy projection for a resource-scoped agent session grant.
    PolicyUnavailable,
}

impl AgentAuthRejection {
    /// Canonical wire-code string from `error-code-registry.json`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::VerificationMethodPrincipalMismatch
            | Self::PairingRequestExpired
            | Self::AgentKeyAuthorizationExpired
            | Self::AgentRequestedScopeCommitmentInvalid
            | Self::AgentProvisionScopeMigrationRequired
            | Self::AgentKeyScopeReauthorizationRequired
            | Self::AgentSessionScopeRefreshRequired
            | Self::AgentDeactivated
            | Self::AgentPaused => arkret_wire::ErrorCode::FAILED_PRECONDITION,
            Self::ProofInvalid => arkret_wire::ErrorCode::SIGNATURE_INVALID,
            // `accountability_grant_missing` is delivered as a
            // `failed_precondition` HTTP rejection with `reason` carrying
            // this canonical string (see operations↔error mapping §0.8).
            Self::AccountabilityGrantMissing => arkret_wire::ErrorCode::FAILED_PRECONDITION,
            Self::CapabilityDenied => arkret_wire::ErrorCode::CAPABILITY_DENIED,
            Self::PolicyViolation => arkret_wire::ErrorCode::POLICY_VIOLATION,
            Self::PolicyUnavailable => arkret_wire::ErrorCode::POLICY_UNAVAILABLE,
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
            | Self::AgentKeyAuthorizationExpired
            | Self::ProofInvalid => http::StatusCode::UNAUTHORIZED,
            Self::AgentRequestedScopeCommitmentInvalid
            | Self::AgentProvisionScopeMigrationRequired
            | Self::AgentKeyScopeReauthorizationRequired
            | Self::AgentSessionScopeRefreshRequired => http::StatusCode::PRECONDITION_FAILED,
            Self::AgentPaused
            | Self::AgentDeactivated
            | Self::CapabilityDenied
            | Self::PolicyViolation => http::StatusCode::FORBIDDEN,
            Self::AccountabilityGrantMissing => http::StatusCode::BAD_REQUEST,
            Self::PolicyUnavailable => http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Build an [`AppError`] whose body carries the canonical wire code.
    /// The handler attaches the rendered code in the error response title
    /// per the rest of the coauth wire surface.
    #[must_use]
    pub fn into_app_error(self) -> AppError {
        let code = self.code();
        let error = match self.http_status() {
            http::StatusCode::UNAUTHORIZED => AppError::unauthorized(code),
            http::StatusCode::FORBIDDEN => AppError::forbidden(code),
            http::StatusCode::BAD_REQUEST => AppError::bad_request(code),
            other => AppError::new(other, code),
        };
        error.with_protocol_code(self.reason_code().unwrap_or(code))
    }

    #[must_use]
    pub fn reason_code(self) -> Option<&'static str> {
        match self {
            Self::VerificationMethodPrincipalMismatch => {
                Some("verification_method_principal_mismatch")
            }
            Self::PairingRequestExpired => Some("pairing_request_expired"),
            Self::AgentKeyAuthorizationExpired => {
                Some(arkret_wire::ReasonCode::AGENT_KEY_AUTHORIZATION_EXPIRED)
            }
            Self::AgentRequestedScopeCommitmentInvalid => {
                Some("agent_requested_scope_commitment_invalid")
            }
            Self::AgentProvisionScopeMigrationRequired => {
                Some(arkret_wire::ReasonCode::AGENT_PROVISION_SCOPE_MIGRATION_REQUIRED)
            }
            Self::AgentKeyScopeReauthorizationRequired => {
                Some(arkret_wire::ReasonCode::AGENT_KEY_SCOPE_REAUTHORIZATION_REQUIRED)
            }
            Self::AgentSessionScopeRefreshRequired => {
                Some(arkret_wire::ReasonCode::AGENT_SESSION_SCOPE_REFRESH_REQUIRED)
            }
            Self::ProofInvalid => Some("proof_invalid"),
            Self::AgentDeactivated => Some("agent_deactivated"),
            Self::AgentPaused => Some("agent_paused"),
            Self::AccountabilityGrantMissing => {
                Some(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)
            }
            Self::CapabilityDenied | Self::PolicyViolation | Self::PolicyUnavailable => None,
        }
    }
}

/// AUTH-3 — revocation freshness window. When an agent is paused, any
/// outstanding session tokens MUST fail closed within this window even
/// before the reducer fan-out catches up. Default 30 s per spec discussion,
/// always bounded by the capped agent-session TTL under the natural-expiry
/// strategy (the full ceiling tunable lives on the deployment config and is
/// surfaced under `ak.profile.agent_runtime.v1` in a follow-up).
// TODO(R3.1): plumb a deployment-config override
// (`arkret.agent_runtime.revocation_freshness_window_seconds`) so SREs
// can dial this in for tighter / looser windows.
pub const PAUSED_REVOCATION_FRESHNESS_WINDOW: chrono::Duration = chrono::Duration::seconds(30);

/// AUTH-1: fail-closed DID match. Returns
/// [`AgentAuthRejection::VerificationMethodPrincipalMismatch`] when the
/// proof's verification_method DID does not exactly equal the agent
/// principal DID derived from the agent_id in the request body.
/// This MUST be invoked **before** the proof validator so a crypto bug
/// can't mask a principal-binding bug.
///
/// `verification_method` is the DID URL extracted from the JWS header (or
/// the embedded `verification_method` claim); `agent_principal_did` is the
/// canonical DID carried by `agent_id`.
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
