//! AKP-0008 personal-agent controller-approval endpoints.
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
//! `arkret.principal_servers[].session_grant_introspection_bearer` —
//! the same trust anchor used elsewhere for server-to-server strands.
//! Browser sessions and end-user OAuth tokens are NOT accepted.
//!
//! Persistence: coauth stores the accountability grant, writes a signed
//! audit row, and queues soland fan-out. soland remains the reducer-side
//! authority for agent lifecycle state.
//!
//! Wire shape: see [`AccountabilityGrantRequestBody`] and
//! [`AccountabilityGrantOutcome`].

mod accountability;
mod error_matrix;
mod key_pair;
mod proof;
mod session_proof;

#[cfg(test)]
mod tests;

pub use accountability::{
    AccountabilityGrantOutcome, AccountabilityGrantRequestBody, post_accountability_grant,
    revoke_accountability_grant_by_id, revoke_accountability_grants_for_agent,
    revoke_accountability_grants_for_controller,
};
pub use error_matrix::{
    AgentAuthRejection, PAUSED_REVOCATION_FRESHNESS_WINDOW, enforce_agent_lifecycle_gate,
    enforce_paused_revocation_freshness, enforce_verification_method_binding,
};
pub use key_pair::post_agent_key_pair;
pub use session_proof::{
    AGENT_SESSION_MAX_TTL, AgentSessionAuthorization, AgentSessionProofError,
    enforce_authoritative_agent_lifecycle, enforce_authoritative_pairing_handle,
    validate_agent_session_proof,
};
