//! Agent controller approval, pairing and session authorization.
//!
//! Client-visible operations use their canonical sender-constrained session
//! contracts. Split Account Authority calls to the owning Station use the
//! Station DID's delegated `#account-authority` RFC 9421 service signature;
//! the deployment bearer remains confined to the owner-current channel
//! registered by `service-http-binding.md` §2.2.3.

mod error_matrix;
mod key_pair;
mod proof;
mod session_proof;

#[cfg(test)]
mod tests;

pub use error_matrix::{
    AgentAuthRejection, PAUSED_REVOCATION_FRESHNESS_WINDOW, enforce_agent_lifecycle_gate,
    enforce_paused_revocation_freshness, enforce_verification_method_binding,
};
pub use key_pair::post_agent_key_pair;
pub use session_proof::{
    AGENT_SESSION_MAX_TTL, AgentSessionAuthorization, AgentSessionProofError,
    enforce_authoritative_agent_lifecycle, enforce_authoritative_pairing_handle,
    fetch_agent_participation_overlay, validate_agent_session_proof,
    validate_agent_session_refresh_proof,
};
