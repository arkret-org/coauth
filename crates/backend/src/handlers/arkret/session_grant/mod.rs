mod applet_inventory;
mod device_revocation_gate;
mod introspection;
mod issuance;
mod issue;
mod refresh;
mod revoke;
mod session_logout;
mod types;

pub use applet_inventory::applet_delegated_session_inventory;
pub(crate) use arkret_models_identity::SignedSessionGrantClaims;
pub(crate) use device_revocation_gate::acquire_private_current_device_binding;
pub use introspection::introspect_session_grant;
#[cfg(test)]
pub(crate) use introspection::{introspection_status, session_grant_jwt_digest};
#[cfg(debug_assertions)]
pub(crate) use issuance::issue_test_session_grant_for_audience;
pub(crate) use issuance::{
    commit_session_grant_issuance, issue_recovery_session_grant_for_audience,
    issue_session_grant_for_audience, mint_agent_session_grant, new_session_grant_record,
    persist_session_grant,
};
#[cfg(test)]
pub(crate) use issuance::{issue_session_grant, persist_unbound_session_grant};
pub use issue::issue_session_grant_endpoint;
pub(crate) use issue::map_oidc_exchange_error;
pub use refresh::refresh_session_grant;
pub use revoke::revoke_session_grant_endpoint;
pub use session_logout::logout_auth_session;
pub use types::{
    PatchPrimaryHandlePreferenceRequestBody, PrimaryHandlePreferenceOutcome, SessionGrantMaterial,
};
pub(crate) use types::{
    SessionGrantIssuanceSeed, SessionGrantRecord, SessionGrantTarget, account_lifecycle_status,
};

/// Map a stored grant lifecycle onto the wire replay state, or `None` when the
/// grant is still `Active` and therefore has no terminal state to report.
///
/// The `Active` arm is deliberately left to the caller: `issue`/`revoke` reach
/// this code only after an `!= Active` guard and treat it as unreachable, while
/// `refresh`'s ledger outcome can legitimately carry an active predecessor and
/// answers `session_grant_replay_expired` instead. Collapsing the two into one
/// helper would force one of those two behaviours onto the other.
pub(crate) const fn replay_terminal_state(
    state: coauth_data::SessionGrantLifecycleState,
) -> Option<arkret_wire::SessionGrantReplayTerminalState> {
    match state {
        coauth_data::SessionGrantLifecycleState::Revoked => {
            Some(arkret_wire::SessionGrantReplayTerminalState::Revoked)
        }
        coauth_data::SessionGrantLifecycleState::Superseded => {
            Some(arkret_wire::SessionGrantReplayTerminalState::Superseded)
        }
        coauth_data::SessionGrantLifecycleState::Active => None,
    }
}
