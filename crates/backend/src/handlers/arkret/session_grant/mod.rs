mod device_revocation_gate;
mod introspection;
mod issuance;
mod issue;
mod refresh;
mod revoke;
mod session_logout;
mod types;

pub(crate) use arkret_models_identity::SignedSessionGrantClaims;
pub(crate) use device_revocation_gate::acquire_human_device_binding;
pub use introspection::introspect_session_grant;
#[cfg(test)]
pub(crate) use introspection::{introspection_status, session_grant_jwt_digest};
pub(crate) use issuance::{
    commit_session_grant_issuance, issue_recovery_session_grant_for_audience,
    issue_session_grant_for_audience, mint_agent_session_grant, new_session_grant_record,
    persist_session_grant,
};
#[cfg(debug_assertions)]
pub(crate) use issuance::issue_test_session_grant_for_audience;
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
