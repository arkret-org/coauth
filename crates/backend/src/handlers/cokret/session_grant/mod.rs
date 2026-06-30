mod admin;
mod handle;
mod introspection;
mod issuance;
mod issue;
mod refresh;
mod revoke;
mod session_logout;
mod types;

pub use admin::{list_session_grants, revoke_session_grant};
pub use handle::patch_primary_handle_preference;
pub use introspection::introspect_session_grant;
#[cfg(test)]
pub(crate) use introspection::{introspection_status, session_grant_jwt_hash};
#[cfg(test)]
pub(crate) use issuance::issue_session_grant;
pub(crate) use issuance::{
    issue_session_grant_for_audience, issue_test_session_grant_for_audience,
    mint_agent_session_grant, persist_session_grant, persist_unbound_session_grant,
};
pub use issue::issue_session_grant_endpoint;
pub use refresh::refresh_session_grant;
pub use revoke::revoke_session_grant_endpoint;
pub use session_logout::logout_auth_session;
pub use types::{
    PatchPrimaryHandlePreferenceRequestBody, PrimaryHandlePreferenceOutcome,
    SessionGrantConfirmation, SessionGrantMaterial, SessionGrantPayload,
};
pub(crate) use types::{
    SessionGrantIntrospectionProofClaims, SessionGrantRecord, SessionGrantTarget,
};
