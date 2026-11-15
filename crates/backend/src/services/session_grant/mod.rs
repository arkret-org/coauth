//! Opaque credentials and issuer-ledger mutations inside the caller's transaction.
//! HTTP parsing, proof consumption, response rendering and save/cancel stay with
//! the caller. Typed authorization metadata belongs to the SDK.
mod error;
mod issuance;
mod ledger;
mod types;

pub use error::SessionGrantError;
#[cfg(test)]
pub(crate) use issuance::issue_session_grant;
pub(crate) use issuance::{
    issue_recovery_session_grant_for_audience, issue_session_grant_for_audience,
    mint_agent_session_grant,
};
pub(crate) use ledger::{IssuanceCommit, commit_session_grant_issuance, new_session_grant_record};
#[cfg(test)]
pub(crate) use ledger::{persist_session_grant, persist_unbound_session_grant};
pub use types::SessionGrantMaterial;
#[cfg(test)]
pub(crate) use types::TestGrantIssuance;
pub(crate) use types::{
    AgentGrantIssuance, HumanGrantIssuance, RecoveryGrantIssuance, SessionGrantIssuanceSeed,
};
