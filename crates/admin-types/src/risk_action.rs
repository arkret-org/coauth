//! Admin risk-action workflow request and read-side shapes.
//!
//! These are the input bodies for the
//! `POST /api/admin/v1/accounts/{id}/risk-action`,
//! `…/risk-action/{proposal_id}/approve`, and `…/{proposal_id}/execute`
//! endpoints, plus the GET-side `current` snapshot and history transition
//! record. They migrated out of
//! `coauth/crates/backend/src/handlers/admin/v1/accounts/risk_action.rs`
//! so that `sodmin` can build the same struct it serializes against the
//! one the backend deserializes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::envelope::Resource;

/// Stage a new risk-action proposal against an account.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema),
    serde(rename = "AccountRiskActionProposalRequest")
)]
pub struct AccountRiskActionProposalRequest {
    /// Risk action to stage for approval: `lock`, `disable`, `erase`, or
    /// `reset_recovery`.
    #[serde(default)]
    pub action: String,

    /// Human reason for the requested action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Optional ticket or incident reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,

    /// Optional approver identifier. Leave empty while the request is still a
    /// draft proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
}

/// Approve a previously staged risk-action proposal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema),
    serde(rename = "AccountRiskActionApprovalRequest")
)]
pub struct AccountRiskActionApprovalRequest {
    /// Risk action being approved.
    #[serde(default)]
    pub action: String,

    /// Optional ticket or incident reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,

    /// Optional approver identifier. If present, the backend requires it to
    /// match the authenticated caller's admin DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,

    /// Human approval note for the scaffold audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_note: Option<String>,

    /// Detached EdDSA JWS over the canonical approval transcript.
    ///
    /// The payload segment MUST be empty (`protected..signature`). The
    /// detached payload is canonical JSON binding
    /// `proposal_id`, `account_id`, `action`, `ticket`, `approval_note`,
    /// and `approved_by`.
    #[serde(default)]
    pub approval_proof_jws: String,
}

/// Execute an approved risk-action proposal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema),
    serde(rename = "AccountRiskActionExecuteRequest")
)]
pub struct AccountRiskActionExecuteRequest {
    /// Risk action being executed.
    #[serde(default)]
    pub action: String,

    /// Optional ticket or incident reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,

    /// Human execution note for the scaffold trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_note: Option<String>,
}

/// Outcome of staging a new risk-action proposal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AccountRiskActionProposalResponse {
    /// Stable persisted state-record identifier for this risk-action state
    /// machine.
    #[serde(default)]
    pub state_record_id: String,

    /// Proposal identifier for tracking and later approval.
    #[serde(default)]
    pub proposal_id: String,

    /// Account targeted by the proposal.
    #[serde(default)]
    pub account_id: String,

    /// Requested action.
    #[serde(default)]
    pub action: String,

    /// Human reason supplied by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Optional ticket or incident reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,

    /// Optional approver identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,

    /// When the proposal was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<DateTime<Utc>>,

    /// Admin identifier that submitted the proposal scaffold, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,

    /// Admin handle that submitted the proposal scaffold, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by_handle: Option<String>,

    /// Previous lifecycle state before this transition.
    #[serde(default)]
    pub previous_state: String,

    /// Proposal state reported by the scaffold contract.
    #[serde(default)]
    pub proposal_state: String,

    /// Monotonic state-machine revision.
    #[serde(default)]
    pub state_revision: u64,

    /// Explicit transition kind written by this scaffold.
    #[serde(default)]
    pub transition_kind: String,

    /// Approval mode expected before executing the real mutation endpoint.
    #[serde(default)]
    pub approval_mode: String,

    /// Allowed next transitions from this proposal state.
    #[serde(default)]
    pub allowed_next_transitions: Vec<String>,

    /// Final execution endpoint that would perform the mutation after approval.
    #[serde(default)]
    pub execution_endpoint: String,

    /// How this scaffold persists the state machine today.
    #[serde(default)]
    pub state_store_kind: String,

    /// Remaining implementation work for this scaffold.
    #[serde(default)]
    pub todo: String,
}

/// Outcome of approving a previously staged risk-action proposal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AccountRiskActionApprovalResponse {
    /// Stable persisted state-record identifier for this risk-action state
    /// machine.
    #[serde(default)]
    pub state_record_id: String,

    /// Proposal identifier being approved.
    #[serde(default)]
    pub proposal_id: String,

    /// Account targeted by the proposal.
    #[serde(default)]
    pub account_id: String,

    /// Approved action.
    #[serde(default)]
    pub action: String,

    /// Optional ticket or incident reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,

    /// Previous lifecycle state before this transition.
    #[serde(default)]
    pub previous_state: String,

    /// Approval state reported by the scaffold contract.
    #[serde(default)]
    pub approval_state: String,

    /// Monotonic state-machine revision.
    #[serde(default)]
    pub state_revision: u64,

    /// Explicit transition kind written by this scaffold.
    #[serde(default)]
    pub transition_kind: String,

    /// When the approval was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,

    /// Admin identifier that approved the proposal, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,

    /// Admin handle that approved the proposal, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by_handle: Option<String>,

    /// Human approval note for the scaffold trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_note: Option<String>,

    /// Final execution endpoint that would perform the mutation after approval.
    #[serde(default)]
    pub execution_endpoint: String,

    /// Allowed next transitions from this approved state.
    #[serde(default)]
    pub allowed_next_transitions: Vec<String>,

    /// How this scaffold persists the state machine today.
    #[serde(default)]
    pub state_store_kind: String,

    /// Remaining implementation work for this scaffold.
    #[serde(default)]
    pub todo: String,
}

/// Current risk-action lifecycle snapshot for one account.
///
/// `recorded_at` is `Option` because an account that has never had a
/// risk-action proposal returns an empty snapshot; clients should treat
/// missing fields as "no transition has been recorded yet".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AccountRiskActionCurrentResponse {
    /// Account targeted by the current risk-action state machine.
    #[serde(default)]
    pub account_id: String,

    /// Stable persisted state-record identifier, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_record_id: Option<String>,

    /// Latest proposal identifier, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,

    /// Latest recorded action, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Current lifecycle state derived from the latest scaffold record.
    #[serde(default)]
    pub lifecycle_state: String,

    /// Latest recorded operation name, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_operation: Option<String>,

    /// Explicit transition kind on the current record, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_kind: Option<String>,

    /// Previous lifecycle state before the current transition, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<String>,

    /// Monotonic state-machine revision, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_revision: Option<u64>,

    /// Allowed next transitions from the current lifecycle state.
    #[serde(default)]
    pub allowed_next_transitions: Vec<String>,

    /// Optional ticket or incident reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,

    /// When the current state record was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<DateTime<Utc>>,

    /// Admin identifier associated with the latest state record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_by: Option<String>,

    /// Admin handle associated with the latest state record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_by_handle: Option<String>,

    /// Execution endpoint referenced by the latest proposal/approval state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_endpoint: Option<String>,

    /// Mutation endpoint referenced by the latest execute state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_endpoint: Option<String>,

    /// How this scaffold persists the state machine today.
    #[serde(default)]
    pub state_store_kind: String,

    /// Remaining implementation work for this scaffold state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub todo: Option<String>,
}

impl Resource for AccountRiskActionCurrentResponse {
    const KIND: &'static str = "account-risk-action-current";
    const PATH: &'static str = "/api/admin/v1/accounts";

    fn id(&self) -> String {
        self.account_id.clone()
    }

    fn path(&self) -> String {
        format!(
            "/api/admin/v1/accounts/{}/risk-action/current",
            self.account_id
        )
    }
}

/// Page of risk-action transitions for an account.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AccountRiskActionHistoryResponse {
    #[serde(default)]
    pub data: Vec<AccountRiskActionTransitionRecord>,
}

/// One persisted entry in the risk-action transition history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AccountRiskActionTransitionRecord {
    /// Account targeted by the persisted transition record.
    #[serde(default)]
    pub account_id: String,

    /// Stable persisted state-record identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_record_id: Option<String>,

    /// Proposal identifier associated with the state machine, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,

    /// Action tracked by the state machine, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Explicit transition kind recorded for this transition.
    #[serde(default)]
    pub transition_kind: String,

    /// Previous lifecycle state before this transition, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<String>,

    /// Lifecycle state after this transition.
    #[serde(default)]
    pub next_state: String,

    /// Monotonic state-machine revision, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_revision: Option<u64>,

    /// Optional ticket or incident reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,

    /// When the transition record was written.
    ///
    /// Wire-side this is always present, but is `Option` here so a
    /// scaffold backend that cannot supply it deserializes cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<DateTime<Utc>>,

    /// Admin identifier associated with the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_by: Option<String>,

    /// Admin handle associated with the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_by_handle: Option<String>,

    /// Execution endpoint referenced by this transition, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_endpoint: Option<String>,

    /// Mutation endpoint referenced by this transition, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_endpoint: Option<String>,

    /// Approval note captured by this transition, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_note: Option<String>,

    /// Execution note captured by this transition, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_note: Option<String>,

    /// How this scaffold persists the state machine today.
    #[serde(default)]
    pub state_store_kind: String,

    /// Remaining implementation work captured on this transition, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub todo: Option<String>,
}
