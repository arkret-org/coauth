//! Admin risk-action workflow request shapes.
//!
//! These are the input bodies for the
//! `POST /api/admin/v1/accounts/{id}/risk-action`,
//! `…/risk-action/{proposal_id}/approve`, and `…/{proposal_id}/execute`
//! endpoints. They migrated out of
//! `coauth/crates/backend/src/handlers/admin/v1/accounts/risk_action.rs`
//! so that `sodmin` can build the same struct it serializes against the
//! one the backend deserializes.

use serde::{Deserialize, Serialize};

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

    /// Optional approver identifier override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,

    /// Human approval note for the scaffold audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_note: Option<String>,
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
