//! Admin DTOs for the coauth admin-bridge discovery surface.
//!
//! Mirrors the wire shape emitted by:
//!
//! - `GET /api/admin/v1/bridge/describe` —
//!   `AdminBridgeDescribeResponse` from
//!   `coauth/crates/backend/src/handlers/admin/v1/accounts.rs`,
//!   bundled with the `AdminBridgeRiskAction*Example` request examples.
//!
//! Round-34 (C34.2): lifted out of the inline
//! `AdminBridgeDescribeResponse` / `AdminBridgeRiskActionExamples` /
//! `AdminBridgeRiskAction{Proposal,Approval,Execute}Example` definitions
//! on the backend and the divergent `CoauthAdminBridgeDescribe` /
//! `CoauthAdminBridgeRiskActionExamples` decoder shims in
//! `sodmin/src/api/coauth.rs`. The sodmin shim collapsed the three
//! example payloads down to opaque `serde_json::Value`, silently dropping
//! the typed structure (`action`, `reason`, `ticket`, `approved_by`,
//! `approval_note`, `execution_note`) that the backend actually emits and
//! that the admin SPA needs to render the example payloads as anything
//! more than a JSON blob in a `<span>`. The shared shape now carries
//! every field, and the sodmin formatter formats the typed shape into
//! the same display string the SPA was rendering before. The example
//! constructors below are intentionally part of the shared crate so the
//! backend OpenAPI surface and admin bridge consumers see the same
//! discovery payload.

use serde::{Deserialize, Serialize};

pub const ADMIN_BRIDGE_CONTRACT: &str = "cx.contract.coauth_admin_bridge.v1";
pub const ADMIN_BRIDGE_VERSION: &str = "0.2.0-durable-proposals";
pub const ADMIN_BRIDGE_API_BASE_PATH: &str = "/api/admin/v1";
pub const ADMIN_BRIDGE_ACCOUNTS_PATH: &str = "/api/admin/v1/accounts";
pub const ADMIN_BRIDGE_ACCOUNT_DETAIL_PATH_TEMPLATE: &str = "/api/admin/v1/accounts/{account_id}";
pub const ADMIN_BRIDGE_ACCOUNT_DIDS_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/dids";
pub const ADMIN_BRIDGE_ACCOUNT_CLAIMS_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/claims";
pub const ADMIN_BRIDGE_ACCOUNT_SESSION_GRANTS_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/session-grants";
pub const ADMIN_BRIDGE_RISK_ACTION_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/risk-action";
pub const ADMIN_BRIDGE_RISK_ACTION_CURRENT_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/risk-action/current";
pub const ADMIN_BRIDGE_RISK_ACTION_HISTORY_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/risk-action/history";
pub const ADMIN_BRIDGE_RISK_ACTION_APPROVE_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/approve";
pub const ADMIN_BRIDGE_RISK_ACTION_EXECUTE_PATH_TEMPLATE: &str =
    "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/execute";
pub const ADMIN_BRIDGE_RISK_ACTION_APPROVAL_MODE: &str = "durable_proposal_required";

/// Discovery response for the coauth admin bridge contract surface.
///
/// Field order mirrors the backend discovery response exactly so any
/// rename/reorder lands in lock-step with the consumer.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminBridgeDescribe {
    /// Scaffold contract identifier for coauth admin integration discovery.
    #[serde(default)]
    pub contract: String,

    /// Scaffold contract version.
    #[serde(default)]
    pub version: String,

    /// Base path for this admin REST surface.
    #[serde(default)]
    pub api_base_path: String,

    /// Collection path for account administration.
    #[serde(default)]
    pub accounts_path: String,

    /// Template path for one account.
    #[serde(default)]
    pub account_detail_path_template: String,

    /// Template path for DID binding inventory.
    #[serde(default)]
    pub account_dids_path_template: String,

    /// Template path for claim inventory.
    #[serde(default)]
    pub account_claims_path_template: String,

    /// Template path for session-grant inventory.
    #[serde(default)]
    pub account_session_grants_path_template: String,

    /// Template path for staging a risk action proposal.
    #[serde(default)]
    pub risk_action_path_template: String,

    /// Template path for current risk-action state.
    #[serde(default)]
    pub risk_action_current_path_template: String,

    /// Template path for risk-action transition history.
    #[serde(default)]
    pub risk_action_history_path_template: String,

    /// Template path for approving a proposal.
    #[serde(default)]
    pub risk_action_approve_path_template: String,

    /// Template path for executing an approved proposal.
    #[serde(default)]
    pub risk_action_execute_path_template: String,

    /// How the current scaffold persists risk-action state.
    #[serde(default)]
    pub risk_action_state_store_kind: String,

    /// Approval mode exposed by the current scaffold.
    #[serde(default)]
    pub risk_action_approval_mode: String,

    /// Machine-readable request examples for the risk-action REST workflow.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(example = admin_bridge_risk_action_examples())
    )]
    pub risk_action_examples: AdminBridgeRiskActionExamples,

    /// Remaining scaffold tasks.
    #[serde(default)]
    pub todos: Vec<String>,
}

/// Bundle of three example payloads — one per risk-action verb.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminBridgeRiskActionExamples {
    /// Example payload for `POST /risk-action`.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(example = admin_bridge_risk_action_proposal_example())
    )]
    pub proposal_request: AdminBridgeRiskActionProposalExample,

    /// Example payload for `POST /risk-action/{proposal_id}/approve`.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(example = admin_bridge_risk_action_approval_example())
    )]
    pub approve_request: AdminBridgeRiskActionApprovalExample,

    /// Example payload for `POST /risk-action/{proposal_id}/execute`.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(example = admin_bridge_risk_action_execute_example())
    )]
    pub execute_request: AdminBridgeRiskActionExecuteExample,
}

/// Example shape for the proposal request body.
///
/// `approved_by` is `Option<String>` to mirror the backend's
/// `Option<&'static str>` — the proposal-stage payload may legitimately
/// omit the approver (it is filled in at the approve stage).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminBridgeRiskActionProposalExample {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub ticket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
}

/// Example shape for the approve request body.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminBridgeRiskActionApprovalExample {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub approved_by: String,
    #[serde(default)]
    pub approval_note: String,
    #[serde(default)]
    pub approval_proof_jws: String,
}

/// Example shape for the execute request body.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AdminBridgeRiskActionExecuteExample {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub execution_note: String,
}

#[must_use]
pub fn admin_bridge_describe(
    risk_action_state_store_kind: impl Into<String>,
) -> AdminBridgeDescribe {
    AdminBridgeDescribe {
        contract: ADMIN_BRIDGE_CONTRACT.to_owned(),
        version: ADMIN_BRIDGE_VERSION.to_owned(),
        api_base_path: ADMIN_BRIDGE_API_BASE_PATH.to_owned(),
        accounts_path: ADMIN_BRIDGE_ACCOUNTS_PATH.to_owned(),
        account_detail_path_template: ADMIN_BRIDGE_ACCOUNT_DETAIL_PATH_TEMPLATE.to_owned(),
        account_dids_path_template: ADMIN_BRIDGE_ACCOUNT_DIDS_PATH_TEMPLATE.to_owned(),
        account_claims_path_template: ADMIN_BRIDGE_ACCOUNT_CLAIMS_PATH_TEMPLATE.to_owned(),
        account_session_grants_path_template: ADMIN_BRIDGE_ACCOUNT_SESSION_GRANTS_PATH_TEMPLATE
            .to_owned(),
        risk_action_path_template: ADMIN_BRIDGE_RISK_ACTION_PATH_TEMPLATE.to_owned(),
        risk_action_current_path_template: ADMIN_BRIDGE_RISK_ACTION_CURRENT_PATH_TEMPLATE
            .to_owned(),
        risk_action_history_path_template: ADMIN_BRIDGE_RISK_ACTION_HISTORY_PATH_TEMPLATE
            .to_owned(),
        risk_action_approve_path_template: ADMIN_BRIDGE_RISK_ACTION_APPROVE_PATH_TEMPLATE
            .to_owned(),
        risk_action_execute_path_template: ADMIN_BRIDGE_RISK_ACTION_EXECUTE_PATH_TEMPLATE
            .to_owned(),
        risk_action_state_store_kind: risk_action_state_store_kind.into(),
        risk_action_approval_mode: ADMIN_BRIDGE_RISK_ACTION_APPROVAL_MODE.to_owned(),
        risk_action_examples: admin_bridge_risk_action_examples(),
        todos: Vec::new(),
    }
}

#[must_use]
pub fn admin_bridge_describe_example() -> AdminBridgeDescribe {
    admin_bridge_describe("pg_risk_action_proposals_with_admin_audit_trail")
}

#[must_use]
pub fn admin_bridge_risk_action_examples() -> AdminBridgeRiskActionExamples {
    AdminBridgeRiskActionExamples {
        proposal_request: admin_bridge_risk_action_proposal_example(),
        approve_request: admin_bridge_risk_action_approval_example(),
        execute_request: admin_bridge_risk_action_execute_example(),
    }
}

#[must_use]
pub fn admin_bridge_risk_action_proposal_example() -> AdminBridgeRiskActionProposalExample {
    AdminBridgeRiskActionProposalExample {
        action: "lock".to_owned(),
        reason: "suspicious session recovery detected".to_owned(),
        ticket: "INC-2026-0504".to_owned(),
        approved_by: None,
    }
}

#[must_use]
pub fn admin_bridge_risk_action_approval_example() -> AdminBridgeRiskActionApprovalExample {
    AdminBridgeRiskActionApprovalExample {
        action: "lock".to_owned(),
        ticket: "INC-2026-0504".to_owned(),
        approved_by: "did:web:admin.example".to_owned(),
        approval_note: "approved for controlled execution".to_owned(),
        approval_proof_jws: "protected..signature".to_owned(),
    }
}

#[must_use]
pub fn admin_bridge_risk_action_execute_example() -> AdminBridgeRiskActionExecuteExample {
    AdminBridgeRiskActionExecuteExample {
        action: "lock".to_owned(),
        ticket: "INC-2026-0504".to_owned(),
        execution_note: "execute via controlled mutation worker".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_default_round_trips_through_serde_json() {
        let d = AdminBridgeDescribe::default();
        let s = serde_json::to_string(&d).unwrap();
        let back: AdminBridgeDescribe = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn describe_decodes_backend_wire_payload() {
        // Mirrors what `accounts::admin_bridge_describe` actually emits.
        let wire = serde_json::to_string(&admin_bridge_describe_example()).unwrap();
        let d: AdminBridgeDescribe = serde_json::from_str(&wire).unwrap();
        assert_eq!(d.contract, ADMIN_BRIDGE_CONTRACT);
        assert_eq!(d.version, ADMIN_BRIDGE_VERSION);
        assert_eq!(
            d.risk_action_state_store_kind,
            "pg_risk_action_proposals_with_admin_audit_trail"
        );
        assert_eq!(d.risk_action_examples.proposal_request.action, "lock");
        assert_eq!(d.risk_action_examples.proposal_request.approved_by, None);
        assert_eq!(
            d.risk_action_examples.approve_request.approved_by,
            "did:web:admin.example"
        );
        assert_eq!(
            d.risk_action_examples.execute_request.execution_note,
            "execute via controlled mutation worker"
        );
        assert!(d.todos.is_empty());
    }

    #[test]
    fn describe_still_decodes_legacy_todo_payload() {
        let wire = r#"{
            "contract": "cx.contract.coauth_admin_bridge.v1",
            "version": "0.2.0-durable-proposals",
            "api_base_path": "/api/admin/v1",
            "accounts_path": "/api/admin/v1/accounts",
            "account_detail_path_template": "/api/admin/v1/accounts/{account_id}",
            "account_dids_path_template": "/api/admin/v1/accounts/{account_id}/dids",
            "account_claims_path_template": "/api/admin/v1/accounts/{account_id}/claims",
            "account_session_grants_path_template": "/api/admin/v1/accounts/{account_id}/session-grants",
            "risk_action_path_template": "/api/admin/v1/accounts/{account_id}/risk-action",
            "risk_action_current_path_template": "/api/admin/v1/accounts/{account_id}/risk-action/current",
            "risk_action_history_path_template": "/api/admin/v1/accounts/{account_id}/risk-action/history",
            "risk_action_approve_path_template": "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/approve",
            "risk_action_execute_path_template": "/api/admin/v1/accounts/{account_id}/risk-action/{proposal_id}/execute",
            "risk_action_state_store_kind": "pg_risk_action_proposals_with_admin_audit_trail",
            "risk_action_approval_mode": "durable_proposal_required",
            "risk_action_examples": {
                "proposal_request": {
                    "action": "lock",
                    "reason": "suspicious session recovery detected",
                    "ticket": "INC-2026-0504",
                    "approved_by": null
                },
                "approve_request": {
                    "action": "lock",
                    "ticket": "INC-2026-0504",
                    "approved_by": "did:web:admin.example",
                    "approval_note": "approved for controlled execution",
                    "approval_proof_jws": "protected..signature"
                },
                "execute_request": {
                    "action": "lock",
                    "ticket": "INC-2026-0504",
                    "execution_note": "execute via controlled mutation worker"
                }
            },
            "todos": ["legacy inline scaffold note"]
        }"#;
        let d: AdminBridgeDescribe = serde_json::from_str(wire).unwrap();
        assert_eq!(d.contract, "cx.contract.coauth_admin_bridge.v1");
        assert_eq!(d.version, "0.2.0-durable-proposals");
        assert_eq!(
            d.risk_action_state_store_kind,
            "pg_risk_action_proposals_with_admin_audit_trail"
        );
        assert_eq!(d.risk_action_examples.proposal_request.action, "lock");
        assert_eq!(d.risk_action_examples.proposal_request.approved_by, None);
        assert_eq!(
            d.risk_action_examples.approve_request.approved_by,
            "did:web:admin.example"
        );
        assert_eq!(
            d.risk_action_examples.approve_request.approval_proof_jws,
            "protected..signature"
        );
        assert_eq!(
            d.risk_action_examples.execute_request.execution_note,
            "execute via controlled mutation worker"
        );
        assert_eq!(d.todos.len(), 1);
    }

    #[test]
    fn proposal_example_omits_approved_by_when_none() {
        let p = AdminBridgeRiskActionProposalExample {
            action: "lock".into(),
            reason: "x".into(),
            ticket: "T".into(),
            approved_by: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(!s.contains("approved_by"));
    }

    #[test]
    fn proposal_example_includes_approved_by_when_some() {
        let p = AdminBridgeRiskActionProposalExample {
            action: "lock".into(),
            reason: "x".into(),
            ticket: "T".into(),
            approved_by: Some("did:web:a".into()),
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"approved_by\":\"did:web:a\""));
    }

    #[test]
    fn examples_default_is_all_empty_strings() {
        let e = AdminBridgeRiskActionExamples::default();
        assert!(e.proposal_request.action.is_empty());
        assert!(e.approve_request.approval_note.is_empty());
        assert!(e.execute_request.execution_note.is_empty());
    }

    #[test]
    fn shared_examples_match_openapi_documentation_values() {
        let e = admin_bridge_risk_action_examples();
        assert_eq!(e.proposal_request.action, "lock");
        assert_eq!(
            e.proposal_request.reason,
            "suspicious session recovery detected"
        );
        assert_eq!(e.proposal_request.ticket, "INC-2026-0504");
        assert_eq!(
            e.approve_request.approval_note,
            "approved for controlled execution"
        );
        assert_eq!(
            e.execute_request.execution_note,
            "execute via controlled mutation worker"
        );
    }
}
