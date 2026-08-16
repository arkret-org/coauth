//! Admin DTOs for the coauth admin-bridge discovery surface.
//!
//! Mirrors the wire shape emitted by:
//!
//! - `GET /_coauth/admin/bridge/describe` — `AdminBridgeDescribeResponse` from
//!   `coauth/crates/backend/src/handlers/admin/v1/accounts.rs`, bundled with the
//!   `AdminBridgeRiskAction*Example` request examples.
//!
//! The request examples are typed so the backend OpenAPI surface and
//! sodmin consume the same product contract.

use serde::{Deserialize, Serialize};

pub const ADMIN_BRIDGE_CONTRACT: &str = "org.arkret.coauth.contract.admin_bridge.v1";
pub const ADMIN_BRIDGE_API_BASE_PATH: &str = "/_coauth/admin";
pub const ADMIN_BRIDGE_ACCOUNTS_PATH: &str = "/_coauth/admin/accounts";
pub const ADMIN_BRIDGE_ACCOUNT_DETAIL_PATH_TEMPLATE: &str = "/_coauth/admin/accounts/{account_id}";
pub const ADMIN_BRIDGE_ACCOUNT_DIDS_PATH_TEMPLATE: &str =
    "/_coauth/admin/accounts/{account_id}/dids";
pub const ADMIN_BRIDGE_ACCOUNT_CLAIMS_PATH_TEMPLATE: &str =
    "/_coauth/admin/accounts/{account_id}/claims";
pub const ADMIN_BRIDGE_RISK_ACTION_PATH_TEMPLATE: &str =
    "/_coauth/admin/accounts/{account_id}/risk-action";
pub const ADMIN_BRIDGE_RISK_ACTION_CURRENT_PATH_TEMPLATE: &str =
    "/_coauth/admin/accounts/{account_id}/risk-action/current";
pub const ADMIN_BRIDGE_RISK_ACTION_HISTORY_PATH_TEMPLATE: &str =
    "/_coauth/admin/accounts/{account_id}/risk-action/history";
pub const ADMIN_BRIDGE_RISK_ACTION_APPROVE_PATH_TEMPLATE: &str =
    "/_coauth/admin/accounts/{account_id}/risk-action/{proposal_id}/approve";
pub const ADMIN_BRIDGE_RISK_ACTION_EXECUTE_PATH_TEMPLATE: &str =
    "/_coauth/admin/accounts/{account_id}/risk-action/{proposal_id}/execute";
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
    /// Contract identifier for coauth admin integration discovery.
    #[serde(default)]
    pub contract: String,

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

    /// Approval mode exposed by the risk-action workflow.
    #[serde(default)]
    pub risk_action_approval_mode: String,

    /// Machine-readable request examples for the risk-action REST workflow.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(example = admin_bridge_risk_action_examples())
    )]
    pub risk_action_examples: AdminBridgeRiskActionExamples,
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
pub fn admin_bridge_describe() -> AdminBridgeDescribe {
    AdminBridgeDescribe {
        contract: ADMIN_BRIDGE_CONTRACT.to_owned(),
        api_base_path: ADMIN_BRIDGE_API_BASE_PATH.to_owned(),
        accounts_path: ADMIN_BRIDGE_ACCOUNTS_PATH.to_owned(),
        account_detail_path_template: ADMIN_BRIDGE_ACCOUNT_DETAIL_PATH_TEMPLATE.to_owned(),
        account_dids_path_template: ADMIN_BRIDGE_ACCOUNT_DIDS_PATH_TEMPLATE.to_owned(),
        account_claims_path_template: ADMIN_BRIDGE_ACCOUNT_CLAIMS_PATH_TEMPLATE.to_owned(),
        risk_action_path_template: ADMIN_BRIDGE_RISK_ACTION_PATH_TEMPLATE.to_owned(),
        risk_action_current_path_template: ADMIN_BRIDGE_RISK_ACTION_CURRENT_PATH_TEMPLATE
            .to_owned(),
        risk_action_history_path_template: ADMIN_BRIDGE_RISK_ACTION_HISTORY_PATH_TEMPLATE
            .to_owned(),
        risk_action_approve_path_template: ADMIN_BRIDGE_RISK_ACTION_APPROVE_PATH_TEMPLATE
            .to_owned(),
        risk_action_execute_path_template: ADMIN_BRIDGE_RISK_ACTION_EXECUTE_PATH_TEMPLATE
            .to_owned(),
        risk_action_approval_mode: ADMIN_BRIDGE_RISK_ACTION_APPROVAL_MODE.to_owned(),
        risk_action_examples: admin_bridge_risk_action_examples(),
    }
}

#[must_use]
pub fn admin_bridge_describe_example() -> AdminBridgeDescribe {
    admin_bridge_describe()
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
