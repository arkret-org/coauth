use std::sync::Arc;

use ulid::Ulid;

pub type RiskActionStateServiceHandle = Arc<dyn RiskActionStateService>;

pub trait RiskActionStateService: Send + Sync {
    fn record_id(&self, account_id: Ulid, proposal_id: &str) -> String;
    fn allowed_next_transitions(&self, state: &str) -> Vec<String>;
}

#[derive(Default)]
pub struct AuditLogRiskActionStateService;

impl RiskActionStateService for AuditLogRiskActionStateService {
    fn record_id(&self, account_id: Ulid, proposal_id: &str) -> String {
        format!("risk-action:{account_id}:{proposal_id}")
    }

    fn allowed_next_transitions(&self, state: &str) -> Vec<String> {
        match state {
            "draft" => vec![
                "proposal_approved".to_owned(),
                "proposal_replaced".to_owned(),
                "proposal_cancelled".to_owned(),
            ],
            "approved" => vec![
                "proposal_executed".to_owned(),
                "proposal_rejected".to_owned(),
                "proposal_cancelled".to_owned(),
            ],
            "executed_pending_mutation" => vec![
                "mutation_recorded".to_owned(),
                "mutation_failed".to_owned(),
                "rollback_requested".to_owned(),
            ],
            "mutation_recorded" => vec!["case_closed".to_owned(), "rollback_requested".to_owned()],
            "mutation_failed" => vec![
                "retry_requested".to_owned(),
                "rollback_requested".to_owned(),
            ],
            _ => vec!["proposal_requested".to_owned()],
        }
    }
}

#[must_use]
pub fn default_risk_action_state_service() -> RiskActionStateServiceHandle {
    Arc::new(AuditLogRiskActionStateService)
}
