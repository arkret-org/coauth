use std::sync::Arc;

use ulid::Ulid;

use crate::AppError;

pub type RiskActionStateServiceHandle = Arc<dyn RiskActionStateService>;

pub trait RiskActionStateService: Send + Sync {
    fn state_store_kind(&self) -> &'static str;
    fn record_id(&self, account_id: Ulid, proposal_id: &str) -> String;
    fn execution_endpoint(&self, action: &str, account_id: Ulid) -> Result<String, AppError>;
    fn allowed_next_transitions(&self, state: &str) -> Vec<String>;
}

#[derive(Default)]
pub struct AuditLogRiskActionStateService;

impl RiskActionStateService for AuditLogRiskActionStateService {
    fn state_store_kind(&self) -> &'static str {
        "admin_audit_persisted_state_machine_scaffold"
    }

    fn record_id(&self, account_id: Ulid, proposal_id: &str) -> String {
        format!("risk-action:{account_id}:{proposal_id}")
    }

    fn execution_endpoint(&self, action: &str, account_id: Ulid) -> Result<String, AppError> {
        let action_path = match action {
            "lock" => "lock",
            "disable" => "disable",
            "erase" => "erase",
            "reset_recovery" => "reset-recovery",
            other => {
                return Err(AppError::bad_request(format!(
                    "Unknown account risk action: {other}"
                )));
            }
        };

        Ok(format!("/api/admin/v1/accounts/{account_id}/{action_path}"))
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
