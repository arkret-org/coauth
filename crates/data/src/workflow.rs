use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Ulid;
pub use crate::{pg::workflow::PgWorkflowRepository, storage::workflow::*};

/// A persisted workflow instance coordinating a multi-step business flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowInstance {
    /// Stable unique identifier for the workflow.
    pub id: Ulid,
    /// Application-defined workflow kind, for example `registration`.
    pub workflow_key: String,
    /// Business subject the workflow operates on.
    pub subject: WorkflowSubject,
    /// Actor that created or resumed the workflow.
    pub trigger: WorkflowActor,
    /// Workflow lifecycle status.
    pub status: WorkflowInstanceStatus,
    /// Optional current step key for quick inspection.
    pub current_step_key: Option<String>,
    /// Immutable structured input captured at workflow creation.
    pub input: Value,
    /// Mutable structured context shared across steps.
    pub context: Value,
    /// Optional cross-system correlation key.
    pub correlation_key: Option<String>,
    /// When execution first began.
    pub started_at: Option<DateTime<Utc>>,
    /// When the workflow completed successfully.
    pub completed_at: Option<DateTime<Utc>>,
    /// When the workflow failed terminally.
    pub failed_at: Option<DateTime<Utc>>,
    /// When the workflow was cancelled explicitly.
    pub cancelled_at: Option<DateTime<Utc>>,
    /// When the workflow expires automatically, if applicable.
    pub expires_at: Option<DateTime<Utc>>,
    /// When the workflow record was created.
    pub created_at: DateTime<Utc>,
    /// Last state mutation timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Lifecycle state for a workflow instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowInstanceStatus {
    Pending,
    Active,
    Waiting,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
}

impl WorkflowInstanceStatus {
    /// Returns `true` when the workflow cannot progress without an explicit
    /// state reset.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Expired
        )
    }
}

/// Business subject attached to a workflow instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkflowSubject {
    User {
        user_id: Ulid,
    },
    UserRegistration {
        user_registration_id: Ulid,
    },
    UserRecoverySession {
        user_recovery_session_id: Ulid,
    },
    UserEmailAuthentication {
        user_email_authentication_id: Ulid,
    },
    UserPhoneAuthentication {
        user_phone_authentication_id: Ulid,
    },
    NotificationRequest {
        notification_request_id: Ulid,
    },
    ConnectorProvisioning {
        connector: String,
        external_id: String,
    },
    System {
        subject_key: String,
    },
}

/// Actor recorded against workflow events and audits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkflowActor {
    System,
    Worker {
        worker: String,
    },
    Admin {
        user_id: Ulid,
    },
    User {
        user_id: Ulid,
    },
    External {
        provider: String,
        subject: Option<String>,
    },
}

/// A single executable or informational step inside a workflow instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Stable unique identifier for the step row.
    pub id: Ulid,
    /// Parent workflow instance.
    pub workflow_instance_id: Ulid,
    /// Application-defined step key, for example `verify_email`.
    pub step_key: String,
    /// Stable execution order within the workflow.
    pub sequence: u32,
    /// Step lifecycle state.
    pub status: WorkflowStepStatus,
    /// Optional assignee or execution owner.
    pub assignee: Option<WorkflowAssignee>,
    /// Immutable step input captured at scheduling time.
    pub input: Value,
    /// Structured step output captured on completion.
    pub output: Option<Value>,
    /// Number of times this step has been attempted.
    pub attempt_count: u32,
    /// Optional machine-readable error code from the latest failure.
    pub last_error_code: Option<String>,
    /// Optional human-readable error message from the latest failure.
    pub last_error_message: Option<String>,
    /// When the step became eligible to run.
    pub scheduled_at: Option<DateTime<Utc>>,
    /// When execution started.
    pub started_at: Option<DateTime<Utc>>,
    /// When the step completed successfully.
    pub completed_at: Option<DateTime<Utc>>,
    /// When the step failed terminally or most recently.
    pub failed_at: Option<DateTime<Utc>>,
    /// When the step record was created.
    pub created_at: DateTime<Utc>,
    /// Last step mutation timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Lifecycle state for a workflow step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepStatus {
    Pending,
    Scheduled,
    Running,
    Waiting,
    Succeeded,
    Failed,
    Cancelled,
    Skipped,
}

impl WorkflowStepStatus {
    /// Returns `true` when the step cannot progress without a retry or reset.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Skipped
        )
    }
}

/// Execution owner for a workflow step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkflowAssignee {
    WorkerQueue { queue: String },
    Service { service: String },
    User { user_id: Ulid },
    Admin { user_id: Ulid },
}

/// Immutable event emitted by workflow execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowEvent {
    /// Stable unique identifier for the event.
    pub id: Ulid,
    /// Parent workflow instance.
    pub workflow_instance_id: Ulid,
    /// Related step when the event is step-specific.
    pub workflow_step_id: Option<Ulid>,
    /// Event kind.
    pub kind: WorkflowEventKind,
    /// Actor that triggered the event.
    pub actor: WorkflowActor,
    /// Structured event payload.
    pub payload: Value,
    /// When the event occurred.
    pub occurred_at: DateTime<Utc>,
}

/// Immutable workflow event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowEventKind {
    InstanceCreated,
    InstanceActivated,
    StepScheduled,
    StepStarted,
    StepSucceeded,
    StepFailed,
    StepSkipped,
    WaitingEntered,
    WaitingResolved,
    DeadlineScheduled,
    DeadlineSatisfied,
    DeadlineMissed,
    InstanceSucceeded,
    InstanceFailed,
    InstanceCancelled,
    InstanceExpired,
}

/// A persisted deadline or SLA attached to a workflow or step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowDeadline {
    /// Stable unique identifier for the deadline.
    pub id: Ulid,
    /// Parent workflow instance.
    pub workflow_instance_id: Ulid,
    /// Related step when the deadline is step-specific.
    pub workflow_step_id: Option<Ulid>,
    /// Application-defined deadline key, for example `verify_email_timeout`.
    pub deadline_key: String,
    /// Deadline lifecycle state.
    pub status: WorkflowDeadlineStatus,
    /// Structured metadata for the deadline or timer source.
    pub payload: Value,
    /// When the deadline becomes due.
    pub due_at: DateTime<Utc>,
    /// When the deadline was satisfied normally.
    pub satisfied_at: Option<DateTime<Utc>>,
    /// When the deadline was explicitly cancelled.
    pub cancelled_at: Option<DateTime<Utc>>,
    /// When the deadline record was created.
    pub created_at: DateTime<Utc>,
}

impl WorkflowDeadline {
    /// Returns `true` when the deadline is open and past due.
    #[must_use]
    pub fn is_overdue(&self, now: DateTime<Utc>) -> bool {
        matches!(self.status, WorkflowDeadlineStatus::Open) && self.due_at <= now
    }
}

/// Lifecycle state for a persisted deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowDeadlineStatus {
    Open,
    Satisfied,
    Missed,
    Cancelled,
}

impl WorkflowDeadlineStatus {
    /// Returns `true` when the deadline no longer requires monitoring.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Satisfied | Self::Missed | Self::Cancelled)
    }
}

/// Human/audit-oriented workflow log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowAuditLog {
    /// Stable unique identifier for the audit entry.
    pub id: Ulid,
    /// Parent workflow instance.
    pub workflow_instance_id: Ulid,
    /// Related step when the audit entry is step-specific.
    pub workflow_step_id: Option<Ulid>,
    /// Audit action kind.
    pub action: WorkflowAuditAction,
    /// Actor responsible for the audited action.
    pub actor: WorkflowActor,
    /// Optional human-readable summary.
    pub summary: Option<String>,
    /// Structured audit metadata for debugging and reports.
    pub metadata: Value,
    /// When the action occurred.
    pub occurred_at: DateTime<Utc>,
}

/// Human/audit-oriented action category for workflow logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowAuditAction {
    Created,
    StatusChanged,
    StepRequeued,
    DeadlineAdjusted,
    ManuallyOverridden,
    NotificationScheduled,
    ExternalCallRecorded,
    DataPatched,
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use serde_json::Value;

    use super::{
        WorkflowDeadline, WorkflowDeadlineStatus, WorkflowInstanceStatus, WorkflowStepStatus,
    };

    #[test]
    fn workflow_instance_terminal_states_are_explicit() {
        assert!(!WorkflowInstanceStatus::Pending.is_terminal());
        assert!(!WorkflowInstanceStatus::Active.is_terminal());
        assert!(!WorkflowInstanceStatus::Waiting.is_terminal());
        assert!(WorkflowInstanceStatus::Succeeded.is_terminal());
        assert!(WorkflowInstanceStatus::Failed.is_terminal());
        assert!(WorkflowInstanceStatus::Cancelled.is_terminal());
        assert!(WorkflowInstanceStatus::Expired.is_terminal());
    }

    #[test]
    fn workflow_step_terminal_states_are_explicit() {
        assert!(!WorkflowStepStatus::Pending.is_terminal());
        assert!(!WorkflowStepStatus::Scheduled.is_terminal());
        assert!(!WorkflowStepStatus::Running.is_terminal());
        assert!(!WorkflowStepStatus::Waiting.is_terminal());
        assert!(WorkflowStepStatus::Succeeded.is_terminal());
        assert!(WorkflowStepStatus::Failed.is_terminal());
        assert!(WorkflowStepStatus::Cancelled.is_terminal());
        assert!(WorkflowStepStatus::Skipped.is_terminal());
    }

    #[test]
    fn open_deadline_becomes_overdue_after_due_time() {
        let now = Utc::now();
        let deadline = WorkflowDeadline {
            id: ulid::Ulid::nil(),
            workflow_instance_id: ulid::Ulid::nil(),
            workflow_step_id: None,
            deadline_key: "verify_email_timeout".to_owned(),
            status: WorkflowDeadlineStatus::Open,
            payload: Value::Null,
            due_at: now - Duration::minutes(1),
            satisfied_at: None,
            cancelled_at: None,
            created_at: now - Duration::minutes(5),
        };

        assert!(deadline.is_overdue(now));
        assert!(!WorkflowDeadlineStatus::Open.is_terminal());
        assert!(WorkflowDeadlineStatus::Satisfied.is_terminal());
        assert!(WorkflowDeadlineStatus::Missed.is_terminal());
        assert!(WorkflowDeadlineStatus::Cancelled.is_terminal());
    }
}
