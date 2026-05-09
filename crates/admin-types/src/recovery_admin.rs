//! Admin DTOs for the soland recovery / restore-ticket surface.
//!
//! Mirrors the wire contracts spoken between sodmin and soland's
//! `recovery_bridge`:
//!
//! - `GET    /api/admin/v1/coauth/recovery-tickets` — paginated list
//!   of active recovery tickets. Status filter is `?status=`.
//! - `GET    /api/admin/v1/coauth/recovery-tickets/{id}` — per-ticket
//!   detail with full timeline + restore-state machine projection.
//! - `POST   /api/admin/v1/coauth/recovery-tickets/{id}/approve`
//! - `POST   /api/admin/v1/coauth/recovery-tickets/{id}/reject`
//! - `POST   /api/admin/v1/coauth/recovery-tickets/{id}/advance`
//! - `POST   /api/admin/v1/coauth/recovery-tickets/{id}/cancel`
//! - `GET    /api/admin/v1/coauth/recovery/audit` — audit-log feed.
//! - `GET    /api/admin/v1/coauth/recovery/describe` — read-only soland
//!   recovery describe surface; coauth's `recovery_bridge` describe is
//!   projected forward.
//!
//! Round-27 migrated these out of `sodmin/src/types/recovery.rs` (where
//! they were flagged `TODO(a0-shared-crate)`) to here so a single
//! `pub use` makes the wire shape rustc-checked across both sides. The
//! sodmin inline copies are intentionally left untouched in this round —
//! sodmin's next round will switch its imports.

use serde::{Deserialize, Serialize};

/// Lifecycle state for a recovery ticket. Mirrors the soland
/// recovery-FSM (`pending` → `approved` → `executor_running` →
/// `complete`) with terminal `cancelled` / `rejected` / `failed`
/// states. Wire format is snake_case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTicketStatus {
    Pending,
    Approved,
    ExecutorRunning,
    Complete,
    Cancelled,
    Rejected,
    Failed,
}

impl RecoveryTicketStatus {
    pub fn label(&self) -> &'static str {
        match self {
            RecoveryTicketStatus::Pending => "Pending",
            RecoveryTicketStatus::Approved => "Approved",
            RecoveryTicketStatus::ExecutorRunning => "Executor running",
            RecoveryTicketStatus::Complete => "Complete",
            RecoveryTicketStatus::Cancelled => "Cancelled",
            RecoveryTicketStatus::Rejected => "Rejected",
            RecoveryTicketStatus::Failed => "Failed",
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(RecoveryTicketStatus::Pending),
            "approved" => Some(RecoveryTicketStatus::Approved),
            "executor_running" | "running" => Some(RecoveryTicketStatus::ExecutorRunning),
            "complete" | "completed" => Some(RecoveryTicketStatus::Complete),
            "cancelled" | "canceled" => Some(RecoveryTicketStatus::Cancelled),
            "rejected" => Some(RecoveryTicketStatus::Rejected),
            "failed" => Some(RecoveryTicketStatus::Failed),
            _ => None,
        }
    }

    /// True if the ticket is in a state where an admin Approve/Reject
    /// transition is meaningful.
    pub fn is_approvable(&self) -> bool {
        matches!(self, RecoveryTicketStatus::Pending)
    }

    /// True if `advance` is meaningful — only when the ticket is past
    /// approval but the executor needs a manual nudge.
    pub fn is_advanceable(&self) -> bool {
        matches!(
            self,
            RecoveryTicketStatus::Approved | RecoveryTicketStatus::ExecutorRunning
        )
    }

    /// True if `cancel` is meaningful — anywhere in the open lifecycle.
    pub fn is_cancellable(&self) -> bool {
        !matches!(
            self,
            RecoveryTicketStatus::Complete
                | RecoveryTicketStatus::Cancelled
                | RecoveryTicketStatus::Rejected
                | RecoveryTicketStatus::Failed
        )
    }

    /// Whether this status is a terminal / closed state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            RecoveryTicketStatus::Complete
                | RecoveryTicketStatus::Cancelled
                | RecoveryTicketStatus::Rejected
                | RecoveryTicketStatus::Failed
        )
    }
}

/// One row in the recovery tickets admin list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryTicket {
    #[serde(default)]
    pub ticket_id: String,
    #[serde(default)]
    pub account_did: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl RecoveryTicket {
    pub fn status_typed(&self) -> RecoveryTicketStatus {
        RecoveryTicketStatus::from_wire(&self.status).unwrap_or(RecoveryTicketStatus::Pending)
    }
}

/// Status timeline entry — soland appends one per state transition
/// during the recovery lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryTimelineEntry {
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub from_status: Option<String>,
    #[serde(default)]
    pub to_status: String,
    #[serde(default)]
    pub actor_did: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Per-ticket detail returned by
/// `GET /api/admin/v1/coauth/recovery-tickets/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryTicketDetail {
    #[serde(flatten, default)]
    pub ticket: RecoveryTicket,
    #[serde(default)]
    pub timeline: Vec<RecoveryTimelineEntry>,
    /// Restore-state-machine view (pending → approved → executor_running
    /// → complete) — separate from the broader status timeline.
    #[serde(default)]
    pub restore_state: Vec<RestoreStateNode>,
}

/// A node in the restore-state machine. The names mirror the
/// `RecoveryTicketStatus` lifecycle but are emitted as a parallel
/// projection so the admin UI can render the linear progress
/// indicator.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RestoreStateNode {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub entered_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl RestoreStateNode {
    pub fn state_typed(&self) -> RecoveryTicketStatus {
        RecoveryTicketStatus::from_wire(&self.state).unwrap_or(RecoveryTicketStatus::Pending)
    }
}

/// Body POSTed to the approve/reject/cancel endpoints. `note` is the
/// admin's free-form comment that gets appended to the audit log.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryActionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One row in the recovery audit log feed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryAuditEntry {
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub ticket_id: Option<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub actor_did: Option<String>,
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Read-only soland recovery describe surface. Mirrors what the
/// `recovery_bridge_panel.rs` already shows for coauth — the sodmin
/// page is just a dedicated route into the same data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryDescribe {
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub recovery_modes: Vec<String>,
    #[serde(default)]
    pub verification_event_kinds: Vec<String>,
    #[serde(default)]
    pub paths: Vec<RecoveryDescribePath>,
}

/// One labeled path entry inside `RecoveryDescribe`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecoveryDescribePath {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_wire_round_trip() {
        for (wire, label) in [
            ("pending", "Pending"),
            ("approved", "Approved"),
            ("executor_running", "Executor running"),
            ("complete", "Complete"),
            ("cancelled", "Cancelled"),
            ("rejected", "Rejected"),
            ("failed", "Failed"),
        ] {
            let s = RecoveryTicketStatus::from_wire(wire).expect("variant");
            assert_eq!(s.label(), label);
        }
        assert!(RecoveryTicketStatus::from_wire("nope").is_none());
        assert_eq!(
            RecoveryTicketStatus::from_wire("running"),
            Some(RecoveryTicketStatus::ExecutorRunning)
        );
        assert_eq!(
            RecoveryTicketStatus::from_wire("completed"),
            Some(RecoveryTicketStatus::Complete)
        );
    }

    #[test]
    fn approve_advance_cancel_gates() {
        assert!(RecoveryTicketStatus::Pending.is_approvable());
        assert!(!RecoveryTicketStatus::Approved.is_approvable());
        assert!(!RecoveryTicketStatus::Complete.is_approvable());

        assert!(RecoveryTicketStatus::Approved.is_advanceable());
        assert!(RecoveryTicketStatus::ExecutorRunning.is_advanceable());
        assert!(!RecoveryTicketStatus::Pending.is_advanceable());
        assert!(!RecoveryTicketStatus::Complete.is_advanceable());

        assert!(RecoveryTicketStatus::Pending.is_cancellable());
        assert!(RecoveryTicketStatus::Approved.is_cancellable());
        assert!(RecoveryTicketStatus::ExecutorRunning.is_cancellable());
        assert!(!RecoveryTicketStatus::Complete.is_cancellable());
        assert!(!RecoveryTicketStatus::Cancelled.is_cancellable());
        assert!(!RecoveryTicketStatus::Failed.is_cancellable());
    }

    #[test]
    fn ticket_status_typed_falls_back_to_pending() {
        let t = RecoveryTicket {
            status: "garbage".into(),
            ..Default::default()
        };
        assert_eq!(t.status_typed(), RecoveryTicketStatus::Pending);
        let t = RecoveryTicket {
            status: "approved".into(),
            ..Default::default()
        };
        assert_eq!(t.status_typed(), RecoveryTicketStatus::Approved);
    }

    #[test]
    fn terminal_states_are_closed() {
        assert!(RecoveryTicketStatus::Complete.is_terminal());
        assert!(RecoveryTicketStatus::Cancelled.is_terminal());
        assert!(RecoveryTicketStatus::Rejected.is_terminal());
        assert!(RecoveryTicketStatus::Failed.is_terminal());
        assert!(!RecoveryTicketStatus::Pending.is_terminal());
        assert!(!RecoveryTicketStatus::Approved.is_terminal());
        assert!(!RecoveryTicketStatus::ExecutorRunning.is_terminal());
    }

    #[test]
    fn restore_state_node_falls_back_to_pending() {
        let n = RestoreStateNode {
            state: "garbage".into(),
            ..Default::default()
        };
        assert_eq!(n.state_typed(), RecoveryTicketStatus::Pending);
        let n = RestoreStateNode {
            state: "executor_running".into(),
            ..Default::default()
        };
        assert_eq!(n.state_typed(), RecoveryTicketStatus::ExecutorRunning);
    }

    #[test]
    fn action_request_omits_empty_note() {
        let req = RecoveryActionRequest { note: None };
        let s = serde_json::to_string(&req).unwrap();
        assert!(!s.contains("note"));

        let req = RecoveryActionRequest {
            note: Some("ack".into()),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"note\":\"ack\""));
    }
}
