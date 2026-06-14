//! Admin DTOs for the soland applets/agents/directory surfaces.
//!
//! Round-26 introduced a full mutation strand (F1 / F2 / F3) for the
//! applet, agent, and directory admin surfaces. The shared lifecycle is
//! `Pending → Approved → Suspended (soft-revoke) → Revoked (terminal)`,
//! with re-approval allowed from any non-Approved state.
//!
//! The coauth-side shared-crate extraction is complete here; sodmin import
//! cleanup is tracked as the cross-repo pairing item.

use serde::{Deserialize, Serialize};

/// Lifecycle for an applet / agent / directory entry.
///
/// State machine:
///
/// ```text
///     Pending --approve--> Approved --suspend--> Suspended
///       |                    |                     |
///       |                  revoke                approve / revoke
///       v                    v                     v
///    Revoked <-----------------------------+ (terminal)
/// ```
///
/// `Suspended` is a soft-revoke: the registration is temporarily
/// disabled but its identity is preserved so an operator can resume it
/// (re-approve) without re-registration. `Revoked` is terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Suspended,
    Revoked,
}

impl ApprovalStatus {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "Pending",
            ApprovalStatus::Approved => "Approved",
            ApprovalStatus::Suspended => "Suspended",
            ApprovalStatus::Revoked => "Revoked",
        }
    }

    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(ApprovalStatus::Pending),
            "approved" => Some(ApprovalStatus::Approved),
            "suspended" => Some(ApprovalStatus::Suspended),
            "revoked" => Some(ApprovalStatus::Revoked),
            _ => None,
        }
    }

    /// Approve transition is valid from any non-Approved state — Pending,
    /// Suspended (resume), or Revoked (re-instate).
    #[must_use]
    pub fn is_approvable(&self) -> bool {
        matches!(
            self,
            ApprovalStatus::Pending | ApprovalStatus::Suspended | ApprovalStatus::Revoked
        )
    }

    /// Suspend is only valid for Approved entries — Pending hasn't been
    /// approved yet, Suspended is a no-op, Revoked is terminal.
    #[must_use]
    pub fn is_suspendable(&self) -> bool {
        matches!(self, ApprovalStatus::Approved)
    }

    /// Revoke is valid from any non-Revoked state.
    #[must_use]
    pub fn is_revocable(&self) -> bool {
        matches!(
            self,
            ApprovalStatus::Pending | ApprovalStatus::Approved | ApprovalStatus::Suspended
        )
    }
}

/// One row in the soland-side applets admin list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AppletAdminRow {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub owner_did: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub registered_at: Option<String>,
}

impl AppletAdminRow {
    #[must_use]
    pub fn status_typed(&self) -> ApprovalStatus {
        ApprovalStatus::from_wire(&self.status).unwrap_or(ApprovalStatus::Pending)
    }
}

/// One row in the soland-side agents admin list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct AgentAdminRow {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub owner_did: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub registered_at: Option<String>,
}

impl AgentAdminRow {
    #[must_use]
    pub fn status_typed(&self) -> ApprovalStatus {
        ApprovalStatus::from_wire(&self.status).unwrap_or(ApprovalStatus::Pending)
    }
}

/// One row in the soland-side directory admin list (public actor /
/// space discovery directory).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct DirectoryAdminRow {
    #[serde(default)]
    pub entry_id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub owner_did: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub published_at: Option<String>,
}

impl DirectoryAdminRow {
    #[must_use]
    pub fn status_typed(&self) -> ApprovalStatus {
        ApprovalStatus::from_wire(&self.status).unwrap_or(ApprovalStatus::Pending)
    }
}

/// Body for the per-row Approve / Revoke buttons. Same shape across
/// all three admin surfaces; soland keys on the URL path.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ApprovalActionRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_status_round_trip() {
        for (wire, label) in [
            ("pending", "Pending"),
            ("approved", "Approved"),
            ("suspended", "Suspended"),
            ("revoked", "Revoked"),
        ] {
            let s = ApprovalStatus::from_wire(wire).expect("variant");
            assert_eq!(s.label(), label);
        }
        assert!(ApprovalStatus::from_wire("nope").is_none());
    }

    #[test]
    fn approval_status_gates_match_lifecycle() {
        // Approve: valid from anything-but-Approved
        assert!(ApprovalStatus::Pending.is_approvable());
        assert!(ApprovalStatus::Suspended.is_approvable());
        assert!(ApprovalStatus::Revoked.is_approvable());
        assert!(!ApprovalStatus::Approved.is_approvable());

        // Suspend: only valid from Approved (a soft-revoke)
        assert!(ApprovalStatus::Approved.is_suspendable());
        assert!(!ApprovalStatus::Pending.is_suspendable());
        assert!(!ApprovalStatus::Suspended.is_suspendable());
        assert!(!ApprovalStatus::Revoked.is_suspendable());

        // Revoke: valid from anything-but-Revoked
        assert!(ApprovalStatus::Approved.is_revocable());
        assert!(ApprovalStatus::Pending.is_revocable());
        assert!(ApprovalStatus::Suspended.is_revocable());
        assert!(!ApprovalStatus::Revoked.is_revocable());
    }

    #[test]
    fn rows_default_to_pending_on_unknown_status() {
        let r = AppletAdminRow {
            status: "garbage".into(),
            ..Default::default()
        };
        assert_eq!(r.status_typed(), ApprovalStatus::Pending);
        let r = AgentAdminRow {
            status: "approved".into(),
            ..Default::default()
        };
        assert_eq!(r.status_typed(), ApprovalStatus::Approved);
        let r = DirectoryAdminRow {
            status: "revoked".into(),
            ..Default::default()
        };
        assert_eq!(r.status_typed(), ApprovalStatus::Revoked);
    }

    #[test]
    fn action_request_omits_empty_note() {
        let req = ApprovalActionRequestBody { note: None };
        let s = serde_json::to_string(&req).unwrap();
        assert!(!s.contains("note"));
    }
}
