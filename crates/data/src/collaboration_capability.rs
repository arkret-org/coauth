//! Durable collaboration capability grants.
//!
//! This module owns the shared domain types for collaboration capability
//! grants used by productivity and policy profiles (`ck.pin.*`,
//! `ck.rsvp.set`, and Realm policy facet actions). Operator-facing admin
//! DTOs re-export these types so stored and wire action names cannot drift
//! from the canonical capability-action registry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::circle_capability::RiskTier;
pub use crate::pg::collaboration_capability::PgCollaborationCapabilityGrantRepository;
pub use crate::storage::collaboration_capability::*;

/// One collaboration capability action, stored as the exact registry string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationCapabilityAction {
    /// `ck.rsvp.set` — write RSVP state for calendar events.
    #[serde(rename = "ck.rsvp.set")]
    RsvpSet,
    /// `ck.pin.add` — add or update a pinned item.
    #[serde(rename = "ck.pin.add")]
    PinAdd,
    /// `ck.pin.remove` — remove a pinned item.
    #[serde(rename = "ck.pin.remove")]
    PinRemove,
    /// `ck.pin.reorder` — update pinned-item ordering.
    #[serde(rename = "ck.pin.reorder")]
    PinReorder,
    /// `ck.realm.disappearing_policy` — manage disappearing-message policy.
    #[serde(rename = "ck.realm.disappearing_policy")]
    RealmDisappearingPolicy,
    /// `ck.realm.search_policy` — manage blind-search policy.
    #[serde(rename = "ck.realm.search_policy")]
    RealmSearchPolicy,
}

impl CollaborationCapabilityAction {
    /// All registered collaboration actions in registry order.
    #[must_use]
    pub fn all() -> [Self; 6] {
        [
            Self::RsvpSet,
            Self::PinAdd,
            Self::PinRemove,
            Self::PinReorder,
            Self::RealmDisappearingPolicy,
            Self::RealmSearchPolicy,
        ]
    }

    /// The canonical action string from capability-action-registry.json.
    #[must_use]
    pub fn as_action_str(&self) -> &'static str {
        match self {
            Self::RsvpSet => "ck.rsvp.set",
            Self::PinAdd => "ck.pin.add",
            Self::PinRemove => "ck.pin.remove",
            Self::PinReorder => "ck.pin.reorder",
            Self::RealmDisappearingPolicy => "ck.realm.disappearing_policy",
            Self::RealmSearchPolicy => "ck.realm.search_policy",
        }
    }

    /// UI/grouping category for admin tooling.
    #[must_use]
    pub fn category(&self) -> CapabilityCategory {
        match self {
            Self::RsvpSet | Self::PinAdd | Self::PinRemove | Self::PinReorder => {
                CapabilityCategory::Discussion
            }
            Self::RealmDisappearingPolicy | Self::RealmSearchPolicy => {
                CapabilityCategory::Management
            }
        }
    }

    /// Risk tier from the canonical capability-action registry.
    #[must_use]
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            Self::RsvpSet => RiskTier::Low,
            Self::PinAdd | Self::PinRemove | Self::PinReorder => RiskTier::Medium,
            Self::RealmDisappearingPolicy | Self::RealmSearchPolicy => RiskTier::High,
        }
    }

    /// Event kind covered by this action. These currently map same-name.
    #[must_use]
    pub fn target_event_kind(&self) -> &'static str {
        self.as_action_str()
    }

    /// Profile that must be declared by deployments using this action.
    #[must_use]
    pub fn profile(&self) -> &'static str {
        match self {
            Self::RsvpSet => "ck.profile.calendar_event.v1",
            Self::PinAdd | Self::PinRemove | Self::PinReorder => "ck.profile.pinned_items.v1",
            Self::RealmDisappearingPolicy => "ck.profile.disappearing.v1",
            Self::RealmSearchPolicy => "ck.profile.search.blind_index.v1",
        }
    }

    /// Whether issuing this action requires a separate approval workflow.
    #[must_use]
    pub fn requires_approval(&self) -> bool {
        matches!(self.risk_tier(), RiskTier::High)
    }

    /// Whether this action requires a finite expiry.
    #[must_use]
    pub fn requires_expires_at(&self) -> bool {
        matches!(self.risk_tier(), RiskTier::High)
    }
}

impl std::fmt::Display for CollaborationCapabilityAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_action_str())
    }
}

impl std::str::FromStr for CollaborationCapabilityAction {
    type Err = ParseCollaborationCapabilityActionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ck.rsvp.set" => Ok(Self::RsvpSet),
            "ck.pin.add" => Ok(Self::PinAdd),
            "ck.pin.remove" => Ok(Self::PinRemove),
            "ck.pin.reorder" => Ok(Self::PinReorder),
            "ck.realm.disappearing_policy" => Ok(Self::RealmDisappearingPolicy),
            "ck.realm.search_policy" => Ok(Self::RealmSearchPolicy),
            _ => Err(ParseCollaborationCapabilityActionError),
        }
    }
}

/// Parse error for collaboration capability action strings.
#[derive(Debug, thiserror::Error)]
#[error("unknown collaboration capability action")]
pub struct ParseCollaborationCapabilityActionError;

/// Admin category for collaboration actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCategory {
    /// Discussion-level collaboration actions.
    Discussion,
    /// Realm management and policy actions.
    Management,
}

impl CapabilityCategory {
    /// Stable category string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discussion => "discussion",
            Self::Management => "management",
        }
    }
}

/// A durable collaboration capability grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CollaborationCapabilityGrant {
    /// ULID of the grant row itself.
    pub id: String,
    /// Subject (account or DID) that holds the grant.
    pub subject: String,
    /// Realm the grant is scoped to.
    pub realm_id: String,
    /// The capability action this grant authorizes.
    pub action: CollaborationCapabilityAction,
    /// Optional grant expiry. Required for high-risk policy actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Evidence binding for high-risk approval, if required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence_ref: Option<String>,
    /// Who granted it.
    pub granted_by: String,
    /// Grant timestamp.
    pub granted_at: DateTime<Utc>,
    /// Optional revocation timestamp; `None` = non-revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_action_strings_match_spec() {
        let actual: Vec<_> = CollaborationCapabilityAction::all()
            .into_iter()
            .map(|action| action.as_action_str())
            .collect();
        assert_eq!(
            actual,
            vec![
                "ck.rsvp.set",
                "ck.pin.add",
                "ck.pin.remove",
                "ck.pin.reorder",
                "ck.realm.disappearing_policy",
                "ck.realm.search_policy",
            ]
        );
    }

    #[test]
    fn high_risk_policy_actions_require_expiry_and_approval() {
        assert!(CollaborationCapabilityAction::RealmDisappearingPolicy.requires_expires_at());
        assert!(CollaborationCapabilityAction::RealmSearchPolicy.requires_approval());
        assert!(!CollaborationCapabilityAction::PinAdd.requires_approval());
    }
}
