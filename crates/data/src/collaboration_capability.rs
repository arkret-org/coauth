//! Durable collaboration capability grants.
//!
//! This module owns the shared domain types for collaboration capability
//! grants used by productivity and policy profiles (`ak.pin.*`,
//! `ak.rsvp.set`, and Realm policy facet actions). Operator-facing admin
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
    /// `ak.rsvp.set` — write RSVP state for calendar events.
    #[serde(rename = "ak.rsvp.set")]
    RsvpSet,
    /// `ak.pin.add` — add or update a pinned item.
    #[serde(rename = "ak.pin.add")]
    PinAdd,
    /// `ak.pin.remove` — remove a pinned item.
    #[serde(rename = "ak.pin.remove")]
    PinRemove,
    /// `ak.pin.reorder` — update pinned-item ordering.
    #[serde(rename = "ak.pin.reorder")]
    PinReorder,
    /// `ak.realm.disappearing_policy` — manage disappearing-message policy.
    #[serde(rename = "ak.realm.disappearing_policy")]
    RealmDisappearingPolicy,
    /// `ak.realm.search_policy` — manage blind-search policy.
    #[serde(rename = "ak.realm.search_policy")]
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
            Self::RsvpSet => "ak.rsvp.set",
            Self::PinAdd => "ak.pin.add",
            Self::PinRemove => "ak.pin.remove",
            Self::PinReorder => "ak.pin.reorder",
            Self::RealmDisappearingPolicy => "ak.realm.disappearing_policy",
            Self::RealmSearchPolicy => "ak.realm.search_policy",
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
            Self::RsvpSet => "ak.profile.calendar_event.v1",
            Self::PinAdd | Self::PinRemove | Self::PinReorder => "ak.profile.pinned_items.v1",
            Self::RealmDisappearingPolicy => "ak.profile.disappearing.v1",
            Self::RealmSearchPolicy => "ak.profile.search.blind_index.v1",
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
            "ak.rsvp.set" => Ok(Self::RsvpSet),
            "ak.pin.add" => Ok(Self::PinAdd),
            "ak.pin.remove" => Ok(Self::PinRemove),
            "ak.pin.reorder" => Ok(Self::PinReorder),
            "ak.realm.disappearing_policy" => Ok(Self::RealmDisappearingPolicy),
            "ak.realm.search_policy" => Ok(Self::RealmSearchPolicy),
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
    /// Standard protocol grant id materialized by the soland fan-out.
    pub capability_grant_id: String,
    /// Standard `ak.capability.grant` event id queued for soland ingestion.
    pub grant_event_id: String,
    /// Standard `ak.capability.revoke` event id, when revocation is queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_event_id: Option<String>,
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
    /// Canonical digest of the queued grant fan-out payload.
    pub grant_raw_payload_digest: String,
    /// Idempotency key used for the grant fan-out job.
    pub grant_fanout_idempotency_key: String,
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
                "ak.rsvp.set",
                "ak.pin.add",
                "ak.pin.remove",
                "ak.pin.reorder",
                "ak.realm.disappearing_policy",
                "ak.realm.search_policy",
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
