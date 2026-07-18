use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub enum CircleCapabilityAction {
    #[serde(rename = "ak.circle.create")]
    Create,
    #[serde(rename = "ak.circle.manage")]
    Manage,
    #[serde(rename = "ak.circle.member.add")]
    MemberAdd,
    #[serde(rename = "ak.circle.member.manage")]
    MemberManage,
    #[serde(rename = "ak.circle.member.add.others")]
    MemberAddOthers,
    #[serde(rename = "ak.circle.audit")]
    Audit,
}

impl CircleCapabilityAction {
    #[must_use]
    pub fn all() -> [Self; 6] {
        [
            Self::Create,
            Self::Manage,
            Self::MemberAdd,
            Self::MemberManage,
            Self::MemberAddOthers,
            Self::Audit,
        ]
    }

    #[must_use]
    pub fn as_action_str(&self) -> &'static str {
        match self {
            Self::Create => "ak.circle.create",
            Self::Manage => "ak.circle.manage",
            Self::MemberAdd => "ak.circle.member.add",
            Self::MemberManage => "ak.circle.member.manage",
            Self::MemberAddOthers => "ak.circle.member.add.others",
            Self::Audit => "ak.circle.audit",
        }
    }

    #[must_use]
    pub fn requires_allowed_circle_ids(&self) -> bool {
        matches!(
            self,
            Self::Manage | Self::MemberManage | Self::MemberAddOthers
        )
    }

    #[must_use]
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            Self::MemberAdd => RiskTier::Low,
            Self::Create | Self::Manage | Self::MemberManage => RiskTier::Medium,
            Self::MemberAddOthers | Self::Audit => RiskTier::High,
        }
    }
}

impl std::fmt::Display for CircleCapabilityAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_action_str())
    }
}

impl std::str::FromStr for CircleCapabilityAction {
    type Err = ParseCircleCapabilityActionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ak.circle.create" => Ok(Self::Create),
            "ak.circle.manage" => Ok(Self::Manage),
            "ak.circle.member.add" => Ok(Self::MemberAdd),
            "ak.circle.member.manage" => Ok(Self::MemberManage),
            "ak.circle.member.add.others" => Ok(Self::MemberAddOthers),
            "ak.circle.audit" => Ok(Self::Audit),
            _ => Err(ParseCircleCapabilityActionError),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown Circle capability action")]
pub struct ParseCircleCapabilityActionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "lowercase")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CircleCapabilityGrant {
    pub id: String,
    pub subject: String,
    pub realm_id: String,
    pub action: CircleCapabilityAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_circle_ids: Vec<String>,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub enum CollaborationCapabilityAction {
    #[serde(rename = "ak.rsvp.set")]
    RsvpSet,
    #[serde(rename = "ak.pin.add")]
    PinAdd,
    #[serde(rename = "ak.pin.remove")]
    PinRemove,
    #[serde(rename = "ak.pin.reorder")]
    PinReorder,
    #[serde(rename = "ak.realm.disappearing_policy")]
    RealmDisappearingPolicy,
    #[serde(rename = "ak.realm.search_policy")]
    RealmSearchPolicy,
}

impl CollaborationCapabilityAction {
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

    #[must_use]
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            Self::RsvpSet => RiskTier::Low,
            Self::PinAdd | Self::PinRemove | Self::PinReorder => RiskTier::Medium,
            Self::RealmDisappearingPolicy | Self::RealmSearchPolicy => RiskTier::High,
        }
    }

    #[must_use]
    pub fn target_event_kind(&self) -> &'static str {
        self.as_action_str()
    }

    #[must_use]
    pub fn profile(&self) -> &'static str {
        match self {
            Self::RsvpSet => "ak.profile.calendar_event.v1",
            Self::PinAdd | Self::PinRemove | Self::PinReorder => "ak.profile.pinned_items.v1",
            Self::RealmDisappearingPolicy => "ak.profile.disappearing.v1",
            Self::RealmSearchPolicy => "ak.profile.search.blind_index.v1",
        }
    }

    #[must_use]
    pub fn requires_approval(&self) -> bool {
        matches!(self.risk_tier(), RiskTier::High)
    }

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

#[derive(Debug, thiserror::Error)]
#[error("unknown collaboration capability action")]
pub struct ParseCollaborationCapabilityActionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCategory {
    Discussion,
    Management,
}

impl CapabilityCategory {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discussion => "discussion",
            Self::Management => "management",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CollaborationCapabilityGrant {
    pub id: String,
    pub capability_grant_id: String,
    pub grant_event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_event_id: Option<String>,
    pub subject: String,
    pub realm_id: String,
    pub action: CollaborationCapabilityAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence_ref: Option<String>,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub grant_raw_payload_digest: String,
    pub grant_fanout_idempotency_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_strings_match_registry() {
        assert_eq!(
            CollaborationCapabilityAction::all().map(|action| action.as_action_str()),
            [
                "ak.rsvp.set",
                "ak.pin.add",
                "ak.pin.remove",
                "ak.pin.reorder",
                "ak.realm.disappearing_policy",
                "ak.realm.search_policy",
            ]
        );
        assert_eq!(
            CircleCapabilityAction::Manage.as_action_str(),
            "ak.circle.manage"
        );
    }
}
