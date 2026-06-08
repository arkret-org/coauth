//! Admin DTOs for collaboration capability templates introduced by the
//! productivity / policy profiles.
//!
//! Source of truth:
//! `cokret-spec/spec/v1/artifacts/registry/capability-action-registry.json`.
//! These actions intentionally use the exact registry action string; admin
//! tooling MUST NOT grant umbrella strings such as `ck.pin.*`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::circle_capability_admin::RiskTier;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationCapabilityAction {
    #[serde(rename = "ck.rsvp.set")]
    RsvpSet,
    #[serde(rename = "ck.pin.add")]
    PinAdd,
    #[serde(rename = "ck.pin.remove")]
    PinRemove,
    #[serde(rename = "ck.pin.reorder")]
    PinReorder,
    #[serde(rename = "ck.realm.disappearing_policy")]
    RealmDisappearingPolicy,
    #[serde(rename = "ck.realm.search_policy")]
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
            Self::RsvpSet => "ck.rsvp.set",
            Self::PinAdd => "ck.pin.add",
            Self::PinRemove => "ck.pin.remove",
            Self::PinReorder => "ck.pin.reorder",
            Self::RealmDisappearingPolicy => "ck.realm.disappearing_policy",
            Self::RealmSearchPolicy => "ck.realm.search_policy",
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
            Self::RsvpSet => "ck.profile.calendar_event.v1",
            Self::PinAdd | Self::PinRemove | Self::PinReorder => "ck.profile.pinned_items.v1",
            Self::RealmDisappearingPolicy => "ck.profile.disappearing.v1",
            Self::RealmSearchPolicy => "ck.profile.search.blind_index.v1",
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
pub struct CollaborationCapabilityTemplate {
    pub action: CollaborationCapabilityAction,
    pub category: CapabilityCategory,
    pub risk_tier: RiskTier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_constraints: Vec<String>,
    pub target_event_kinds: Vec<String>,
    pub profile: String,
    pub event_mapping_kind: String,
    pub requires_approval: bool,
    pub requires_expires_at: bool,
}

impl From<CollaborationCapabilityAction> for CollaborationCapabilityTemplate {
    fn from(action: CollaborationCapabilityAction) -> Self {
        Self {
            action,
            category: action.category(),
            risk_tier: action.risk_tier(),
            required_constraints: Vec::new(),
            target_event_kinds: vec![action.target_event_kind().to_owned()],
            profile: action.profile().to_owned(),
            event_mapping_kind: "same_name".to_owned(),
            requires_approval: action.requires_approval(),
            requires_expires_at: action.requires_expires_at(),
        }
    }
}

#[must_use]
pub fn collaboration_capability_templates() -> Vec<CollaborationCapabilityTemplate> {
    CollaborationCapabilityAction::all()
        .into_iter()
        .map(CollaborationCapabilityTemplate::from)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CollaborationCapabilityGrant {
    pub id: String,
    pub subject: String,
    pub realm_id: String,
    pub action: CollaborationCapabilityAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CreateCollaborationCapabilityGrant {
    pub subject: String,
    pub realm_id: String,
    pub action: CollaborationCapabilityAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence_ref: Option<String>,
}

impl CreateCollaborationCapabilityGrant {
    /// Validate operator-side guardrails that are independent of Cedar.
    ///
    /// High-risk Realm policy actions require both a finite grant expiry and
    /// approval evidence. Low/medium actions may still carry an expiry, but it
    /// is not mandatory by the registry.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string when a required field or guardrail
    /// is missing.
    pub fn validate(&self) -> Result<(), String> {
        if self.subject.is_empty() {
            return Err("subject is required".into());
        }
        if self.realm_id.is_empty() {
            return Err("realm_id is required".into());
        }
        if self.action.requires_expires_at() && self.expires_at.is_none() {
            return Err(format!(
                "action `{}` requires expires_at",
                self.action.as_action_str()
            ));
        }
        if self.action.requires_approval()
            && match self.approval_evidence_ref.as_deref() {
                Some(value) => value.is_empty(),
                None => true,
            }
        {
            return Err(format!(
                "action `{}` requires approval_evidence_ref",
                self.action.as_action_str()
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ListCollaborationCapabilityTemplatesOutcome {
    pub data: Vec<CollaborationCapabilityTemplate>,
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
    fn templates_match_spec_registry_fields() {
        let templates = collaboration_capability_templates();
        assert_eq!(templates.len(), 6);

        let rsvp = &templates[0];
        assert_eq!(rsvp.action, CollaborationCapabilityAction::RsvpSet);
        assert_eq!(rsvp.category, CapabilityCategory::Discussion);
        assert_eq!(rsvp.risk_tier, RiskTier::Low);
        assert!(rsvp.required_constraints.is_empty());
        assert_eq!(rsvp.target_event_kinds, vec!["ck.rsvp.set"]);
        assert_eq!(rsvp.profile, "ck.profile.calendar_event.v1");
        assert_eq!(rsvp.event_mapping_kind, "same_name");

        let search_policy = templates.last().unwrap();
        assert_eq!(
            search_policy.action,
            CollaborationCapabilityAction::RealmSearchPolicy
        );
        assert_eq!(search_policy.category, CapabilityCategory::Management);
        assert_eq!(search_policy.risk_tier, RiskTier::High);
        assert_eq!(
            search_policy.target_event_kinds,
            vec!["ck.realm.search_policy"]
        );
        assert_eq!(search_policy.profile, "ck.profile.search.blind_index.v1");
        assert!(search_policy.requires_approval);
        assert!(search_policy.requires_expires_at);
    }

    #[test]
    fn wildcard_actions_are_not_grantable() {
        use std::str::FromStr;

        assert!(CollaborationCapabilityAction::from_str("ck.pin.*").is_err());
        assert!(CollaborationCapabilityAction::from_str("ck.realm.*").is_err());
    }

    #[test]
    fn high_risk_policy_actions_require_expiry_and_approval() {
        let req = CreateCollaborationCapabilityGrant {
            subject: "did:web:admin.example".into(),
            realm_id: "ck:realm:01JS0SP000000000000000000".into(),
            action: CollaborationCapabilityAction::RealmDisappearingPolicy,
            expires_at: None,
            approval_evidence_ref: None,
        };
        assert!(req.validate().unwrap_err().contains("expires_at"));

        let req = CreateCollaborationCapabilityGrant {
            expires_at: Some(Utc::now()),
            ..req
        };
        assert!(
            req.validate()
                .unwrap_err()
                .contains("approval_evidence_ref")
        );
    }

    #[test]
    fn low_and_medium_actions_do_not_require_approval() {
        for action in [
            CollaborationCapabilityAction::RsvpSet,
            CollaborationCapabilityAction::PinAdd,
            CollaborationCapabilityAction::PinRemove,
            CollaborationCapabilityAction::PinReorder,
        ] {
            let req = CreateCollaborationCapabilityGrant {
                subject: "did:web:alice.example".into(),
                realm_id: "ck:realm:01JS0SP000000000000000000".into(),
                action,
                expires_at: None,
                approval_evidence_ref: None,
            };
            assert!(req.validate().is_ok(), "{action} should validate");
        }
    }
}
