//! Admin DTOs for collaboration capability templates introduced by the
//! productivity / policy profiles.
//!
//! Source of truth:
//! `arkret-spec/spec/v1/artifacts/registry/capability-action-registry.json`.
//! These actions intentionally use the exact registry action string; admin
//! tooling MUST NOT grant umbrella strings such as `ak.pin.*`.

use coauth_data_model::{COLLABORATION_CAPABILITY_ACTIONS, collaboration_action_requires_approval};
pub use coauth_data_model::{CapabilityActionId, CapabilityRiskTier, CollaborationCapabilityGrant};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CollaborationCapabilityTemplate {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub action: CapabilityActionId,
    pub category: String,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub risk_tier: CapabilityRiskTier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_constraints: Vec<String>,
    pub target_event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub event_mapping_kind: String,
    pub requires_approval: bool,
    pub requires_expires_at: bool,
}

impl From<CapabilityActionId> for CollaborationCapabilityTemplate {
    fn from(action: CapabilityActionId) -> Self {
        let descriptor = arkret_schema::capability_action_descriptor(action);
        let requires_approval = collaboration_action_requires_approval(action);
        Self {
            action,
            category: descriptor.category.to_owned(),
            risk_tier: descriptor.risk_tier,
            required_constraints: descriptor
                .required_constraints
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            target_event_kinds: descriptor
                .target_event_kinds
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            profile: descriptor.profile.map(str::to_owned),
            event_mapping_kind: descriptor.event_mapping_kind.to_owned(),
            requires_approval,
            requires_expires_at: requires_approval,
        }
    }
}

#[must_use]
pub fn collaboration_capability_templates() -> Vec<CollaborationCapabilityTemplate> {
    COLLABORATION_CAPABILITY_ACTIONS
        .iter()
        .copied()
        .map(CollaborationCapabilityTemplate::from)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ListCollaborationCapabilityTemplatesOutcome {
    pub data: Vec<CollaborationCapabilityTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ListCollaborationCapabilityGrantsOutcome {
    pub data: Vec<CollaborationCapabilityGrant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_action_strings_match_spec() {
        let actual: Vec<_> = COLLABORATION_CAPABILITY_ACTIONS
            .iter()
            .copied()
            .map(CapabilityActionId::as_str)
            .collect();
        assert_eq!(
            actual,
            vec![
                "ak.rsvp.set",
                "ak.pin.add",
                "ak.pin.remove",
                "ak.pin.reorder",
                "ak.realm.search_policy",
            ]
        );
    }

    #[test]
    fn templates_match_spec_registry_fields() {
        let templates = collaboration_capability_templates();
        assert_eq!(templates.len(), 5);

        let rsvp = &templates[0];
        assert_eq!(rsvp.action, CapabilityActionId::RsvpSet);
        assert_eq!(rsvp.category, "discussion");
        assert_eq!(rsvp.risk_tier, CapabilityRiskTier::Low);
        assert!(rsvp.required_constraints.is_empty());
        assert_eq!(rsvp.target_event_kinds, vec!["ak.rsvp.set"]);
        assert_eq!(
            rsvp.profile.as_deref(),
            Some("ak.profile.calendar_event.v1")
        );
        assert_eq!(rsvp.event_mapping_kind, "same_name");

        let search_policy = templates.last().unwrap();
        assert_eq!(search_policy.action, CapabilityActionId::RealmSearchPolicy);
        assert_eq!(search_policy.category, "management");
        assert_eq!(search_policy.risk_tier, CapabilityRiskTier::High);
        assert_eq!(
            search_policy.target_event_kinds,
            vec!["ak.realm.search_policy"]
        );
        assert_eq!(
            search_policy.profile.as_deref(),
            Some("ak.profile.search.blind_index.v1")
        );
        assert!(search_policy.requires_approval);
        assert!(search_policy.requires_expires_at);
    }
}
