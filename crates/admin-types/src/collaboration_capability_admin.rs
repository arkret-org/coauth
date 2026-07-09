//! Admin DTOs for collaboration capability templates introduced by the
//! productivity / policy profiles.
//!
//! Source of truth:
//! `arkret-spec/spec/v1/artifacts/registry/capability-action-registry.json`.
//! These actions intentionally use the exact registry action string; admin
//! tooling MUST NOT grant umbrella strings such as `ck.pin.*`.

use chrono::{DateTime, Utc};
pub use coauth_data::circle_capability::RiskTier;
pub use coauth_data::collaboration_capability::{
    CapabilityCategory, CollaborationCapabilityAction, CollaborationCapabilityGrant,
    ParseCollaborationCapabilityActionError,
};
use serde::{Deserialize, Serialize};

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
            realm_id: "ak:realm:01JS0SP000000000000000000".into(),
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
                realm_id: "ak:realm:01JS0SP000000000000000000".into(),
                action,
                expires_at: None,
                approval_evidence_ref: None,
            };
            assert!(req.validate().is_ok(), "{action} should validate");
        }
    }
}
