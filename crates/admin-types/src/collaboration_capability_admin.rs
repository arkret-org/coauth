//! Admin DTOs for collaboration capability templates introduced by the
//! productivity / policy profiles.
//!
//! Source of truth:
//! `arkret-spec/spec/v1/artifacts/registry/capability-action-registry.json`.
//! These actions intentionally use the exact registry action string; admin
//! tooling MUST NOT grant umbrella strings such as `ak.pin.*`.

use chrono::{DateTime, Utc};
use coauth_data_model::{
    COLLABORATION_CAPABILITY_ACTIONS, collaboration_action_requires_approval,
    is_collaboration_capability_action,
};
pub use coauth_data_model::{CapabilityActionId, CapabilityRiskTier};
use serde::{Deserialize, Serialize};

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
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub action: CapabilityActionId,
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

impl From<coauth_data_model::CollaborationCapabilityGrant> for CollaborationCapabilityGrant {
    fn from(value: coauth_data_model::CollaborationCapabilityGrant) -> Self {
        Self {
            id: value.id,
            capability_grant_id: value.capability_grant_id,
            grant_event_id: value.grant_event_id,
            revoke_event_id: value.revoke_event_id,
            subject: value.subject,
            realm_id: value.realm_id,
            action: value.action,
            expires_at: value.expires_at,
            approval_evidence_ref: value.approval_evidence_ref,
            granted_by: value.granted_by,
            granted_at: value.granted_at,
            revoked_at: value.revoked_at,
            grant_raw_payload_digest: value.grant_raw_payload_digest,
            grant_fanout_idempotency_key: value.grant_fanout_idempotency_key,
        }
    }
}

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
pub struct CreateCollaborationCapabilityGrant {
    pub subject: String,
    pub realm_id: String,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub action: CapabilityActionId,
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
        if !is_collaboration_capability_action(self.action) {
            return Err(format!(
                "action `{}` is not supported by the collaboration grant surface",
                self.action
            ));
        }
        if collaboration_action_requires_approval(self.action) && self.expires_at.is_none() {
            return Err(format!("action `{}` requires expires_at", self.action));
        }
        if collaboration_action_requires_approval(self.action)
            && match self.approval_evidence_ref.as_deref() {
                Some(value) => value.is_empty(),
                None => true,
            }
        {
            return Err(format!(
                "action `{}` requires approval_evidence_ref",
                self.action
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
                "ak.realm.disappearing_policy",
                "ak.realm.search_policy",
            ]
        );
    }

    #[test]
    fn templates_match_spec_registry_fields() {
        let templates = collaboration_capability_templates();
        assert_eq!(templates.len(), 6);

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

    #[test]
    fn wildcard_actions_are_not_grantable() {
        let body = r#"{
            "subject":"did:web:alice.example",
            "realm_id":"ak:realm:demo",
            "action":"ak.pin.*"
        }"#;

        assert!(serde_json::from_str::<CreateCollaborationCapabilityGrant>(body).is_err());
    }

    #[test]
    fn high_risk_policy_actions_require_expiry_and_approval() {
        let req = CreateCollaborationCapabilityGrant {
            subject: "did:web:admin.example".into(),
            realm_id: "ak:realm:01JS0SP000000000000000000".into(),
            action: CapabilityActionId::RealmDisappearingPolicy,
            expires_at: None,
            approval_evidence_ref: None,
        };
        assert!(req.validate().unwrap_err().contains("expires_at"));

        let req = CreateCollaborationCapabilityGrant {
            expires_at: Some("2099-01-01T00:00:00.000Z".parse().unwrap()),
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
            CapabilityActionId::RsvpSet,
            CapabilityActionId::PinAdd,
            CapabilityActionId::PinRemove,
            CapabilityActionId::PinReorder,
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

    #[test]
    fn registered_action_outside_product_subset_is_rejected() {
        let req = CreateCollaborationCapabilityGrant {
            subject: "did:web:alice.example".into(),
            realm_id: "ak:realm:01JS0SP000000000000000000".into(),
            action: CapabilityActionId::MessageCreate,
            expires_at: None,
            approval_evidence_ref: None,
        };

        assert!(req.validate().is_err());
    }
}
