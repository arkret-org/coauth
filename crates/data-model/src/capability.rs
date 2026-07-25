pub use arkret_schema::CapabilityRiskTier;
pub use arkret_wire::CapabilityActionId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Circle actions supported by Coauth's Circle grant administration product
/// surface. Action identity and metadata remain owned by the spec-generated SDK.
pub const CIRCLE_CAPABILITY_ACTIONS: &[CapabilityActionId] = &[
    CapabilityActionId::CircleCreate,
    CapabilityActionId::CircleManage,
    CapabilityActionId::CircleMemberAdd,
    CapabilityActionId::CircleMemberManage,
    CapabilityActionId::CircleMemberAddOthers,
    CapabilityActionId::CircleAudit,
];

/// Collaboration actions supported by Coauth's collaboration grant product
/// surface. This is a product subset, not a second action registry.
pub const COLLABORATION_CAPABILITY_ACTIONS: &[CapabilityActionId] = &[
    CapabilityActionId::RsvpSet,
    CapabilityActionId::PinAdd,
    CapabilityActionId::PinRemove,
    CapabilityActionId::PinReorder,
    CapabilityActionId::RealmDisappearingPolicy,
    CapabilityActionId::RealmSearchPolicy,
];

#[must_use]
pub fn is_circle_capability_action(action: CapabilityActionId) -> bool {
    CIRCLE_CAPABILITY_ACTIONS.contains(&action)
}

#[must_use]
pub fn is_collaboration_capability_action(action: CapabilityActionId) -> bool {
    COLLABORATION_CAPABILITY_ACTIONS.contains(&action)
}

#[must_use]
pub fn capability_action_risk_tier(action: CapabilityActionId) -> CapabilityRiskTier {
    arkret_schema::capability_action_descriptor(action).risk_tier
}

#[must_use]
pub fn circle_action_requires_allowed_circle_ids(action: CapabilityActionId) -> bool {
    is_circle_capability_action(action)
        && arkret_schema::capability_action_descriptor(action)
            .required_constraints
            .contains(&"allowed_circle_ids")
}

#[must_use]
pub fn collaboration_action_requires_approval(action: CapabilityActionId) -> bool {
    is_collaboration_capability_action(action)
        && capability_action_risk_tier(action) == CapabilityRiskTier::High
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
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub action: CapabilityActionId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_circle_ids: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_subsets_use_canonical_registry_ids() {
        assert_eq!(
            COLLABORATION_CAPABILITY_ACTIONS
                .iter()
                .copied()
                .map(CapabilityActionId::as_str)
                .collect::<Vec<_>>(),
            [
                "ak.rsvp.set",
                "ak.pin.add",
                "ak.pin.remove",
                "ak.pin.reorder",
                "ak.realm.disappearing_policy",
                "ak.realm.search_policy",
            ]
        );
        assert!(is_circle_capability_action(
            CapabilityActionId::CircleManage
        ));
        assert!(!is_circle_capability_action(CapabilityActionId::PinAdd));
    }

    #[test]
    fn product_rules_read_canonical_registry_metadata() {
        assert!(circle_action_requires_allowed_circle_ids(
            CapabilityActionId::CircleManage
        ));
        assert!(!circle_action_requires_allowed_circle_ids(
            CapabilityActionId::CircleCreate
        ));
        assert!(collaboration_action_requires_approval(
            CapabilityActionId::RealmSearchPolicy
        ));
        assert!(!collaboration_action_requires_approval(
            CapabilityActionId::PinAdd
        ));
    }
}
