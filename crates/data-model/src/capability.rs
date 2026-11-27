pub use arkret_schema::CapabilityRiskTier;
pub use arkret_wire::{CapabilityActionId, DidCoreId};
/// Collaboration actions supported by Coauth's collaboration grant product
/// surface. This is a product subset, not a second action registry.
pub const COLLABORATION_CAPABILITY_ACTIONS: &[CapabilityActionId] = &[
    CapabilityActionId::RsvpSet,
    CapabilityActionId::PinAdd,
    CapabilityActionId::PinRemove,
    CapabilityActionId::PinReorder,
    CapabilityActionId::RealmSearchPolicy,
];

#[must_use]
pub fn is_collaboration_capability_action(action: CapabilityActionId) -> bool {
    COLLABORATION_CAPABILITY_ACTIONS.contains(&action)
}

#[must_use]
pub fn capability_action_risk_tier(action: CapabilityActionId) -> CapabilityRiskTier {
    arkret_schema::capability_action_descriptor(action).risk_tier
}

#[must_use]
pub fn collaboration_action_requires_approval(action: CapabilityActionId) -> bool {
    is_collaboration_capability_action(action)
        && capability_action_risk_tier(action) == CapabilityRiskTier::High
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
                "ak.realm.search_policy",
            ]
        );
    }

    #[test]
    fn product_rules_read_canonical_registry_metadata() {
        assert!(collaboration_action_requires_approval(
            CapabilityActionId::RealmSearchPolicy
        ));
        assert!(!collaboration_action_requires_approval(
            CapabilityActionId::PinAdd
        ));
    }
}
