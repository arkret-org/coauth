//! Collaboration capability persistence boundary.

pub use coauth_data_model::{
    COLLABORATION_CAPABILITY_ACTIONS, CapabilityActionId, CapabilityRiskTier,
    CollaborationCapabilityGrant, capability_action_risk_tier,
    collaboration_action_requires_approval, is_collaboration_capability_action,
};

pub use crate::storage::collaboration_capability::*;
