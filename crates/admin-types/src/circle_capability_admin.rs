//! Admin DTOs for managing AKP-0007 `ak.circle.*` capability grants.
//!
//! AKP-0007 introduces a Circle primitive — an encrypted sub-boundary
//! inside a Realm — and ships six capability actions that govern who can
//! create / manage / audit Circles and their membership:
//!
//! | action                       | risk   | required_constraints     |
//! |------------------------------|--------|--------------------------|
//! | `ak.circle.create`           | medium | (none)                   |
//! | `ak.circle.manage`           | medium | `allowed_circle_ids`     |
//! | `ak.circle.member.add`       | low    | (none)                   |
//! | `ak.circle.member.manage`    | medium | `allowed_circle_ids`     |
//! | `ak.circle.member.add.others`| high   | `allowed_circle_ids`     |
//! | `ak.circle.audit`            | high   | (none, requires pairing) |
//!
//! Source: arkret-spec
//! `spec/v1/artifacts/registry/capability-action-registry.json`.
//!
//! Action semantics and the response grant shape come from the storage-neutral
//! domain model; this crate owns only the admin request and envelope types.

pub use coauth_data_model::{CapabilityActionId, CapabilityRiskTier, CircleCapabilityGrant};
use coauth_data_model::{circle_action_requires_allowed_circle_ids, is_circle_capability_action};
use serde::{Deserialize, Serialize};

/// Request body for `POST /_coauth/admin/circles/capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CreateCircleCapabilityGrant {
    pub subject: String,
    pub realm_id: String,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub action: CapabilityActionId,
    #[serde(default)]
    pub allowed_circle_ids: Vec<String>,
}

impl CreateCircleCapabilityGrant {
    /// Validate that the request satisfies the constraint requirements of
    /// its action. Mirrors the spec's `required_constraints`.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string when a required constraint
    /// is missing.
    pub fn validate(&self) -> Result<(), String> {
        if self.subject.is_empty() {
            return Err("subject is required".into());
        }
        if self.realm_id.is_empty() {
            return Err("realm_id is required".into());
        }
        if !is_circle_capability_action(self.action) {
            return Err(format!(
                "action `{}` is not supported by the Circle grant surface",
                self.action
            ));
        }
        if circle_action_requires_allowed_circle_ids(self.action)
            && self.allowed_circle_ids.is_empty()
        {
            return Err(format!(
                "action `{}` requires non-empty allowed_circle_ids",
                self.action
            ));
        }
        Ok(())
    }
}

/// Response body for `GET /_coauth/admin/circles/capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ListCircleCapabilityGrantsOutcome {
    pub data: Vec<CircleCapabilityGrant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_missing_constraint() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "ak:realm:1".into(),
            action: CapabilityActionId::CircleManage,
            allowed_circle_ids: vec![],
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_accepts_scoped_grant() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "ak:realm:1".into(),
            action: CapabilityActionId::CircleManage,
            allowed_circle_ids: vec!["ak:circle:abc".into()],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_rejects_registered_action_outside_circle_product_subset() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "ak:realm:1".into(),
            action: CapabilityActionId::PinAdd,
            allowed_circle_ids: vec![],
        };

        assert!(req.validate().is_err());
    }
}
