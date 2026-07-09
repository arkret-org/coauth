//! Admin DTOs for managing CKP-0007 `ck.circle.*` capability grants.
//!
//! CKP-0007 introduces a Circle primitive — an encrypted sub-boundary
//! inside a Realm — and ships six capability actions that govern who can
//! create / manage / audit Circles and their membership:
//!
//! | action                       | risk   | required_constraints     |
//! |------------------------------|--------|--------------------------|
//! | `ck.circle.create`           | medium | (none)                   |
//! | `ck.circle.manage`           | medium | `allowed_circle_ids`     |
//! | `ck.circle.member.add`       | low    | (none)                   |
//! | `ck.circle.member.manage`    | medium | `allowed_circle_ids`     |
//! | `ck.circle.member.add.others`| high   | `allowed_circle_ids`     |
//! | `ck.circle.audit`            | high   | (none, requires pairing) |
//!
//! Source: arkret-spec
//! `spec/v1/artifacts/registry/capability-action-registry.json`.
//!
//! The shared domain types ([`CircleCapabilityAction`], [`RiskTier`],
//! [`CircleCapabilityGrant`]) are owned by the persistence layer
//! (`coauth-data`) — both the repository and this admin surface speak the
//! same shape, so they are re-exported here rather than redefined. Only the
//! request body and list-response envelope are admin-API-specific and remain
//! local to this crate. The actual cedar policy evaluation lives in
//! `coauth-policy`.

pub use coauth_data::circle_capability::{
    CircleCapabilityAction, CircleCapabilityGrant, ParseCircleCapabilityActionError, RiskTier,
};
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
    pub action: CircleCapabilityAction,
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
        if self.action.requires_allowed_circle_ids() && self.allowed_circle_ids.is_empty() {
            return Err(format!(
                "action `{}` requires non-empty allowed_circle_ids",
                self.action.as_action_str()
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
            action: CircleCapabilityAction::Manage,
            allowed_circle_ids: vec![],
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_accepts_scoped_grant() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "ak:realm:1".into(),
            action: CircleCapabilityAction::Manage,
            allowed_circle_ids: vec!["ak:circle:abc".into()],
        };
        assert!(req.validate().is_ok());
    }
}
