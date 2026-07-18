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
//! Action semantics come from the storage-neutral domain model. Response DTOs
//! are owned here and are populated through explicit domain-to-wire mapping.

use chrono::{DateTime, Utc};
pub use coauth_data_model::{CircleCapabilityAction, ParseCircleCapabilityActionError, RiskTier};
use serde::{Deserialize, Serialize};

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

impl From<coauth_data_model::CircleCapabilityGrant> for CircleCapabilityGrant {
    fn from(value: coauth_data_model::CircleCapabilityGrant) -> Self {
        Self {
            id: value.id,
            subject: value.subject,
            realm_id: value.realm_id,
            action: value.action,
            allowed_circle_ids: value.allowed_circle_ids,
            granted_by: value.granted_by,
            granted_at: value.granted_at,
            revoked_at: value.revoked_at,
        }
    }
}

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
