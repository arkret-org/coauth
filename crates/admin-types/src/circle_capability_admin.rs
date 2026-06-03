//! Admin DTOs for managing CXP-0007 `cx.circle.*` capability grants.
//!
//! CXP-0007 introduces a Circle primitive — an encrypted sub-boundary
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
//! Source: cokret-spec
//! `spec/v1/artifacts/registry/capability-action-registry.json`.
//!
//! Wire shape goal: the admin SPA (sodmin) needs to (a) enumerate the
//! current grant set for an account / realm, (b) propose a new grant, and
//! (c) revoke an existing one. The actual cedar policy evaluation lives
//! in `coauth-policy`; this crate only defines the operator-facing JSON.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One of the six CXP-0007 capability actions. Stored as the literal
/// registry string so the wire shape is stable across rollouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum CircleCapabilityAction {
    /// `ck.circle.create` — create new Circles in the target realm.
    #[serde(rename = "ck.circle.create")]
    Create,
    /// `ck.circle.manage` — update / archive / restore / tombstone an
    /// existing Circle. Requires `allowed_circle_ids` constraint.
    #[serde(rename = "ck.circle.manage")]
    Manage,
    /// `ck.circle.member.add` — add the *authenticated principal* to a
    /// Circle (i.e. join with a capability).
    #[serde(rename = "ck.circle.member.add")]
    MemberAdd,
    /// `ck.circle.member.manage` — change member state (role, leave,
    /// kick) for members of a constrained Circle set.
    #[serde(rename = "ck.circle.member.manage")]
    MemberManage,
    /// `ck.circle.member.add.others` — invite/add other principals into a
    /// Circle. High-risk; always requires `allowed_circle_ids`.
    #[serde(rename = "ck.circle.member.add.others")]
    MemberAddOthers,
    /// `ck.circle.audit` — read audit events for the Circle. Paired with
    /// the `audit_pair_required` evaluator check.
    #[serde(rename = "ck.circle.audit")]
    Audit,
}

impl CircleCapabilityAction {
    /// All six actions, in registry order. Convenient for admin UIs that
    /// enumerate the grant matrix.
    #[must_use]
    pub fn all() -> [Self; 6] {
        [
            Self::Create,
            Self::Manage,
            Self::MemberAdd,
            Self::MemberManage,
            Self::MemberAddOthers,
            Self::Audit,
        ]
    }

    /// The registry string (`cx.circle.*`) for this action.
    #[must_use]
    pub fn as_action_str(&self) -> &'static str {
        match self {
            Self::Create => "ck.circle.create",
            Self::Manage => "ck.circle.manage",
            Self::MemberAdd => "ck.circle.member.add",
            Self::MemberManage => "ck.circle.member.manage",
            Self::MemberAddOthers => "ck.circle.member.add.others",
            Self::Audit => "ck.circle.audit",
        }
    }

    /// Whether the action requires the operator to scope it to a finite
    /// set of Circle IDs via `allowed_circle_ids`. Mirrors the spec's
    /// `required_constraints` field.
    #[must_use]
    pub fn requires_allowed_circle_ids(&self) -> bool {
        matches!(
            self,
            Self::Manage | Self::MemberManage | Self::MemberAddOthers
        )
    }
}

impl std::fmt::Display for CircleCapabilityAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_action_str())
    }
}

impl std::str::FromStr for CircleCapabilityAction {
    type Err = ParseCircleCapabilityActionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ck.circle.create" => Ok(Self::Create),
            "ck.circle.manage" => Ok(Self::Manage),
            "ck.circle.member.add" => Ok(Self::MemberAdd),
            "ck.circle.member.manage" => Ok(Self::MemberManage),
            "ck.circle.member.add.others" => Ok(Self::MemberAddOthers),
            "ck.circle.audit" => Ok(Self::Audit),
            _ => Err(ParseCircleCapabilityActionError),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown Circle capability action")]
pub struct ParseCircleCapabilityActionError;

/// Risk tier per the capability-action-registry. Drives whether the
/// admin SPA renders a confirmation modal and whether the route gates
/// on a separate approval proof (see `risk_action` module).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "lowercase")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl CircleCapabilityAction {
    /// Risk tier per the spec registry.
    #[must_use]
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            Self::MemberAdd => RiskTier::Low,
            Self::Create | Self::Manage | Self::MemberManage => RiskTier::Medium,
            Self::MemberAddOthers | Self::Audit => RiskTier::High,
        }
    }
}

/// A capability grant as returned by `GET /_cokret/local/admin/circles/capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct CircleCapabilityGrant {
    /// ULID of the grant row itself.
    pub id: String,
    /// Subject (account or DID) that holds the grant.
    pub subject: String,
    /// Realm the grant is scoped to (the Realm containing the Circles).
    pub realm_id: String,
    /// The capability action this grant authorizes.
    pub action: CircleCapabilityAction,
    /// Optional set of typed Circle IDs the grant is limited to. Required
    /// for actions that have `allowed_circle_ids` in their
    /// `required_constraints`; empty for unconstrained grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_circle_ids: Vec<String>,
    /// Who granted it (admin DID or `system`).
    pub granted_by: String,
    /// Grant timestamp (RFC 3339 UTC on the wire).
    pub granted_at: DateTime<Utc>,
    /// Optional revocation timestamp; `None` = active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Request body for `POST /_cokret/local/admin/circles/capabilities`.
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

/// Response body for `GET /_cokret/local/admin/circles/capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ListCircleCapabilityGrantsResponse {
    pub data: Vec<CircleCapabilityGrant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_action_strings_match_spec() {
        // These six strings come directly from
        // cokret-spec/spec/v1/artifacts/registry/capability-action-registry.json
        // and MUST NOT drift.
        assert_eq!(
            CircleCapabilityAction::Create.as_action_str(),
            "ck.circle.create"
        );
        assert_eq!(
            CircleCapabilityAction::Manage.as_action_str(),
            "ck.circle.manage"
        );
        assert_eq!(
            CircleCapabilityAction::MemberAdd.as_action_str(),
            "ck.circle.member.add"
        );
        assert_eq!(
            CircleCapabilityAction::MemberManage.as_action_str(),
            "ck.circle.member.manage"
        );
        assert_eq!(
            CircleCapabilityAction::MemberAddOthers.as_action_str(),
            "ck.circle.member.add.others"
        );
        assert_eq!(
            CircleCapabilityAction::Audit.as_action_str(),
            "ck.circle.audit"
        );
    }

    #[test]
    fn allowed_circle_ids_required_only_for_scoped_actions() {
        for action in CircleCapabilityAction::all() {
            let needs = action.requires_allowed_circle_ids();
            let expected = matches!(
                action,
                CircleCapabilityAction::Manage
                    | CircleCapabilityAction::MemberManage
                    | CircleCapabilityAction::MemberAddOthers
            );
            assert_eq!(needs, expected, "mismatch for {action:?}");
        }
    }

    #[test]
    fn validate_rejects_missing_constraint() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "ck:realm:1".into(),
            action: CircleCapabilityAction::Manage,
            allowed_circle_ids: vec![],
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_accepts_scoped_grant() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "ck:realm:1".into(),
            action: CircleCapabilityAction::Manage,
            allowed_circle_ids: vec!["ck:circle:abc".into()],
        };
        assert!(req.validate().is_ok());
    }
}
