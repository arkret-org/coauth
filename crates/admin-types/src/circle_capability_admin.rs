//! Admin DTOs for managing CXP-0007 `cx.circle.*` capability grants.
//!
//! CXP-0007 introduces a Circle primitive — an encrypted sub-boundary
//! inside a Realm — and ships six capability actions that govern who can
//! create / manage / audit Circles and their membership:
//!
//! | action                       | risk   | required_constraints     |
//! |------------------------------|--------|--------------------------|
//! | `cx.circle.create`           | medium | (none)                   |
//! | `cx.circle.manage`           | medium | `allowed_circle_refs`    |
//! | `cx.circle.member.add`       | low    | (none)                   |
//! | `cx.circle.member.manage`    | medium | `allowed_circle_refs`    |
//! | `cx.circle.member.add.others`| high   | `allowed_circle_refs`    |
//! | `cx.circle.audit`            | high   | (none, requires pairing) |
//!
//! Source: contrix-spec
//! `spec/v1/artifacts/registry/capability-action-registry.json`.
//!
//! Wire shape goal: the admin SPA (sodmin) needs to (a) enumerate the
//! current grant set for an account / realm, (b) propose a new grant, and
//! (c) revoke an existing one. The actual cedar policy evaluation lives
//! in `coauth-policy`; this crate only defines the operator-facing JSON.

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
    /// `cx.circle.create` — create new Circles in the target realm.
    #[serde(rename = "cx.circle.create")]
    Create,
    /// `cx.circle.manage` — update / archive / restore / tombstone an
    /// existing Circle. Requires `allowed_circle_refs` constraint.
    #[serde(rename = "cx.circle.manage")]
    Manage,
    /// `cx.circle.member.add` — add the *authenticated principal* to a
    /// Circle (i.e. join with a capability).
    #[serde(rename = "cx.circle.member.add")]
    MemberAdd,
    /// `cx.circle.member.manage` — change member state (role, leave,
    /// kick) for members of a constrained Circle set.
    #[serde(rename = "cx.circle.member.manage")]
    MemberManage,
    /// `cx.circle.member.add.others` — invite/add other principals into a
    /// Circle. High-risk; always requires `allowed_circle_refs`.
    #[serde(rename = "cx.circle.member.add.others")]
    MemberAddOthers,
    /// `cx.circle.audit` — read audit events for the Circle. Paired with
    /// the `audit_pair_required` evaluator check.
    #[serde(rename = "cx.circle.audit")]
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
            Self::Create => "cx.circle.create",
            Self::Manage => "cx.circle.manage",
            Self::MemberAdd => "cx.circle.member.add",
            Self::MemberManage => "cx.circle.member.manage",
            Self::MemberAddOthers => "cx.circle.member.add.others",
            Self::Audit => "cx.circle.audit",
        }
    }

    /// Whether the action requires the operator to scope it to a finite
    /// set of Circle IDs via `allowed_circle_refs`. Mirrors the spec's
    /// `required_constraints` field.
    #[must_use]
    pub fn requires_allowed_circle_refs(&self) -> bool {
        matches!(self, Self::Manage | Self::MemberManage | Self::MemberAddOthers)
    }
}

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

/// A capability grant as returned by `GET /api/admin/v1/circles/capabilities`.
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
    /// for actions that have `allowed_circle_refs` in their
    /// `required_constraints`; empty for unconstrained grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_circle_refs: Vec<String>,
    /// Who granted it (admin DID or `system`).
    pub granted_by: String,
    /// RFC 3339 grant timestamp.
    pub granted_at: String,
    /// Optional revocation timestamp; `None` = active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

/// Request body for `POST /api/admin/v1/circles/capabilities`.
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
    pub allowed_circle_refs: Vec<String>,
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
        if self.action.requires_allowed_circle_refs() && self.allowed_circle_refs.is_empty() {
            return Err(format!(
                "action `{}` requires non-empty allowed_circle_refs",
                self.action.as_action_str()
            ));
        }
        Ok(())
    }
}

/// Response body for `GET /api/admin/v1/circles/capabilities`.
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
        // contrix-spec/spec/v1/artifacts/registry/capability-action-registry.json
        // and MUST NOT drift.
        assert_eq!(CircleCapabilityAction::Create.as_action_str(), "cx.circle.create");
        assert_eq!(CircleCapabilityAction::Manage.as_action_str(), "cx.circle.manage");
        assert_eq!(
            CircleCapabilityAction::MemberAdd.as_action_str(),
            "cx.circle.member.add"
        );
        assert_eq!(
            CircleCapabilityAction::MemberManage.as_action_str(),
            "cx.circle.member.manage"
        );
        assert_eq!(
            CircleCapabilityAction::MemberAddOthers.as_action_str(),
            "cx.circle.member.add.others"
        );
        assert_eq!(CircleCapabilityAction::Audit.as_action_str(), "cx.circle.audit");
    }

    #[test]
    fn allowed_circle_refs_required_only_for_scoped_actions() {
        for action in CircleCapabilityAction::all() {
            let needs = action.requires_allowed_circle_refs();
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
            realm_id: "cx:realm:1".into(),
            action: CircleCapabilityAction::Manage,
            allowed_circle_refs: vec![],
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_accepts_scoped_grant() {
        let req = CreateCircleCapabilityGrant {
            subject: "user:alice".into(),
            realm_id: "cx:realm:1".into(),
            action: CircleCapabilityAction::Manage,
            allowed_circle_refs: vec!["cx:circle:abc".into()],
        };
        assert!(req.validate().is_ok());
    }
}
