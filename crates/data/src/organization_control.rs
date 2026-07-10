//! Organization principal control state and organization DID delegations.
//!
//! Models the COA-ORG (organization-realm-control) surface. An organization
//! principal is a controllable DID principal — it has a DID Document,
//! governance policy, delegated services, and a Principal Control Realm (PCR)
//! — and is explicitly **not** a human account behind a shared
//! username/password. This module therefore stores only DID / control-stream
//! references and delegation state; it never stores a shared login credential.
//!
//! Two durable shapes live here:
//!
//! - [`OrganizationPrincipalControl`] — one row per organization DID. Holds the organization DID,
//!   its Principal Control Realm id, control-stream / PCR refs, the bootstrap authorization
//!   boundary (controller proof vs delegated governance / Account Authority), and the human/service
//!   principal that *executed* the bootstrap (`executed_by`) without becoming the organization
//!   principal.
//! - [`OrganizationDelegation`] — a delegation the organization DID Document / governance profile
//!   grants to an Account Authority or governance service. It backs the SDK
//!   `RealmOrganizationDelegationResolver` and the audit / management API.
//!
//! These types deliberately use the SDK enums
//! ([`RealmOrganizationRelationship`], [`RealmOrganizationControlScope`],
//! [`RealmOrganizationIssuerRole`]) so the storage shape and the on-wire
//! `ak.realm.organization` shape cannot drift. The `schema` feature gates the
//! `schemars` / `salvo` derives so pure clients do not pull those deps.

use arkret_core::models::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use crate::pg::organization_control::PgOrganizationControlRepository;
pub use crate::storage::organization_control::*;

/// How an organization PCR genesis / control state was authorized.
///
/// Mirrors `identity-did.md` §7 "Organization principal 与 Account Authority
/// 边界": a PCR can only be created or accepted from one of two authorization
/// shapes. A human OIDC / passkey / password session is never one of them — it
/// can only ever appear as the `executed_by` of a delegated bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationBootstrapAuthorization {
    /// Proof of the organization DID method inception / controller key, bound
    /// to `principal_control_realm_id`, `fields.purpose = "principal_control"`
    /// and `ak.profile.principal_control_realm.v1`.
    DidControllerProof,
    /// A delegation declared in the organization DID Document / governance
    /// profile to an Account Authority or `CokretGovernanceService` whose
    /// delegation purpose covers `principal_control_realm_bootstrap`.
    DelegatedGovernance,
}

impl OrganizationBootstrapAuthorization {
    /// Stable wire string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DidControllerProof => "did_controller_proof",
            Self::DelegatedGovernance => "delegated_governance",
        }
    }

    /// Parse the wire string back to the enum.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "did_controller_proof" => Some(Self::DidControllerProof),
            "delegated_governance" => Some(Self::DelegatedGovernance),
            _ => None,
        }
    }

    /// Whether this authorization shape MUST carry a resolvable delegation
    /// reference (delegated governance) rather than a direct controller proof.
    #[must_use]
    pub fn requires_delegation(&self) -> bool {
        matches!(self, Self::DelegatedGovernance)
    }
}

/// Durable organization principal control state, one row per organization DID.
///
/// There is intentionally no password / shared-credential column: the
/// organization principal is controlled by DID keys + delegations only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct OrganizationPrincipalControl {
    /// ULID of the control row itself.
    pub id: String,
    /// The organization principal DID (e.g. `did:webvh:...:acme.example`).
    pub organization_did: String,
    /// Principal Control Realm id bound to the organization DID
    /// (`principal_control_realm_id`).
    pub principal_control_realm_id: String,
    /// Optional reference to the control stream / PCR genesis event
    /// (`ak:event:...` or equivalent control-state ref).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_stream_ref: Option<String>,
    /// Optional digest / ref of the most recent control frontier the
    /// organization control state was evaluated against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_frontier_digest: Option<String>,
    /// How the PCR genesis was authorized.
    pub bootstrap_authorization: OrganizationBootstrapAuthorization,
    /// When `bootstrap_authorization` is `DelegatedGovernance`, the
    /// organization delegation ref the bootstrap relied on. MUST be present
    /// for delegated bootstraps and absent for controller-proof bootstraps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_delegation_ref: Option<String>,
    /// The human admin / service principal DID that executed the bootstrap.
    /// This is the *executor*, not the organization principal; it carries no
    /// organization control authority by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<String>,
    /// Opaque digest of the authorization proof boundary (controller proof or
    /// delegated governance decision id) recorded for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_proof_digest: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Lifecycle status of an [`OrganizationDelegation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationDelegationStatus {
    Active,
    Revoked,
}

impl OrganizationDelegationStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A delegation the organization DID grants to an Account Authority or
/// governance service. Backs the SDK delegation resolver and the management
/// API. Relationship / control-scope shapes reuse the SDK enums so the
/// resolver can be satisfied without re-mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct OrganizationDelegation {
    /// ULID of the delegation row itself.
    pub id: String,
    /// Object ref clients put into `authorization.delegation_ref`
    /// (e.g. `ak:grant:<uuid7>` or a DID-document delegation URL). Unique.
    pub delegation_ref: String,
    /// Organization principal DID the delegation is anchored to.
    pub organization_did: String,
    /// The delegated principal (Account Authority / governance service DID).
    pub delegate_did: String,
    /// Issuer role the delegate is allowed to act as on
    /// `ak.realm.organization` statements.
    // The SDK enums only impl `salvo::oapi::ToSchema` (and only behind their own
    // `salvo` feature) — never `schemars::JsonSchema` — so we present them to
    // both schema generators as their snake_case wire string form.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub issuer_role: RealmOrganizationIssuerRole,
    /// Declared delegation purposes (free-form per governance profile).
    /// Includes values such as `principal_control_realm_bootstrap`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purposes: Vec<String>,
    /// Relationships the delegation authorizes the delegate to assert.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = Vec<String>)))]
    pub covered_relationships: Vec<RealmOrganizationRelationship>,
    /// Control scopes the delegation authorizes (a statement's
    /// `control_scopes` MUST be a subset).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = Vec<String>)))]
    pub covered_control_scopes: Vec<RealmOrganizationControlScope>,
    pub status: OrganizationDelegationStatus,
    pub valid_from: DateTime<Utc>,
    /// Nullable expiry; `None` means no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Admin/service actor that recorded the delegation.
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl OrganizationDelegation {
    /// Whether this delegation is currently live: active status and inside its
    /// validity window at `now`.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.status == OrganizationDelegationStatus::Active
            && self.revoked_at.is_none()
            && now >= self.valid_from
            && self.valid_until.is_none_or(|until| now < until)
    }

    /// Whether this delegation's purposes cover
    /// `principal_control_realm_bootstrap` — the purpose required to bootstrap
    /// an organization PCR via delegated governance.
    #[must_use]
    pub fn covers_pcr_bootstrap(&self) -> bool {
        self.purposes
            .iter()
            .any(|purpose| purpose == PRINCIPAL_CONTROL_REALM_BOOTSTRAP_PURPOSE)
    }
}

/// The delegation purpose that a governance / Account Authority delegation
/// MUST carry to be allowed to bootstrap an organization PCR. Source:
/// `identity-did.md` §7.
pub const PRINCIPAL_CONTROL_REALM_BOOTSTRAP_PURPOSE: &str = "principal_control_realm_bootstrap";

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn delegation(status: OrganizationDelegationStatus) -> OrganizationDelegation {
        OrganizationDelegation {
            id: "01J0".to_owned(),
            delegation_ref: "ak:grant:01904100-0000-7000-8000-000000000001".to_owned(),
            organization_did: "did:webvh:example.test:orgs:org1".to_owned(),
            delegate_did: "did:web:server.acme.example".to_owned(),
            issuer_role: RealmOrganizationIssuerRole::GovernanceService,
            purposes: vec![PRINCIPAL_CONTROL_REALM_BOOTSTRAP_PURPOSE.to_owned()],
            covered_relationships: vec![RealmOrganizationRelationship::Owner],
            covered_control_scopes: vec![RealmOrganizationControlScope::RealmAdmin],
            status,
            valid_from: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            valid_until: Some(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()),
            created_by: "did:web:admin.example".to_owned(),
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            revoked_at: None,
        }
    }

    #[test]
    fn live_inside_window_active() {
        let d = delegation(OrganizationDelegationStatus::Active);
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        assert!(d.is_live(now));
    }

    #[test]
    fn not_live_when_revoked() {
        let mut d = delegation(OrganizationDelegationStatus::Revoked);
        d.revoked_at = Some(Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap());
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        assert!(!d.is_live(now));
    }

    #[test]
    fn not_live_when_expired() {
        let d = delegation(OrganizationDelegationStatus::Active);
        let now = Utc.with_ymd_and_hms(2028, 1, 1, 0, 0, 0).unwrap();
        assert!(!d.is_live(now));
    }

    #[test]
    fn covers_pcr_bootstrap_purpose() {
        let d = delegation(OrganizationDelegationStatus::Active);
        assert!(d.covers_pcr_bootstrap());
        let mut without = d.clone();
        without.purposes = vec!["space_endorsement".to_owned()];
        assert!(!without.covers_pcr_bootstrap());
    }

    #[test]
    fn bootstrap_authorization_roundtrip() {
        for value in [
            OrganizationBootstrapAuthorization::DidControllerProof,
            OrganizationBootstrapAuthorization::DelegatedGovernance,
        ] {
            assert_eq!(
                OrganizationBootstrapAuthorization::parse(value.as_str()),
                Some(value)
            );
        }
        assert!(OrganizationBootstrapAuthorization::DelegatedGovernance.requires_delegation());
        assert!(!OrganizationBootstrapAuthorization::DidControllerProof.requires_delegation());
    }
}
