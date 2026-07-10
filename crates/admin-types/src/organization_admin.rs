//! Admin DTOs for COA-ORG organization principal control + delegation
//! management (`identity-did.md` §7, `ak.realm.organization`).
//!
//! The shared domain types ([`OrganizationPrincipalControl`],
//! [`OrganizationDelegation`], [`OrganizationDelegationStatus`],
//! [`OrganizationBootstrapAuthorization`]) are owned by the persistence layer
//! (`coauth-data`) and re-exported here so the storage shape, the SDK
//! `ak.realm.organization` shape, and this admin surface cannot drift. Only the
//! request bodies + list/response envelopes are admin-API-specific and remain
//! local to this crate.
//!
//! sodmin can render the full organization control state from these DTOs
//! without touching the database or parsing any product-private fields.

pub use coauth_data::organization_control::{
    OrganizationBootstrapAuthorization, OrganizationDelegation, OrganizationDelegationStatus,
    OrganizationPrincipalControl,
};
use arkret_core::models::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
    RealmOrganizationStatus,
};
use serde::{Deserialize, Serialize};

/// How a bootstrap request authorizes the organization PCR genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BootstrapAuthorizationInput {
    /// Bootstrap from a verified DID controller proof. `proof_digest` is the
    /// opaque digest of the controller proof the caller already verified.
    DidControllerProof { proof_digest: String },
    /// Bootstrap from a `principal_control_realm_bootstrap` delegation already
    /// recorded for this organization.
    DelegatedGovernance { delegation_ref: String },
}

/// Request body for `POST /_coauth/admin/organizations/bootstrap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct BootstrapOrganizationRequest {
    /// Organization principal DID being bootstrapped.
    pub organization_did: String,
    /// Principal Control Realm id (`principal_control_realm_id`).
    pub principal_control_realm_id: String,
    /// Optional control-stream / PCR genesis event ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_stream_ref: Option<String>,
    /// Optional control-frontier digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_frontier_digest: Option<String>,
    /// How the bootstrap is authorized.
    pub authorization: BootstrapAuthorizationInput,
}

/// Request body for `POST /_coauth/admin/organizations/{org}/delegations`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RecordOrganizationDelegationRequest {
    /// Object ref clients put into `authorization.delegation_ref`.
    pub delegation_ref: String,
    /// The delegated principal (Account Authority / governance service DID).
    pub delegate_did: String,
    /// Issuer role the delegate may act as.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub issuer_role: RealmOrganizationIssuerRole,
    /// Declared delegation purposes (e.g. `principal_control_realm_bootstrap`).
    #[serde(default)]
    pub purposes: Vec<String>,
    /// Relationships the delegation authorizes.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = Vec<String>)))]
    pub covered_relationships: Vec<RealmOrganizationRelationship>,
    /// Control scopes the delegation authorizes.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = Vec<String>)))]
    pub covered_control_scopes: Vec<RealmOrganizationControlScope>,
    /// Start of the validity window. Defaults to now when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    /// End of the validity window. `None` means no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request body for `POST /_coauth/admin/organizations/{org}/delegations/{ref}/renew`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RenewOrganizationDelegationRequest {
    /// New validity-window end. `None` clears the expiry (no expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request body for `POST /_coauth/admin/organizations/{org}/rotate-controller`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct RotateOrganizationControllerRequest {
    /// New control-stream / control-state reference after the rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_stream_ref: Option<String>,
    /// New control-frontier digest after the rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_frontier_digest: Option<String>,
}

/// Request body for `POST /_coauth/admin/organizations/{org}/statements`.
///
/// Produces an organization-side `ak.realm.organization` statement. The signed
/// statement is returned as the SDK [`arkret_core::models::RealmOrganizationPayload`]
/// type — no admin-private wire struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct IssueOrganizationStatementRequest {
    /// Realm the statement is bound to.
    pub realm_id: String,
    /// Stable id of this statement (audit identity). Generated when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_id: Option<String>,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub relationship: RealmOrganizationRelationship,
    #[serde(default = "default_active_status")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub status: RealmOrganizationStatus,
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = Vec<String>)))]
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub issuer_role: RealmOrganizationIssuerRole,
    /// REQUIRED for delegated issuer roles; MUST be absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_statement_id: Option<String>,
    /// REQUIRED when `status == revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revokes_statement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_frontier_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_policy_ref: Option<String>,
}

fn default_active_status() -> RealmOrganizationStatus {
    RealmOrganizationStatus::Active
}

/// Response body for `GET /_coauth/admin/organizations/{org}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct OrganizationControlView {
    pub control: OrganizationPrincipalControl,
    /// Delegations anchored to this organization, newest first.
    #[serde(default)]
    pub delegations: Vec<OrganizationDelegation>,
}

/// Response body for `GET /_coauth/admin/organizations/{org}/delegations`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct ListOrganizationDelegationsOutcome {
    pub data: Vec<OrganizationDelegation>,
}
