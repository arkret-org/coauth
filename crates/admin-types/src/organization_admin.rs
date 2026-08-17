//! Admin DTOs for COA-ORG organization principal control + delegation
//! management (`identity-did.md` §7, `ak.realm.organization`).
//!
//! Domain enums come from the storage-neutral model crate. Response records
//! are private admin-wire DTOs populated through explicit mappings.
//!
//! sodmin can render the full organization control state from these DTOs
//! without touching the database or parsing any product-private fields.

use arkret_models_collaboration::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
    RealmOrganizationStatus,
};
use chrono::{DateTime, Utc};
pub use coauth_data_model::{OrganizationBootstrapAuthorization, OrganizationDelegationStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct OrganizationPrincipalControl {
    pub id: String,
    pub organization_did: String,
    pub principal_control_realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_stream_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_frontier_digest: Option<String>,
    pub bootstrap_authorization: OrganizationBootstrapAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_delegation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_proof_digest: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<coauth_data_model::OrganizationPrincipalControl> for OrganizationPrincipalControl {
    fn from(value: coauth_data_model::OrganizationPrincipalControl) -> Self {
        Self {
            id: value.id,
            organization_did: value.organization_did,
            principal_control_realm_id: value.principal_control_realm_id,
            control_stream_ref: value.control_stream_ref,
            pcr_frontier_digest: value.pcr_frontier_digest,
            bootstrap_authorization: value.bootstrap_authorization,
            bootstrap_delegation_ref: value.bootstrap_delegation_ref,
            executed_by: value.executed_by,
            bootstrap_proof_digest: value.bootstrap_proof_digest,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct OrganizationDelegation {
    pub id: String,
    pub delegation_ref: String,
    pub organization_did: String,
    pub delegate_did: String,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = String)))]
    pub issuer_role: RealmOrganizationIssuerRole,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purposes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = Vec<String>)))]
    pub covered_relationships: Vec<RealmOrganizationRelationship>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    #[cfg_attr(feature = "schema", salvo(schema(value_type = Vec<String>)))]
    pub covered_control_scopes: Vec<RealmOrganizationControlScope>,
    pub status: OrganizationDelegationStatus,
    pub valid_from: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<coauth_data_model::OrganizationDelegation> for OrganizationDelegation {
    fn from(value: coauth_data_model::OrganizationDelegation) -> Self {
        Self {
            id: value.id,
            delegation_ref: value.delegation_ref,
            organization_did: value.organization_did,
            delegate_did: value.delegate_did,
            issuer_role: value.issuer_role,
            purposes: value.purposes,
            covered_relationships: value.covered_relationships,
            covered_control_scopes: value.covered_control_scopes,
            status: value.status,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            created_by: value.created_by,
            created_at: value.created_at,
            updated_at: value.updated_at,
            revoked_at: value.revoked_at,
        }
    }
}

/// How a bootstrap request authorizes the organization PCR genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BootstrapAuthorizationInput {
    /// Bootstrap from a detached JWS signed by a verification method
    /// controlled by the organization DID.
    DidControllerProof { proof_jws: String },
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
    /// Event-derived Principal Control Realm id. It must equal a retype of
    /// `control_stream_ref` at bootstrap.
    pub principal_control_realm_id: String,
    /// Accepted PCR create Event ref. `principal_control_realm_id` must be a
    /// retype of this Event ref.
    pub control_stream_ref: String,
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
/// statement is returned as the SDK [`arkret_models_collaboration::RealmOrganizationPayload`]
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
