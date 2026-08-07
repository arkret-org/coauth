use arkret_models_collaboration::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const PRINCIPAL_CONTROL_REALM_BOOTSTRAP_PURPOSE: &str = "principal_control_realm_bootstrap";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationBootstrapAuthorization {
    DidControllerProof,
    DelegatedGovernance,
}

impl OrganizationBootstrapAuthorization {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DidControllerProof => "did_controller_proof",
            Self::DelegatedGovernance => "delegated_governance",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "did_controller_proof" => Some(Self::DidControllerProof),
            "delegated_governance" => Some(Self::DelegatedGovernance),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl OrganizationDelegation {
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.status == OrganizationDelegationStatus::Active
            && self.revoked_at.is_none()
            && now >= self.valid_from
            && self.valid_until.is_none_or(|until| now < until)
    }

    #[must_use]
    pub fn covers_pcr_bootstrap(&self) -> bool {
        self.purposes
            .iter()
            .any(|purpose| purpose == PRINCIPAL_CONTROL_REALM_BOOTSTRAP_PURPOSE)
    }
}
