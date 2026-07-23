//! Organization principal control + organization delegation repository.

use arkret_models_collaboration::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::Clock;
use coauth_data::organization_control::{
    OrganizationBootstrapAuthorization, OrganizationDelegation, OrganizationPrincipalControl,
};
use rand_core::RngCore;

use crate::repository_impl;

/// Parameters used to bootstrap an organization principal control row.
///
/// The caller is responsible for having verified the controller proof or the
/// `principal_control_realm_bootstrap` delegation *before* calling `bootstrap`;
/// this struct only carries the verified outcome to persist.
#[derive(Debug, Clone)]
pub struct NewOrganizationPrincipalControl {
    /// Organization principal DID this control row governs.
    pub organization_did: String,
    /// Realm id the principal-control / PCR bootstrap is scoped to.
    pub principal_control_realm_id: String,
    /// Optional reference to the organization control stream.
    pub control_stream_ref: Option<String>,
    /// Optional digest of the PCR control frontier evaluated at bootstrap.
    pub pcr_frontier_digest: Option<String>,
    /// Authorization basis under which the bootstrap was accepted.
    pub bootstrap_authorization: OrganizationBootstrapAuthorization,
    /// Delegation reference backing a delegated bootstrap, when applicable.
    pub bootstrap_delegation_ref: Option<String>,
    /// Human admin / service principal that executed the bootstrap (executor
    /// identity only — never the organization principal).
    pub executed_by: Option<String>,
    /// Digest of the verified bootstrap proof transcript.
    pub bootstrap_proof_digest: Option<String>,
}

/// Parameters used to record an organization delegation.
#[derive(Debug, Clone)]
pub struct NewOrganizationDelegation {
    /// Stable delegation reference (unique).
    pub delegation_ref: String,
    /// Organization principal DID that granted the delegation.
    pub organization_did: String,
    /// DID the delegation is granted to (the delegate).
    pub delegate_did: String,
    /// Issuer role the delegate may act under.
    pub issuer_role: RealmOrganizationIssuerRole,
    /// Delegation purposes (e.g. `principal_control_realm_bootstrap`).
    pub purposes: Vec<String>,
    /// Realm relationships the delegation is allowed to cover.
    pub covered_relationships: Vec<RealmOrganizationRelationship>,
    /// Control scopes the delegation is allowed to cover.
    pub covered_control_scopes: Vec<RealmOrganizationControlScope>,
    /// Start of the delegation validity window.
    pub valid_from: DateTime<Utc>,
    /// Optional end of the delegation validity window.
    pub valid_until: Option<DateTime<Utc>>,
    /// Admin / service principal that recorded the delegation.
    pub created_by: String,
}

/// Repository for organization principal control state and delegations.
#[async_trait]
pub trait OrganizationControlRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Persist a freshly-bootstrapped organization principal control row. The
    /// `(organization_did)` unique constraint surfaces a re-bootstrap attempt
    /// as an error.
    async fn bootstrap(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewOrganizationPrincipalControl,
    ) -> Result<OrganizationPrincipalControl, Self::Error>;

    /// Fetch the control row for an organization DID.
    async fn get_control_by_did(
        &mut self,
        organization_did: &str,
    ) -> Result<Option<OrganizationPrincipalControl>, Self::Error>;

    /// Update the control-stream / frontier refs and (optionally) rotate the
    /// recorded controller boundary. Returns `None` when the org is unknown.
    async fn update_control(
        &mut self,
        clock: &dyn Clock,
        organization_did: &str,
        control_stream_ref: Option<String>,
        pcr_frontier_digest: Option<String>,
    ) -> Result<Option<OrganizationPrincipalControl>, Self::Error>;

    /// Record a new active delegation. The `(delegation_ref)` unique
    /// constraint surfaces duplicates as an error.
    async fn add_delegation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewOrganizationDelegation,
    ) -> Result<OrganizationDelegation, Self::Error>;

    /// Resolve a delegation by its `delegation_ref`.
    async fn get_delegation_by_ref(
        &mut self,
        delegation_ref: &str,
    ) -> Result<Option<OrganizationDelegation>, Self::Error>;

    /// List all delegations anchored to an organization DID, newest first.
    async fn list_delegations_for_org(
        &mut self,
        organization_did: &str,
    ) -> Result<Vec<OrganizationDelegation>, Self::Error>;

    /// Revoke an active delegation by `delegation_ref`. Returns `None` when the
    /// delegation is absent or already revoked.
    async fn revoke_delegation(
        &mut self,
        clock: &dyn Clock,
        organization_did: &str,
        delegation_ref: &str,
    ) -> Result<Option<OrganizationDelegation>, Self::Error>;

    /// Extend the validity window of an active delegation. Returns `None` when
    /// the delegation is absent or revoked.
    async fn renew_delegation(
        &mut self,
        clock: &dyn Clock,
        organization_did: &str,
        delegation_ref: &str,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Option<OrganizationDelegation>, Self::Error>;
}

repository_impl!(OrganizationControlRepository:
    async fn bootstrap(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewOrganizationPrincipalControl,
    ) -> Result<OrganizationPrincipalControl, Self::Error>;
    async fn get_control_by_did(
        &mut self,
        organization_did: &str,
    ) -> Result<Option<OrganizationPrincipalControl>, Self::Error>;
    async fn update_control(
        &mut self,
        clock: &dyn Clock,
        organization_did: &str,
        control_stream_ref: Option<String>,
        pcr_frontier_digest: Option<String>,
    ) -> Result<Option<OrganizationPrincipalControl>, Self::Error>;
    async fn add_delegation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewOrganizationDelegation,
    ) -> Result<OrganizationDelegation, Self::Error>;
    async fn get_delegation_by_ref(
        &mut self,
        delegation_ref: &str,
    ) -> Result<Option<OrganizationDelegation>, Self::Error>;
    async fn list_delegations_for_org(
        &mut self,
        organization_did: &str,
    ) -> Result<Vec<OrganizationDelegation>, Self::Error>;
    async fn revoke_delegation(
        &mut self,
        clock: &dyn Clock,
        organization_did: &str,
        delegation_ref: &str,
    ) -> Result<Option<OrganizationDelegation>, Self::Error>;
    async fn renew_delegation(
        &mut self,
        clock: &dyn Clock,
        organization_did: &str,
        delegation_ref: &str,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Option<OrganizationDelegation>, Self::Error>;
);
