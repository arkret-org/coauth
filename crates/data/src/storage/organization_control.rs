//! Organization principal control + organization delegation repository.

use arkret_identifiers::{Did, DidCoreId, EventId, Hash};
use arkret_models_collaboration::{
    RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
};
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
    /// Stable organization principal identity this control row governs.
    pub organization_id: DidCoreId,
    /// Exact resolvable organization DID accepted as bootstrap evidence.
    pub organization_did: Did,
    /// Event-derived Realm id of the accepted PCR create Event named by
    /// `control_stream_ref`. Storage rejects a missing or mismatched pair.
    pub principal_control_realm_id: String,
    /// Accepted PCR create Event at bootstrap. `principal_control_realm_id`
    /// MUST be a retype of it; later rotations replace it with the current
    /// organization control-stream head, never with nothing.
    pub control_stream_ref: String,
    /// Optional digest of the PCR control frontier evaluated at bootstrap.
    pub pcr_frontier_digest: Option<String>,
    /// Authorization basis under which the bootstrap was accepted.
    pub bootstrap_authorization: OrganizationBootstrapAuthorization,
    /// Delegation reference backing a delegated bootstrap, when applicable.
    pub bootstrap_delegation_ref: Option<String>,
    /// Human admin / service principal that executed the bootstrap (executor
    /// identity only — never the organization principal).
    pub executed_by: Option<DidCoreId>,
    /// Digest of the verified bootstrap proof transcript.
    pub bootstrap_proof_digest: Option<String>,
}

/// Complete organization control state declared by one controller rotation.
///
/// Rotation is a whole-state replacement, so this struct carries every mutable
/// control column. There is deliberately no way to express "leave this column
/// as it is": a rotation that did not restate the frontier is a rotation onto a
/// state that has no frontier yet.
#[derive(Debug, Clone)]
pub struct RotatedOrganizationControl {
    /// Control-stream head the organization rotates onto.
    pub control_stream_ref: EventId,
    /// Control-frontier digest of the rotated-to state, when it already has one.
    pub pcr_frontier_digest: Option<Hash>,
}

/// Parameters used to record an organization delegation.
#[derive(Debug, Clone)]
pub struct NewOrganizationDelegation {
    /// Stable delegation reference (unique).
    pub delegation_ref: String,
    /// Stable organization principal identity that granted the delegation.
    pub organization_id: DidCoreId,
    /// Stable principal identity the delegation is granted to.
    pub delegate_id: DidCoreId,
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
    pub created_by: DidCoreId,
}

repository_impl! {
    /// Repository for organization principal control state and delegations.
    pub trait OrganizationControlRepository {
        /// Backend error type.
        type Error;

        /// Persist a freshly-bootstrapped organization principal control row. The
        /// `(organization_id)` unique constraint surfaces a re-bootstrap attempt
        /// as an error.
        async fn bootstrap(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            params: NewOrganizationPrincipalControl,
        ) -> Result<OrganizationPrincipalControl, Self::Error>;

        /// Fetch the control row for a stable organization identity.
        async fn get_control_by_id(
            &mut self,
            organization_id: &DidCoreId,
        ) -> Result<Option<OrganizationPrincipalControl>, Self::Error>;

        /// Atomically replace the organization's control state with the state a
        /// rotation declares. Returns `None` when the org is unknown.
        async fn replace_control_state(
            &mut self,
            clock: &dyn Clock,
            organization_id: &DidCoreId,
            rotated: RotatedOrganizationControl,
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

        /// List all delegations anchored to a stable organization identity, newest first.
        async fn list_delegations_for_org(
            &mut self,
            organization_id: &DidCoreId,
        ) -> Result<Vec<OrganizationDelegation>, Self::Error>;

        /// Revoke an active delegation by `delegation_ref`. Returns `None` when the
        /// delegation is absent or already revoked.
        async fn revoke_delegation(
            &mut self,
            clock: &dyn Clock,
            organization_id: &DidCoreId,
            delegation_ref: &str,
        ) -> Result<Option<OrganizationDelegation>, Self::Error>;

        /// Extend the validity window of an active delegation. Returns `None` when
        /// the delegation is absent or revoked.
        async fn renew_delegation(
            &mut self,
            clock: &dyn Clock,
            organization_id: &DidCoreId,
            delegation_ref: &str,
            valid_until: Option<DateTime<Utc>>,
        ) -> Result<Option<OrganizationDelegation>, Self::Error>;
    }
}
