//! Repository for verified service-account to principal-DID bindings.

use coauth_data::{Clock, PrincipalDidBinding, User};
use rand_core::RngCore;

use crate::repository_impl;

/// Typed input for persisting one authority-verified principal DID binding.
#[derive(Clone, Debug)]
pub struct VerifiedPrincipalDidBindingInput {
    /// Station audience_id for which this binding was verified.
    pub audience_id: arkret_identifiers::DidCoreId,
    /// Principal DID controlled by the account holder.
    pub principal_id: arkret_identifiers::DidCoreId,
    /// Verified head of the principal DID's WebVH history.
    pub key_log_head: arkret_identifiers::Hash,
    /// Complete DID independently verified when this private binding was accepted.
    pub verified_did: arkret_identifiers::Did,
    /// Adapter-defined version identifier pinned at verification time.
    pub verified_version_id: String,
    /// Canonical Account Authority binding receipt retained for exact replay
    /// and audit. This snapshot is private state, never PCR resolution truth.
    pub binding_receipt: arkret_models_identity::AccountBindingReceipt,
    /// Stable owning Station id accepted by the principal binding. Gate
    /// attestations bind to this exact Account Authority identity.
    pub accepted_id: arkret_identifiers::DidCoreId,
    /// Monotonic private Account Authority binding generation.
    pub binding_version: u64,
    /// Digest of the complete authority-signed binding receipt that installed
    /// this generation.
    pub binding_receipt_digest: arkret_identifiers::Hash,
    /// Public account authority coordinate accepted at registration.
    pub account_id: arkret_wire::AccountId,
    /// Exact PCR accepted by the registration genesis operation.
    pub principal_control_realm_id: arkret_identifiers::RealmId,
}

repository_impl! {
    /// Persistence boundary for principal DIDs verified by an authoritative host.
    pub trait PrincipalDidRepository {
        /// The error type returned by the repository.
        type Error;

        /// Fetch the binding for one account and Station audience_id.
        async fn get_for_user_and_audience(
            &mut self,
            user: &User,
            audience_id: &str,
        ) -> Result<Option<PrincipalDidBinding>, Self::Error>;

        /// Fetch a binding by its stable principal core id.
        async fn get_by_principal_id(
            &mut self,
            principal_id: &str,
        ) -> Result<Option<PrincipalDidBinding>, Self::Error>;

        /// Fetch a binding by stable principal core id and Station audience_id.
        async fn get_by_principal_id_and_audience(
            &mut self,
            principal_id: &str,
            audience_id: &str,
        ) -> Result<Option<PrincipalDidBinding>, Self::Error>;

        /// Persist a binding only after the caller has verified the client
        /// submission with the authoritative DID host.
        async fn add_verified(
            &mut self,
            rng: &mut (dyn RngCore + Send),
            clock: &dyn Clock,
            user: &User,
            input: VerifiedPrincipalDidBindingInput,
        ) -> Result<PrincipalDidBinding, Self::Error>;

        /// Remove every audience_id binding for this account and stable principal
        /// core. Revocation is deliberately core-only: callers do not select a
        /// stale `did` to decide which binding is revoked.
        async fn remove_for_user_and_core(
            &mut self,
            user: &User,
            principal_id: &str,
        ) -> Result<(), Self::Error>;
    }
}
