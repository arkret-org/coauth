//! Repository for verified service-account to principal-DID bindings.

use async_trait::async_trait;
use coauth_data::{Clock, PrincipalDidBinding, User};
use rand_core::RngCore;

use crate::repository_impl;

/// Typed input for persisting one authority-verified principal DID binding.
#[derive(Clone, Debug)]
pub struct VerifiedPrincipalDidBindingInput {
    /// Principal Server audience for which this binding was verified.
    pub audience: arkret_identifiers::DidCoreId,
    /// Principal DID controlled by the account holder.
    pub principal_id: arkret_identifiers::DidCoreId,
    /// Verified head of the principal DID's WebVH history.
    pub key_log_head: arkret_identifiers::Hash,
    /// Complete DID independently verified when this private binding was accepted.
    pub verified_full_id: arkret_identifiers::DidFullId,
    /// Adapter-defined version identifier pinned at verification time.
    pub verified_version_id: String,
    /// Canonical Account Authority binding receipt retained for exact replay
    /// and audit. This snapshot is private state, never PCR resolution truth.
    pub binding_receipt: arkret_models_identity::AccountBindingReceipt,
    /// Stable service identity core accepted by the principal binding. Gate
    /// attestations bind to this exact accepting service identity.
    pub accepted_service_id: arkret_identifiers::DidCoreId,
    /// Monotonic private Account Authority binding generation.
    pub binding_version: u64,
    /// Digest of the complete authority-signed binding receipt that installed
    /// this generation.
    pub binding_frontier_digest: arkret_identifiers::Hash,
    /// Exact PCR authority selected at registration. Bare identity equality
    /// must never substitute for this five-field instance.
    pub authority_instance: arkret_wire::PrincipalAuthorityInstance,
}

/// Persistence boundary for principal DIDs verified by an authoritative host.
#[async_trait]
pub trait PrincipalDidRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Fetch the binding for one account and Principal Server audience.
    async fn get_for_user_and_audience(
        &mut self,
        user: &User,
        audience: &str,
    ) -> Result<Option<PrincipalDidBinding>, Self::Error>;

    /// Fetch a binding by its principal DID.
    async fn get_by_did(&mut self, did: &str) -> Result<Option<PrincipalDidBinding>, Self::Error>;

    /// Fetch a binding by principal DID and Principal Server audience.
    async fn get_by_did_and_audience(
        &mut self,
        did: &str,
        audience: &str,
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

    /// Remove every audience binding for this account and stable principal
    /// core. Revocation is deliberately core-only: callers do not select a
    /// stale `full_id` to decide which binding is revoked.
    async fn remove_for_user_and_core(
        &mut self,
        user: &User,
        principal_id: &str,
    ) -> Result<(), Self::Error>;
}

repository_impl!(PrincipalDidRepository:
    async fn get_for_user_and_audience(
        &mut self,
        user: &User,
        audience: &str,
    ) -> Result<Option<PrincipalDidBinding>, Self::Error>;
    async fn get_by_did(
        &mut self,
        did: &str,
    ) -> Result<Option<PrincipalDidBinding>, Self::Error>;
    async fn get_by_did_and_audience(
        &mut self,
        did: &str,
        audience: &str,
    ) -> Result<Option<PrincipalDidBinding>, Self::Error>;
    async fn add_verified(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        input: VerifiedPrincipalDidBindingInput,
    ) -> Result<PrincipalDidBinding, Self::Error>;
    async fn remove_for_user_and_core(
        &mut self,
        user: &User,
        principal_id: &str,
    ) -> Result<(), Self::Error>;
);
