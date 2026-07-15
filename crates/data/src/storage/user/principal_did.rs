//! Repository for verified service-account to principal-DID bindings.

use async_trait::async_trait;
use coauth_data::{Clock, PrincipalDidBinding, User};
use rand_core::RngCore;

use crate::repository_impl;

/// Typed input for persisting one authority-verified principal DID binding.
#[derive(Clone, Debug)]
pub struct VerifiedPrincipalDidBindingInput {
    /// Principal Server audience for which this binding was verified.
    pub audience: String,
    /// Principal DID controlled by the account holder.
    pub principal_id: String,
    /// Verified head of the principal DID's WebVH history.
    pub key_log_head: arkret_core::Hash,
    /// DID of the authority that attested the enrollment delegation.
    pub enrollment_authority_did: arkret_core::Did,
    /// DID URL of the delegated enrollment authority service.
    pub enrollment_authority_ref: String,
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

    /// Remove every audience binding for this account and principal DID.
    async fn remove_for_user_and_did(
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
    async fn remove_for_user_and_did(
        &mut self,
        user: &User,
        principal_id: &str,
    ) -> Result<(), Self::Error>;
);
