//! Repository for `did:webvh` update-key material that coauth mints against
//! an embedded principal-server provider (soland's
//! soland private WebVH registration endpoint).
//!
//! Distinct from `crate::services::starid_adapter` — starid mints and retains
//! the update key server-side; soland's embedded path requires coauth to
//! construct + sign the inception entry locally, so we **must** retain the
//! ed25519 update-key seed (encrypted) for future rotations.

use async_trait::async_trait;
use coauth_data::{Clock, PrincipalDidUpdateKey, User};
use rand_core::RngCore;

use crate::repository_impl;

/// A [`PrincipalDidRepository`] persists [`PrincipalDidUpdateKey`] rows for
/// users whose principal DID was minted through an embedded provider.
#[async_trait]
pub trait PrincipalDidRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Fetch the update-key material for `user` against `audience`. Returns
    /// `None` if no DID has been minted for the pair yet.
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn get_for_user_and_audience(
        &mut self,
        user: &User,
        audience: &str,
    ) -> Result<Option<PrincipalDidUpdateKey>, Self::Error>;

    /// Fetch the update-key material by DID. Useful when an inbound request
    /// arrives with the DID but no user context (e.g. resolver lookup).
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn get_by_did(&mut self, did: &str)
    -> Result<Option<PrincipalDidUpdateKey>, Self::Error>;

    /// Insert a freshly-minted DID. The `(user_id, audience)` unique
    /// constraint and the `(did)` unique constraint surface conflicts as
    /// errors — callers should pre-check via `get_for_user_and_audience` to
    /// keep the embedded webvh `cas_conflict` semantics clean.
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the underlying repository fails.
    #[allow(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        audience: String,
        did: String,
        did_public_key_multibase: String,
        update_public_key_multibase: String,
        update_secret_b64: String,
        key_log_head: Option<String>,
    ) -> Result<PrincipalDidUpdateKey, Self::Error>;
}

repository_impl!(PrincipalDidRepository:
    async fn get_for_user_and_audience(
        &mut self,
        user: &User,
        audience: &str,
    ) -> Result<Option<PrincipalDidUpdateKey>, Self::Error>;
    async fn get_by_did(
        &mut self,
        did: &str,
    ) -> Result<Option<PrincipalDidUpdateKey>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        audience: String,
        did: String,
        did_public_key_multibase: String,
        update_public_key_multibase: String,
        update_secret_b64: String,
        key_log_head: Option<String>,
    ) -> Result<PrincipalDidUpdateKey, Self::Error>;
);
