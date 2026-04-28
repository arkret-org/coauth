use async_trait::async_trait;
use coauth_data::{Clock, User, UserTotpConfig};
use rand_core::RngCore;

use crate::repository_impl;

/// A [`UserTotpRepository`] helps interacting with [`UserTotpConfig`] saved in
/// the storage backend
#[async_trait]
pub trait UserTotpRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Get the TOTP configuration for a user
    ///
    /// Returns `None` if the user has no TOTP configuration
    ///
    /// # Parameters
    ///
    /// * `user`: The user to get the TOTP configuration for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn get_for_user(&mut self, user: &User) -> Result<Option<UserTotpConfig>, Self::Error>;

    /// Add a new TOTP configuration for a user
    ///
    /// Returns the newly created [`UserTotpConfig`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The user to add the TOTP configuration for
    /// * `secret`: The TOTP secret
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        secret: String,
    ) -> Result<UserTotpConfig, Self::Error>;

    /// Confirm a TOTP configuration
    ///
    /// Returns the confirmed [`UserTotpConfig`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `config`: The TOTP configuration to confirm
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn confirm(
        &mut self,
        clock: &dyn Clock,
        config: UserTotpConfig,
    ) -> Result<UserTotpConfig, Self::Error>;

    /// Remove a TOTP configuration
    ///
    /// # Parameters
    ///
    /// * `config`: The TOTP configuration to remove
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn remove(&mut self, config: UserTotpConfig) -> Result<(), Self::Error>;
}

repository_impl!(UserTotpRepository:
    async fn get_for_user(&mut self, user: &User) -> Result<Option<UserTotpConfig>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        secret: String,
    ) -> Result<UserTotpConfig, Self::Error>;
    async fn confirm(
        &mut self,
        clock: &dyn Clock,
        config: UserTotpConfig,
    ) -> Result<UserTotpConfig, Self::Error>;
    async fn remove(&mut self, config: UserTotpConfig) -> Result<(), Self::Error>;
);
