use async_trait::async_trait;
use coauth_data::{
    Clock, User, UserPhone, UserPhoneAuthentication, UserPhoneAuthenticationCode, UserRegistration,
};
use rand_core::RngCore;
use ulid::Ulid;

use crate::repository_impl;

/// A [`UserPhoneRepository`] helps interacting with [`UserPhone`] saved in the
/// storage backend
#[async_trait]
pub trait UserPhoneRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`UserPhone`] by its ID
    ///
    /// Returns `None` if no [`UserPhone`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserPhone`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPhone>, Self::Error>;

    /// Lookup a [`UserPhone`] by its phone number
    ///
    /// Returns `None` if no matching [`UserPhone`] was found or if multiple
    /// [`UserPhone`] are found
    ///
    /// # Parameters
    ///
    /// * `phone`: The phone number to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_phone(&mut self, phone: &str) -> Result<Option<UserPhone>, Self::Error>;

    /// Get all [`UserPhone`] of a [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] for whom to lookup the [`UserPhone`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all(&mut self, user: &User) -> Result<Vec<UserPhone>, Self::Error>;

    /// Create a new [`UserPhone`] for a [`User`]
    ///
    /// Returns the newly created [`UserPhone`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `user`: The [`User`] for whom to create the [`UserPhone`]
    /// * `phone`: The phone number of the [`UserPhone`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        phone: String,
    ) -> Result<UserPhone, Self::Error>;

    /// Delete a [`UserPhone`]
    ///
    /// # Parameters
    ///
    /// * `user_phone`: The [`UserPhone`] to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn remove(&mut self, user_phone: UserPhone) -> Result<(), Self::Error>;

    /// Add a new [`UserPhoneAuthentication`] for a [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `phone`: The phone number to add
    /// * `registration`: The [`UserRegistration`] for which to add the [`UserPhoneAuthentication`]
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        phone: String,
        registration: &UserRegistration,
    ) -> Result<UserPhoneAuthentication, Self::Error>;

    /// Add a new [`UserPhoneAuthenticationCode`] for a
    /// [`UserPhoneAuthentication`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `duration`: The duration for which the code is valid
    /// * `authentication`: The [`UserPhoneAuthentication`] for which to add the
    ///   [`UserPhoneAuthenticationCode`]
    /// * `code`: The code to add
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails or if the code
    /// already exists for this session
    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        authentication: &UserPhoneAuthentication,
        code: String,
    ) -> Result<UserPhoneAuthenticationCode, Self::Error>;

    /// Lookup a [`UserPhoneAuthentication`]
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserPhoneAuthentication`] to lookup
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserPhoneAuthentication>, Self::Error>;

    /// Find a [`UserPhoneAuthenticationCode`] by its code and authentication
    ///
    /// # Parameters
    ///
    /// * `authentication`: The [`UserPhoneAuthentication`] to find the code for
    /// * `code`: The code of the [`UserPhoneAuthentication`] to lookup
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn find_authentication_code(
        &mut self,
        authentication: &UserPhoneAuthentication,
        code: &str,
    ) -> Result<Option<UserPhoneAuthenticationCode>, Self::Error>;

    /// Complete a [`UserPhoneAuthentication`] by using the given code
    ///
    /// Returns the completed [`UserPhoneAuthentication`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock to use to generate timestamps
    /// * `authentication`: The [`UserPhoneAuthentication`] to complete
    /// * `code`: The [`UserPhoneAuthenticationCode`] to use
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn complete_authentication_with_code(
        &mut self,
        clock: &dyn Clock,
        authentication: UserPhoneAuthentication,
        code: &UserPhoneAuthenticationCode,
    ) -> Result<UserPhoneAuthentication, Self::Error>;
}

repository_impl!(UserPhoneRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPhone>, Self::Error>;
    async fn find_by_phone(&mut self, phone: &str) -> Result<Option<UserPhone>, Self::Error>;

    async fn all(&mut self, user: &User) -> Result<Vec<UserPhone>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        phone: String,
    ) -> Result<UserPhone, Self::Error>;
    async fn remove(&mut self, user_phone: UserPhone) -> Result<(), Self::Error>;

    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        phone: String,
        registration: &UserRegistration,
    ) -> Result<UserPhoneAuthentication, Self::Error>;

    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        authentication: &UserPhoneAuthentication,
        code: String,
    ) -> Result<UserPhoneAuthenticationCode, Self::Error>;

    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserPhoneAuthentication>, Self::Error>;

    async fn find_authentication_code(
        &mut self,
        authentication: &UserPhoneAuthentication,
        code: &str,
    ) -> Result<Option<UserPhoneAuthenticationCode>, Self::Error>;

    async fn complete_authentication_with_code(
        &mut self,
        clock: &dyn Clock,
        authentication: UserPhoneAuthentication,
        code: &UserPhoneAuthenticationCode,
    ) -> Result<UserPhoneAuthentication, Self::Error>;
);
