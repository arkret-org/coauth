//! Repositories to interact with entities related to user accounts

pub use arkret_models_collaboration::objects::account_status::AccountStatus as UserStatus;
use async_trait::async_trait;
use coauth_data::{Clock, User, UserPatch, UserProfilePatch};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Page, Pagination, repository_impl};

mod email;
mod password;
mod phone;
mod primary_handle;
mod principal_did;
mod recovery;
mod registration;
mod registration_token;
mod session;
mod terms;
mod totp;

pub use self::email::{UserEmailFilter, UserEmailRepository};
pub use self::password::UserPasswordRepository;
pub use self::phone::UserPhoneRepository;
pub use self::primary_handle::UserPrimaryHandlePreferenceRepository;
pub use self::principal_did::{PrincipalDidRepository, VerifiedPrincipalDidBindingInput};
pub use self::recovery::UserRecoveryRepository;
pub use self::registration::UserRegistrationRepository;
pub use self::registration_token::{UserRegistrationTokenFilter, UserRegistrationTokenRepository};
pub use self::session::{BrowserSessionFilter, BrowserSessionRepository};
pub use self::terms::UserTermsRepository;
pub use self::totp::UserTotpRepository;

/// Filter parameters for listing users
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UserFilter<'a> {
    status: Option<UserStatus>,
    can_request_admin: Option<bool>,
    search: Option<&'a str>,
}

impl<'a> UserFilter<'a> {
    /// Create a new [`UserFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter for active users
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.status = Some(UserStatus::Active);
        self
    }

    /// Filter for locked users
    #[must_use]
    pub fn locked_only(mut self) -> Self {
        self.status = Some(UserStatus::Locked);
        self
    }

    /// Filter for deactivated users
    #[must_use]
    pub fn deactivated_only(mut self) -> Self {
        self.status = Some(UserStatus::Deactivated);
        self
    }

    /// Filter for users pending erasure.
    #[must_use]
    pub fn erasure_pending_only(mut self) -> Self {
        self.status = Some(UserStatus::ErasurePending);
        self
    }

    /// Filter for suspended users.
    #[must_use]
    pub fn suspended_only(mut self) -> Self {
        self.status = Some(UserStatus::Suspended);
        self
    }

    /// Filter for soft-logged-out users.
    #[must_use]
    pub fn soft_logged_out_only(mut self) -> Self {
        self.status = Some(UserStatus::SoftLoggedOut);
        self
    }

    /// Filter for users that can request admin privileges
    #[must_use]
    pub fn can_request_admin_only(mut self) -> Self {
        self.can_request_admin = Some(true);
        self
    }

    /// Filter for users that can't request admin privileges
    #[must_use]
    pub fn cannot_request_admin_only(mut self) -> Self {
        self.can_request_admin = Some(false);
        self
    }

    /// Filter for users that match the given search string
    #[must_use]
    pub fn matching_search(mut self, search: &'a str) -> Self {
        self.search = Some(search);
        self
    }

    /// Get the status filter
    ///
    /// Returns [`None`] if no status filter was set
    #[must_use]
    pub fn status(&self) -> Option<UserStatus> {
        self.status
    }

    /// Get the can request admin filter
    ///
    /// Returns [`None`] if no can request admin filter was set
    #[must_use]
    pub fn can_request_admin(&self) -> Option<bool> {
        self.can_request_admin
    }

    /// Get the search filter
    ///
    /// Returns [`None`] if no search filter was set
    #[must_use]
    pub fn search(&self) -> Option<&'a str> {
        self.search
    }
}

/// A [`UserRepository`] helps interacting with [`User`] saved in the storage
/// backend
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`User`] by its ID
    ///
    /// Returns `None` if no [`User`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`User`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error>;

    /// Find a [`User`] by a handle localpart after applying the Arkret handle
    /// preparation profile.
    ///
    /// Returns `None` if no [`User`] was found
    ///
    /// # Parameters
    ///
    /// * `handle`: The handle localpart of the [`User`] to look up
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_handle(&mut self, handle: &str) -> Result<Option<User>, Self::Error>;

    /// Create a new [`User`]
    ///
    /// Returns the newly created [`User`]
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator to generate the [`User`] ID
    /// * `clock`: The clock used to generate timestamps
    /// * `handle`: The handle localpart of the [`User`]; implementations must store its prepared
    ///   canonical form
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        handle: String,
    ) -> Result<User, Self::Error>;

    /// Update the editable profile fields of a [`User`].
    async fn update_profile(
        &mut self,
        clock: &dyn Clock,
        user: User,
        patch: UserProfilePatch,
    ) -> Result<User, Self::Error>;

    /// Apply a unified patch to a [`User`].
    async fn patch(
        &mut self,
        clock: &dyn Clock,
        user: User,
        patch: UserPatch,
    ) -> Result<User, Self::Error>;

    /// Set a user's account lifecycle status.
    async fn set_account_lifecycle_state(
        &mut self,
        clock: &dyn Clock,
        user: User,
        status: UserStatus,
    ) -> Result<User, Self::Error>;

    /// Check if a [`User`] exists
    ///
    /// Returns `true` if the [`User`] exists, `false` otherwise
    ///
    /// # Parameters
    ///
    /// * `handle`: The handle localpart of the [`User`] to look up, after applying the Arkret
    ///   handle preparation profile
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn exists(&mut self, handle: &str) -> Result<bool, Self::Error>;

    /// Lock a [`User`]
    ///
    /// Returns the locked [`User`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The [`User`] to lock
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lock(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;

    /// Unlock a [`User`]
    ///
    /// Returns the unlocked [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to unlock
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn unlock(&mut self, user: User) -> Result<User, Self::Error>;

    /// Deactivate a [`User`]
    ///
    /// Returns the deactivated [`User`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The [`User`] to deactivate
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn deactivate(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;

    /// Reactivate a [`User`]
    ///
    /// Returns the reactivated [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to reactivate
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn reactivate(&mut self, user: User) -> Result<User, Self::Error>;

    /// Set whether a [`User`] can request admin
    ///
    /// Returns the [`User`] with the new `can_request_admin` value
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to update
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn set_can_request_admin(
        &mut self,
        user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error>;

    /// List [`User`] with the given filter and pagination
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list(
        &mut self,
        filter: UserFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<User>, Self::Error>;

    /// Count the [`User`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UserFilter<'_>) -> Result<usize, Self::Error>;

    /// Acquire a transaction-scoped lock that serializes first-admin bootstrap
    /// decisions across concurrent registrations.
    ///
    /// The lock is released when the repository transaction is saved or rolled
    /// back.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn acquire_bootstrap_admin_lock(&mut self) -> Result<(), Self::Error>;

    /// Acquire a lock on the user to make sure device operations are done in a
    /// sequential way. The lock is released when the repository is saved or
    /// rolled back.
    ///
    /// # Parameters
    ///
    /// * `user`: The user to lock
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn acquire_lock_for_sync(&mut self, user: &User) -> Result<(), Self::Error>;
}

repository_impl!(UserRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error>;
    async fn find_by_handle(&mut self, handle: &str) -> Result<Option<User>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        handle: String,
    ) -> Result<User, Self::Error>;
    async fn update_profile(
        &mut self,
        clock: &dyn Clock,
        user: User,
        patch: UserProfilePatch,
    ) -> Result<User, Self::Error>;
    async fn patch(
        &mut self,
        clock: &dyn Clock,
        user: User,
        patch: UserPatch,
    ) -> Result<User, Self::Error>;
    async fn set_account_lifecycle_state(
        &mut self,
        clock: &dyn Clock,
        user: User,
        status: UserStatus,
    ) -> Result<User, Self::Error>;
    async fn exists(&mut self, handle: &str) -> Result<bool, Self::Error>;
    async fn lock(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;
    async fn unlock(&mut self, user: User) -> Result<User, Self::Error>;
    async fn deactivate(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;
    async fn reactivate(&mut self, user: User) -> Result<User, Self::Error>;
    async fn set_can_request_admin(
        &mut self,
        user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error>;
    async fn list(
        &mut self,
        filter: UserFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<User>, Self::Error>;
    async fn count(&mut self, filter: UserFilter<'_>) -> Result<usize, Self::Error>;
    async fn acquire_bootstrap_admin_lock(&mut self) -> Result<(), Self::Error>;
    async fn acquire_lock_for_sync(&mut self, user: &User) -> Result<(), Self::Error>;
);
