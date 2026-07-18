//! Interactions with the storage backend
//!
//! This crate provides a set of traits that can be implemented to interact with
//! the storage backend. Those traits are called repositories and are grouped by
//! the type of data they manage.
//!
//! Each of those reposotories can be accessed via the [`RepositoryAccess`]
//! trait. This trait can be wrapped in a [`BoxRepository`] to allow using it
//! without caring about the underlying storage backend, and without carrying
//! around the generic type parameter.
//!
//! # Defining a new repository
//!
//! To define a new repository, you have to:
//!   1. Define a new (async) repository trait, with the methods you need
//!   2. Write an implementation of this trait for each storage backend you want (currently only for
//!      `coauth-storage-postgres`)
//!   3. Make it accessible via the [`RepositoryAccess`] trait
//!
//! The repository trait definition should look like this:
//!
//! ```ignore
//! #[async_trait]
//! pub trait FakeDataRepository: Send + Sync {
//!     /// The error type returned by the repository
//!     type Error;
//!
//!     /// Lookup a [`FakeData`] by its ID
//!     ///
//!     /// Returns `None` if no [`FakeData`] was found
//!     ///
//!     /// # Parameters
//!     ///
//!     /// * `id`: The ID of the [`FakeData`] to lookup
//!     ///
//!     /// # Errors
//!     ///
//!     /// Returns [`Self::Error`] if the underlying repository fails
//!     async fn lookup(&mut self, id: Ulid) -> Result<Option<FakeData>, Self::Error>;
//!
//!     /// Create a new [`FakeData`]
//!     ///
//!     /// Returns the newly-created [`FakeData`].
//!     ///
//!     /// # Parameters
//!     ///
//!     /// * `rng`: The random number generator to use
//!     /// * `clock`: The clock used to generate timestamps
//!     ///
//!     /// # Errors
//!     ///
//!     /// Returns [`Self::Error`] if the underlying repository fails
//!     async fn add(
//!         &mut self,
//!         rng: &mut (dyn RngCore + Send),
//!         clock: &dyn Clock,
//!     ) -> Result<FakeData, Self::Error>;
//! }
//!
//! repository_impl!(FakeDataRepository:
//!     async fn lookup(&mut self, id: Ulid) -> Result<Option<FakeData>, Self::Error>;
//!     async fn add(
//!         &mut self,
//!         rng: &mut (dyn RngCore + Send),
//!         clock: &dyn Clock,
//!     ) -> Result<FakeData, Self::Error>;
//! );
//! ```
//!
//! Four things to note with the implementation:
//!
//!   1. It defined an associated error type, and all functions are fallible, and use that error
//!      type
//!   2. Lookups return an `Result<Option<T>, Self::Error>`, because 'not found' errors are usually
//!      cases that are handled differently
//!   3. Operations that need to record the current type use a [`coauth_data::Clock`] parameter.
//!      Operations that need to generate new IDs also use a random number generator.
//!   4. All the methods use an `&mut self`. This is ensures only one operation is done at a time on
//!      a single repository instance.
//!
//! Then update the [`RepositoryAccess`] trait to make the new repository
//! available:
//!
//! ```ignore
//! /// Access the various repositories the backend implements.
//! pub trait RepositoryAccess: Send {
//!     /// The backend-specific error type used by each repository.
//!     type Error: std::error::Error + Send + Sync + 'static;
//!
//!     // ...other repositories...
//!
//!     /// Get a [`FakeDataRepository`]
//!     fn fake_data<'c>(&'c mut self) -> Box<dyn FakeDataRepository<Error = Self::Error> + 'c>;
//! }
//! ```

#![deny(clippy::future_not_send, missing_docs)]
#![allow(clippy::module_name_repetitions)]

pub mod pagination;
pub(crate) mod repository;
mod utils;

/// Account aggregate repositories (unified contact points, identity bindings,
/// and security summary).
pub mod account;
pub mod account_handoff;
/// Accountability grant repositories.
pub mod accountability;
/// Agent key authorization + agent-key-proof replay repositories (AKP-0008).
pub mod agent_key;
/// App session repositories.
pub mod app_session;
/// Audit log repositories.
pub mod audit;
/// Circle capability grant repositories.
pub mod circle_capability;
/// Collaboration capability grant repositories.
pub mod collaboration_capability;
/// DPoP proof replay repositories.
pub mod dpop_replay;
/// Append-only handle audit log repository (T3.2: handle reassignment,
/// revocation, TTL expiry, DID Document `alsoKnownAs` divergence).
pub mod handle_audit;
/// Notification persistence repositories.
pub mod notification;
/// Notification template version repositories.
pub mod notification_template;
/// OAuth repositories.
pub mod oauth;
/// Organization principal control + delegation repositories.
pub mod organization_control;
/// Personal access repositories.
pub mod personal;
/// Policy data repositories.
pub mod policy_data;
/// Queue repositories.
pub mod queue;
/// Upstream OAuth repositories.
pub mod upstream_oauth;
/// User repositories.
pub mod user;
/// Workflow instance, step, and event repositories.
pub mod workflow;

pub use self::notification_template::NotificationTemplateRepository;
pub use self::pagination::{Page, Pagination};
pub use self::repository::{
    BoxRepository, BoxRepositoryFactory, Repository, RepositoryAccess, RepositoryError,
    RepositoryFactory, RepositoryTransaction,
};
pub use self::utils::MapErr;
