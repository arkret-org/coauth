use async_trait::async_trait;
use futures_util::future::BoxFuture;
use thiserror::Error;

use super::notification_template::NotificationTemplateRepository;
use crate::account::AccountRepository;
use crate::account_handoff::AccountHandoffRepository;
use crate::accountability::AccountabilityGrantRepository;
use crate::agent_key::AgentKeyAuthorizationRepository;
use crate::app_session::AppSessionRepository;
use crate::audit::AuditRepository;
use crate::circle_capability::CircleCapabilityGrantRepository;
use crate::collaboration_capability::CollaborationCapabilityGrantRepository;
use crate::did_binding::VerifiedDidBindingRepository;
use crate::dpop_replay::DpopReplayRepository;
use crate::erasure_request::UserErasureRequestRepository;
use crate::notification::NotificationRepository;
use crate::oauth::{
    OAuthAccessTokenRepository, OAuthAuthorizationGrantRepository, OAuthClientRepository,
    OAuthDeviceCodeGrantRepository, OAuthRefreshTokenRepository, OAuthSessionRepository,
    SessionGrantRepository,
};
use crate::organization_control::OrganizationControlRepository;
use crate::personal::{PersonalAccessTokenRepository, PersonalSessionRepository};
use crate::policy_data::PolicyDataRepository;
use crate::queue::{QueueJobRepository, QueueScheduleRepository, QueueWorkerRepository};
use crate::storage::recovery_authority::RecoveryAuthorityRepository;
use crate::storage::station_trust::StationTrustRepository;
use crate::upstream_oauth::{
    UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
};
use crate::user::{
    BrowserSessionRepository, PrincipalDidRepository, UserEmailRepository, UserPasswordRepository,
    UserPhoneRepository, UserPrimaryHandlePreferenceRepository, UserRecoveryRepository,
    UserRegistrationRepository, UserRegistrationTokenRepository, UserRepository,
    UserTermsRepository,
};

/// A [`RepositoryFactory`] is a factory that can create a [`BoxRepository`].
///
/// The trait is intentionally not generic over the repository type because
/// a generic parameter would break `dyn`-safety and force every consumer to
/// monomorphise against a concrete repository — we rely on `BoxRepository`
/// type-erasure throughout the HTTP stack.
#[async_trait]
pub trait RepositoryFactory {
    /// Create a new [`BoxRepository`]
    async fn create(&self) -> Result<BoxRepository, RepositoryError>;
}

/// A type-erased [`RepositoryFactory`]
pub type BoxRepositoryFactory = Box<dyn RepositoryFactory + Send + Sync + 'static>;

/// A [`Repository`] helps interacting with the underlying storage backend.
pub trait Repository<E>:
    RepositoryAccess<Error = E> + RepositoryTransaction<Error = E> + Send
where
    E: std::error::Error + Send + Sync + 'static,
{
}

/// An opaque, type-erased error
#[derive(Debug, Error)]
#[error("{source}")]
pub struct RepositoryError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
    unique_violation: bool,
}

impl RepositoryError {
    /// Construct a [`RepositoryError`] from any error kind
    pub fn from_error<E>(value: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(value),
            unique_violation: false,
        }
    }

    /// Construct a repository error classified as a uniqueness violation.
    pub fn from_unique_violation<E>(value: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(value),
            unique_violation: true,
        }
    }

    /// Whether the underlying error is a uniqueness-constraint violation.
    ///
    /// Used by callers that perform a check-then-insert (e.g. registration
    /// finish racing on a handle) to turn a concurrent-insert conflict into a
    /// clean domain rejection instead of a generic 500. Returns `true` only
    /// when the storage adapter classified the failure as a unique violation.
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        self.unique_violation
    }
}

/// A type-erased [`Repository`]
pub type BoxRepository = Box<dyn Repository<RepositoryError> + Send + Sync + 'static>;

/// A [`RepositoryTransaction`] can be saved or cancelled, after a series
/// of operations.
pub trait RepositoryTransaction {
    /// The error type used by the [`Self::save`] and [`Self::cancel`] functions
    type Error;

    /// Commit the transaction
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage backend failed to commit the
    /// transaction.
    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>;

    /// Rollback the transaction
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage backend failed to rollback
    /// the transaction.
    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>;
}

/// Declare the [`RepositoryAccess`] trait and its two forwarding
/// implementations from a single list of accessors.
///
/// Each accessor appears in four places that have to agree exactly: the trait
/// declaration, the [`MapErr`] wrapper that re-types the backend error, the
/// `Box<R>` forwarder that keeps `BoxRepository` object-safe, and the backend's
/// own implementation in `coauth-storage-postgres`. The first three are
/// mechanical in the same way — same signature, same `dyn` return type, only
/// the body differs — so they are generated here and the list below is the one
/// place a new repository has to be registered on this side.
///
/// The accessors deliberately stay one-per-repository rather than collapsing
/// into a generic `fn repo::<T>()`: a generic method is not `dyn`-safe, and
/// `BoxRepository` type erasure is what keeps `coauth-backend` free of a
/// diesel dependency.
macro_rules! repository_access {
    ($(
        $(#[$meta:meta])*
        $name:ident: $($repo:ident)::+
    ),* $(,)?) => {
        /// Access the various repositories the backend implements.
        ///
        /// All the methods return a boxed trait object, which can be used to
        /// access a particular repository. The lifetime of the returned object
        /// is bound to the lifetime of the whole repository, so that only one
        /// mutable reference to the repository is used at a time.
        ///
        /// When adding a new repository, add an entry to the
        /// `repository_access!` list below and implement the accessor on the
        /// storage backend; the wrapper implementations are generated.
        pub trait RepositoryAccess: Send {
            /// The backend-specific error type used by each repository.
            type Error: std::error::Error + Send + Sync + 'static;

            $(
                $(#[$meta])*
                fn $name<'c>(&'c mut self)
                -> ::std::boxed::Box<dyn $($repo)::+ <Error = Self::Error> + 'c>;
            )*
        }

        impl<R, F, E> RepositoryAccess for $crate::MapErr<R, F>
        where
            R: RepositoryAccess,
            R::Error: 'static,
            F: FnMut(R::Error) -> E + Send + Sync + 'static,
            E: std::error::Error + Send + Sync + 'static,
        {
            type Error = E;

            $(
                fn $name<'c>(&'c mut self)
                -> ::std::boxed::Box<dyn $($repo)::+ <Error = Self::Error> + 'c> {
                    ::std::boxed::Box::new($crate::MapErr::new(
                        self.inner.$name(),
                        &mut self.mapper,
                    ))
                }
            )*
        }

        impl<R: RepositoryAccess + ?Sized> RepositoryAccess for ::std::boxed::Box<R> {
            type Error = R::Error;

            $(
                fn $name<'c>(&'c mut self)
                -> ::std::boxed::Box<dyn $($repo)::+ <Error = Self::Error> + 'c> {
                    (**self).$name()
                }
            )*
        }
    };
}

repository_access! {
    /// Get an [`AccountRepository`]
    account: AccountRepository,

    /// Get an [`AccountHandoffRepository`].
    account_handoff: AccountHandoffRepository,

    /// Get the Account Authority issuer ledger.
    account_status_ledger: crate::AccountStatusLedgerRepository,

    /// Get an [`AccountabilityGrantRepository`]
    accountability_grant: AccountabilityGrantRepository,

    /// Get an [`AgentKeyAuthorizationRepository`]
    agent_key_authorization: AgentKeyAuthorizationRepository,

    /// Get a [`CircleCapabilityGrantRepository`].
    circle_capability_grant: CircleCapabilityGrantRepository,

    /// Get a [`CollaborationCapabilityGrantRepository`].
    collaboration_capability_grant: CollaborationCapabilityGrantRepository,

    /// Get an [`OrganizationControlRepository`].
    organization_control: OrganizationControlRepository,

    /// Get a [`VerifiedDidBindingRepository`].
    verified_did_binding: VerifiedDidBindingRepository,

    /// Get a [`DpopReplayRepository`].
    dpop_replay: DpopReplayRepository,

    /// Get a [`UserErasureRequestRepository`].
    user_erasure_request: UserErasureRequestRepository,

    /// Get a [`RecoveryAuthorityRepository`].
    recovery_authority: RecoveryAuthorityRepository,

    /// Get an [`UpstreamOAuthLinkRepository`]
    upstream_oauth_link: UpstreamOAuthLinkRepository,

    /// Get an [`UpstreamOAuthProviderRepository`]
    upstream_oauth_provider: UpstreamOAuthProviderRepository,

    /// Get an [`UpstreamOAuthSessionRepository`]
    upstream_oauth_session: UpstreamOAuthSessionRepository,

    /// Get an [`UserRepository`]
    user: UserRepository,

    /// Get an [`UserEmailRepository`]
    user_email: UserEmailRepository,

    /// Get an [`UserPhoneRepository`]
    user_phone: UserPhoneRepository,

    /// Get an [`UserPasswordRepository`]
    user_password: UserPasswordRepository,

    /// Get an [`UserRecoveryRepository`]
    user_recovery: UserRecoveryRepository,

    /// Get an [`UserRegistrationRepository`]
    user_registration: UserRegistrationRepository,

    /// Get an [`UserRegistrationTokenRepository`]
    user_registration_token: UserRegistrationTokenRepository,

    /// Get an [`UserTermsRepository`]
    user_terms: UserTermsRepository,

    /// Get a [`UserPrimaryHandlePreferenceRepository`].
    user_primary_handle_preference: UserPrimaryHandlePreferenceRepository,

    /// Get a [`PrincipalDidRepository`]
    principal_did: PrincipalDidRepository,

    /// Get a [`BrowserSessionRepository`]
    browser_session: BrowserSessionRepository,

    /// Get a [`AppSessionRepository`]
    app_session: AppSessionRepository,

    /// Get an [`AuditRepository`]
    audit: AuditRepository,

    /// Get an append-only handle audit log repository (T3.2).
    handle_audit: coauth_data::audit::HandleAuditRepository,

    /// Get a [`NotificationRepository`]
    notification: NotificationRepository,

    /// Get an [`OAuthClientRepository`]
    oauth_client: OAuthClientRepository,

    /// Get an [`OAuthAuthorizationGrantRepository`]
    oauth_authorization_grant: OAuthAuthorizationGrantRepository,

    /// Get an [`OAuthSessionRepository`]
    oauth_session: OAuthSessionRepository,

    /// Get a [`SessionGrantRepository`]
    oauth_session_grant: SessionGrantRepository,

    /// Get an [`OAuthAccessTokenRepository`]
    oauth_access_token: OAuthAccessTokenRepository,

    /// Get an [`OAuthRefreshTokenRepository`]
    oauth_refresh_token: OAuthRefreshTokenRepository,

    /// Get an [`OAuthDeviceCodeGrantRepository`]
    oauth_device_code_grant: OAuthDeviceCodeGrantRepository,

    /// Get a [`PersonalAccessTokenRepository`]
    personal_access_token: PersonalAccessTokenRepository,

    /// Get a [`PersonalSessionRepository`]
    personal_session: PersonalSessionRepository,

    /// Get a [`QueueWorkerRepository`]
    queue_worker: QueueWorkerRepository,

    /// Get a [`QueueJobRepository`]
    queue_job: QueueJobRepository,

    /// Get a [`QueueScheduleRepository`]
    queue_schedule: QueueScheduleRepository,

    /// Get a [`PolicyDataRepository`]
    policy_data: PolicyDataRepository,

    /// Get a [`StationTrustRepository`]
    station_trust: StationTrustRepository,

    /// Get a [`NotificationTemplateRepository`]
    notification_template: NotificationTemplateRepository,
}

use futures_util::{FutureExt, TryFutureExt};

use crate::MapErr;

// --- Repository ---
impl<R, F, E1, E2> Repository<E2> for MapErr<R, F>
where
    R: Repository<E1> + RepositoryAccess<Error = E1> + RepositoryTransaction<Error = E1>,
    F: FnMut(E1) -> E2 + Send + Sync + 'static,
    E1: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
{
}

// --- RepositoryTransaction --
impl<R, F, E> RepositoryTransaction for MapErr<R, F>
where
    R: RepositoryTransaction,
    R::Error: 'static,
    F: FnMut(R::Error) -> E + Send + Sync + 'static,
    E: std::error::Error,
{
    type Error = E;

    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        Box::new(self.inner).save().map_err(self.mapper).boxed()
    }

    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        Box::new(self.inner).cancel().map_err(self.mapper).boxed()
    }
}
