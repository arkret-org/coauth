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
use crate::dpop_replay::DpopReplayRepository;
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
use crate::upstream_oauth::{
    UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
};
use crate::user::{
    BrowserSessionRepository, PrincipalDidRepository, UserEmailRepository, UserPasswordRepository,
    UserPhoneRepository, UserPrimaryHandlePreferenceRepository, UserRecoveryRepository,
    UserRegistrationRepository, UserRegistrationTokenRepository, UserRepository,
    UserTermsRepository, UserTotpRepository,
};
use crate::workflow::WorkflowRepository;

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

/// Access the various repositories the backend implements.
///
/// All the methods return a boxed trait object, which can be used to access a
/// particular repository. The lifetime of the returned object is bound to the
/// lifetime of the whole repository, so that only one mutable reference to the
/// repository is used at a time.
///
/// When adding a new repository, you should add a new method to this trait, and
/// update the implementations for [`crate::MapErr`] and [`Box<R>`] below.
///
/// Note: this used to have generic associated types to avoid boxing all the
/// repository traits, but that was removed because it made almost impossible to
/// box the trait object. This might be a shortcoming of the initial
/// implementation of generic associated types, and might be fixed in the
/// future.
pub trait RepositoryAccess: Send {
    /// The backend-specific error type used by each repository.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get an [`AccountRepository`]
    fn account<'c>(&'c mut self) -> Box<dyn AccountRepository<Error = Self::Error> + 'c>;

    /// Get an [`AccountHandoffRepository`].
    fn account_handoff<'c>(
        &'c mut self,
    ) -> Box<dyn AccountHandoffRepository<Error = Self::Error> + 'c>;

    /// Get an [`AccountabilityGrantRepository`]
    fn accountability_grant<'c>(
        &'c mut self,
    ) -> Box<dyn AccountabilityGrantRepository<Error = Self::Error> + 'c>;

    /// Get an [`AgentKeyAuthorizationRepository`]
    fn agent_key_authorization<'c>(
        &'c mut self,
    ) -> Box<dyn AgentKeyAuthorizationRepository<Error = Self::Error> + 'c>;

    /// Get a [`CircleCapabilityGrantRepository`].
    fn circle_capability_grant<'c>(
        &'c mut self,
    ) -> Box<dyn CircleCapabilityGrantRepository<Error = Self::Error> + 'c>;

    /// Get a [`CollaborationCapabilityGrantRepository`].
    fn collaboration_capability_grant<'c>(
        &'c mut self,
    ) -> Box<dyn CollaborationCapabilityGrantRepository<Error = Self::Error> + 'c>;

    /// Get an [`OrganizationControlRepository`].
    fn organization_control<'c>(
        &'c mut self,
    ) -> Box<dyn OrganizationControlRepository<Error = Self::Error> + 'c>;

    /// Get a [`DpopReplayRepository`].
    fn dpop_replay<'c>(&'c mut self) -> Box<dyn DpopReplayRepository<Error = Self::Error> + 'c>;

    /// Get an [`UpstreamOAuthLinkRepository`]
    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c>;

    /// Get an [`UpstreamOAuthProviderRepository`]
    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c>;

    /// Get an [`UpstreamOAuthSessionRepository`]
    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserRepository`]
    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserEmailRepository`]
    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserPhoneRepository`]
    fn user_phone<'c>(&'c mut self) -> Box<dyn UserPhoneRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserPasswordRepository`]
    fn user_password<'c>(&'c mut self)
    -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserRecoveryRepository`]
    fn user_recovery<'c>(&'c mut self)
    -> Box<dyn UserRecoveryRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserRegistrationRepository`]
    fn user_registration<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserRegistrationTokenRepository`]
    fn user_registration_token<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationTokenRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserTermsRepository`]
    fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserTotpRepository`]
    fn user_totp<'c>(&'c mut self) -> Box<dyn UserTotpRepository<Error = Self::Error> + 'c>;

    /// Get a [`UserPrimaryHandlePreferenceRepository`].
    fn user_primary_handle_preference<'c>(
        &'c mut self,
    ) -> Box<dyn UserPrimaryHandlePreferenceRepository<Error = Self::Error> + 'c>;

    /// Get a [`PrincipalDidRepository`]
    fn principal_did<'c>(&'c mut self)
    -> Box<dyn PrincipalDidRepository<Error = Self::Error> + 'c>;

    /// Get a [`BrowserSessionRepository`]
    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c>;

    /// Get a [`AppSessionRepository`]
    fn app_session<'c>(&'c mut self) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c>;

    /// Get an [`AuditRepository`]
    fn audit<'c>(&'c mut self) -> Box<dyn AuditRepository<Error = Self::Error> + 'c>;

    /// Get an append-only handle audit log repository (T3.2).
    fn handle_audit<'c>(
        &'c mut self,
    ) -> Box<dyn coauth_data::audit::HandleAuditRepository<Error = Self::Error> + 'c>;

    /// Get a [`NotificationRepository`]
    fn notification<'c>(&'c mut self) -> Box<dyn NotificationRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuthClientRepository`]
    fn oauth_client<'c>(&'c mut self) -> Box<dyn OAuthClientRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuthAuthorizationGrantRepository`]
    fn oauth_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthAuthorizationGrantRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuthSessionRepository`]
    fn oauth_session<'c>(&'c mut self)
    -> Box<dyn OAuthSessionRepository<Error = Self::Error> + 'c>;

    /// Get a [`SessionGrantRepository`]
    fn oauth_session_grant<'c>(
        &'c mut self,
    ) -> Box<dyn SessionGrantRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuthAccessTokenRepository`]
    fn oauth_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthAccessTokenRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuthRefreshTokenRepository`]
    fn oauth_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthRefreshTokenRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuthDeviceCodeGrantRepository`]
    fn oauth_device_code_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthDeviceCodeGrantRepository<Error = Self::Error> + 'c>;

    /// Get a [`PersonalAccessTokenRepository`]
    fn personal_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn PersonalAccessTokenRepository<Error = Self::Error> + 'c>;

    /// Get a [`PersonalSessionRepository`]
    fn personal_session<'c>(
        &'c mut self,
    ) -> Box<dyn PersonalSessionRepository<Error = Self::Error> + 'c>;

    /// Get a [`QueueWorkerRepository`]
    fn queue_worker<'c>(&'c mut self) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c>;

    /// Get a [`QueueJobRepository`]
    fn queue_job<'c>(&'c mut self) -> Box<dyn QueueJobRepository<Error = Self::Error> + 'c>;

    /// Get a [`QueueScheduleRepository`]
    fn queue_schedule<'c>(
        &'c mut self,
    ) -> Box<dyn QueueScheduleRepository<Error = Self::Error> + 'c>;

    /// Get a [`PolicyDataRepository`]
    fn policy_data<'c>(&'c mut self) -> Box<dyn PolicyDataRepository<Error = Self::Error> + 'c>;

    /// Get a [`NotificationTemplateRepository`]
    fn notification_template<'c>(
        &'c mut self,
    ) -> Box<dyn NotificationTemplateRepository<Error = Self::Error> + 'c>;

    /// Get a [`WorkflowRepository`]
    fn workflow<'c>(&'c mut self) -> Box<dyn WorkflowRepository<Error = Self::Error> + 'c>;
}

/// Implementations of the [`RepositoryAccess`], [`RepositoryTransaction`] and
/// [`Repository`] for the [`crate::MapErr`] wrapper and [`Box<R>`]
mod impls {
    use futures_util::future::BoxFuture;
    use futures_util::{FutureExt, TryFutureExt};

    use super::RepositoryAccess;
    use crate::account::AccountRepository;
    use crate::account_handoff::AccountHandoffRepository;
    use crate::accountability::AccountabilityGrantRepository;
    use crate::agent_key::AgentKeyAuthorizationRepository;
    use crate::app_session::AppSessionRepository;
    use crate::audit::AuditRepository;
    use crate::circle_capability::CircleCapabilityGrantRepository;
    use crate::collaboration_capability::CollaborationCapabilityGrantRepository;
    use crate::dpop_replay::DpopReplayRepository;
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
    use crate::storage::notification_template::NotificationTemplateRepository;
    use crate::upstream_oauth::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    };
    use crate::user::{
        BrowserSessionRepository, PrincipalDidRepository, UserEmailRepository,
        UserPasswordRepository, UserPhoneRepository, UserPrimaryHandlePreferenceRepository,
        UserRegistrationRepository, UserRegistrationTokenRepository, UserRepository,
        UserTermsRepository, UserTotpRepository,
    };
    use crate::workflow::WorkflowRepository;
    use crate::{MapErr, Repository, RepositoryTransaction};

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

    // --- RepositoryAccess --
    impl<R, F, E> RepositoryAccess for MapErr<R, F>
    where
        R: RepositoryAccess,
        R::Error: 'static,
        F: FnMut(R::Error) -> E + Send + Sync + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        type Error = E;

        fn account<'c>(&'c mut self) -> Box<dyn AccountRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.account(), &mut self.mapper))
        }

        fn account_handoff<'c>(
            &'c mut self,
        ) -> Box<dyn AccountHandoffRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.account_handoff(), &mut self.mapper))
        }

        fn accountability_grant<'c>(
            &'c mut self,
        ) -> Box<dyn AccountabilityGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.accountability_grant(),
                &mut self.mapper,
            ))
        }

        fn agent_key_authorization<'c>(
            &'c mut self,
        ) -> Box<dyn AgentKeyAuthorizationRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.agent_key_authorization(),
                &mut self.mapper,
            ))
        }

        fn circle_capability_grant<'c>(
            &'c mut self,
        ) -> Box<dyn CircleCapabilityGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.circle_capability_grant(),
                &mut self.mapper,
            ))
        }

        fn organization_control<'c>(
            &'c mut self,
        ) -> Box<dyn OrganizationControlRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.organization_control(),
                &mut self.mapper,
            ))
        }

        fn collaboration_capability_grant<'c>(
            &'c mut self,
        ) -> Box<dyn CollaborationCapabilityGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.collaboration_capability_grant(),
                &mut self.mapper,
            ))
        }

        fn dpop_replay<'c>(
            &'c mut self,
        ) -> Box<dyn DpopReplayRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.dpop_replay(), &mut self.mapper))
        }

        fn upstream_oauth_link<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.upstream_oauth_link(),
                &mut self.mapper,
            ))
        }

        fn upstream_oauth_provider<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.upstream_oauth_provider(),
                &mut self.mapper,
            ))
        }

        fn upstream_oauth_session<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.upstream_oauth_session(),
                &mut self.mapper,
            ))
        }

        fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user(), &mut self.mapper))
        }

        fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_email(), &mut self.mapper))
        }

        fn user_phone<'c>(&'c mut self) -> Box<dyn UserPhoneRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_phone(), &mut self.mapper))
        }

        fn user_password<'c>(
            &'c mut self,
        ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_password(), &mut self.mapper))
        }

        fn user_recovery<'c>(
            &'c mut self,
        ) -> Box<dyn crate::user::UserRecoveryRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_recovery(), &mut self.mapper))
        }

        fn user_registration<'c>(
            &'c mut self,
        ) -> Box<dyn UserRegistrationRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.user_registration(),
                &mut self.mapper,
            ))
        }

        fn user_registration_token<'c>(
            &'c mut self,
        ) -> Box<dyn UserRegistrationTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.user_registration_token(),
                &mut self.mapper,
            ))
        }

        fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_terms(), &mut self.mapper))
        }

        fn user_totp<'c>(&'c mut self) -> Box<dyn UserTotpRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_totp(), &mut self.mapper))
        }

        fn user_primary_handle_preference<'c>(
            &'c mut self,
        ) -> Box<dyn UserPrimaryHandlePreferenceRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.user_primary_handle_preference(),
                &mut self.mapper,
            ))
        }

        fn principal_did<'c>(
            &'c mut self,
        ) -> Box<dyn PrincipalDidRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.principal_did(), &mut self.mapper))
        }

        fn browser_session<'c>(
            &'c mut self,
        ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.browser_session(), &mut self.mapper))
        }

        fn app_session<'c>(
            &'c mut self,
        ) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.app_session(), &mut self.mapper))
        }

        fn audit<'c>(&'c mut self) -> Box<dyn AuditRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.audit(), &mut self.mapper))
        }

        fn handle_audit<'c>(
            &'c mut self,
        ) -> Box<dyn coauth_data::audit::HandleAuditRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.handle_audit(), &mut self.mapper))
        }

        fn notification<'c>(
            &'c mut self,
        ) -> Box<dyn NotificationRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.notification(), &mut self.mapper))
        }

        fn oauth_client<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthClientRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.oauth_client(), &mut self.mapper))
        }

        fn oauth_authorization_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthAuthorizationGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth_authorization_grant(),
                &mut self.mapper,
            ))
        }

        fn oauth_session<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.oauth_session(), &mut self.mapper))
        }

        fn oauth_session_grant<'c>(
            &'c mut self,
        ) -> Box<dyn SessionGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth_session_grant(),
                &mut self.mapper,
            ))
        }

        fn oauth_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthAccessTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth_access_token(),
                &mut self.mapper,
            ))
        }

        fn oauth_refresh_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthRefreshTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth_refresh_token(),
                &mut self.mapper,
            ))
        }

        fn oauth_device_code_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthDeviceCodeGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth_device_code_grant(),
                &mut self.mapper,
            ))
        }

        fn personal_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn PersonalAccessTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.personal_access_token(),
                &mut self.mapper,
            ))
        }

        fn personal_session<'c>(
            &'c mut self,
        ) -> Box<dyn PersonalSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.personal_session(), &mut self.mapper))
        }

        fn queue_worker<'c>(
            &'c mut self,
        ) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.queue_worker(), &mut self.mapper))
        }

        fn queue_job<'c>(&'c mut self) -> Box<dyn QueueJobRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.queue_job(), &mut self.mapper))
        }

        fn queue_schedule<'c>(
            &'c mut self,
        ) -> Box<dyn QueueScheduleRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.queue_schedule(), &mut self.mapper))
        }

        fn policy_data<'c>(
            &'c mut self,
        ) -> Box<dyn PolicyDataRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.policy_data(), &mut self.mapper))
        }

        fn notification_template<'c>(
            &'c mut self,
        ) -> Box<dyn NotificationTemplateRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.notification_template(),
                &mut self.mapper,
            ))
        }

        fn workflow<'c>(&'c mut self) -> Box<dyn WorkflowRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.workflow(), &mut self.mapper))
        }
    }

    impl<R: RepositoryAccess + ?Sized> RepositoryAccess for Box<R> {
        type Error = R::Error;

        fn account<'c>(&'c mut self) -> Box<dyn AccountRepository<Error = Self::Error> + 'c> {
            (**self).account()
        }

        fn account_handoff<'c>(
            &'c mut self,
        ) -> Box<dyn AccountHandoffRepository<Error = Self::Error> + 'c> {
            (**self).account_handoff()
        }

        fn accountability_grant<'c>(
            &'c mut self,
        ) -> Box<dyn AccountabilityGrantRepository<Error = Self::Error> + 'c> {
            (**self).accountability_grant()
        }

        fn agent_key_authorization<'c>(
            &'c mut self,
        ) -> Box<dyn AgentKeyAuthorizationRepository<Error = Self::Error> + 'c> {
            (**self).agent_key_authorization()
        }

        fn circle_capability_grant<'c>(
            &'c mut self,
        ) -> Box<dyn CircleCapabilityGrantRepository<Error = Self::Error> + 'c> {
            (**self).circle_capability_grant()
        }

        fn organization_control<'c>(
            &'c mut self,
        ) -> Box<dyn OrganizationControlRepository<Error = Self::Error> + 'c> {
            (**self).organization_control()
        }

        fn collaboration_capability_grant<'c>(
            &'c mut self,
        ) -> Box<dyn CollaborationCapabilityGrantRepository<Error = Self::Error> + 'c> {
            (**self).collaboration_capability_grant()
        }

        fn dpop_replay<'c>(
            &'c mut self,
        ) -> Box<dyn DpopReplayRepository<Error = Self::Error> + 'c> {
            (**self).dpop_replay()
        }

        fn upstream_oauth_link<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
            (**self).upstream_oauth_link()
        }

        fn upstream_oauth_provider<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
            (**self).upstream_oauth_provider()
        }

        fn upstream_oauth_session<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
            (**self).upstream_oauth_session()
        }

        fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
            (**self).user()
        }

        fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
            (**self).user_email()
        }

        fn user_phone<'c>(&'c mut self) -> Box<dyn UserPhoneRepository<Error = Self::Error> + 'c> {
            (**self).user_phone()
        }

        fn user_password<'c>(
            &'c mut self,
        ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
            (**self).user_password()
        }

        fn user_recovery<'c>(
            &'c mut self,
        ) -> Box<dyn crate::user::UserRecoveryRepository<Error = Self::Error> + 'c> {
            (**self).user_recovery()
        }

        fn user_registration<'c>(
            &'c mut self,
        ) -> Box<dyn UserRegistrationRepository<Error = Self::Error> + 'c> {
            (**self).user_registration()
        }

        fn user_registration_token<'c>(
            &'c mut self,
        ) -> Box<dyn UserRegistrationTokenRepository<Error = Self::Error> + 'c> {
            (**self).user_registration_token()
        }

        fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c> {
            (**self).user_terms()
        }

        fn principal_did<'c>(
            &'c mut self,
        ) -> Box<dyn PrincipalDidRepository<Error = Self::Error> + 'c> {
            (**self).principal_did()
        }

        fn user_totp<'c>(&'c mut self) -> Box<dyn UserTotpRepository<Error = Self::Error> + 'c> {
            (**self).user_totp()
        }

        fn user_primary_handle_preference<'c>(
            &'c mut self,
        ) -> Box<dyn UserPrimaryHandlePreferenceRepository<Error = Self::Error> + 'c> {
            (**self).user_primary_handle_preference()
        }

        fn browser_session<'c>(
            &'c mut self,
        ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
            (**self).browser_session()
        }

        fn app_session<'c>(
            &'c mut self,
        ) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c> {
            (**self).app_session()
        }

        fn audit<'c>(&'c mut self) -> Box<dyn AuditRepository<Error = Self::Error> + 'c> {
            (**self).audit()
        }

        fn handle_audit<'c>(
            &'c mut self,
        ) -> Box<dyn coauth_data::audit::HandleAuditRepository<Error = Self::Error> + 'c> {
            (**self).handle_audit()
        }

        fn notification<'c>(
            &'c mut self,
        ) -> Box<dyn NotificationRepository<Error = Self::Error> + 'c> {
            (**self).notification()
        }

        fn oauth_client<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthClientRepository<Error = Self::Error> + 'c> {
            (**self).oauth_client()
        }

        fn oauth_authorization_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthAuthorizationGrantRepository<Error = Self::Error> + 'c> {
            (**self).oauth_authorization_grant()
        }

        fn oauth_session<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthSessionRepository<Error = Self::Error> + 'c> {
            (**self).oauth_session()
        }

        fn oauth_session_grant<'c>(
            &'c mut self,
        ) -> Box<dyn SessionGrantRepository<Error = Self::Error> + 'c> {
            (**self).oauth_session_grant()
        }

        fn oauth_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthAccessTokenRepository<Error = Self::Error> + 'c> {
            (**self).oauth_access_token()
        }

        fn oauth_refresh_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthRefreshTokenRepository<Error = Self::Error> + 'c> {
            (**self).oauth_refresh_token()
        }

        fn oauth_device_code_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuthDeviceCodeGrantRepository<Error = Self::Error> + 'c> {
            (**self).oauth_device_code_grant()
        }

        fn personal_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn PersonalAccessTokenRepository<Error = Self::Error> + 'c> {
            (**self).personal_access_token()
        }

        fn personal_session<'c>(
            &'c mut self,
        ) -> Box<dyn PersonalSessionRepository<Error = Self::Error> + 'c> {
            (**self).personal_session()
        }

        fn queue_worker<'c>(
            &'c mut self,
        ) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c> {
            (**self).queue_worker()
        }

        fn queue_job<'c>(&'c mut self) -> Box<dyn QueueJobRepository<Error = Self::Error> + 'c> {
            (**self).queue_job()
        }

        fn queue_schedule<'c>(
            &'c mut self,
        ) -> Box<dyn QueueScheduleRepository<Error = Self::Error> + 'c> {
            (**self).queue_schedule()
        }

        fn policy_data<'c>(
            &'c mut self,
        ) -> Box<dyn PolicyDataRepository<Error = Self::Error> + 'c> {
            (**self).policy_data()
        }

        fn notification_template<'c>(
            &'c mut self,
        ) -> Box<dyn NotificationTemplateRepository<Error = Self::Error> + 'c> {
            (**self).notification_template()
        }

        fn workflow<'c>(&'c mut self) -> Box<dyn WorkflowRepository<Error = Self::Error> + 'c> {
            (**self).workflow()
        }
    }
}
