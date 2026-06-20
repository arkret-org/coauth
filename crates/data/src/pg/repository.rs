use async_trait::async_trait;
use coauth_data::account::AccountRepository;
use coauth_data::accountability::AccountabilityGrantRepository;
use coauth_data::agent_key::AgentKeyAuthorizationRepository;
use coauth_data::app_session::AppSessionRepository;
use coauth_data::audit::{AuditRepository, HandleAuditRepository, PgHandleAuditRepository};
use coauth_data::circle_capability::CircleCapabilityGrantRepository;
use coauth_data::collaboration_capability::CollaborationCapabilityGrantRepository;
use coauth_data::notification::{NotificationRepository, NotificationTemplateRepository};
use coauth_data::oauth::{
    OAuthAccessTokenRepository, OAuthAuthorizationGrantRepository, OAuthClientRepository,
    OAuthDeviceCodeGrantRepository, OAuthRefreshTokenRepository, OAuthSessionRepository,
    SessionGrantRepository,
};
use coauth_data::personal::PersonalSessionRepository;
use coauth_data::policy_data::PolicyDataRepository;
use coauth_data::queue::{QueueJobRepository, QueueScheduleRepository, QueueWorkerRepository};
use coauth_data::upstream_oauth::{
    UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
};
use coauth_data::user::{
    BrowserSessionRepository, PrincipalDidRepository, UserEmailRepository, UserPasswordRepository,
    UserPhoneRepository, UserPrimaryHandlePreferenceRepository, UserRecoveryRepository,
    UserRegistrationRepository, UserRegistrationTokenRepository, UserRepository,
    UserTermsRepository, UserTotpRepository,
};
use coauth_data::workflow::WorkflowRepository;
use coauth_data::{
    BoxRepository, BoxRepositoryFactory, MapErr, Repository, RepositoryAccess, RepositoryError,
    RepositoryFactory, RepositoryTransaction,
};
use diesel_async::pooled_connection::deadpool::{Object as PooledConnection, Pool};
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use tracing::Instrument;

use crate::DatabaseError;
use crate::account::PgAccountRepository;
use crate::accountability::PgAccountabilityGrantRepository;
use crate::agent_key::PgAgentKeyAuthorizationRepository;
use crate::app_session::PgAppSessionRepository;
use crate::audit::PgAuditRepository;
use crate::circle_capability::PgCircleCapabilityGrantRepository;
use crate::collaboration_capability::PgCollaborationCapabilityGrantRepository;
use crate::notification::{PgNotificationRepository, PgNotificationTemplateRepository};
use crate::oauth::{
    PgOAuthAccessTokenRepository, PgOAuthAuthorizationGrantRepository, PgOAuthClientRepository,
    PgOAuthDeviceCodeGrantRepository, PgOAuthRefreshTokenRepository, PgOAuthSessionGrantRepository,
    PgOAuthSessionRepository,
};
use crate::personal::{PgPersonalAccessTokenRepository, PgPersonalSessionRepository};
use crate::pg::telemetry::DB_CLIENT_CONNECTIONS_CREATE_TIME_HISTOGRAM;
use crate::policy_data::PgPolicyDataRepository;
use crate::queue::job::PgQueueJobRepository;
use crate::queue::schedule::PgQueueScheduleRepository;
use crate::queue::worker::PgQueueWorkerRepository;
use crate::upstream_oauth::{
    PgUpstreamOAuthLinkRepository, PgUpstreamOAuthProviderRepository,
    PgUpstreamOAuthSessionRepository,
};
use crate::user::{
    PgBrowserSessionRepository, PgPrincipalDidRepository, PgUserEmailRepository,
    PgUserPasswordRepository, PgUserPhoneRepository, PgUserPrimaryHandlePreferenceRepository,
    PgUserRecoveryRepository, PgUserRegistrationRepository, PgUserRegistrationTokenRepository,
    PgUserRepository, PgUserTermsRepository, PgUserTotpRepository,
};
use crate::workflow::PgWorkflowRepository;

/// An implementation of the [`RepositoryFactory`] trait backed by a
/// diesel-async deadpool connection pool.
#[derive(Clone)]
pub struct PgRepositoryFactory {
    pool: Pool<AsyncPgConnection>,
}

impl PgRepositoryFactory {
    /// Create a new [`PgRepositoryFactory`] from a diesel-async connection
    /// pool.
    #[must_use]
    pub fn new(pool: Pool<AsyncPgConnection>) -> Self {
        Self { pool }
    }

    /// Box the factory
    #[must_use]
    pub fn boxed(self) -> BoxRepositoryFactory {
        Box::new(self)
    }

    /// Get the underlying connection pool
    #[must_use]
    pub fn pool(&self) -> &Pool<AsyncPgConnection> {
        &self.pool
    }
}

#[async_trait]
impl RepositoryFactory for PgRepositoryFactory {
    async fn create(&self) -> Result<BoxRepository, RepositoryError> {
        let start = std::time::Instant::now();
        let mut conn = self.pool.get().await.map_err(|e| {
            RepositoryError::from_error(DatabaseError::Pool {
                source: Box::new(e),
            })
        })?;

        // Start a transaction so that all operations within one request are
        // atomic. The transaction is committed by `save()` or rolled back by
        // `cancel()` / on drop.
        diesel::sql_query("BEGIN")
            .execute(&mut *conn)
            .await
            .map_err(|e| RepositoryError::from_error(DatabaseError::from(e)))?;

        let repo = PgRepository::new(conn).boxed();

        // Measure the time it took to create the connection
        let duration = start.elapsed();
        let duration_ms = duration.as_millis().try_into().unwrap_or(u64::MAX);
        DB_CLIENT_CONNECTIONS_CREATE_TIME_HISTOGRAM.record(duration_ms, &[]);

        Ok(repo)
    }
}

/// An implementation of the [`Repository`] trait backed by a diesel-async
/// PostgreSQL connection from a deadpool pool, wrapped in a transaction.
///
/// A `BEGIN` is issued when the repository is created (via
/// [`PgRepositoryFactory::create`]). Calling [`RepositoryTransaction::save`]
/// issues `COMMIT`; calling [`RepositoryTransaction::cancel`] issues
/// `ROLLBACK`. If the repository is dropped without either, the connection is
/// returned to the pool and PostgreSQL will automatically roll back the
/// incomplete transaction.
pub struct PgRepository {
    conn: PooledConnection<AsyncPgConnection>,
}

impl PgRepository {
    /// Create a new [`PgRepository`] from a pooled connection.
    ///
    /// **Important:** The caller is responsible for issuing `BEGIN` before
    /// constructing this, or using [`PgRepositoryFactory::create`] which does
    /// it automatically.
    pub fn new(conn: PooledConnection<AsyncPgConnection>) -> Self {
        Self { conn }
    }

    /// Transform the repository into a type-erased [`BoxRepository`]
    pub fn boxed(self) -> BoxRepository {
        Box::new(MapErr::new(self, RepositoryError::from_error))
    }

    /// Consume this [`PgRepository`], returning the underlying connection.
    pub fn into_inner(self) -> PooledConnection<AsyncPgConnection> {
        self.conn
    }
}

impl Repository<DatabaseError> for PgRepository {}

impl RepositoryTransaction for PgRepository {
    type Error = DatabaseError;

    fn save(mut self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        let span = tracing::info_span!("db.save");
        async move {
            diesel::sql_query("COMMIT").execute(&mut *self.conn).await?;
            Ok(())
        }
        .instrument(span)
        .boxed()
    }

    fn cancel(mut self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        let span = tracing::info_span!("db.cancel");
        async move {
            diesel::sql_query("ROLLBACK")
                .execute(&mut *self.conn)
                .await?;
            Ok(())
        }
        .instrument(span)
        .boxed()
    }
}

impl RepositoryAccess for PgRepository {
    type Error = DatabaseError;

    fn account<'c>(&'c mut self) -> Box<dyn AccountRepository<Error = Self::Error> + 'c> {
        Box::new(PgAccountRepository::new(&mut self.conn))
    }

    fn accountability_grant<'c>(
        &'c mut self,
    ) -> Box<dyn AccountabilityGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgAccountabilityGrantRepository::new(&mut self.conn))
    }

    fn agent_key_authorization<'c>(
        &'c mut self,
    ) -> Box<dyn AgentKeyAuthorizationRepository<Error = Self::Error> + 'c> {
        Box::new(PgAgentKeyAuthorizationRepository::new(&mut self.conn))
    }

    fn circle_capability_grant<'c>(
        &'c mut self,
    ) -> Box<dyn CircleCapabilityGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgCircleCapabilityGrantRepository::new(&mut self.conn))
    }

    fn collaboration_capability_grant<'c>(
        &'c mut self,
    ) -> Box<dyn CollaborationCapabilityGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgCollaborationCapabilityGrantRepository::new(
            &mut self.conn,
        ))
    }

    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthLinkRepository::new(&mut self.conn))
    }

    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthProviderRepository::new(&mut self.conn))
    }

    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthSessionRepository::new(&mut self.conn))
    }

    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRepository::new(&mut self.conn))
    }

    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserEmailRepository::new(&mut self.conn))
    }

    fn user_phone<'c>(&'c mut self) -> Box<dyn UserPhoneRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserPhoneRepository::new(&mut self.conn))
    }

    fn user_password<'c>(
        &'c mut self,
    ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserPasswordRepository::new(&mut self.conn))
    }

    fn user_recovery<'c>(
        &'c mut self,
    ) -> Box<dyn UserRecoveryRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRecoveryRepository::new(&mut self.conn))
    }

    fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserTermsRepository::new(&mut self.conn))
    }

    fn user_totp<'c>(&'c mut self) -> Box<dyn UserTotpRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserTotpRepository::new(&mut self.conn))
    }

    fn user_primary_handle_preference<'c>(
        &'c mut self,
    ) -> Box<dyn UserPrimaryHandlePreferenceRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserPrimaryHandlePreferenceRepository::new(&mut self.conn))
    }

    fn principal_did<'c>(
        &'c mut self,
    ) -> Box<dyn PrincipalDidRepository<Error = Self::Error> + 'c> {
        Box::new(PgPrincipalDidRepository::new(&mut self.conn))
    }

    fn user_registration<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRegistrationRepository::new(&mut self.conn))
    }

    fn user_registration_token<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRegistrationTokenRepository::new(&mut self.conn))
    }

    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgBrowserSessionRepository::new(&mut self.conn))
    }

    fn app_session<'c>(&'c mut self) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgAppSessionRepository::new(&mut self.conn))
    }

    fn audit<'c>(&'c mut self) -> Box<dyn AuditRepository<Error = Self::Error> + 'c> {
        Box::new(PgAuditRepository::new(&mut self.conn))
    }

    fn handle_audit<'c>(&'c mut self) -> Box<dyn HandleAuditRepository<Error = Self::Error> + 'c> {
        Box::new(PgHandleAuditRepository::new(&mut self.conn))
    }

    fn notification<'c>(&'c mut self) -> Box<dyn NotificationRepository<Error = Self::Error> + 'c> {
        Box::new(PgNotificationRepository::new(&mut self.conn))
    }

    fn oauth_client<'c>(&'c mut self) -> Box<dyn OAuthClientRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuthClientRepository::new(&mut self.conn))
    }

    fn oauth_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthAuthorizationGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuthAuthorizationGrantRepository::new(&mut self.conn))
    }

    fn oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuthSessionRepository::new(&mut self.conn))
    }

    fn oauth_session_grant<'c>(
        &'c mut self,
    ) -> Box<dyn SessionGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuthSessionGrantRepository::new(&mut self.conn))
    }

    fn oauth_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthAccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuthAccessTokenRepository::new(&mut self.conn))
    }

    fn oauth_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthRefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuthRefreshTokenRepository::new(&mut self.conn))
    }

    fn oauth_device_code_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuthDeviceCodeGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuthDeviceCodeGrantRepository::new(&mut self.conn))
    }

    fn personal_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn coauth_data::personal::PersonalAccessTokenRepository<Error = Self::Error> + 'c>
    {
        Box::new(PgPersonalAccessTokenRepository::new(&mut self.conn))
    }

    fn personal_session<'c>(
        &'c mut self,
    ) -> Box<dyn PersonalSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgPersonalSessionRepository::new(&mut self.conn))
    }

    fn queue_worker<'c>(&'c mut self) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueWorkerRepository::new(&mut self.conn))
    }

    fn queue_job<'c>(&'c mut self) -> Box<dyn QueueJobRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueJobRepository::new(&mut self.conn))
    }

    fn queue_schedule<'c>(
        &'c mut self,
    ) -> Box<dyn QueueScheduleRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueScheduleRepository::new(&mut self.conn))
    }

    fn policy_data<'c>(&'c mut self) -> Box<dyn PolicyDataRepository<Error = Self::Error> + 'c> {
        Box::new(PgPolicyDataRepository::new(&mut self.conn))
    }

    fn notification_template<'c>(
        &'c mut self,
    ) -> Box<dyn NotificationTemplateRepository<Error = Self::Error> + 'c> {
        Box::new(PgNotificationTemplateRepository::new(&mut self.conn))
    }

    fn workflow<'c>(&'c mut self) -> Box<dyn WorkflowRepository<Error = Self::Error> + 'c> {
        Box::new(PgWorkflowRepository::new(&mut self.conn))
    }
}
