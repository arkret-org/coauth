use async_trait::async_trait;
use diesel_async::{
    AsyncPgConnection, RunQueryDsl as _,
    pooled_connection::deadpool::{Object as PooledConnection, Pool},
};
use futures_util::{FutureExt, future::BoxFuture};
use coauth_data::{
    BoxRepository, BoxRepositoryFactory, MapErr, Repository, RepositoryAccess, RepositoryError,
    RepositoryFactory, RepositoryTransaction,
    account::AccountRepository,
    app_session::AppSessionRepository,
    audit::AuditRepository,
    notification::{NotificationRepository, NotificationTemplateRepository},
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository, OAuth2ClientRepository,
        OAuth2DeviceCodeGrantRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    personal::PersonalSessionRepository,
    policy_data::PolicyDataRepository,
    queue::{QueueJobRepository, QueueScheduleRepository, QueueWorkerRepository},
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
    user::{
        BrowserSessionRepository, UserEmailRepository, UserPasswordRepository, UserPhoneRepository,
        UserRecoveryRepository, UserRegistrationRepository, UserRegistrationTokenRepository,
        UserRepository, UserTermsRepository, UserTotpRepository,
    },
    workflow::WorkflowRepository,
};
use tracing::Instrument;

use crate::{
    DatabaseError,
    account::PgAccountRepository,
    app_session::PgAppSessionRepository,
    audit::PgAuditRepository,
    notification::{PgNotificationRepository, PgNotificationTemplateRepository},
    oauth2::{
        PgOAuth2AccessTokenRepository, PgOAuth2AuthorizationGrantRepository,
        PgOAuth2ClientRepository, PgOAuth2DeviceCodeGrantRepository,
        PgOAuth2RefreshTokenRepository, PgOAuth2SessionRepository,
    },
    personal::{PgPersonalAccessTokenRepository, PgPersonalSessionRepository},
    pg::telemetry::DB_CLIENT_CONNECTIONS_CREATE_TIME_HISTOGRAM,
    policy_data::PgPolicyDataRepository,
    queue::{
        job::PgQueueJobRepository, schedule::PgQueueScheduleRepository,
        worker::PgQueueWorkerRepository,
    },
    upstream_oauth2::{
        PgUpstreamOAuthLinkRepository, PgUpstreamOAuthProviderRepository,
        PgUpstreamOAuthSessionRepository,
    },
    user::{
        PgBrowserSessionRepository, PgUserEmailRepository, PgUserPasswordRepository,
        PgUserPhoneRepository, PgUserRecoveryRepository, PgUserRegistrationRepository,
        PgUserRegistrationTokenRepository, PgUserRepository, PgUserTermsRepository,
        PgUserTotpRepository,
    },
    workflow::PgWorkflowRepository,
};

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
        Box::new(PgAccountRepository::new(&mut *self.conn))
    }

    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthLinkRepository::new(&mut *self.conn))
    }

    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthProviderRepository::new(&mut *self.conn))
    }

    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthSessionRepository::new(&mut *self.conn))
    }

    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRepository::new(&mut *self.conn))
    }

    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserEmailRepository::new(&mut *self.conn))
    }

    fn user_phone<'c>(&'c mut self) -> Box<dyn UserPhoneRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserPhoneRepository::new(&mut *self.conn))
    }

    fn user_password<'c>(
        &'c mut self,
    ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserPasswordRepository::new(&mut *self.conn))
    }

    fn user_recovery<'c>(
        &'c mut self,
    ) -> Box<dyn UserRecoveryRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRecoveryRepository::new(&mut *self.conn))
    }

    fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserTermsRepository::new(&mut *self.conn))
    }

    fn user_totp<'c>(&'c mut self) -> Box<dyn UserTotpRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserTotpRepository::new(&mut *self.conn))
    }

    fn user_registration<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRegistrationRepository::new(&mut *self.conn))
    }

    fn user_registration_token<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRegistrationTokenRepository::new(&mut *self.conn))
    }

    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgBrowserSessionRepository::new(&mut *self.conn))
    }

    fn app_session<'c>(&'c mut self) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgAppSessionRepository::new(&mut *self.conn))
    }

    fn audit<'c>(&'c mut self) -> Box<dyn AuditRepository<Error = Self::Error> + 'c> {
        Box::new(PgAuditRepository::new(&mut *self.conn))
    }

    fn notification<'c>(&'c mut self) -> Box<dyn NotificationRepository<Error = Self::Error> + 'c> {
        Box::new(PgNotificationRepository::new(&mut *self.conn))
    }

    fn oauth2_client<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2ClientRepository::new(&mut *self.conn))
    }

    fn oauth2_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2AuthorizationGrantRepository::new(&mut *self.conn))
    }

    fn oauth2_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2SessionRepository::new(&mut *self.conn))
    }

    fn oauth2_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2AccessTokenRepository::new(&mut *self.conn))
    }

    fn oauth2_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2RefreshTokenRepository::new(&mut *self.conn))
    }

    fn oauth2_device_code_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2DeviceCodeGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2DeviceCodeGrantRepository::new(&mut *self.conn))
    }

    fn personal_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn coauth_data::personal::PersonalAccessTokenRepository<Error = Self::Error> + 'c>
    {
        Box::new(PgPersonalAccessTokenRepository::new(&mut *self.conn))
    }

    fn personal_session<'c>(
        &'c mut self,
    ) -> Box<dyn PersonalSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgPersonalSessionRepository::new(&mut *self.conn))
    }

    fn queue_worker<'c>(&'c mut self) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueWorkerRepository::new(&mut *self.conn))
    }

    fn queue_job<'c>(&'c mut self) -> Box<dyn QueueJobRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueJobRepository::new(&mut *self.conn))
    }

    fn queue_schedule<'c>(
        &'c mut self,
    ) -> Box<dyn QueueScheduleRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueScheduleRepository::new(&mut *self.conn))
    }

    fn policy_data<'c>(&'c mut self) -> Box<dyn PolicyDataRepository<Error = Self::Error> + 'c> {
        Box::new(PgPolicyDataRepository::new(&mut *self.conn))
    }

    fn notification_template<'c>(
        &'c mut self,
    ) -> Box<dyn NotificationTemplateRepository<Error = Self::Error> + 'c> {
        Box::new(PgNotificationTemplateRepository::new(&mut *self.conn))
    }

    fn workflow<'c>(&'c mut self) -> Box<dyn WorkflowRepository<Error = Self::Error> + 'c> {
        Box::new(PgWorkflowRepository::new(&mut *self.conn))
    }
}
