use async_trait::async_trait;
use coauth_data::account::AccountRepository;
use coauth_data::account_handoff::AccountHandoffRepository;
use coauth_data::accountability::AccountabilityGrantRepository;
use coauth_data::agent_key::AgentKeyAuthorizationRepository;
use coauth_data::app_session::AppSessionRepository;
use coauth_data::audit::{AuditRepository, HandleAuditRepository};
use coauth_data::circle_capability::CircleCapabilityGrantRepository;
use coauth_data::collaboration_capability::CollaborationCapabilityGrantRepository;
use coauth_data::did_binding::VerifiedDidBindingRepository;
use coauth_data::dpop_replay::DpopReplayRepository;
use coauth_data::erasure_request::UserErasureRequestRepository;
use coauth_data::notification::{NotificationRepository, NotificationTemplateRepository};
use coauth_data::oauth::{
    OAuthAccessTokenRepository, OAuthAuthorizationGrantRepository, OAuthClientRepository,
    OAuthDeviceCodeGrantRepository, OAuthRefreshTokenRepository, OAuthSessionRepository,
    SessionGrantRepository,
};
use coauth_data::organization_control::OrganizationControlRepository;
use coauth_data::personal::PersonalSessionRepository;
use coauth_data::policy_data::PolicyDataRepository;
use coauth_data::queue::{QueueJobRepository, QueueScheduleRepository, QueueWorkerRepository};
use coauth_data::storage::recovery_authority::RecoveryAuthorityRepository;
use coauth_data::upstream_oauth::{
    UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
};
use coauth_data::user::{
    BrowserSessionRepository, PrincipalDidRepository, UserEmailRepository, UserPasswordRepository,
    UserPhoneRepository, UserPrimaryHandlePreferenceRepository, UserRecoveryRepository,
    UserRegistrationRepository, UserRegistrationTokenRepository, UserRepository,
    UserTermsRepository,
};
use coauth_data::{
    AccountStatusLedgerRepository, BoxRepository, BoxRepositoryFactory, MapErr, Repository,
    RepositoryAccess, RepositoryError, RepositoryFactory, RepositoryTransaction,
};
use diesel_async::pooled_connection::deadpool::{Object as PooledConnection, Pool};
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use tracing::Instrument;

use crate::DatabaseError;
use crate::account::PgAccountRepository;
use crate::account_handoff::PgAccountHandoffRepository;
use crate::account_status::PgAccountStatusLedgerRepository;
use crate::accountability::PgAccountabilityGrantRepository;
use crate::agent_key::PgAgentKeyAuthorizationRepository;
use crate::app_session::PgAppSessionRepository;
use crate::audit::PgAuditRepository;
use crate::circle_capability::PgCircleCapabilityGrantRepository;
use crate::collaboration_capability::PgCollaborationCapabilityGrantRepository;
use crate::did_binding::PgVerifiedDidBindingRepository;
use crate::dpop_replay::PgDpopReplayRepository;
use crate::erasure_request::PgUserErasureRequestRepository;
use crate::handle_audit::PgHandleAuditRepository;
use crate::notification::PgNotificationRepository;
use crate::notification_template::PgNotificationTemplateRepository;
use crate::oauth::{
    PgOAuthAccessTokenRepository, PgOAuthAuthorizationGrantRepository, PgOAuthClientRepository,
    PgOAuthDeviceCodeGrantRepository, PgOAuthRefreshTokenRepository, PgOAuthSessionGrantRepository,
    PgOAuthSessionRepository,
};
use crate::organization_control::PgOrganizationControlRepository;
use crate::personal::{PgPersonalAccessTokenRepository, PgPersonalSessionRepository};
use crate::policy_data::PgPolicyDataRepository;
use crate::queue::job::PgQueueJobRepository;
use crate::queue::schedule::PgQueueScheduleRepository;
use crate::queue::worker::PgQueueWorkerRepository;
use crate::recovery_authority::PgRecoveryAuthorityRepository;
use crate::station_trust::PgStationTrustRepository;
use crate::telemetry::DB_CLIENT_CONNECTIONS_CREATE_TIME_HISTOGRAM;
use crate::upstream_oauth::{
    PgUpstreamOAuthLinkRepository, PgUpstreamOAuthProviderRepository,
    PgUpstreamOAuthSessionRepository,
};
use crate::user::{
    PgBrowserSessionRepository, PgPrincipalDidRepository, PgUserEmailRepository,
    PgUserPasswordRepository, PgUserPhoneRepository, PgUserPrimaryHandlePreferenceRepository,
    PgUserRecoveryRepository, PgUserRegistrationRepository, PgUserRegistrationTokenRepository,
    PgUserRepository, PgUserTermsRepository,
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
        let conn = self.pool.get().await.map_err(|e| {
            RepositoryError::from_error(DatabaseError::Pool {
                source: Box::new(e),
            })
        })?;

        let mut repo = PgRepository::new(conn);
        // Start a transaction so that all operations within one request are
        // atomic. The transaction is committed by `save()` or rolled back by
        // `cancel()` / on drop.
        diesel::sql_query("BEGIN")
            .execute(repo.connection())
            .await
            .map_err(|e| RepositoryError::from_error(DatabaseError::from(e)))?;

        let repo = repo.boxed();

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
/// `ROLLBACK`. If the repository is dropped without either, its physical
/// connection is detached from the pool and closed, so PostgreSQL rolls back
/// the transaction before another checkout can observe it.
pub struct PgRepository {
    conn: Option<PooledConnection<AsyncPgConnection>>,
}

impl PgRepository {
    /// Create a new [`PgRepository`] from a pooled connection.
    ///
    /// The factory wraps the connection before issuing `BEGIN` so cancellation
    /// during transaction creation also closes the physical connection.
    pub fn new(conn: PooledConnection<AsyncPgConnection>) -> Self {
        Self { conn: Some(conn) }
    }

    /// Transform the repository into a type-erased [`BoxRepository`]
    pub fn boxed(self) -> BoxRepository {
        Box::new(MapErr::new(self, |error: DatabaseError| {
            if error.is_unique_violation() {
                RepositoryError::from_unique_violation(error)
            } else {
                RepositoryError::from_error(error)
            }
        }))
    }

    /// Borrow the connection for SQL while retaining its cancellation guard.
    pub fn connection(&mut self) -> &mut AsyncPgConnection {
        self.conn.as_mut().expect("open repository transaction")
    }
}

impl Drop for PgRepository {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            drop(PooledConnection::take(conn));
        }
    }
}

impl Repository<DatabaseError> for PgRepository {}

impl RepositoryTransaction for PgRepository {
    type Error = DatabaseError;

    fn save(mut self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        let span = tracing::info_span!("db.save");
        async move {
            diesel::sql_query("COMMIT")
                .execute(self.connection())
                .await?;
            drop(self.conn.take());
            Ok(())
        }
        .instrument(span)
        .boxed()
    }

    fn cancel(mut self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        let span = tracing::info_span!("db.cancel");
        async move {
            diesel::sql_query("ROLLBACK")
                .execute(self.connection())
                .await?;
            drop(self.conn.take());
            Ok(())
        }
        .instrument(span)
        .boxed()
    }
}

/// Implement [`RepositoryAccess`] for [`PgRepository`] from a list of
/// `accessor: DataTrait => PgRepositoryType` triples.
///
/// Every accessor has the same body — box the backend repository over a
/// borrow of the open connection — so only the three names differ. Keeping
/// them as one list makes the diff for a new repository a single line and
/// stops the trait and its backend implementation from drifting apart.
macro_rules! pg_repository_access {
    ($(
        $name:ident: $($repo:ident)::+ => $pg:ident
    ),* $(,)?) => {
        impl RepositoryAccess for PgRepository {
            type Error = DatabaseError;

            $(
                fn $name<'c>(&'c mut self)
                -> Box<dyn $($repo)::+ <Error = Self::Error> + 'c> {
                    Box::new($pg::new(self.connection()))
                }
            )*
        }
    };
}

pg_repository_access! {
    account: AccountRepository => PgAccountRepository,
    account_handoff: AccountHandoffRepository => PgAccountHandoffRepository,
    account_status_ledger: AccountStatusLedgerRepository => PgAccountStatusLedgerRepository,
    accountability_grant: AccountabilityGrantRepository => PgAccountabilityGrantRepository,
    agent_key_authorization: AgentKeyAuthorizationRepository => PgAgentKeyAuthorizationRepository,
    circle_capability_grant: CircleCapabilityGrantRepository => PgCircleCapabilityGrantRepository,
    collaboration_capability_grant: CollaborationCapabilityGrantRepository => PgCollaborationCapabilityGrantRepository,
    organization_control: OrganizationControlRepository => PgOrganizationControlRepository,
    verified_did_binding: VerifiedDidBindingRepository => PgVerifiedDidBindingRepository,
    dpop_replay: DpopReplayRepository => PgDpopReplayRepository,
    user_erasure_request: UserErasureRequestRepository => PgUserErasureRequestRepository,
    recovery_authority: RecoveryAuthorityRepository => PgRecoveryAuthorityRepository,
    upstream_oauth_link: UpstreamOAuthLinkRepository => PgUpstreamOAuthLinkRepository,
    upstream_oauth_provider: UpstreamOAuthProviderRepository => PgUpstreamOAuthProviderRepository,
    upstream_oauth_session: UpstreamOAuthSessionRepository => PgUpstreamOAuthSessionRepository,
    user: UserRepository => PgUserRepository,
    user_email: UserEmailRepository => PgUserEmailRepository,
    user_phone: UserPhoneRepository => PgUserPhoneRepository,
    user_password: UserPasswordRepository => PgUserPasswordRepository,
    user_recovery: UserRecoveryRepository => PgUserRecoveryRepository,
    user_terms: UserTermsRepository => PgUserTermsRepository,
    user_primary_handle_preference: UserPrimaryHandlePreferenceRepository => PgUserPrimaryHandlePreferenceRepository,
    principal_did: PrincipalDidRepository => PgPrincipalDidRepository,
    user_registration: UserRegistrationRepository => PgUserRegistrationRepository,
    user_registration_token: UserRegistrationTokenRepository => PgUserRegistrationTokenRepository,
    browser_session: BrowserSessionRepository => PgBrowserSessionRepository,
    app_session: AppSessionRepository => PgAppSessionRepository,
    audit: AuditRepository => PgAuditRepository,
    handle_audit: HandleAuditRepository => PgHandleAuditRepository,
    notification: NotificationRepository => PgNotificationRepository,
    oauth_client: OAuthClientRepository => PgOAuthClientRepository,
    oauth_authorization_grant: OAuthAuthorizationGrantRepository => PgOAuthAuthorizationGrantRepository,
    oauth_session: OAuthSessionRepository => PgOAuthSessionRepository,
    oauth_session_grant: SessionGrantRepository => PgOAuthSessionGrantRepository,
    oauth_access_token: OAuthAccessTokenRepository => PgOAuthAccessTokenRepository,
    oauth_refresh_token: OAuthRefreshTokenRepository => PgOAuthRefreshTokenRepository,
    oauth_device_code_grant: OAuthDeviceCodeGrantRepository => PgOAuthDeviceCodeGrantRepository,
    personal_access_token: coauth_data::personal::PersonalAccessTokenRepository => PgPersonalAccessTokenRepository,
    personal_session: PersonalSessionRepository => PgPersonalSessionRepository,
    queue_worker: QueueWorkerRepository => PgQueueWorkerRepository,
    queue_job: QueueJobRepository => PgQueueJobRepository,
    queue_schedule: QueueScheduleRepository => PgQueueScheduleRepository,
    policy_data: PolicyDataRepository => PgPolicyDataRepository,
    station_trust: coauth_data::storage::station_trust::StationTrustRepository => PgStationTrustRepository,
    notification_template: NotificationTemplateRepository => PgNotificationTemplateRepository,
}
