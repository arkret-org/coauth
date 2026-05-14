//! Asynchronous job queue for the coauth authentication service.
//!
//! Jobs are enqueued by HTTP handlers and executed in the background by a
//! PostgreSQL-backed worker.  The main categories are:
//!
//! * **Notifications** -- verification codes, password-reset links, etc.
//! * **principal provisioning** -- principal user creation / deactivation.
//! * **Cleanup** -- expiring stale sessions, tokens, and grants.
//! * **Account recovery** -- recovery-ticket workflows.
//!
//! Start here:
//!
//! * [`init`] registers every handler and returns an idle [`QueueWorker`].
//! * [`init_and_run`] does the same but immediately spawns the worker.

use std::sync::{Arc, LazyLock};

use coauth_data::{
    BoxRepository, Clock, PgRepositoryFactory, RepositoryError, RepositoryFactory, SiteConfig,
    UrlBuilder,
};
use coauth_messaging::NotificationCenter;
use coauth_principal::PrincipalServerAdmin;
use diesel_async::{AsyncPgConnection, pooled_connection::deadpool::Pool as DieselPool};
use new_queue::QueueRunnerError;
use opentelemetry::metrics::Meter;
use rand_core::SeedableRng;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub use crate::new_queue::QueueWorker;

// ── Sub-modules ─────────────────────────────────────────────────────────
mod cleanup;
mod email;
mod new_queue;
mod notifications;
mod principal;
mod recovery;
mod sessions;
mod sms;
mod user;

// ── Telemetry ───────────────────────────────────────────────────────────

static METER: LazyLock<Meter> = LazyLock::new(|| {
    let scope = opentelemetry::InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
        .build();

    opentelemetry::global::meter_with_scope(scope)
});

// ── Shared worker state ─────────────────────────────────────────────────

/// Shared state that every background job receives.
#[derive(Clone)]
struct State {
    repo_factory: PgRepositoryFactory,
    /// Raw database URL kept around for tokio-postgres `LISTEN`/`NOTIFY`.
    db_url: String,
    notifier: NotificationCenter,
    wall_clock: Arc<dyn Clock>,
    principal_connection: Arc<dyn PrincipalServerAdmin>,
    urls: UrlBuilder,
    site_cfg: SiteConfig,
}

impl State {
    /// Build a new `State` from its constituent parts.
    pub fn new(
        repo_factory: PgRepositoryFactory,
        db_url: String,
        clock: impl Clock + 'static,
        notifier: NotificationCenter,
        principal: impl PrincipalServerAdmin + 'static,
        urls: UrlBuilder,
        site_cfg: SiteConfig,
    ) -> Self {
        Self {
            repo_factory,
            db_url,
            notifier,
            wall_clock: Arc::new(clock),
            principal_connection: Arc::new(principal),
            urls,
            site_cfg,
        }
    }

    // -- Accessors --------------------------------------------------------

    pub fn pool(&self) -> &DieselPool<AsyncPgConnection> {
        self.repo_factory.pool()
    }

    pub fn database_url(&self) -> &str {
        &self.db_url
    }

    pub fn clock(&self) -> &dyn Clock {
        &self.wall_clock
    }

    pub fn notifications(&self) -> &NotificationCenter {
        &self.notifier
    }

    /// Seed a fresh CSPRNG from the OS entropy source.
    #[allow(clippy::unused_self)]
    pub fn rng(&self) -> rand_chacha::ChaChaRng {
        rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).expect("failed to seed rng")
    }

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        self.repo_factory.create().await
    }

    pub fn principal_connection(&self) -> &dyn PrincipalServerAdmin {
        self.principal_connection.as_ref()
    }

    pub fn url_builder(&self) -> &UrlBuilder {
        &self.urls
    }

    pub fn site_config(&self) -> &SiteConfig {
        &self.site_cfg
    }
}

// ── Handler registration ────────────────────────────────────────────────

/// Wire up every known job type so the worker can dispatch them.
fn register_all_handlers(w: &mut QueueWorker) {
    use coauth_data::queue;

    // Token & session cleanup
    w.register_handler::<queue::CleanupRevokedOAuthAccessTokensJob>();
    w.register_handler::<queue::CleanupExpiredOAuthAccessTokensJob>();
    w.register_handler::<queue::CleanupRevokedOAuthRefreshTokensJob>();
    w.register_handler::<queue::CleanupConsumedOAuthRefreshTokensJob>();
    w.register_handler::<queue::CleanupFinishedOAuthSessionsJob>();
    w.register_handler::<queue::CleanupFinishedUserSessionsJob>();
    w.register_handler::<queue::CleanupExpiredSessionGrantsJob>();

    // Grant & device-code cleanup
    w.register_handler::<queue::CleanupOAuthAuthorizationGrantsJob>();
    w.register_handler::<queue::CleanupOAuthDeviceCodeGrantsJob>();

    // User-related cleanup
    w.register_handler::<queue::CleanupUserRegistrationsJob>();
    w.register_handler::<queue::CleanupUserRecoverySessionsJob>();
    w.register_handler::<queue::CleanupUserEmailAuthenticationsJob>();

    // Upstream OAuth cleanup
    w.register_handler::<queue::CleanupUpstreamOAuthSessionsJob>();
    w.register_handler::<queue::CleanupUpstreamOAuthLinksJob>();

    // Queue self-maintenance
    w.register_handler::<queue::CleanupQueueJobsJob>();

    // IP address cleanup
    w.register_handler::<queue::CleanupInactiveOAuthSessionIpsJob>();
    w.register_handler::<queue::CleanupInactiveUserSessionIpsJob>();

    // User lifecycle
    w.register_handler::<queue::DeactivateUserJob>();
    w.register_handler::<queue::ReactivateUserJob>();

    // principal device management
    w.register_handler::<queue::DeleteDeviceJob>();
    w.register_handler::<queue::ProvisionDeviceJob>();
    w.register_handler::<queue::ProvisionUserJob>();
    w.register_handler::<queue::SyncDevicesJob>();

    // Notifications & messaging
    w.register_handler::<queue::ProcessNotificationDeliveriesJob>();
    w.register_handler::<queue::DispatchNotificationJob>();
    w.register_handler::<queue::SendAccountRecoveryEmailsJob>();
    w.register_handler::<queue::SendEmailAuthenticationCodeJob>();
    w.register_handler::<queue::SendSmsAuthenticationCodeJob>();
    w.register_handler::<queue::VerifyEmailJob>();

    // Session expiry
    w.register_handler::<queue::ExpireInactiveSessionsJob>();
    w.register_handler::<queue::ExpireInactiveOAuthSessionsJob>();
    w.register_handler::<queue::ExpireInactiveUserSessionsJob>();

    // Policy data pruning
    w.register_handler::<queue::PruneStalePolicyDataJob>();

    // Queues that existed in earlier versions but have been superseded.
    w.register_deprecated_queue("cleanup-expired-tokens");
    w.register_deprecated_queue("cleanup-finished-compat-sessions");
    w.register_deprecated_queue("expire-inactive-compat-sessions");
    w.register_deprecated_queue("cleanup-inactive-compat-session-ips");
}

// ── Recurring schedules ─────────────────────────────────────────────────

/// Set up every cron-driven recurring job.
///
/// Schedules are deliberately spread across the hour in ~5-minute increments
/// to keep database load even.
fn attach_recurring_schedules(w: &mut QueueWorker) -> Result<(), QueueRunnerError> {
    use coauth_data::queue;

    // -- High-frequency: notification delivery (every minute) -------------
    w.add_schedule(
        "process-notification-deliveries",
        "15 * * * * *".parse()?,
        queue::ProcessNotificationDeliveriesJob::default(),
    );

    // -- Hourly token cleanup (minutes 0, 5) ------------------------------
    w.add_schedule(
        "cleanup-revoked-oauth-access-tokens",
        "0 0 * * * *".parse()?,
        queue::CleanupRevokedOAuthAccessTokensJob,
    );
    w.add_schedule(
        "cleanup-revoked-oauth-refresh-tokens",
        "0 5 * * * *".parse()?,
        queue::CleanupRevokedOAuthRefreshTokensJob,
    );
    w.add_schedule(
        "cleanup-consumed-oauth-refresh-tokens",
        "0 5 * * * *".parse()?,
        queue::CleanupConsumedOAuthRefreshTokensJob,
    );

    // -- Hourly session cleanup (minutes 15-25) ---------------------------
    w.add_schedule(
        "cleanup-finished-oauth-sessions",
        "0 15 * * * *".parse()?,
        queue::CleanupFinishedOAuthSessionsJob,
    );
    w.add_schedule(
        "cleanup-finished-user-sessions",
        "0 20 * * * *".parse()?,
        queue::CleanupFinishedUserSessionsJob,
    );
    w.add_schedule(
        "cleanup-inactive-oauth-session-ips",
        "0 25 * * * *".parse()?,
        queue::CleanupInactiveOAuthSessionIpsJob,
    );
    w.add_schedule(
        "cleanup-inactive-user-session-ips",
        "0 25 * * * *".parse()?,
        queue::CleanupInactiveUserSessionIpsJob,
    );
    w.add_schedule(
        "cleanup-expired-session-grants",
        // Hourly at minute 27, just ahead of the auth-grant slot.
        "0 27 * * * *".parse()?,
        queue::CleanupExpiredSessionGrantsJob,
    );

    // -- Hourly grant cleanup (minutes 30-35) -----------------------------
    w.add_schedule(
        "cleanup-oauth-authorization-grants",
        "0 30 * * * *".parse()?,
        queue::CleanupOAuthAuthorizationGrantsJob,
    );
    w.add_schedule(
        "cleanup-oauth-device-code-grants",
        "0 35 * * * *".parse()?,
        queue::CleanupOAuthDeviceCodeGrantsJob,
    );

    // -- Hourly upstream OAuth cleanup (minute 40) ------------------------
    w.add_schedule(
        "cleanup-upstream-oauth-sessions",
        "0 40 * * * *".parse()?,
        queue::CleanupUpstreamOAuthSessionsJob,
    );
    w.add_schedule(
        "cleanup-upstream-oauth-links",
        "0 40 * * * *".parse()?,
        queue::CleanupUpstreamOAuthLinksJob,
    );

    // -- Hourly user-related cleanup (minutes 45-55) ----------------------
    w.add_schedule(
        "cleanup-user-registrations",
        "0 45 * * * *".parse()?,
        queue::CleanupUserRegistrationsJob,
    );
    w.add_schedule(
        "cleanup-user-recovery-sessions",
        "0 50 * * * *".parse()?,
        queue::CleanupUserRecoverySessionsJob,
    );
    w.add_schedule(
        "cleanup-user-email-authentications",
        "0 50 * * * *".parse()?,
        queue::CleanupUserEmailAuthenticationsJob,
    );
    w.add_schedule(
        "cleanup-queue-jobs",
        "0 55 * * * *".parse()?,
        queue::CleanupQueueJobsJob,
    );

    // -- Less frequent schedules ------------------------------------------
    w.add_schedule(
        "cleanup-expired-oauth-access-tokens",
        // Every 4 hours at minute 5
        "0 5 */4 * * *".parse()?,
        queue::CleanupExpiredOAuthAccessTokensJob,
    );
    w.add_schedule(
        "expire-inactive-sessions",
        // Every 15 minutes at second 30
        "30 */15 * * * *".parse()?,
        queue::ExpireInactiveSessionsJob,
    );
    w.add_schedule(
        "prune-stale-policy-data",
        // Once a day at 02:00
        "0 0 2 * * *".parse()?,
        queue::PruneStalePolicyDataJob,
    );

    Ok(())
}

// ── Public entry points ─────────────────────────────────────────────────

/// Build the worker with all handlers and schedules but do **not** start it.
///
/// Useful in integration tests where you want to drive the worker manually.
///
/// # Errors
///
/// Returns an error when the initial database connection fails.
pub async fn init(
    repository_factory: PgRepositoryFactory,
    database_url: String,
    clock: impl Clock + 'static,
    notifications: &NotificationCenter,
    principal: impl PrincipalServerAdmin + 'static,
    url_builder: UrlBuilder,
    site_config: &SiteConfig,
    cancellation_token: CancellationToken,
) -> Result<QueueWorker, QueueRunnerError> {
    let shared = State::new(
        repository_factory,
        database_url,
        clock,
        notifications.clone(),
        principal,
        url_builder,
        site_config.clone(),
    );

    let mut worker = QueueWorker::new(shared, cancellation_token).await?;

    register_all_handlers(&mut worker);
    attach_recurring_schedules(&mut worker)?;

    Ok(worker)
}

/// Build the worker **and** spawn it onto the given [`TaskTracker`].
///
/// # Errors
///
/// Returns an error when the initial database connection fails.
#[expect(clippy::too_many_arguments, reason = "this is fine")]
pub async fn init_and_run(
    repository_factory: PgRepositoryFactory,
    database_url: String,
    clock: impl Clock + 'static,
    notifications: &NotificationCenter,
    principal: impl PrincipalServerAdmin + 'static,
    url_builder: UrlBuilder,
    site_config: &SiteConfig,
    cancellation_token: CancellationToken,
    task_tracker: &TaskTracker,
) -> Result<(), QueueRunnerError> {
    let worker = init(
        repository_factory,
        database_url,
        clock,
        notifications,
        principal,
        url_builder,
        site_config,
        cancellation_token,
    )
    .await?;

    task_tracker.spawn(worker.run());

    Ok(())
}
