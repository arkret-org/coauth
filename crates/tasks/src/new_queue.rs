use chrono::{DateTime, Utc};
use coauth_data::queue::{InsertableJob, Worker};
use cron::Schedule;
use opentelemetry::metrics::{Counter, Histogram};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::State;

mod job_types;
mod leader;
mod repository;
mod runtime;
mod shared;
mod tracker;

pub(crate) use self::job_types::{FromJob, JobContext, JobError, JobErrorDecision, RunnableJob};
use self::leader::ScheduleDefinition;
use self::repository as repo_runtime;
use self::runtime::{ListenerRuntime, WorkerMetrics};
pub use self::shared::QueueRunnerError;
use self::shared::{MAX_ATTEMPTS, retry_delay};
use self::tracker::JobTracker;

/// The main queue worker.
///
/// It connects to PostgreSQL via LISTEN/NOTIFY to be woken up when new jobs
/// arrive, fetches available jobs, and dispatches them to a bounded set of
/// Tokio tasks.
pub struct QueueWorker {
    /// Receives LISTEN/NOTIFY messages from PostgreSQL.
    notification_rx: tokio::sync::mpsc::UnboundedReceiver<tokio_postgres::Notification>,
    /// Kept alive so the underlying LISTEN connection stays open.
    _pg_client: tokio_postgres::Client,
    /// Our registration record in the `queue_workers` table.
    registration: Worker,
    /// Whether this worker currently holds the leader lease.
    am_i_leader: bool,
    /// Timestamp of the last heartbeat we sent.
    last_heartbeat: DateTime<Utc>,
    /// Monotonic time when the previous tick started.
    last_tick_started_at: Instant,
    /// Top-level cancellation token for graceful shutdown.
    cancellation_token: CancellationToken,
    /// Ensures the token is cancelled when this struct is dropped.
    #[expect(dead_code, reason = "This is used on Drop")]
    cancellation_guard: tokio_util::sync::DropGuard,
    /// Shared application state (DB pool, clock, etc.).
    state: State,
    /// Cron schedule definitions evaluated by the leader.
    schedules: Vec<ScheduleDefinition>,
    /// Tracks in-flight job tasks and their results.
    tracker: JobTracker,
    /// Counts why the worker woke up (sleep / task / notification).
    wakeup_reason: Counter<u64>,
    /// Measures total tick duration including leader duties.
    tick_time: Histogram<u64>,
}

impl QueueWorker {
    /// Create a new worker, register it in the database, and set up
    /// LISTEN/NOTIFY on the PostgreSQL connection.
    #[tracing::instrument(
        name = "worker.init",
        skip_all,
        fields(worker.id)
    )]
    pub(crate) async fn new(
        state: State,
        cancellation_token: CancellationToken,
    ) -> Result<Self, QueueRunnerError> {
        let ListenerRuntime {
            client: pg_client,
            notifications: notification_rx,
        } = runtime::connect_listener(&state).await?;

        let (registration, now) = repo_runtime::register_worker(&state).await?;
        tracing::Span::current().record("worker.id", tracing::field::display(registration.id));
        tracing::info!(worker.id = %registration.id, "Registered worker");

        let WorkerMetrics {
            wakeups: wakeup_reason,
            tick_time,
        } = runtime::build_worker_metrics();

        let cancellation_guard = cancellation_token.clone().drop_guard();

        Ok(Self {
            notification_rx,
            _pg_client: pg_client,
            registration,
            am_i_leader: false,
            last_heartbeat: now,
            last_tick_started_at: Instant::now(),
            cancellation_token,
            cancellation_guard,
            state,
            schedules: Vec::new(),
            tracker: JobTracker::new(),
            wakeup_reason,
            tick_time,
        })
    }

    /// Register a concrete job type so the worker knows how to deserialize and
    /// run it.
    pub(crate) fn register_handler<T: RunnableJob + InsertableJob + FromJob>(
        &mut self,
    ) -> &mut Self {
        self.tracker.register_handler::<T>();
        self
    }

    /// Add a cron schedule that the leader will evaluate each tick.
    pub(crate) fn add_schedule<T: InsertableJob>(
        &mut self,
        schedule_name: &'static str,
        expression: Schedule,
        job: T,
    ) -> &mut Self {
        self.schedules
            .push(ScheduleDefinition::new(schedule_name, expression, job));

        self
    }

    /// Run the worker until the cancellation token fires.
    ///
    /// Initialization errors remain fatal, but an established worker treats
    /// database failures from an individual tick as transient. Dropping the
    /// worker also drops its cancellation guard, which shuts down the entire
    /// service, so a single exhausted pool checkout must not end this future.
    pub(crate) async fn run(mut self) {
        if let Err(e) = self.setup_schedules().await {
            tracing::error!(
                error = &e as &dyn std::error::Error,
                "Failed to initialize new queue"
            );
            return;
        }

        let mut consecutive_failures = 0_u32;
        loop {
            if self.cancellation_token.is_cancelled() {
                break;
            }

            match self.run_loop().await {
                Ok(()) => consecutive_failures = 0,
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let retry_delay = runtime_retry_delay(consecutive_failures);
                    tracing::warn!(
                        error = &error as &dyn std::error::Error,
                        consecutive_failures,
                        retry_delay_ms = retry_delay.as_millis(),
                        "Queue tick failed, retrying"
                    );

                    tokio::select! {
                        () = self.cancellation_token.cancelled() => break,
                        () = tokio::time::sleep(retry_delay) => {}
                    }
                }
            }
        }

        if let Err(error) = self.shutdown().await {
            tracing::error!(
                error = &error as &dyn std::error::Error,
                "Failed to shut down new queue cleanly"
            );
        }
    }

    /// Ensure all schedule names are present in the `queue_schedules` table.
    #[tracing::instrument(name = "worker.setup_schedules", skip_all)]
    pub(crate) async fn setup_schedules(&mut self) -> Result<(), QueueRunnerError> {
        repo_runtime::setup_schedules(&self.state, &self.schedules).await
    }

    /// One iteration of the main loop: wait, tick, leader duties.
    #[tracing::instrument(name = "worker.run_loop", skip_all)]
    async fn run_loop(&mut self) -> Result<(), QueueRunnerError> {
        self.wait_until_wakeup().await?;

        if self.cancellation_token.is_cancelled() {
            return Ok(());
        }

        let tick_started_at = Instant::now();
        let tick_gap = tick_started_at.duration_since(self.last_tick_started_at);
        if tick_gap > std::time::Duration::from_secs(5) {
            tracing::warn!(
                worker.id = %self.registration.id,
                tick.gap_ms = tick_gap.as_millis(),
                running_jobs = self.tracker.running_jobs(),
                am_i_leader = self.am_i_leader,
                "Worker loop stalled before the next tick"
            );
        }
        self.last_tick_started_at = tick_started_at;

        let start = Instant::now();
        self.tick().await?;

        if self.am_i_leader {
            self.perform_leader_duties().await?;
        }

        self.record_tick_duration(start);

        Ok(())
    }

    fn record_tick_duration(&self, started_at: Instant) {
        let elapsed_ms = started_at
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        self.tick_time.record(elapsed_ms, &[]);
    }

    /// Drain running jobs and deregister the worker.
    #[tracing::instrument(name = "worker.shutdown", skip_all)]
    async fn shutdown(&mut self) -> Result<(), QueueRunnerError> {
        tracing::info!("Shutting down worker");

        repo_runtime::shutdown_worker(&self.state, &self.registration, &mut self.tracker).await
    }

    /// Block until one of: cancellation, sleep timer, task completion, or
    /// PostgreSQL notification.
    #[tracing::instrument(name = "worker.wait_until_wakeup", skip_all)]
    async fn wait_until_wakeup(&mut self) -> Result<(), QueueRunnerError> {
        runtime::wait_until_wakeup(
            &self.state,
            &self.cancellation_token,
            &mut self.tracker,
            &mut self.notification_rx,
            &self.wakeup_reason,
        )
        .await;

        Ok(())
    }

    /// Heartbeat, leader election, process finished tasks, fetch new jobs.
    #[tracing::instrument(
        name = "worker.tick",
        skip_all,
        fields(worker.id = %self.registration.id),
    )]
    async fn tick(&mut self) -> Result<(), QueueRunnerError> {
        tracing::debug!("Tick");
        let leader = repo_runtime::tick_worker(
            &self.state,
            &self.registration,
            &mut self.last_heartbeat,
            &mut self.tracker,
            &self.cancellation_token,
        )
        .await?;

        self.update_leader_state(leader);

        Ok(())
    }

    fn update_leader_state(&mut self, leader: bool) {
        if leader == self.am_i_leader {
            return;
        }

        self.am_i_leader = leader;
        if leader {
            tracing::info!("I'm the leader now");
        } else {
            tracing::warn!("I am no longer the leader");
        }
    }

    /// Leader-only duties: evaluate cron schedules, clean up dead workers,
    /// mark scheduled jobs as available.
    #[tracing::instrument(name = "worker.perform_leader_duties", skip_all)]
    async fn perform_leader_duties(&mut self) -> Result<(), QueueRunnerError> {
        self.am_i_leader
            .then_some(())
            .ok_or(QueueRunnerError::NotLeader)?;

        leader::run_leader_duties(&self.state, &self.schedules).await
    }
}

fn runtime_retry_delay(consecutive_failures: u32) -> std::time::Duration {
    const MAX_RETRY_SECONDS: u64 = 30;
    let exponent = consecutive_failures.saturating_sub(1).min(5);
    std::time::Duration::from_secs((1_u64 << exponent).min(MAX_RETRY_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::runtime_retry_delay;

    #[test]
    fn runtime_retry_delay_backs_off_and_caps() {
        let seconds = (1..=8)
            .map(|attempt| runtime_retry_delay(attempt).as_secs())
            .collect::<Vec<_>>();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }
}
