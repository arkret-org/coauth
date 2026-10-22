use std::collections::HashMap;
use std::sync::Arc;

use coauth_data::queue::InsertableJob;
use coauth_data::{Clock, RepositoryAccess};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Histogram, UpDownCounter};
use rand_core::RngCore;
use tokio::task::JoinSet;
use tracing::Instrument as _;

use super::job_types::{JobPayload, box_runnable_job};
use super::{
    FromJob, JobContext, JobError, JobErrorDecision, MAX_ATTEMPTS, RunnableJob, retry_delay,
};
use crate::{METER, State};

type JobResult = (std::time::Duration, Result<(), JobError>);
type JobFactory = Arc<dyn Fn(JobPayload) -> Box<dyn RunnableJob> + Send + Sync>;

/// Manages running job tasks and records their outcomes.
pub(super) struct JobTracker {
    /// Maps queue names to the factory that can produce a boxed
    /// [`RunnableJob`].
    factories: HashMap<&'static str, JobFactory>,
    /// All currently-executing Tokio tasks.
    running_jobs: JoinSet<JobResult>,
    /// Maps Tokio task IDs back to their [`JobContext`] so we can record
    /// metrics and update the database when they finish.
    job_contexts: HashMap<tokio::task::Id, JobContext>,
    /// Holds the most recent `join_next_with_id` result that has not yet been
    /// processed.
    last_join_result: Option<Result<(tokio::task::Id, JobResult), tokio::task::JoinError>>,
    /// Records how long each job takes to run.
    job_processing_time: Histogram<u64>,
    /// Gauge for the number of jobs currently executing.
    in_flight_jobs: UpDownCounter<i64>,
}

impl JobTracker {
    pub(super) fn new() -> Self {
        let job_processing_time = METER
            .u64_histogram("job.process.duration")
            .with_description("The time it takes to process a job in milliseconds")
            .with_unit("ms")
            .build();

        let in_flight_jobs = METER
            .i64_up_down_counter("job.active_tasks")
            .with_description("The number of jobs currently in flight")
            .with_unit("{job}")
            .build();

        Self {
            factories: HashMap::new(),
            running_jobs: JoinSet::new(),
            job_contexts: HashMap::new(),
            last_join_result: None,
            job_processing_time,
            in_flight_jobs,
        }
    }

    pub(super) fn register_handler<T>(&mut self)
    where
        T: RunnableJob + InsertableJob + FromJob,
    {
        let factory = |payload: JobPayload| {
            box_runnable_job(T::from_job(payload).expect("Failed to deserialize job"))
        };

        self.factories.insert(T::QUEUE_NAME, Arc::new(factory));
    }

    /// All queue names this tracker knows about.
    pub(super) fn queues(&self) -> Vec<&'static str> {
        self.factories.keys().copied().collect()
    }

    /// Spawn a job as a Tokio task and track it.
    pub(super) fn spawn_job(&mut self, state: State, context: JobContext, payload: JobPayload) {
        let factory = self.factories.get(context.queue_name.as_str()).cloned();
        let task = {
            let context = context.clone();
            let span = context.span();
            async move {
                let job = factory.expect("unknown job factory")(payload);
                tracing::info!(
                    job.id = %context.id,
                    job.queue.name = %context.queue_name,
                    job.attempt = %context.attempt,
                    "Running job"
                );
                let result = match job.timeout() {
                    Some(limit) => {
                        match tokio::time::timeout(limit, job.run(&state, context.clone())).await {
                            Ok(result) => result,
                            Err(_) => {
                                context.cancellation_token.cancel();
                                Err(JobError::retry(anyhow::anyhow!(
                                    "job exceeded its {limit:?} execution timeout"
                                )))
                            }
                        }
                    }
                    None => job.run(&state, context.clone()).await,
                };

                match &result {
                    Ok(()) => {
                        tracing::info!(
                            job.id = %context.id,
                            job.queue.name = %context.queue_name,
                            job.attempt = %context.attempt,
                            "Job completed"
                        );
                    }

                    Err(JobError {
                        decision: JobErrorDecision::Fail,
                        error,
                    }) => {
                        tracing::error!(
                            error = &**error as &dyn std::error::Error,
                            job.id = %context.id,
                            job.queue.name = %context.queue_name,
                            job.attempt = %context.attempt,
                            "Job failed, not retrying"
                        );
                    }

                    Err(JobError {
                        decision: JobErrorDecision::Retry,
                        error,
                    }) if context.attempt < MAX_ATTEMPTS => {
                        let delay = retry_delay(context.attempt);
                        tracing::warn!(
                            error = &**error as &dyn std::error::Error,
                            job.id = %context.id,
                            job.queue.name = %context.queue_name,
                            job.attempt = %context.attempt,
                            "Job failed, will retry in {}s",
                            delay.num_seconds()
                        );
                    }

                    Err(JobError {
                        decision: JobErrorDecision::Retry,
                        error,
                    }) => {
                        tracing::error!(
                            error = &**error as &dyn std::error::Error,
                            job.id = %context.id,
                            job.queue.name = %context.queue_name,
                            job.attempt = %context.attempt,
                            "Job failed too many times, abandoning"
                        );
                    }
                }

                (context.start.elapsed(), result)
            }
            .instrument(span)
        };

        self.in_flight_jobs.add(
            1,
            &[KeyValue::new("job.queue.name", context.queue_name.clone())],
        );

        let handle = self.running_jobs.spawn(task);
        self.job_contexts.insert(handle.id(), context);
    }

    /// `true` when at least one task is executing.
    pub(super) fn has_jobs(&self) -> bool {
        !self.running_jobs.is_empty()
    }

    /// Total number of tracked jobs (running + pending result).
    pub(super) fn running_jobs(&self) -> usize {
        self.running_jobs.len() + usize::from(self.last_join_result.is_some())
    }

    /// Wait for any one running task to finish and stash its result for later
    /// processing.
    pub(super) async fn collect_next_job(&mut self) {
        if self.last_join_result.is_some() {
            return;
        }

        self.last_join_result = self.running_jobs.join_next_with_id().await;
    }

    /// Drain finished job results, updating the database for each one.
    ///
    /// Only process finished tasks. Never wait for a task while holding a
    /// repository: that task may need the same connection pool.
    pub(super) async fn process_jobs<E: std::error::Error + Send + Sync + 'static>(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        repo: &mut dyn RepositoryAccess<Error = E>,
    ) -> Result<(), E> {
        if self.last_join_result.is_none() {
            self.last_join_result = self.running_jobs.try_join_next_with_id();
        }

        while let Some(result) = self.last_join_result.take() {
            match result {
                Ok((id, (elapsed, Ok(())))) => {
                    let context = self
                        .job_contexts
                        .remove(&id)
                        .expect("Job context not found");

                    self.in_flight_jobs.add(
                        -1,
                        &[KeyValue::new("job.queue.name", context.queue_name.clone())],
                    );

                    let elapsed_ms = elapsed.as_millis().try_into().unwrap_or(u64::MAX);
                    self.job_processing_time.record(
                        elapsed_ms,
                        &[
                            KeyValue::new("job.queue.name", context.queue_name),
                            KeyValue::new("job.result", "success"),
                        ],
                    );

                    repo.queue_job()
                        .mark_as_completed(clock, context.id)
                        .await?;
                }

                Ok((id, (elapsed, Err(e)))) => {
                    let context = self
                        .job_contexts
                        .remove(&id)
                        .expect("Job context not found");

                    self.in_flight_jobs.add(
                        -1,
                        &[KeyValue::new("job.queue.name", context.queue_name.clone())],
                    );

                    let reason = format!("{:?}", e.error);
                    repo.queue_job()
                        .mark_as_failed(clock, context.id, &reason)
                        .await?;

                    let elapsed_ms = elapsed.as_millis().try_into().unwrap_or(u64::MAX);
                    match e.decision {
                        JobErrorDecision::Fail => {
                            self.job_processing_time.record(
                                elapsed_ms,
                                &[
                                    KeyValue::new("job.queue.name", context.queue_name),
                                    KeyValue::new("job.result", "failed"),
                                    KeyValue::new("job.decision", "fail"),
                                ],
                            );
                        }

                        JobErrorDecision::Retry if context.attempt < MAX_ATTEMPTS => {
                            self.job_processing_time.record(
                                elapsed_ms,
                                &[
                                    KeyValue::new("job.queue.name", context.queue_name),
                                    KeyValue::new("job.result", "failed"),
                                    KeyValue::new("job.decision", "retry"),
                                ],
                            );

                            let delay = retry_delay(context.attempt);
                            repo.queue_job()
                                .retry(&mut *rng, clock, context.id, delay)
                                .await?;
                        }

                        JobErrorDecision::Retry => {
                            self.job_processing_time.record(
                                elapsed_ms,
                                &[
                                    KeyValue::new("job.queue.name", context.queue_name),
                                    KeyValue::new("job.result", "failed"),
                                    KeyValue::new("job.decision", "abandon"),
                                ],
                            );
                        }
                    }
                }

                Err(e) => {
                    let id = e.id();
                    let context = self
                        .job_contexts
                        .remove(&id)
                        .expect("Job context not found");

                    self.in_flight_jobs.add(
                        -1,
                        &[KeyValue::new("job.queue.name", context.queue_name.clone())],
                    );

                    let elapsed = context
                        .start
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX);

                    let reason = e.to_string();
                    repo.queue_job()
                        .mark_as_failed(clock, context.id, &reason)
                        .await?;

                    if context.attempt < MAX_ATTEMPTS {
                        let delay = retry_delay(context.attempt);
                        tracing::error!(
                            error = &e as &dyn std::error::Error,
                            job.id = %context.id,
                            job.queue.name = %context.queue_name,
                            job.attempt = %context.attempt,
                            job.elapsed = format!("{elapsed}ms"),
                            "Job crashed, will retry in {}s",
                            delay.num_seconds()
                        );

                        self.job_processing_time.record(
                            elapsed,
                            &[
                                KeyValue::new("job.queue.name", context.queue_name),
                                KeyValue::new("job.result", "crashed"),
                                KeyValue::new("job.decision", "retry"),
                            ],
                        );

                        repo.queue_job()
                            .retry(&mut *rng, clock, context.id, delay)
                            .await?;
                    } else {
                        tracing::error!(
                            error = &e as &dyn std::error::Error,
                            job.id = %context.id,
                            job.queue.name = %context.queue_name,
                            job.attempt = %context.attempt,
                            job.elapsed = format!("{elapsed}ms"),
                            "Job crashed too many times, abandoning"
                        );

                        self.job_processing_time.record(
                            elapsed,
                            &[
                                KeyValue::new("job.queue.name", context.queue_name),
                                KeyValue::new("job.result", "crashed"),
                                KeyValue::new("job.decision", "abandon"),
                            ],
                        );
                    }
                }
            }

            self.last_join_result = self.running_jobs.try_join_next_with_id();
        }

        Ok(())
    }
}

#[cfg(test)]
mod pool_wait_tests {
    use std::time::Duration;

    use coauth_data::{RepositoryAccess, SystemClock};
    use coauth_storage_postgres::PgRepository;
    use diesel_async::RunQueryDsl as _;
    use rand_core::SeedableRng as _;
    use tokio_util::sync::CancellationToken;

    use super::{JobContext, JobTracker};

    #[tokio::test]
    async fn draining_jobs_leaves_the_single_pool_connection_available() {
        let database = coauth_storage_postgres::test_utils::setup_test_pool()
            .await
            .expect("test database required");
        let pool = &*database;
        pool.resize(1);
        let clock = SystemClock::default();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let mut repo = PgRepository::new(
            coauth_storage_postgres::pool::get_connection(pool)
                .await
                .unwrap(),
        );
        let worker = repo
            .queue_worker()
            .register(&mut rng, &clock)
            .await
            .unwrap();
        repo.queue_job()
            .schedule(
                &mut rng,
                &clock,
                "checkout-test",
                serde_json::json!({}),
                serde_json::json!({}),
            )
            .await
            .unwrap();
        let job = repo
            .queue_job()
            .reserve(&clock, &worker, &["checkout-test"], 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        drop(repo);

        let mut tracker = JobTracker::new();
        let job_pool = pool.clone();
        let (release, start) = tokio::sync::oneshot::channel();
        let handle = tracker.running_jobs.spawn(async move {
            start.await.unwrap();
            let mut conn = coauth_storage_postgres::pool::get_connection(&job_pool)
                .await
                .unwrap();
            diesel::sql_query("SELECT 1")
                .execute(&mut *conn)
                .await
                .unwrap();
            (Duration::ZERO, Ok(()))
        });
        tracker.job_contexts.insert(
            handle.id(),
            JobContext {
                id: job.id,
                metadata: job.metadata,
                queue_name: job.queue_name,
                attempt: job.attempt,
                start: tokio::time::Instant::now(),
                cancellation_token: CancellationToken::new(),
            },
        );

        // Processing pending tasks with a repository must return immediately.
        let mut repo = PgRepository::new(
            coauth_storage_postgres::pool::get_connection(pool)
                .await
                .unwrap(),
        );
        tokio::time::timeout(
            Duration::from_millis(200),
            tracker.process_jobs(&mut rng, &clock, &mut repo),
        )
        .await
        .unwrap()
        .unwrap();
        drop(repo);
        release.send(()).unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            super::super::repository::drain_jobs(pool, &mut rng, &clock, &mut tracker),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(tracker.running_jobs(), 0);
        let mut conn = coauth_storage_postgres::pool::get_connection(pool)
            .await
            .unwrap();
        #[derive(diesel::QueryableByName)]
        struct JobStatus {
            #[diesel(sql_type = diesel::sql_types::Text)]
            status: String,
        }
        let status: JobStatus =
            diesel::sql_query("SELECT status FROM queue_jobs WHERE queue_name = 'checkout-test'")
                .get_result(&mut *conn)
                .await
                .unwrap();
        assert_eq!(status.status, "completed");
    }
}
