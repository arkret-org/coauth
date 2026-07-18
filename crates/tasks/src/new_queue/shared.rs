use chrono::Duration;
use coauth_data::RepositoryError;
use coauth_storage_postgres::DatabaseError;
use thiserror::Error;

/// Errors that can occur while operating the queue worker.
#[derive(Debug, Error)]
pub enum QueueRunnerError {
    #[error("Failed to setup listener")]
    SetupListener(#[source] tokio_postgres::Error),

    #[error("Failed to get connection from pool")]
    Pool(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error("Invalid schedule expression")]
    InvalidSchedule(#[from] cron::error::Error),

    #[error("Worker is not the leader")]
    NotLeader,
}

// Workers sleep between polls with a small random jitter so they don't all
// wake at exactly the same instant.
pub(super) const MIN_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(900);
pub(super) const MAX_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(1100);

/// Maximum number of jobs a single worker will run concurrently.
pub(super) const MAX_CONCURRENT_JOBS: usize = 10;

/// Maximum number of jobs to pull from the database in a single fetch.
pub(super) const MAX_JOBS_TO_FETCH: usize = 5;

/// Maximum number of times a failed job will be retried before being abandoned.
pub(super) const MAX_ATTEMPTS: usize = 10;

/// Compute the back-off delay for a given attempt number.
///
/// Exponential: 5 s, 10 s, 20 s, 40 s, 80 s, 160 s, 320 s, 650 s, ...
pub(super) fn retry_delay(attempt: usize) -> Duration {
    let exp = u32::try_from(attempt).unwrap_or(u32::MAX);
    Duration::milliseconds(2_i64.saturating_pow(exp) * 5_000)
}
