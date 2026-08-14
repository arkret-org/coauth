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

/// Back-off curve for durable queue jobs: 5 s, 10 s, 20 s, … saturating at
/// 2,560 s (the value the tenth attempt reached before), with the shared 0–20%
/// jitter span applied on top.
///
/// This is deliberately *not* [`arkret_retry::RetryPolicy::arkret_default`]:
/// `sync/api-conventions.md` §9 scopes its curve — and its 5-retries-per-5-minutes
/// budget — to retries of an HTTP endpoint, which would be wrong for a durable
/// queue whose retry horizon is hours. Only the jitter span is adopted, because
/// the queue previously jittered its poll loop but not its retry schedule.
pub(super) const RETRY_POLICY: arkret_retry::RetryPolicy = arkret_retry::RetryPolicy::exponential(
    std::time::Duration::from_secs(5),
    std::time::Duration::from_secs(2_560),
)
.with_max_retries(10);

/// Maximum number of times a failed job will be retried before being abandoned.
pub(super) const MAX_ATTEMPTS: usize = RETRY_POLICY.max_retries() as usize;

/// Compute the back-off delay for a given attempt number.
pub(super) fn retry_delay(attempt: usize) -> Duration {
    let retry = u32::try_from(attempt).unwrap_or(u32::MAX);
    let mut jitter = arkret_retry::Jitter::from_seed(retry_jitter_seed(retry));
    Duration::from_std(RETRY_POLICY.delay(retry, &mut jitter))
        .unwrap_or_else(|_| Duration::seconds(0))
}

/// Per-call jitter seed so concurrent workers retrying the same attempt number
/// do not schedule themselves onto the same instant.
fn retry_jitter_seed(retry: u32) -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    nanos ^ u64::from(retry).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}
