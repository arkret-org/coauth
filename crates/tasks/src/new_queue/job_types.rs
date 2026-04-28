use async_trait::async_trait;
use coauth_data::queue::JobMetadata;
use serde::de::DeserializeOwned;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use ulid::Ulid;

use crate::State;

pub(super) type JobPayload = serde_json::Value;

/// Metadata and handles passed to every running job.
#[derive(Clone)]
pub struct JobContext {
    /// Unique identifier for this job.
    pub id: Ulid,
    /// Tracing metadata carried from the enqueue site.
    pub metadata: JobMetadata,
    /// Name of the queue this job belongs to.
    pub queue_name: String,
    /// How many times this job has been attempted so far.
    pub attempt: usize,
    /// Wall-clock instant when execution started.
    pub start: Instant,
    /// Token that is cancelled when the worker is shutting down or the job
    /// should be aborted.
    pub cancellation_token: CancellationToken,
}

impl JobContext {
    /// Build a tracing span for this job, linked to the original enqueue span.
    pub fn span(&self) -> Span {
        let span = tracing::info_span!(
            parent: Span::none(),
            "job.run",
            job.id = %self.id,
            job.queue.name = self.queue_name,
            job.attempt = self.attempt,
        );

        span.add_link(self.metadata.span_context());

        span
    }
}

/// Whether a failed job should be retried or permanently abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JobErrorDecision {
    /// Re-enqueue the job with exponential back-off.
    Retry,

    /// Mark the job as permanently failed.
    #[default]
    Fail,
}

impl std::fmt::Display for JobErrorDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry => f.write_str("retry"),
            Self::Fail => f.write_str("fail"),
        }
    }
}

/// Error type returned by [`RunnableJob::run`].
#[derive(Debug, thiserror::Error)]
#[error("Job failed to run, will {decision}")]
pub struct JobError {
    pub(crate) decision: JobErrorDecision,
    #[source]
    pub(crate) error: anyhow::Error,
}

impl JobError {
    /// Construct a retryable error from any error type.
    pub fn retry<T: Into<anyhow::Error>>(error: T) -> Self {
        Self {
            decision: JobErrorDecision::Retry,
            error: error.into(),
        }
    }

    /// Construct a non-retryable (permanent) error from any error type.
    pub fn fail<T: Into<anyhow::Error>>(error: T) -> Self {
        Self {
            decision: JobErrorDecision::Fail,
            error: error.into(),
        }
    }
}

/// Deserialize a job payload into a concrete job type.
pub trait FromJob {
    fn from_job(payload: JobPayload) -> Result<Self, anyhow::Error>
    where
        Self: Sized;
}

impl<T> FromJob for T
where
    T: DeserializeOwned,
{
    fn from_job(payload: JobPayload) -> Result<Self, anyhow::Error> {
        serde_json::from_value(payload).map_err(Into::into)
    }
}

/// A job that can be executed by the worker.
#[async_trait]
pub trait RunnableJob: Send + 'static {
    /// Execute the job.
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError>;

    /// Optional per-job timeout. When elapsed the job's cancellation token is
    /// triggered so the implementation can shut down gracefully.
    fn timeout(&self) -> Option<std::time::Duration> {
        None
    }
}

pub(super) fn box_runnable_job<T: RunnableJob + 'static>(job: T) -> Box<dyn RunnableJob> {
    Box::new(job)
}
