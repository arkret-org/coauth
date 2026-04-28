//! Miscellaneous cleanup tasks

use coauth_data::queue::{CleanupQueueJobsJob, PruneStalePolicyDataJob};

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

cleanup_ulid_cursor_job!(
    job = CleanupQueueJobsJob,
    span = "job.cleanup_queue_jobs",
    repo = queue_job,
    method = cleanup,
    cutoff = |state: &crate::State| state.clock().now() - chrono::Duration::days(30),
    timeout_secs = 10 * 60,
    empty = "no queue jobs to clean up",
    done = "cleaned up queue jobs",
);

#[async_trait::async_trait]
impl RunnableJob for PruneStalePolicyDataJob {
    #[tracing::instrument(name = "job.prune_stale_policy_data", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let retained_snapshots = 10;

        let removed = repo
            .policy_data()
            .prune(retained_snapshots)
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;
        super::log_cleanup_result(
            removed,
            "no stale policy data to prune",
            "pruned stale policy data",
        );

        Ok(())
    }
}
