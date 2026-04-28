use async_trait::async_trait;
use coauth_data::queue::{SendEmailAuthenticationCodeJob, VerifyEmailJob};
use tracing::instrument;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
    notifications,
};

#[async_trait]
impl RunnableJob for VerifyEmailJob {
    #[instrument(
        name = "job.verify_email",
        fields(user_email.id = %self.user_email_id()),
        skip_all,
    )]
    async fn run(&self, _state: &State, _context: JobContext) -> Result<(), JobError> {
        // This job was for the old email verification flow, which has been replaced.
        // We still want to consume existing jobs in the queue, so we just make them
        // permanently fail.
        Err(JobError::fail(anyhow::anyhow!("Not implemented")))
    }
}

#[async_trait]
impl RunnableJob for SendEmailAuthenticationCodeJob {
    #[instrument(
        name = "job.send_email_authentication_code",
        fields(user_email_authentication.id = %self.user_email_authentication_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        notifications::send_email_authentication_code(
            state,
            self.user_email_authentication_id(),
            self.language(),
        )
        .await
    }
}
