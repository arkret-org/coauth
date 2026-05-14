use async_trait::async_trait;
use coauth_data::queue::SendEmailAuthenticationCodeJob;
use tracing::instrument;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
    notifications,
};

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
