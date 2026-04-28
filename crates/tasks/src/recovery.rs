use async_trait::async_trait;
use coauth_data::queue::SendAccountRecoveryEmailsJob;
use tracing::instrument;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
    notifications,
};

/// Job to send account recovery emails for a given recovery session.
#[async_trait]
impl RunnableJob for SendAccountRecoveryEmailsJob {
    #[instrument(
        name = "job.send_account_recovery_email",
        fields(
            user_recovery_session.id = %self.user_recovery_session_id(),
            user_recovery_session.email,
        ),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        notifications::send_account_recovery(state, self.user_recovery_session_id()).await
    }
}
