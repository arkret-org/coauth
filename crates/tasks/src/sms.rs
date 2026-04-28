use async_trait::async_trait;
use coauth_data::queue::SendSmsAuthenticationCodeJob;
use tracing::instrument;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
    notifications,
};

#[async_trait]
impl RunnableJob for SendSmsAuthenticationCodeJob {
    #[instrument(
        name = "job.send_sms_authentication_code",
        fields(user_phone_authentication.id = %self.user_phone_authentication_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        notifications::send_sms_authentication_code(
            state,
            self.user_phone_authentication_id(),
            self.language(),
        )
        .await
    }
}
