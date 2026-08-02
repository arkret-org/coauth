//! Durable delivery of exact account-status publication bodies.

use arkret_canonical::canonical_sha256;
use async_trait::async_trait;
use coauth_data::queue::AccountStatusPublicationJob;
use coauth_principal::PrincipalAccountStatusPublicationRequest;

use crate::State;
use crate::new_queue::{JobContext, JobError, RunnableJob};

#[async_trait]
impl RunnableJob for AccountStatusPublicationJob {
    #[tracing::instrument(
        name = "job.account_status_publication",
        fields(
            destination = self.destination_name(),
            event_id = %self.event_id(),
        ),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        self.body().validate_shape().map_err(JobError::fail)?;
        if self.event_id() != &self.body().publication.event().event_id {
            return Err(JobError::fail(anyhow::anyhow!(
                "account-status publication event id does not match immutable job index"
            )));
        }
        let digest = arkret_wire::Hash::new(canonical_sha256(self.body()).map_err(JobError::fail)?)
            .map_err(JobError::fail)?;
        if &digest != self.body_digest() {
            return Err(JobError::fail(anyhow::anyhow!(
                "account-status publication body digest mismatch"
            )));
        }

        let request = PrincipalAccountStatusPublicationRequest::new(
            self.destination_name().to_owned(),
            self.idempotency_key().to_owned(),
            digest,
            self.body().clone(),
        );
        state
            .principal_connection()
            .submit_account_status_publication(&request)
            .await
            .map_err(JobError::retry)
    }
}
