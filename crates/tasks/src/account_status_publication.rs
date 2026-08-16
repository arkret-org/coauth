//! Durable delivery of exact account-status publication bodies.

use arkret_canonical::canonical_sha256;
use async_trait::async_trait;
use coauth_data::queue::AccountStatusPublicationJob;
use coauth_principal::{PrincipalAccountStatusPublicationRequest, PrincipalErasureReceiptRequest};

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
            .map_err(JobError::retry)?;

        let payload: arkret_models_collaboration::events_payloads::account::AccountStatusPayload =
            serde_json::from_value(
                serde_json::to_value(&self.body().publication.event().payload)
                    .map_err(JobError::fail)?,
            )
            .map_err(JobError::fail)?;
        if payload.status
            != arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending
        {
            return Ok(());
        }
        let receipt_request = PrincipalErasureReceiptRequest::new(
            self.destination_name().to_owned(),
            self.event_id().clone(),
            self.body().authority_evidence.account_id.to_string(),
            self.body().authority_evidence.principal_id.clone(),
        );
        let Some(package) = state
            .principal_connection()
            .erasure_receipt(&receipt_request)
            .await
            .map_err(JobError::retry)?
        else {
            return Err(JobError::retry(anyhow::anyhow!(
                "physical erasure receipt is not available yet"
            )));
        };
        tracing::info!(
            receipt_id = package.receipt.receipt_id,
            outcome = ?package.receipt.outcome,
            "verified terminal physical-erasure receipt"
        );
        Ok(())
    }
}
