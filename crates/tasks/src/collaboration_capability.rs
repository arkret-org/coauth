//! Background fan-out for collaboration capability grant/revoke events.

use async_trait::async_trait;
use coauth_data::queue::{
    CollaborationCapabilityFanoutJob, CollaborationCapabilityFanoutOperation,
};
use coauth_principal::{PrincipalCapabilityFanoutOperation, PrincipalCapabilityFanoutRequest};
use cokret_core::canonical::canonical_sha256;

use crate::State;
use crate::new_queue::{JobContext, JobError, RunnableJob};

#[async_trait]
impl RunnableJob for CollaborationCapabilityFanoutJob {
    #[tracing::instrument(
        name = "job.collaboration_capability_fanout",
        fields(
            operation = self.operation().as_str(),
            capability_grant_id = self.capability_grant_id(),
            event_id = self.event_id(),
        ),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let computed_digest = canonical_sha256(self.payload()).map_err(JobError::fail)?;
        if computed_digest != self.raw_payload_digest() {
            return Err(JobError::fail(anyhow::anyhow!(
                "collaboration capability fanout payload digest mismatch: expected {}, got {}",
                self.raw_payload_digest(),
                computed_digest
            )));
        }

        let operation = match self.operation() {
            CollaborationCapabilityFanoutOperation::Grant => {
                PrincipalCapabilityFanoutOperation::Grant
            }
            CollaborationCapabilityFanoutOperation::Revoke => {
                PrincipalCapabilityFanoutOperation::Revoke
            }
        };
        let request = PrincipalCapabilityFanoutRequest::new(
            operation,
            self.idempotency_key().to_owned(),
            self.capability_grant_id().to_owned(),
            self.event_id().to_owned(),
            self.raw_payload_digest().to_owned(),
            self.payload().clone(),
        );

        state
            .principal_connection()
            .submit_collaboration_capability_fanout(&request)
            .await
            .map_err(JobError::retry)
    }
}
