//! Durable delivery of exact account-status publication bodies.

use arkret_canonical::canonical_sha256;
use async_trait::async_trait;
use coauth_data::queue::AccountStatusPublicationJob;
use coauth_data::storage::RepositoryAccess as _;
use coauth_principal::{PrincipalAccountStatusPublicationRequest, PrincipalErasureReceiptRequest};

use crate::State;
use crate::new_queue::{JobContext, JobError, RunnableJob};

#[async_trait]
impl RunnableJob for AccountStatusPublicationJob {
    #[tracing::instrument(
        name = "job.account_status_publication",
        fields(
            destination = self.destination_name(),
            record_id = %self.record_id(),
        ),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        self.body().validate_shape().map_err(JobError::fail)?;
        if self.record_id() != &self.body().publication.record().account_status_record_id {
            return Err(JobError::fail(anyhow::anyhow!(
                "account-status publication record id does not match immutable job index"
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
        let outcome = state
            .principal_connection()
            .submit_account_status_publication(&request)
            .await
            .map_err(JobError::retry)?;
        if outcome.status
            == arkret_models_collaboration::account_lifecycle::AccountStatusPublicationStatus::DependencyMissing
        {
            let required = outcome.required_status_seq.ok_or_else(|| {
                JobError::fail(anyhow::anyhow!(
                    "dependency_missing outcome omits required_status_seq"
                ))
            })?;
            let record = self.body().publication.record();
            if required >= record.status_seq {
                return Err(JobError::fail(anyhow::anyhow!(
                    "dependency_missing required_status_seq does not precede submitted record"
                )));
            }
            let limit = u16::try_from(record.status_seq - required).map_err(JobError::fail)?;
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            let missing = repo
                .account_status_ledger()
                .resolve(
                    record.account_authority_id.as_str(),
                    record.account_id.as_str(),
                    required,
                    limit.min(128),
                )
                .await
                .map_err(JobError::retry)?;
            if missing.is_empty() {
                return Err(JobError::fail(anyhow::anyhow!(
                    "issuer ledger cannot satisfy receiver predecessor gap"
                )));
            }
            for predecessor in missing {
                let body = arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody {
                    publication: arkret_models_collaboration::account_lifecycle::AccountStatusPublication::Initial(
                        arkret_models_collaboration::account_lifecycle::AccountStatusInitialPublication {
                            record: predecessor.clone(),
                        },
                    ),
                };
                let body_digest = arkret_wire::Hash::new(
                    canonical_sha256(&body).map_err(JobError::fail)?,
                )
                .map_err(JobError::fail)?;
                let recovery = PrincipalAccountStatusPublicationRequest::new(
                    self.destination_name().to_owned(),
                    predecessor.account_status_record_id.to_string(),
                    body_digest,
                    body,
                );
                let recovered = state
                    .principal_connection()
                    .submit_account_status_publication(&recovery)
                    .await
                    .map_err(JobError::retry)?;
                if !matches!(
                    recovered.status,
                    arkret_models_collaboration::account_lifecycle::AccountStatusPublicationStatus::Accepted
                        | arkret_models_collaboration::account_lifecycle::AccountStatusPublicationStatus::Duplicate
                ) {
                    return Err(JobError::retry(anyhow::anyhow!(
                        "receiver still reports an account-status predecessor gap"
                    )));
                }
            }
            return Err(JobError::retry(anyhow::anyhow!(
                "account-status predecessor gap repaired; retrying target record"
            )));
        }

        let record = self.body().publication.record();
        if record.status
            != arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending
        {
            return Ok(());
        }
        let receipt_request = PrincipalErasureReceiptRequest::new(
            self.destination_name().to_owned(),
            self.record_id().clone(),
            record.account_id.to_string(),
            record.principal_authority.principal_id.clone(),
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
