//! Durable retry of the canonical Agent key-pair commit.

use arkret_canonical::canonical_sha256;
use async_trait::async_trait;
use coauth_data::RepositoryAccess as _;
use coauth_data::queue::AgentKeyPairCommitJob;
use coauth_principal::PrincipalAgentKeyPairCommitRequest;

use crate::State;
use crate::new_queue::{JobContext, JobError, RunnableJob};

#[async_trait]
impl RunnableJob for AgentKeyPairCommitJob {
    #[tracing::instrument(
        name = "job.agent_key_pair_commit",
        fields(authorized_event_id = self.authorized_event_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let computed_digest = canonical_sha256(self.body()).map_err(JobError::fail)?;
        if computed_digest != self.request_digest() {
            return Err(JobError::fail(anyhow::anyhow!(
                "Agent key-pair request digest mismatch: expected {}, got {}",
                self.request_digest(),
                computed_digest
            )));
        }
        if self.body().authorize_event.event_id.as_str() != self.authorized_event_id() {
            return Err(JobError::fail(anyhow::anyhow!(
                "Agent key-pair Event id does not match the queued job"
            )));
        }

        let request = PrincipalAgentKeyPairCommitRequest::new(
            self.idempotency_key().to_owned(),
            self.request_digest().to_owned(),
            self.principal_server_name().to_owned(),
            self.body().clone(),
        );
        state
            .principal_connection()
            .commit_agent_key_pair(&request)
            .await
            .map_err(JobError::retry)?;

        let superseded_event_ids = match self.body().authorize_event.payload.get("supersedes") {
            None => Vec::new(),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(|value| {
                    value
                        .get("authorized_event_ref")
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| {
                            JobError::fail(anyhow::anyhow!(
                                "queued Agent pairing supersedes entry omitted authorized_event_ref"
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(JobError::fail(anyhow::anyhow!(
                    "queued Agent pairing supersedes must be an array"
                )));
            }
        };

        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let updated = repo
            .agent_key_authorization()
            .mark_fanout_delivered_and_revoke(
                state.clock(),
                self.authorized_event_id(),
                &superseded_event_ids,
                arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING,
            )
            .await
            .map_err(JobError::retry)?;
        if !updated {
            return Err(JobError::retry(anyhow::anyhow!(
                "Agent key authorization disappeared before commit reconciliation"
            )));
        }
        repo.save().await.map_err(JobError::retry)?;
        Ok(())
    }
}
