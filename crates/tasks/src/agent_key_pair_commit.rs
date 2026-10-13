//! Durable retry of the canonical Agent key-pair commit.

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
        // A queued retry can outlive discovery of collision evidence. Check
        // quarantine before performing the external Station commit.
        let mut preflight_repo = state.repository().await.map_err(JobError::retry)?;
        let authorization = preflight_repo
            .agent_key_authorization()
            .lookup_by_event_id(self.authorized_event_id())
            .await
            .map_err(JobError::retry)?
            .ok_or_else(|| {
                JobError::fail(anyhow::anyhow!(
                    "Agent key authorization is absent before commit"
                ))
            })?;
        let mut custody = coauth_data::agent_key::AgentKeyPairCustody::open(
            &authorization.coland_fanout_payload,
            state.encrypter(),
        )
        .map_err(|_| JobError::fail(anyhow::anyhow!("Agent pairing custody unavailable")))?;
        let (station_name, station_id) = state
            .principal_connection()
            .account_status_destination()
            .map_err(JobError::retry)?;
        custody
            .validate_for(&authorization, &station_id, &station_name)
            .map_err(|_| {
                JobError::fail(anyhow::anyhow!("Agent pairing custody binding mismatch"))
            })?;
        if custody.station_name != self.station_name()
            || custody.request_digest != self.request_digest()
            || self.idempotency_key() != self.authorized_event_id()
        {
            return Err(JobError::fail(anyhow::anyhow!(
                "Agent pairing retry identity mismatch"
            )));
        }
        let body = custody.request.clone();
        let quarantined = authorization.quarantined_at.is_some();
        preflight_repo.cancel().await.map_err(JobError::retry)?;
        if quarantined {
            return Err(JobError::fail(anyhow::anyhow!("witness_disagreement")));
        }

        let request = PrincipalAgentKeyPairCommitRequest::new(
            self.idempotency_key().to_owned(),
            self.request_digest().to_owned(),
            self.station_name().to_owned(),
            body.clone(),
        );
        let outcome = match state
            .principal_connection()
            .commit_agent_key_pair(&request)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(refusal) =
                    error.downcast_ref::<coauth_principal::PrincipalAgentKeyPairRefusal>()
                {
                    // Missing local outcome means only that a response was not
                    // received. The Station may have accepted before a later
                    // controller/lifecycle refusal. Preserve immutable custody
                    // and stop automatic retries; never release this Event id.
                    return Err(JobError::fail(anyhow::anyhow!(
                        "Agent pairing exact intent retained after Station refusal: {} {}",
                        refusal.status(),
                        refusal.code().as_str(),
                    )));
                }
                return Err(JobError::retry(error));
            }
        };

        if outcome.authorize_event_ref.as_str() != self.authorized_event_id() {
            return Err(JobError::fail(anyhow::anyhow!(
                "Agent key-pair outcome bound a different authorization Event"
            )));
        }
        custody.station_outcome = Some(outcome.clone());
        let encrypted = custody
            .seal(state.encrypter())
            .map_err(|error| JobError::fail(anyhow::anyhow!(error)))?;
        let mut custody_repo = state.repository().await.map_err(JobError::retry)?;
        if !custody_repo
            .agent_key_authorization()
            .update_pairing_custody(
                state.clock(),
                self.authorized_event_id(),
                encrypted,
                outcome.activation_state,
            )
            .await
            .map_err(JobError::retry)?
        {
            return Err(JobError::retry(anyhow::anyhow!(
                "Agent pairing custody reconciliation pending"
            )));
        }
        // Only an active accepted authorization can trigger durable fanout.
        match outcome.activation_state {
            arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Cancelled => {
                custody_repo.save().await.map_err(JobError::retry)?;
                return Ok(());
            }
            arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::AwaitingSourceCommit => {
                custody_repo.save().await.map_err(JobError::retry)?;
                return Err(JobError::retry(anyhow::anyhow!(
                    "Agent key-pair authorization awaits source Commit"
                )));
            }
            arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active => {}
        }
        let superseded_event_ids = match body.authorize_event.event.payload.get("supersedes") {
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

        let updated = custody_repo
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
        custody_repo.save().await.map_err(JobError::retry)?;
        Ok(())
    }
}
