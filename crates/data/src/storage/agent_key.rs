//! Agent key authorization + agent-key-proof replay repository (AKP-0008).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::Clock;
use rand_core::RngCore;

use crate::accountability::AccountabilityGrantFanoutState;
use crate::agent_key::AgentKeyAuthorization;
use crate::repository_impl;

/// Parameters used to persist an accepted agent key authorization.
#[derive(Debug, Clone)]
pub struct NewAgentKeyAuthorization {
    /// Minted `ak:event:<uuid7>` authorization event id.
    pub authorized_event_id: String,
    /// Agent principal DID the authorized key belongs to.
    pub agent_id: String,
    /// Stable key id.
    pub key_id: String,
    /// DID URL of the authorized verification method.
    pub verification_method: String,
    /// Spec `PublicKey` JSON object submitted at pairing.
    pub public_key: serde_json::Value,
    /// Controller DID accountable for the agent.
    pub accountable_principal_id: String,
    /// Authorized key scope tier.
    pub agent_key_scope: String,
    /// Audience values the key proof must match.
    pub audience: Vec<String>,
    /// Authorization issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// Optional authorization expiry. `None` means the authorization never
    /// expires by time and stays valid until revoked (key-management §3.6.1).
    pub expires_at: Option<DateTime<Utc>>,
    /// Pairing request id consumed to produce this authorization.
    pub pairing_request_id: String,
    /// `sha256:<hex>` digest the pairing proof was bound to.
    pub request_canonical_digest: String,
    /// `sha256:<hex>` digest of the canonical fan-out payload.
    pub raw_payload_digest: String,
    /// Initial soland fan-out state.
    pub soland_fanout_state: AccountabilityGrantFanoutState,
    /// Idempotency key used for soland fan-out and retry jobs.
    pub soland_fanout_idempotency_key: String,
    /// Payload queued for soland fan-out.
    pub soland_fanout_payload: serde_json::Value,
    /// Initial fan-out attempt count.
    pub soland_fanout_attempt: i32,
    /// Next retry timestamp, if a retry is scheduled.
    pub soland_fanout_next_retry_at: Option<DateTime<Utc>>,
    /// Terminal failure reason, if fan-out entered dead-letter state.
    pub soland_fanout_dead_letter_reason: Option<String>,
}

/// Parameters used to record a one-time consumption of an agent-key-proof
/// challenge.
#[derive(Debug, Clone)]
pub struct NewAgentSessionProofReplay {
    /// Agent principal DID the proof authenticated.
    pub agent_id: String,
    /// Verification method DID URL the proof was signed with.
    pub verification_method: String,
    /// One-time challenge value consumed.
    pub challenge: String,
    /// One-time nonce value consumed.
    pub nonce: String,
    /// `sha256:<hex>` digest the proof covered.
    pub request_canonical_digest: String,
    /// Audience the proof asserted.
    pub audience: String,
    /// Proof `expires_at`.
    pub proof_expires_at: DateTime<Utc>,
    /// Replay-table prune horizon (`proof_expires_at` + grace window).
    pub prune_after: DateTime<Utc>,
}

/// Repository for durable agent key authorizations and the agent-key-proof
/// single-use replay table.
#[async_trait]
pub trait AgentKeyAuthorizationRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Insert a new durable agent key authorization.
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAgentKeyAuthorization,
    ) -> Result<AgentKeyAuthorization, Self::Error>;

    /// Look up an authorization by its minted `ak:event:<uuid7>` id.
    async fn lookup_by_event_id(
        &mut self,
        authorized_event_id: &str,
    ) -> Result<Option<AgentKeyAuthorization>, Self::Error>;

    /// List active (not revoked) authorizations for an agent principal.
    async fn list_active_for_agent(
        &mut self,
        agent_id: &str,
    ) -> Result<Vec<AgentKeyAuthorization>, Self::Error>;

    /// Revoke every active authorization for an agent principal.
    async fn revoke_for_agent(
        &mut self,
        clock: &dyn Clock,
        agent_id: &str,
        reason: &str,
    ) -> Result<usize, Self::Error>;

    /// Mark one authorization as delivered to Soland and atomically revoke
    /// only the authorization Event ids observed in its signed supersedes set.
    async fn mark_fanout_delivered_and_revoke(
        &mut self,
        clock: &dyn Clock,
        authorized_event_id: &str,
        superseded_event_ids: &[String],
        revoked_reason: &str,
    ) -> Result<bool, Self::Error>;

    /// Atomically consume an agent-key-proof challenge. Returns `true` when
    /// this call won the single-use insert (the proof has not been seen before
    /// within its replay window); `false` when the challenge was already
    /// consumed (replay) and the caller MUST fail closed.
    async fn consume_proof_challenge(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAgentSessionProofReplay,
    ) -> Result<bool, Self::Error>;

    /// Delete replay rows past their prune horizon. Returns the number of rows
    /// removed.
    async fn prune_expired_replay(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error>;
}

repository_impl!(AgentKeyAuthorizationRepository:
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAgentKeyAuthorization,
    ) -> Result<AgentKeyAuthorization, Self::Error>;
    async fn lookup_by_event_id(
        &mut self,
        authorized_event_id: &str,
    ) -> Result<Option<AgentKeyAuthorization>, Self::Error>;
    async fn list_active_for_agent(
        &mut self,
        agent_id: &str,
    ) -> Result<Vec<AgentKeyAuthorization>, Self::Error>;
    async fn revoke_for_agent(
        &mut self,
        clock: &dyn Clock,
        agent_id: &str,
        reason: &str,
    ) -> Result<usize, Self::Error>;
    async fn mark_fanout_delivered_and_revoke(
        &mut self,
        clock: &dyn Clock,
        authorized_event_id: &str,
        superseded_event_ids: &[String],
        revoked_reason: &str,
    ) -> Result<bool, Self::Error>;
    async fn consume_proof_challenge(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAgentSessionProofReplay,
    ) -> Result<bool, Self::Error>;
    async fn prune_expired_replay(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error>;
);
