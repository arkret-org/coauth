use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Ulid;
pub use crate::accountability::{
    AccountabilityGrantFanoutState, ParseAccountabilityGrantFanoutStateError,
};
pub use crate::pg::agent_key::PgAgentKeyAuthorizationRepository;
pub use crate::storage::agent_key::*;

/// Durable record of an accepted `ak.agent.key.authorize` (AKP-0008 §4.5).
///
/// coauth validates the runtime key pairing proof-of-possession, persists this
/// row as the local authority for the agent-key-proof session branch, and
/// queues a soland fan-out that materializes the durable `ak.agent.key.authorize`
/// event. Column order tracks
/// `event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentKeyAuthorization {
    /// Storage row id.
    pub id: Ulid,
    /// Minted `ak:event:<uuid7>` id the soland fan-out materializes as the
    /// durable `ak.agent.key.authorize` event. The session-grant agent branch
    /// resolves `agent_key_authorization_ref` against this id.
    pub authorized_event_id: String,
    /// Agent principal DID the authorized key belongs to.
    pub agent_id: String,
    /// Stable key id (`<verification_method>` fragment scope).
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
    /// Timestamp when the authorization was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason recorded when the authorization was revoked.
    pub revoked_reason: Option<String>,
    /// `sha256:<hex>` digest of the canonical fan-out payload.
    pub raw_payload_digest: String,
    /// Current soland fan-out state.
    pub soland_fanout_state: AccountabilityGrantFanoutState,
    /// Idempotency key used for soland fan-out and retry jobs.
    pub soland_fanout_idempotency_key: String,
    /// Payload queued for soland fan-out.
    pub soland_fanout_payload: serde_json::Value,
    /// Current fan-out attempt count.
    pub soland_fanout_attempt: i32,
    /// Next retry timestamp, if a retry is scheduled.
    pub soland_fanout_next_retry_at: Option<DateTime<Utc>>,
    /// Terminal failure reason, if fan-out entered dead-letter state.
    pub soland_fanout_dead_letter_reason: Option<String>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Row update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// A single consumption of an agent-key-proof session challenge (AKP-0008 §4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionProofReplay {
    /// Storage row id.
    pub id: Ulid,
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
    /// Timestamp when the proof was consumed.
    pub consumed_at: DateTime<Utc>,
    /// Proof `expires_at`.
    pub proof_expires_at: DateTime<Utc>,
    /// Replay-table prune horizon (`proof_expires_at` + grace window).
    pub prune_after: DateTime<Utc>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
}
