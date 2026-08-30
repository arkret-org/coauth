use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Ulid;
pub use crate::accountability::{
    AccountabilityGrantFanoutState, ParseAccountabilityGrantFanoutStateError,
};
pub use crate::storage::agent_key::*;

/// Durable record of an accepted `ak.agent.key.authorize` (AKP-0008 §4.5).
///
/// coauth validates the runtime key pairing proof-of-possession, persists this
/// row for the agent-key-proof session branch, and commits the unchanged
/// standard key-pair request to the authoritative Station. The row is
/// usable only after that server durably accepts the supplied
/// `ak.agent.key.authorize` Event. Column order tracks
/// `event-payload.schema.json#/$defs/agent_key_authorize_payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentKeyAuthorization {
    /// Storage row id.
    pub id: Ulid,
    /// Complete suite-tagged content identity of the durable
    /// `ak.agent.key.authorize` Event accepted by the Station. The
    /// session-grant agent branch resolves `agent_key_authorization_ref`
    /// against this id.
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
    pub accountable_principal_id: arkret_identifiers::DidCoreId,
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
    /// Timestamp when full-hash collision evidence quarantined this Event id.
    pub quarantined_at: Option<DateTime<Utc>>,
    /// Internal quarantine discriminator. Protocol responses use
    /// `witness_disagreement`.
    pub quarantine_reason: Option<String>,
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
