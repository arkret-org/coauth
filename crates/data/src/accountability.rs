use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Ulid;
pub use crate::pg::accountability::PgAccountabilityGrantRepository;
pub use crate::storage::accountability::*;

/// Durable accountability grant issued for a Personal Agent capability set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilityGrant {
    /// Storage row id.
    pub id: Ulid,
    /// Wire typed id: `ak:grant:<uuid7>`.
    pub accountability_grant_id: String,
    /// Agent principal id covered by this grant.
    pub agent_principal_id: String,
    /// Controller DID that accepted accountability for the grant.
    pub controller_did: String,
    /// Canonical capability/action set.
    pub capabilities: Vec<String>,
    /// Deterministic digest of controller, agent, and canonical capabilities.
    pub capabilities_digest: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
    /// Grant issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// Timestamp when this grant was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason recorded when this grant was revoked.
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

/// Durable soland fan-out state for an accountability grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityGrantFanoutState {
    /// Fan-out payload has been queued for retryable delivery.
    Queued,
    /// Fan-out has been accepted by soland.
    Delivered,
    /// Fan-out exhausted retries and needs operator attention.
    DeadLettered,
}

impl AccountabilityGrantFanoutState {
    /// Database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Delivered => "delivered",
            Self::DeadLettered => "dead_lettered",
        }
    }
}

impl std::fmt::Display for AccountabilityGrantFanoutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AccountabilityGrantFanoutState {
    type Err = ParseAccountabilityGrantFanoutStateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "delivered" => Ok(Self::Delivered),
            "dead_lettered" => Ok(Self::DeadLettered),
            _ => Err(ParseAccountabilityGrantFanoutStateError),
        }
    }
}

/// Error returned when a persisted fan-out state is unknown.
#[derive(Debug, thiserror::Error)]
#[error("unknown accountability grant fan-out state")]
pub struct ParseAccountabilityGrantFanoutStateError;

/// Subject kinds used by the accountability revocation index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilitySubjectKind {
    /// Controller DID subject.
    ControllerDid,
    /// Agent principal id subject.
    AgentPrincipalId,
}

impl AccountabilitySubjectKind {
    /// Database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControllerDid => "controller_did",
            Self::AgentPrincipalId => "agent_principal_id",
        }
    }
}

impl std::fmt::Display for AccountabilitySubjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AccountabilitySubjectKind {
    type Err = ParseAccountabilitySubjectKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "controller_did" => Ok(Self::ControllerDid),
            "agent_principal_id" => Ok(Self::AgentPrincipalId),
            _ => Err(ParseAccountabilitySubjectKindError),
        }
    }
}

/// Error returned when a persisted subject kind is unknown.
#[derive(Debug, thiserror::Error)]
#[error("unknown accountability subject kind")]
pub struct ParseAccountabilitySubjectKindError;

/// Durable subject-level revocation marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountabilitySubjectRevocation {
    /// Storage row id.
    pub id: Ulid,
    /// Subject kind.
    pub subject_kind: AccountabilitySubjectKind,
    /// Subject id.
    pub subject_id: String,
    /// Revocation reason.
    pub reason: String,
    /// Timestamp when the subject was revoked.
    pub revoked_at: DateTime<Utc>,
    /// Row creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Row update timestamp.
    pub updated_at: DateTime<Utc>,
}
