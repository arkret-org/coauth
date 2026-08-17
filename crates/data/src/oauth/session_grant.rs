use arkret_identifiers::SessionGrantId;
use arkret_models_identity::SessionGrantProofKind;
use chrono::{DateTime, Utc};
use coauth_oauth_types::scope::Scope;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use crate::{Clock, InvalidTransitionError};

/// Durable issuer-ledger lifecycle state for a session grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantLifecycleState {
    /// The grant may be used until its immutable expiry.
    Active,
    /// The issuer explicitly revoked the grant.
    Revoked,
    /// A refresh atomically replaced the grant with a successor.
    Superseded,
}

/// Durable operation families that may create or terminate a session grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantOperationKind {
    /// Initial session-grant issuance.
    Issue,
    /// Rotation that creates a successor and supersedes its predecessor.
    Refresh,
    /// Explicit revocation/logout/cascade.
    Revoke,
}

/// Closed durable selector for a session-grant operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation_kind", rename_all = "snake_case")]
pub enum SessionGrantOperationDescriptor {
    Issue,
    Refresh {
        predecessor_grant_id: SessionGrantId,
    },
    Revoke {
        #[serde(flatten)]
        selector: SessionGrantRevokeTarget,
    },
}

impl SessionGrantOperationDescriptor {
    #[must_use]
    pub const fn kind(&self) -> SessionGrantOperationKind {
        match self {
            Self::Issue => SessionGrantOperationKind::Issue,
            Self::Refresh { .. } => SessionGrantOperationKind::Refresh,
            Self::Revoke { .. } => SessionGrantOperationKind::Revoke,
        }
    }
}

/// Owned target carried by a durable revoke operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionGrantRevokeTarget {
    Grant { grant_id: SessionGrantId },
    Device { subject: String, device_id: String },
    AllForSubject { subject: String },
}

impl SessionGrantOperationKind {
    /// Stable database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Refresh => "refresh",
            Self::Revoke => "revoke",
        }
    }
}

impl TryFrom<&str> for SessionGrantOperationKind {
    type Error = InvalidTransitionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "issue" => Ok(Self::Issue),
            "refresh" => Ok(Self::Refresh),
            "revoke" => Ok(Self::Revoke),
            _ => Err(InvalidTransitionError),
        }
    }
}

/// State of a durable exact-replay operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantOperationState {
    /// The request identity and canonical intent are reserved; no outcome exists yet.
    Reserved,
    /// A non-local one-shot proof was consumed and its durable authorization checkpoint exists.
    Authorized,
    /// The outcome and every lifecycle transition were committed atomically.
    Committed,
    /// Replay material aged out, while the identity tombstone remains fail-closed.
    Evicted,
}

/// Durable request-identity record used for exact replay and conflict detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionGrantOperation {
    pub id: Ulid,
    pub issuer: String,
    pub operation: SessionGrantOperationDescriptor,
    pub proof_kind: Option<SessionGrantProofKind>,
    pub request_identity: String,
    pub canonical_intent_digest: [u8; 32],
    pub canonical_intent: Option<Vec<u8>>,
    pub issuance_nonce: Option<String>,
    pub session_id: Option<String>,
    pub grant_not_before: Option<DateTime<Utc>>,
    pub grant_expires_at: Option<DateTime<Utc>>,
    pub signing_key_id: Option<String>,
    pub proof_authorization_ref: Option<String>,
    pub proof_authorization_checkpoint: Option<Value>,
    pub proof_expires_at: Option<DateTime<Utc>>,
    pub outcome_digest: Option<[u8; 32]>,
    pub canonical_outcome: Option<Vec<u8>>,
    pub state: SessionGrantOperationState,
    pub target_session_grant_id: Option<SessionGrantId>,
    pub result_grant_id: Option<SessionGrantId>,
    pub affected_grant_ids: Vec<SessionGrantId>,
    pub retained_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionGrant {
    pub id: Ulid,
    pub grant_id: SessionGrantId,
    pub browser_session_id: Option<Ulid>,
    pub issuer: String,
    pub subject: String,
    pub device_id: Option<String>,
    pub applet_id: Option<String>,
    pub effective_scope: Option<Value>,
    pub registration_epoch: Option<String>,
    pub service_id: Option<String>,
    pub capability_grant_refs: Vec<String>,
    pub audience: String,
    pub scope: Scope,
    pub grant_jwt: String,
    pub session_id: String,
    pub issuance_nonce: String,
    pub issuance_preimage: Vec<u8>,
    pub issuance_digest: [u8; 32],
    pub signing_key_id: String,
    pub session_public_key: String,
    pub credential_class: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub lifecycle_state: SessionGrantLifecycleState,
    pub revoked_at: Option<DateTime<Utc>>,
    pub superseded_at: Option<DateTime<Utc>>,
    pub successor_grant_id: Option<SessionGrantId>,
    pub issuance_operation_id: Ulid,
}

impl SessionGrant {
    #[must_use]
    pub fn is_active(&self, clock: &dyn Clock) -> bool {
        self.lifecycle_state == SessionGrantLifecycleState::Active
            && self.revoked_at.is_none()
            && self.superseded_at.is_none()
            && self.expires_at > clock.now()
    }

    pub fn revoke(mut self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        if self.lifecycle_state != SessionGrantLifecycleState::Active
            || self.revoked_at.is_some()
            || self.superseded_at.is_some()
        {
            return Err(InvalidTransitionError);
        }

        self.revoked_at = Some(revoked_at);
        self.lifecycle_state = SessionGrantLifecycleState::Revoked;
        Ok(self)
    }

    pub fn supersede(
        mut self,
        successor_grant_id: SessionGrantId,
        superseded_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        if self.lifecycle_state != SessionGrantLifecycleState::Active
            || self.revoked_at.is_some()
            || self.superseded_at.is_some()
        {
            return Err(InvalidTransitionError);
        }
        self.lifecycle_state = SessionGrantLifecycleState::Superseded;
        self.superseded_at = Some(superseded_at);
        self.successor_grant_id = Some(successor_grant_id);
        Ok(self)
    }
}
