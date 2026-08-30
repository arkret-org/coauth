use std::fmt;
use std::str::FromStr;

use arkret_identifiers::{DidCoreId, SessionGrantId};
use arkret_models_identity::SessionGrantProofKind;
use chrono::{DateTime, Utc};
use coauth_oauth_types::scope::Scope;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use crate::{Clock, InvalidTransitionError};

/// Station-local lookup key for one coauth account row.
///
/// This is deliberately owned by coauth-data: it is not an Arkret protocol
/// identity and must never replace [`arkret_models_identity::AccountId`] at a
/// service boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalAccountId(String);

impl LocalAccountId {
    /// Validate and construct a local account-row key.
    pub fn new(value: impl Into<String>) -> arkret_identifiers::Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
            return Err(arkret_identifiers::IdentifierError::InvalidId(value));
        }
        Ok(Self(value))
    }

    /// Borrow the database representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume this key into its database representation.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for LocalAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for LocalAccountId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for LocalAccountId {
    type Err = arkret_identifiers::IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for LocalAccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LocalAccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Durable issuer_id-ledger lifecycle state for a session grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantLifecycleState {
    /// The grant may be used until its immutable expiry.
    Active,
    /// The issuer_id explicitly revoked the grant.
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
    Grant {
        grant_id: SessionGrantId,
    },
    Device {
        subject_id: DidCoreId,
        device_id: String,
    },
    AllForSubject {
        subject_id: DidCoreId,
    },
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
    pub issuer_id: DidCoreId,
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
    pub issuer_id: DidCoreId,
    pub subject_id: DidCoreId,
    pub local_account_id: LocalAccountId,
    pub device_id: Option<String>,
    pub applet_id: Option<String>,
    pub effective_scope: Option<Value>,
    pub registration_epoch: Option<String>,
    pub service_id: Option<DidCoreId>,
    pub capability_grant_refs: Vec<String>,
    pub audience_id: DidCoreId,
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
