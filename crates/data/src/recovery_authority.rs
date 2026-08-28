//! Durable exact-replay records for recovery-completion login issuance.

use chrono::{DateTime, Utc};
use serde_json::Value;

/// First committed Standard grant outcome for one recovery transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryCompletionGrantIssuance {
    pub transaction_id: String,
    pub transaction_request_digest: String,
    pub service_account_id: crate::Ulid,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub device_id: String,
    pub device_authorization_event_id: String,
    pub result_model_generation_ref: Value,
    pub canonical_request_digest: String,
    pub canonical_request: Vec<u8>,
    pub session_grant_operation_id: crate::Ulid,
    pub canonical_outcome: Vec<u8>,
    pub issued_at: DateTime<Utc>,
}

/// Parameters for atomically recording the first recovery-completion issuance.
#[derive(Clone, Debug)]
pub struct NewRecoveryCompletionGrantIssuance {
    pub transaction_id: String,
    pub transaction_request_digest: String,
    pub service_account_id: crate::Ulid,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub device_id: String,
    pub device_authorization_event_id: String,
    pub result_model_generation_ref: Value,
    pub canonical_request_digest: String,
    pub canonical_request: Vec<u8>,
    pub session_grant_operation_id: crate::Ulid,
    pub canonical_outcome: Vec<u8>,
    pub issued_at: DateTime<Utc>,
}
