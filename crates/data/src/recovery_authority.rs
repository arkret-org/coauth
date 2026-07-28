//! Durable recovery-authority authorization outcomes.

use chrono::{DateTime, Utc};
use serde_json::Value;

/// First accepted outcome for one recovery authority ticket.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryDeviceAuthorization {
    /// Transaction-bound one-time ticket identity.
    pub ticket_id: String,
    /// Recovery transaction identity.
    pub transaction_id: String,
    /// Stable transaction create-request digest.
    pub transaction_request_digest: String,
    /// Candidate DID entry reference independently verified before signing.
    pub did_entry_ref: String,
    /// Candidate DID entry digest independently verified before signing.
    pub did_entry_digest: String,
    /// Candidate-document delegation used for the authority Event.
    pub authorization_ref: String,
    /// Canonical typed request bytes used for exact replay comparison.
    pub canonical_request: Vec<u8>,
    /// First canonical typed response.
    pub outcome: Value,
    /// Time the authority accepted the request.
    pub accepted_at: DateTime<Utc>,
}

/// Parameters for persisting a first recovery authorization outcome.
#[derive(Clone, Debug)]
pub struct NewRecoveryDeviceAuthorization {
    /// Transaction-bound one-time ticket identity.
    pub ticket_id: String,
    /// Recovery transaction identity.
    pub transaction_id: String,
    /// Stable transaction create-request digest.
    pub transaction_request_digest: String,
    /// Candidate DID entry reference.
    pub did_entry_ref: String,
    /// Candidate DID entry digest.
    pub did_entry_digest: String,
    /// Candidate-document delegation used for the authority Event.
    pub authorization_ref: String,
    /// Canonical typed request bytes.
    pub canonical_request: Vec<u8>,
    /// Canonical typed response value.
    pub outcome: Value,
    /// Time the authority accepted the request.
    pub accepted_at: DateTime<Utc>,
}
