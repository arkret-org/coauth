//! Private IVS persistence. None of these records is an Arkret wire type.

use chrono::{DateTime, Utc};

use crate::repository_impl;

/// Encrypted private provisioning record, with only operational indexes exposed.
/// Callers hold the row lock until committing the surrounding repository transaction.
#[derive(Clone)]
pub struct PrivateInviteRecord {
    /// SHA-256 of the unguessable provisioning credential.
    pub handle_digest: String,
    /// Canonical digest of the complete inviter AccountId.
    pub issuer_digest: String,
    /// Canonical Realm digest for issuance quotas (not a 3PID-derived value).
    pub realm_digest: String,
    /// Original registered request identity; retained even after secret cleanup.
    pub request_id: String,
    /// Canonical original unsigned intent digest.
    pub intent_digest: String,
    /// AEAD ciphertext containing SDK outcomes and all private material.
    pub encrypted_record: String,
    /// Non-secret token lookup selector. No raw code is stored here.
    pub token_selector: Option<String>,
    /// Provider-local state, never a Realm current state.
    pub state: String,
    /// Effective invite expiration.
    pub expires_at: DateTime<Utc>,
    /// Last instant an unbound record may be activated.
    pub activation_expires_at: DateTime<Utc>,
    /// Earliest time the durable delivery loop may claim the record.
    pub deliver_after: Option<DateTime<Utc>>,
}

repository_impl! {
    /// Transactional IVS persistence port. The caller owns commit/rollback.
    pub trait ThirdPartyInviteRepository {
        /// Backend error.
        type Error;
        /// Serialize issuance and quotas for one principal or rate-limit bucket.
        async fn lock_namespace(&mut self, namespace: &str) -> Result<(), Self::Error>;
        /// Read the original request ledger under its namespace lock.
        async fn find_request(&mut self, issuer: &str, request_id: &str)
            -> Result<Option<PrivateInviteRecord>, Self::Error>;
        /// Lock one private record by credential digest.
        async fn find(&mut self, handle: &str) -> Result<Option<PrivateInviteRecord>, Self::Error>;
        /// Lock one private record by its token lookup selector.
        async fn find_token(&mut self, selector: &str) -> Result<Option<PrivateInviteRecord>, Self::Error>;
        /// Insert one new record. Both original request and handle are unique.
        async fn insert(&mut self, record: PrivateInviteRecord) -> Result<bool, Self::Error>;
        /// Replace an already locked record without changing its original intent.
        async fn update(&mut self, record: PrivateInviteRecord) -> Result<(), Self::Error>;
        /// Count unactivated records for an inviter and Realm digest.
        async fn unactivated_count(&mut self, issuer: &str, realm: &str, now: DateTime<Utc>)
            -> Result<i64, Self::Error>;
        /// Persist a rate counter; return false without incrementing when full.
        async fn take_rate(&mut self, bucket: &str, window: DateTime<Utc>, maximum: i64)
            -> Result<bool, Self::Error>;
        /// Claim one due delivery/cleanup record, skipping concurrent workers.
        async fn due(&mut self, now: DateTime<Utc>) -> Result<Option<PrivateInviteRecord>, Self::Error>;
    }
}
