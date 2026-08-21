//! Durable self-service account erasure intents
//! (`ak.gate.account.command.request_erasure`, account-lifecycle.md §8.1).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ulid::Ulid;

use crate::repository_impl;

/// One durably recorded self-service erasure request.
///
/// The row is the idempotency carrier for the operation's three-state
/// contract: an exact replay of `request_id` returns the stored
/// `canonical_outcome` bytes verbatim; the same `request_id` with a different
/// `request_digest` is `duplicate_conflict`; a second `request_id` while a row
/// with `record_issued_at IS NULL` exists for the user is
/// `failed_precondition` + `erasure_request_already_pending`.
#[derive(Clone, Debug, PartialEq)]
pub struct UserErasureRequest {
    /// Caller-supplied idempotency identity (`ak:request:*`).
    pub request_id: String,
    /// Owning service account.
    pub user_id: Ulid,
    /// Canonical SHA-256 digest of the request body bytes.
    pub request_digest: String,
    /// Exact canonical acceptance outcome bytes returned on replay.
    pub canonical_outcome: Vec<u8>,
    /// Acceptance instant echoed in the outcome.
    pub recorded_at: DateTime<Utc>,
    /// Deployment withdrawal-window end, when one was granted.
    pub withdrawal_window_ends_at: Option<DateTime<Utc>>,
    /// Set once the `erasure_pending` AccountStatusRecord is signed; a `NULL`
    /// means the intent is still live (record not yet signed).
    pub record_issued_at: Option<DateTime<Utc>>,
    /// The signed `erasure_pending` record id, once issued.
    pub account_status_record_id: Option<String>,
}

impl UserErasureRequest {
    /// Whether the `erasure_pending` record has not been signed yet.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.record_issued_at.is_none()
    }
}

/// Parameters for durably recording a new erasure intent.
#[derive(Clone, Debug)]
pub struct NewUserErasureRequest {
    /// Caller-supplied idempotency identity.
    pub request_id: String,
    /// Owning service account.
    pub user_id: Ulid,
    /// Canonical SHA-256 digest of the request body bytes.
    pub request_digest: String,
    /// Exact canonical acceptance outcome bytes.
    pub canonical_outcome: Vec<u8>,
    /// Acceptance instant.
    pub recorded_at: DateTime<Utc>,
    /// Deployment withdrawal-window end, when one is granted.
    pub withdrawal_window_ends_at: Option<DateTime<Utc>>,
}

/// Repository for durable self-service erasure intents.
#[async_trait]
pub trait UserErasureRequestRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Look up a recorded erasure request by its `request_id`.
    async fn lookup(&mut self, request_id: &str)
    -> Result<Option<UserErasureRequest>, Self::Error>;

    /// Find the user's live intent (recorded, `erasure_pending` record not
    /// yet signed), if any.
    async fn find_live_for_user(
        &mut self,
        user_id: Ulid,
    ) -> Result<Option<UserErasureRequest>, Self::Error>;

    /// Insert a new intent. Returns `false` when another transaction already
    /// recorded the same `request_id` (or the user's single live-intent slot),
    /// in which case the caller must re-read and apply the replay/conflict
    /// rules.
    async fn insert(&mut self, params: NewUserErasureRequest) -> Result<bool, Self::Error>;

    /// Mark the intent's `erasure_pending` record as signed. Returns `false`
    /// when the row does not exist or was already marked.
    async fn mark_record_issued(
        &mut self,
        request_id: &str,
        account_status_record_id: &str,
        issued_at: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;
}

repository_impl!(UserErasureRequestRepository:
    async fn lookup(
        &mut self,
        request_id: &str,
    ) -> Result<Option<UserErasureRequest>, Self::Error>;
    async fn find_live_for_user(
        &mut self,
        user_id: Ulid,
    ) -> Result<Option<UserErasureRequest>, Self::Error>;
    async fn insert(&mut self, params: NewUserErasureRequest) -> Result<bool, Self::Error>;
    async fn mark_record_issued(
        &mut self,
        request_id: &str,
        account_status_record_id: &str,
        issued_at: DateTime<Utc>,
    ) -> Result<bool, Self::Error>;
);
