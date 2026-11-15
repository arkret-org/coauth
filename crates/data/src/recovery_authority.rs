//! Durable single-outcome recovery-completion issuer projection.
use arkret_identifiers::{DidCoreId, Hash, TransactionId};
use arkret_wire::{AccountId, CommittedEventRef};
use chrono::{DateTime, Utc};

/// The business key is the issuer, this operation, full Account and R.transaction_id.
#[derive(Clone, PartialEq)]
pub struct RecoveryCompletionGrantIssuance {
    pub issuer_id: DidCoreId,
    pub account_id: AccountId,
    pub transaction_id: TransactionId,
    pub terminal_receipt_digest: Hash,
    pub local_account_id: crate::Ulid,
    pub reanchor_ref: CommittedEventRef,
    pub device_authorization_ref: CommittedEventRef,
    pub new_model_generation_ref: u64,
    pub canonical_request_digest: Hash,
    pub canonical_request: Vec<u8>,
    pub session_grant_operation_id: crate::Ulid,
    pub canonical_outcome: Vec<u8>,
    pub issued_at: DateTime<Utc>,
}

impl std::fmt::Debug for RecoveryCompletionGrantIssuance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCompletionGrantIssuance")
            .field("issuer_id", &self.issuer_id)
            .field("account_id", &self.account_id)
            .field("transaction_id", &self.transaction_id)
            .finish_non_exhaustive()
    }
}

/// The caller commits this record with the original issuer operation in one DB transaction.
pub type NewRecoveryCompletionGrantIssuance = RecoveryCompletionGrantIssuance;
