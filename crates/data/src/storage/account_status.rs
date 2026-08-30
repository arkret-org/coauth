//! Durable Account Authority issuer ledger.

use arkret_models_collaboration::account_lifecycle::AccountStatusRecord;
use async_trait::async_trait;

use crate::{LocalAccountId, repository_impl};

/// Result of attempting to append an immutable record at the current head.
#[derive(Clone, Debug)]
pub enum AccountStatusAppendOutcome {
    /// The exact record was appended.
    Appended,
    /// The same record already exists.
    Duplicate,
    /// The candidate is not the next record after the durable current head.
    Conflict {
        /// Current durable head, if the ledger is non-empty.
        current: Option<Box<AccountStatusRecord>>,
    },
}

/// Persistence port for Account Authority issuer records.
#[async_trait]
pub trait AccountStatusLedgerRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Append with a durable current-head compare-and-swap.
    async fn append(
        &mut self,
        local_account_id: &LocalAccountId,
        record: &AccountStatusRecord,
    ) -> Result<AccountStatusAppendOutcome, Self::Error>;

    /// Return the current head.
    async fn current(
        &mut self,
        account_authority_id: &str,
        local_account_id: &str,
    ) -> Result<Option<AccountStatusRecord>, Self::Error>;

    /// Return a bounded ascending contiguous range.
    async fn resolve(
        &mut self,
        account_authority_id: &str,
        local_account_id: &str,
        from_status_seq: u64,
        limit: u16,
    ) -> Result<Vec<AccountStatusRecord>, Self::Error>;
}

repository_impl!(AccountStatusLedgerRepository:
    async fn append(
        &mut self,
        local_account_id: &LocalAccountId,
        record: &AccountStatusRecord,
    ) -> Result<AccountStatusAppendOutcome, Self::Error>;
    async fn current(
        &mut self,
        account_authority_id: &str,
        local_account_id: &str,
    ) -> Result<Option<AccountStatusRecord>, Self::Error>;
    async fn resolve(
        &mut self,
        account_authority_id: &str,
        local_account_id: &str,
        from_status_seq: u64,
        limit: u16,
    ) -> Result<Vec<AccountStatusRecord>, Self::Error>;
);
