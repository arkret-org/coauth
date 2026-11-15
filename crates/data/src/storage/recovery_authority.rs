//! Recovery-completion grant issuance replay repository.

use crate::recovery_authority::{
    NewRecoveryCompletionGrantIssuance, RecoveryCompletionGrantIssuance,
};
use crate::repository_impl;

repository_impl! {
    /// Persists the single committed Standard-grant outcome for a completed root recovery.
    pub trait RecoveryAuthorityRepository {
        /// Backend-specific persistence error.
        type Error;

        /// Serialize first acceptance and authoritative unaccepted/expired decisions.
        /// Caller must hold one explicit repository transaction until its decision commits.
        async fn lock_completion_business_key(
            &mut self,
            issuer_id: &arkret_identifiers::DidCoreId,
            account_id: &arkret_wire::AccountId,
            transaction_id: &arkret_identifiers::TransactionId,
        ) -> Result<(), Self::Error>;

        /// Look up the first accepted issuance by its issuer and full-account recovery transaction key.
        async fn lookup_completion_issuance(
            &mut self,
            issuer_id: &arkret_identifiers::DidCoreId,
            account_id: &arkret_wire::AccountId,
            transaction_id: &arkret_identifiers::TransactionId,
        ) -> Result<Option<RecoveryCompletionGrantIssuance>, Self::Error>;

        /// Insert the first accepted issuance. A false result means another
        /// transaction already committed the same recovery transaction id.
        async fn insert_completion_issuance(
            &mut self,
            parameters: NewRecoveryCompletionGrantIssuance,
        ) -> Result<bool, Self::Error>;
    }
}
