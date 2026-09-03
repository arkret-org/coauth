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

        /// Look up the first accepted issuance by its recovery transaction id.
        async fn lookup_completion_issuance(
            &mut self,
            transaction_id: &str,
        ) -> Result<Option<RecoveryCompletionGrantIssuance>, Self::Error>;

        /// Insert the first accepted issuance. A false result means another
        /// transaction already committed the same recovery transaction id.
        async fn insert_completion_issuance(
            &mut self,
            params: NewRecoveryCompletionGrantIssuance,
        ) -> Result<bool, Self::Error>;
    }
}
