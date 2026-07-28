//! Durable recovery-authority authorization repository.

use arkret_identifiers::GrantId;
use async_trait::async_trait;

use crate::recovery_authority::{
    NewRecoveryDeviceAuthorization, NewRecoverySessionGrantPromotion, RecoveryDeviceAuthorization,
    RecoverySessionGrantPromotion,
};
use crate::repository_impl;

/// Persistence boundary for recovery authority ticket consumption and replay.
#[async_trait]
pub trait RecoveryAuthorityRepository: Send + Sync {
    /// Backend error type.
    type Error;

    /// Look up the first outcome by the one-time ticket identity.
    async fn lookup_authorization(
        &mut self,
        ticket_id: &str,
    ) -> Result<Option<RecoveryDeviceAuthorization>, Self::Error>;

    /// Look up the first outcome by recovery transaction identity.
    async fn lookup_authorization_by_transaction(
        &mut self,
        transaction_id: &str,
    ) -> Result<Option<RecoveryDeviceAuthorization>, Self::Error>;

    /// Insert the first outcome. Returns `true` when this transaction won the
    /// ticket-consumption race and `false` when the ticket already exists.
    async fn insert_authorization(
        &mut self,
        params: NewRecoveryDeviceAuthorization,
    ) -> Result<bool, Self::Error>;

    /// Look up the first promotion by its full protocol identity.
    async fn lookup_promotion(
        &mut self,
        transaction_id: &str,
        old_grant_id: &GrantId,
    ) -> Result<Option<RecoverySessionGrantPromotion>, Self::Error>;

    /// Look up a promotion by old grant to reject transaction substitution.
    async fn lookup_promotion_by_old_grant(
        &mut self,
        old_grant_id: &GrantId,
    ) -> Result<Option<RecoverySessionGrantPromotion>, Self::Error>;

    /// Insert the first promotion outcome.
    async fn insert_promotion(
        &mut self,
        params: NewRecoverySessionGrantPromotion,
    ) -> Result<bool, Self::Error>;
}

repository_impl!(RecoveryAuthorityRepository:
    async fn lookup_authorization(
        &mut self,
        ticket_id: &str,
    ) -> Result<Option<RecoveryDeviceAuthorization>, Self::Error>;
    async fn lookup_authorization_by_transaction(
        &mut self,
        transaction_id: &str,
    ) -> Result<Option<RecoveryDeviceAuthorization>, Self::Error>;
    async fn insert_authorization(
        &mut self,
        params: NewRecoveryDeviceAuthorization,
    ) -> Result<bool, Self::Error>;
    async fn lookup_promotion(
        &mut self,
        transaction_id: &str,
        old_grant_id: &GrantId,
    ) -> Result<Option<RecoverySessionGrantPromotion>, Self::Error>;
    async fn lookup_promotion_by_old_grant(
        &mut self,
        old_grant_id: &GrantId,
    ) -> Result<Option<RecoverySessionGrantPromotion>, Self::Error>;
    async fn insert_promotion(
        &mut self,
        params: NewRecoverySessionGrantPromotion,
    ) -> Result<bool, Self::Error>;
);
