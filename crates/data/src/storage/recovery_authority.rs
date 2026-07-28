//! Durable recovery-authority authorization repository.

use async_trait::async_trait;

use crate::recovery_authority::{NewRecoveryDeviceAuthorization, RecoveryDeviceAuthorization};
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
);
