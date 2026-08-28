//! PostgreSQL recovery-completion grant issuance replay repository.

use async_trait::async_trait;
use coauth_data::recovery_authority::{
    NewRecoveryCompletionGrantIssuance, RecoveryCompletionGrantIssuance,
};
use coauth_data::storage::recovery_authority::RecoveryAuthorityRepository;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::DatabaseError;
use crate::schema::recovery_completion_grant_issuances;

/// PostgreSQL-backed durable replay ledger for recovery-completion grant issuance.
pub struct PgRecoveryAuthorityRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgRecoveryAuthorityRepository<'c> {
    /// Creates a repository over the caller's existing transaction connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = recovery_completion_grant_issuances)]
struct RecoveryCompletionGrantIssuanceRow {
    transaction_id: String,
    transaction_request_digest: String,
    service_account_id: uuid::Uuid,
    principal_id: arkret_identifiers::DidCoreId,
    device_id: String,
    device_authorization_event_id: String,
    result_model_generation_ref: serde_json::Value,
    canonical_request_digest: String,
    canonical_request: Vec<u8>,
    session_grant_operation_id: uuid::Uuid,
    canonical_outcome: Vec<u8>,
    issued_at: chrono::DateTime<chrono::Utc>,
}

impl From<RecoveryCompletionGrantIssuanceRow> for RecoveryCompletionGrantIssuance {
    fn from(value: RecoveryCompletionGrantIssuanceRow) -> Self {
        Self {
            transaction_id: value.transaction_id,
            transaction_request_digest: value.transaction_request_digest,
            service_account_id: value.service_account_id.into(),
            principal_id: value.principal_id,
            device_id: value.device_id,
            device_authorization_event_id: value.device_authorization_event_id,
            result_model_generation_ref: value.result_model_generation_ref,
            canonical_request_digest: value.canonical_request_digest,
            canonical_request: value.canonical_request,
            session_grant_operation_id: value.session_grant_operation_id.into(),
            canonical_outcome: value.canonical_outcome,
            issued_at: value.issued_at,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = recovery_completion_grant_issuances)]
struct InsertableRecoveryCompletionGrantIssuance {
    transaction_id: String,
    transaction_request_digest: String,
    service_account_id: uuid::Uuid,
    principal_id: arkret_identifiers::DidCoreId,
    device_id: String,
    device_authorization_event_id: String,
    result_model_generation_ref: serde_json::Value,
    canonical_request_digest: String,
    canonical_request: Vec<u8>,
    session_grant_operation_id: uuid::Uuid,
    canonical_outcome: Vec<u8>,
    issued_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
impl RecoveryAuthorityRepository for PgRecoveryAuthorityRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.recovery_completion.lookup_issuance", skip_all, err)]
    async fn lookup_completion_issuance(
        &mut self,
        transaction_id: &str,
    ) -> Result<Option<RecoveryCompletionGrantIssuance>, Self::Error> {
        recovery_completion_grant_issuances::table
            .filter(recovery_completion_grant_issuances::transaction_id.eq(transaction_id))
            .select(RecoveryCompletionGrantIssuanceRow::as_select())
            .first(self.conn)
            .await
            .optional()
            .map(|row| row.map(Into::into))
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.recovery_completion.insert_issuance", skip_all, err)]
    async fn insert_completion_issuance(
        &mut self,
        params: NewRecoveryCompletionGrantIssuance,
    ) -> Result<bool, Self::Error> {
        let row = InsertableRecoveryCompletionGrantIssuance {
            transaction_id: params.transaction_id,
            transaction_request_digest: params.transaction_request_digest,
            service_account_id: params.service_account_id.into(),
            principal_id: params.principal_id,
            device_id: params.device_id,
            device_authorization_event_id: params.device_authorization_event_id,
            result_model_generation_ref: params.result_model_generation_ref,
            canonical_request_digest: params.canonical_request_digest,
            canonical_request: params.canonical_request,
            session_grant_operation_id: params.session_grant_operation_id.into(),
            canonical_outcome: params.canonical_outcome,
            issued_at: params.issued_at,
        };
        let inserted = diesel::insert_into(recovery_completion_grant_issuances::table)
            .values(row)
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?;
        Ok(inserted == 1)
    }
}
