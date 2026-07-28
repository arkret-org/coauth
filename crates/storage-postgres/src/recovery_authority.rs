//! PostgreSQL recovery-authority authorization repository.

use async_trait::async_trait;
use coauth_data::recovery_authority::{
    NewRecoveryDeviceAuthorization, RecoveryDeviceAuthorization,
};
use coauth_data::storage::recovery_authority::RecoveryAuthorityRepository;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::DatabaseError;
use crate::schema::recovery_device_authorizations;

/// PostgreSQL implementation of [`RecoveryAuthorityRepository`].
pub struct PgRecoveryAuthorityRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgRecoveryAuthorityRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = recovery_device_authorizations)]
struct RecoveryDeviceAuthorizationRow {
    ticket_id: String,
    transaction_id: String,
    transaction_request_digest: String,
    did_entry_ref: String,
    did_entry_digest: String,
    authorization_ref: String,
    canonical_request: Vec<u8>,
    outcome: serde_json::Value,
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl From<RecoveryDeviceAuthorizationRow> for RecoveryDeviceAuthorization {
    fn from(value: RecoveryDeviceAuthorizationRow) -> Self {
        Self {
            ticket_id: value.ticket_id,
            transaction_id: value.transaction_id,
            transaction_request_digest: value.transaction_request_digest,
            did_entry_ref: value.did_entry_ref,
            did_entry_digest: value.did_entry_digest,
            authorization_ref: value.authorization_ref,
            canonical_request: value.canonical_request,
            outcome: value.outcome,
            accepted_at: value.accepted_at,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = recovery_device_authorizations)]
struct InsertableRecoveryDeviceAuthorization {
    ticket_id: String,
    transaction_id: String,
    transaction_request_digest: String,
    did_entry_ref: String,
    did_entry_digest: String,
    authorization_ref: String,
    canonical_request: Vec<u8>,
    outcome: serde_json::Value,
    accepted_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
impl RecoveryAuthorityRepository for PgRecoveryAuthorityRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.recovery_authority.lookup_authorization", skip_all, err)]
    async fn lookup_authorization(
        &mut self,
        ticket_id: &str,
    ) -> Result<Option<RecoveryDeviceAuthorization>, Self::Error> {
        recovery_device_authorizations::table
            .filter(recovery_device_authorizations::ticket_id.eq(ticket_id))
            .select(RecoveryDeviceAuthorizationRow::as_select())
            .first(self.conn)
            .await
            .optional()
            .map(|row| row.map(Into::into))
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.recovery_authority.lookup_authorization_by_transaction",
        skip_all,
        err
    )]
    async fn lookup_authorization_by_transaction(
        &mut self,
        transaction_id: &str,
    ) -> Result<Option<RecoveryDeviceAuthorization>, Self::Error> {
        recovery_device_authorizations::table
            .filter(recovery_device_authorizations::transaction_id.eq(transaction_id))
            .select(RecoveryDeviceAuthorizationRow::as_select())
            .first(self.conn)
            .await
            .optional()
            .map(|row| row.map(Into::into))
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.recovery_authority.insert_authorization", skip_all, err)]
    async fn insert_authorization(
        &mut self,
        params: NewRecoveryDeviceAuthorization,
    ) -> Result<bool, Self::Error> {
        let row = InsertableRecoveryDeviceAuthorization {
            ticket_id: params.ticket_id,
            transaction_id: params.transaction_id,
            transaction_request_digest: params.transaction_request_digest,
            did_entry_ref: params.did_entry_ref,
            did_entry_digest: params.did_entry_digest,
            authorization_ref: params.authorization_ref,
            canonical_request: params.canonical_request,
            outcome: params.outcome,
            accepted_at: params.accepted_at,
        };
        let inserted = diesel::insert_into(recovery_device_authorizations::table)
            .values(row)
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?;
        Ok(inserted == 1)
    }
}
