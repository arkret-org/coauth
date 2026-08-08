//! PostgreSQL recovery-authority authorization repository.

use arkret_identifiers::SessionGrantId;
use async_trait::async_trait;
use coauth_data::recovery_authority::{
    NewRecoveryDeviceAuthorization, NewRecoverySessionGrantPromotion, RecoveryDeviceAuthorization,
    RecoverySessionGrantPromotion,
};
use coauth_data::storage::recovery_authority::RecoveryAuthorityRepository;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::schema::{recovery_device_authorizations, recovery_session_grant_promotions};
use crate::session_grant_codec::session_grant_id_from_bytes;
use crate::{DatabaseError, DatabaseInconsistencyError};

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

#[derive(Queryable, Selectable)]
#[diesel(table_name = recovery_session_grant_promotions)]
struct RecoverySessionGrantPromotionRow {
    transaction_id: String,
    old_grant_id: Vec<u8>,
    transaction_request_digest: String,
    recovery_session_id: String,
    replacement_device_id: String,
    device_authorization_event_id: String,
    model_generation_ref: serde_json::Value,
    canonical_request: Vec<u8>,
    outcome: serde_json::Value,
    consumed_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<RecoverySessionGrantPromotionRow> for RecoverySessionGrantPromotion {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: RecoverySessionGrantPromotionRow) -> Result<Self, Self::Error> {
        let old_grant_id = session_grant_id_from_bytes(&value.old_grant_id).map_err(|error| {
            DatabaseInconsistencyError::on("recovery_session_grant_promotions")
                .column("old_grant_id")
                .source(error)
        })?;
        Ok(Self {
            transaction_id: value.transaction_id,
            old_grant_id,
            transaction_request_digest: value.transaction_request_digest,
            recovery_session_id: value.recovery_session_id,
            replacement_device_id: value.replacement_device_id,
            device_authorization_event_id: value.device_authorization_event_id,
            model_generation_ref: value.model_generation_ref,
            canonical_request: value.canonical_request,
            outcome: value.outcome,
            consumed_at: value.consumed_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = recovery_session_grant_promotions)]
struct InsertableRecoverySessionGrantPromotion {
    transaction_id: String,
    old_grant_id: Vec<u8>,
    transaction_request_digest: String,
    recovery_session_id: String,
    replacement_device_id: String,
    device_authorization_event_id: String,
    model_generation_ref: serde_json::Value,
    canonical_request: Vec<u8>,
    outcome: serde_json::Value,
    consumed_at: chrono::DateTime<chrono::Utc>,
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

    #[tracing::instrument(name = "db.recovery_authority.lookup_promotion", skip_all, err)]
    async fn lookup_promotion(
        &mut self,
        transaction_id: &str,
        old_grant_id: &SessionGrantId,
    ) -> Result<Option<RecoverySessionGrantPromotion>, Self::Error> {
        recovery_session_grant_promotions::table
            .filter(recovery_session_grant_promotions::transaction_id.eq(transaction_id))
            .filter(
                recovery_session_grant_promotions::old_grant_id
                    .eq(old_grant_id.token_bytes().to_vec()),
            )
            .select(RecoverySessionGrantPromotionRow::as_select())
            .first(self.conn)
            .await
            .optional()
            .map_err(DatabaseError::from)?
            .map(RecoverySessionGrantPromotion::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.recovery_authority.lookup_promotion_by_old_grant",
        skip_all,
        err
    )]
    async fn lookup_promotion_by_old_grant(
        &mut self,
        old_grant_id: &SessionGrantId,
    ) -> Result<Option<RecoverySessionGrantPromotion>, Self::Error> {
        recovery_session_grant_promotions::table
            .filter(
                recovery_session_grant_promotions::old_grant_id
                    .eq(old_grant_id.token_bytes().to_vec()),
            )
            .select(RecoverySessionGrantPromotionRow::as_select())
            .first(self.conn)
            .await
            .optional()
            .map_err(DatabaseError::from)?
            .map(RecoverySessionGrantPromotion::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.recovery_authority.insert_promotion", skip_all, err)]
    async fn insert_promotion(
        &mut self,
        params: NewRecoverySessionGrantPromotion,
    ) -> Result<bool, Self::Error> {
        let row = InsertableRecoverySessionGrantPromotion {
            transaction_id: params.transaction_id,
            old_grant_id: params.old_grant_id.token_bytes().to_vec(),
            transaction_request_digest: params.transaction_request_digest,
            recovery_session_id: params.recovery_session_id,
            replacement_device_id: params.replacement_device_id,
            device_authorization_event_id: params.device_authorization_event_id,
            model_generation_ref: params.model_generation_ref,
            canonical_request: params.canonical_request,
            outcome: params.outcome,
            consumed_at: params.consumed_at,
        };
        let inserted = diesel::insert_into(recovery_session_grant_promotions::table)
            .values(row)
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?;
        Ok(inserted == 1)
    }
}
