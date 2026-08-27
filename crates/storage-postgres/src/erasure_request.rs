//! PostgreSQL implementation of the self-service erasure intent repository
//! (`ak.gate.account.command.request_erasure.v1`, account-lifecycle.md §8.1).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::erasure_request::{
    NewUserErasureRequest, UserErasureRequest, UserErasureRequestRepository,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ulid::Ulid;

use crate::DatabaseError;
use crate::schema::user_erasure_requests;

/// PostgreSQL implementation of [`UserErasureRequestRepository`].
pub struct PgUserErasureRequestRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserErasureRequestRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = user_erasure_requests)]
struct UserErasureRequestRow {
    request_id: String,
    user_id: uuid::Uuid,
    request_digest: String,
    canonical_outcome: Vec<u8>,
    recorded_at: DateTime<Utc>,
    withdrawal_window_ends_at: Option<DateTime<Utc>>,
    record_issued_at: Option<DateTime<Utc>>,
    account_status_record_id: Option<String>,
}

impl From<UserErasureRequestRow> for UserErasureRequest {
    fn from(value: UserErasureRequestRow) -> Self {
        Self {
            request_id: value.request_id,
            user_id: value.user_id.into(),
            request_digest: value.request_digest,
            canonical_outcome: value.canonical_outcome,
            recorded_at: value.recorded_at,
            withdrawal_window_ends_at: value.withdrawal_window_ends_at,
            record_issued_at: value.record_issued_at,
            account_status_record_id: value.account_status_record_id,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = user_erasure_requests)]
struct InsertableUserErasureRequest {
    request_id: String,
    user_id: uuid::Uuid,
    request_digest: String,
    canonical_outcome: Vec<u8>,
    recorded_at: DateTime<Utc>,
    withdrawal_window_ends_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl UserErasureRequestRepository for PgUserErasureRequestRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.user_erasure_request.lookup", skip_all, err)]
    async fn lookup(
        &mut self,
        request_id: &str,
    ) -> Result<Option<UserErasureRequest>, Self::Error> {
        user_erasure_requests::table
            .filter(user_erasure_requests::request_id.eq(request_id))
            .select(UserErasureRequestRow::as_select())
            .first(self.conn)
            .await
            .optional()
            .map(|row| row.map(Into::into))
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.user_erasure_request.find_live_for_user", skip_all, err)]
    async fn find_live_for_user(
        &mut self,
        user_id: Ulid,
    ) -> Result<Option<UserErasureRequest>, Self::Error> {
        user_erasure_requests::table
            .filter(user_erasure_requests::user_id.eq(uuid::Uuid::from(user_id)))
            .filter(user_erasure_requests::record_issued_at.is_null())
            .select(UserErasureRequestRow::as_select())
            .first(self.conn)
            .await
            .optional()
            .map(|row| row.map(Into::into))
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.user_erasure_request.insert", skip_all, err)]
    async fn insert(&mut self, params: NewUserErasureRequest) -> Result<bool, Self::Error> {
        let row = InsertableUserErasureRequest {
            request_id: params.request_id,
            user_id: params.user_id.into(),
            request_digest: params.request_digest,
            canonical_outcome: params.canonical_outcome,
            recorded_at: params.recorded_at,
            withdrawal_window_ends_at: params.withdrawal_window_ends_at,
        };
        let inserted = diesel::insert_into(user_erasure_requests::table)
            .values(row)
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?;
        Ok(inserted == 1)
    }

    #[tracing::instrument(name = "db.user_erasure_request.mark_record_issued", skip_all, err)]
    async fn mark_record_issued(
        &mut self,
        request_id: &str,
        account_status_record_id: &str,
        issued_at: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let updated = diesel::update(
            user_erasure_requests::table
                .filter(user_erasure_requests::request_id.eq(request_id))
                .filter(user_erasure_requests::record_issued_at.is_null()),
        )
        .set((
            user_erasure_requests::record_issued_at.eq(issued_at),
            user_erasure_requests::account_status_record_id.eq(account_status_record_id),
        ))
        .execute(self.conn)
        .await?;
        Ok(updated == 1)
    }
}
