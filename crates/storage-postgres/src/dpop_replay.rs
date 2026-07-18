//! PostgreSQL implementation of the DPoP proof replay repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::dpop_replay::{DpopReplayRepository, NewDpopJtiReplay};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::DatabaseError;
use crate::schema::dpop_jti_replay;

/// PostgreSQL implementation of [`DpopReplayRepository`].
pub struct PgDpopReplayRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgDpopReplayRepository<'c> {
    /// Construct from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Insertable)]
#[diesel(table_name = dpop_jti_replay)]
struct InsertableDpopJtiReplay {
    jti_digest: String,
    seen_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl DpopReplayRepository for PgDpopReplayRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.dpop_replay.consume_jti", skip_all, err)]
    async fn consume_jti(&mut self, params: NewDpopJtiReplay) -> Result<bool, Self::Error> {
        diesel::delete(
            dpop_jti_replay::table.filter(dpop_jti_replay::expires_at.le(params.seen_at)),
        )
        .execute(self.conn)
        .await?;

        let row = InsertableDpopJtiReplay {
            jti_digest: params.jti_digest,
            seen_at: params.seen_at,
            expires_at: params.expires_at,
            created_at: params.seen_at,
        };

        let inserted = diesel::insert_into(dpop_jti_replay::table)
            .values(&row)
            .on_conflict(dpop_jti_replay::jti_digest)
            .do_nothing()
            .execute(self.conn)
            .await?;

        Ok(inserted == 1)
    }
}
