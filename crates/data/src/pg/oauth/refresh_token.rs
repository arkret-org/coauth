use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{AccessToken, Clock, RefreshToken, RefreshTokenState, Session, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, schema::oauth_refresh_tokens};

/// An implementation of [`OAuth2RefreshTokenRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2RefreshTokenRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuth2RefreshTokenRepository<'c> {
    /// Create a new [`PgOAuth2RefreshTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading refresh tokens from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_refresh_tokens)]
struct OAuth2RefreshTokenRow {
    id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    oauth_access_token_id: Option<Uuid>,
    oauth_session_id: Uuid,
    next_oauth_refresh_token_id: Option<Uuid>,
}

impl TryFrom<OAuth2RefreshTokenRow> for RefreshToken {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: OAuth2RefreshTokenRow) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let state = match (
            value.revoked_at,
            value.consumed_at,
            value.next_oauth_refresh_token_id,
        ) {
            (None, None, None) => RefreshTokenState::Valid,
            (Some(revoked_at), None, None) => RefreshTokenState::Revoked { revoked_at },
            (None, Some(consumed_at), None) => RefreshTokenState::Consumed {
                consumed_at,
                next_refresh_token_id: None,
            },
            (None, Some(consumed_at), Some(id)) => RefreshTokenState::Consumed {
                consumed_at,
                next_refresh_token_id: Some(Ulid::from(id)),
            },
            _ => {
                return Err(DatabaseInconsistencyError::on("oauth_refresh_tokens")
                    .column("next_oauth_refresh_token_id")
                    .row(id));
            }
        };

        Ok(RefreshToken {
            id,
            state,
            session_id: value.oauth_session_id.into(),
            refresh_token: value.refresh_token,
            created_at: value.created_at,
            access_token_id: value.oauth_access_token_id.map(Ulid::from),
        })
    }
}

/// Insertable row for creating a new refresh token
#[derive(Insertable)]
#[diesel(table_name = oauth_refresh_tokens)]
struct NewOAuth2RefreshToken {
    id: Uuid,
    oauth_session_id: Uuid,
    oauth_access_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
}

/// Row type for cleanup query results via raw SQL
#[derive(Debug, QueryableByName)]
struct CleanupResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_ts: Option<DateTime<Utc>>,
}

#[async_trait]
impl coauth_data::oauth2::OAuth2RefreshTokenRepository for PgOAuth2RefreshTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.lookup",
        skip_all,
        fields(refresh_token.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error> {
        let res = oauth_refresh_tokens::table
            .find(Uuid::from(id))
            .select(OAuth2RefreshTokenRow::as_select())
            .first::<OAuth2RefreshTokenRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(name = "db.oauth2_refresh_token.find_by_token", skip_all, err)]
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error> {
        let res = oauth_refresh_tokens::table
            .filter(oauth_refresh_tokens::refresh_token.eq(refresh_token))
            .select(OAuth2RefreshTokenRow::as_select())
            .first::<OAuth2RefreshTokenRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.add",
        skip_all,
        fields(
            %session.id,
            client.id = %session.client_id,
            refresh_token.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: &AccessToken,
        refresh_token: String,
    ) -> Result<RefreshToken, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("refresh_token.id", tracing::field::display(id));

        let new_row = NewOAuth2RefreshToken {
            id: Uuid::from(id),
            oauth_session_id: Uuid::from(session.id),
            oauth_access_token_id: Uuid::from(access_token.id),
            refresh_token: refresh_token.clone(),
            created_at,
        };

        diesel::insert_into(oauth_refresh_tokens::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(RefreshToken {
            id,
            state: RefreshTokenState::default(),
            session_id: session.id,
            refresh_token,
            access_token_id: Some(access_token.id),
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.consume",
        skip_all,
        fields(
            %refresh_token.id,
            session.id = %refresh_token.session_id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
        replaced_by: &RefreshToken,
    ) -> Result<RefreshToken, Self::Error> {
        let consumed_at = clock.now();
        let rows_affected =
            diesel::update(oauth_refresh_tokens::table.find(Uuid::from(refresh_token.id)))
                .set((
                    oauth_refresh_tokens::consumed_at.eq(Some(consumed_at)),
                    oauth_refresh_tokens::next_oauth_refresh_token_id
                        .eq(Some(Uuid::from(replaced_by.id))),
                ))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        refresh_token
            .consume(consumed_at, replaced_by)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.revoke",
        skip_all,
        fields(
            %refresh_token.id,
            session.id = %refresh_token.session_id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
    ) -> Result<RefreshToken, Self::Error> {
        let revoked_at = clock.now();
        let rows_affected =
            diesel::update(oauth_refresh_tokens::table.find(Uuid::from(refresh_token.id)))
                .set(oauth_refresh_tokens::revoked_at.eq(Some(revoked_at)))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        refresh_token
            .revoke(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.oauth2_refresh_token.cleanup_revoked", skip_all, err)]
    async fn cleanup_revoked(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        let res: CleanupResult = diesel::sql_query(
            r#"
                WITH
                    to_delete AS (
                        SELECT id
                        FROM oauth_refresh_tokens
                        WHERE revoked_at IS NOT NULL
                          AND ($1::timestamptz IS NULL OR revoked_at >= $1::timestamptz)
                          AND revoked_at < $2::timestamptz
                        ORDER BY revoked_at ASC
                        LIMIT $3
                        FOR UPDATE
                    ),

                    deleted AS (
                        DELETE FROM oauth_refresh_tokens
                        USING to_delete
                        WHERE oauth_refresh_tokens.id = to_delete.id
                        RETURNING oauth_refresh_tokens.revoked_at
                    )

                SELECT
                    COUNT(*) as count,
                    MAX(revoked_at) as last_ts
                FROM deleted
            "#,
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(limit_i64)
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }

    #[tracing::instrument(name = "db.oauth2_refresh_token.cleanup_consumed", skip_all, err)]
    async fn cleanup_consumed(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        let res: CleanupResult = diesel::sql_query(
            r#"
                WITH
                    to_delete AS (
                        SELECT rts_to_del.id
                        FROM oauth_refresh_tokens rts_to_del
                        LEFT JOIN oauth_refresh_tokens next_rts
                          ON rts_to_del.next_oauth_refresh_token_id = next_rts.id
                        WHERE rts_to_del.consumed_at IS NOT NULL
                          AND (rts_to_del.next_oauth_refresh_token_id IS NULL OR next_rts.consumed_at IS NOT NULL)
                          AND ($1::timestamptz IS NULL OR rts_to_del.consumed_at >= $1::timestamptz)
                          AND rts_to_del.consumed_at < $2::timestamptz
                        ORDER BY rts_to_del.consumed_at ASC
                        LIMIT $3
                    ),

                    deleted AS (
                        DELETE FROM oauth_refresh_tokens
                        USING to_delete
                        WHERE oauth_refresh_tokens.id = to_delete.id
                        RETURNING oauth_refresh_tokens.consumed_at
                    )

                SELECT
                    COUNT(*) as count,
                    MAX(consumed_at) as last_ts
                FROM deleted
            "#,
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(limit_i64)
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }
}
