use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    AccessToken, Clock, RefreshToken, RefreshTokenChainRevokeOutcome, RefreshTokenState, Session,
    new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::oauth_refresh_tokens;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// An implementation of [`OAuthRefreshTokenRepository`] for a PostgreSQL
/// connection
pub struct PgOAuthRefreshTokenRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuthRefreshTokenRepository<'c> {
    /// Create a new [`PgOAuthRefreshTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading refresh tokens from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_refresh_tokens)]
struct OAuthRefreshTokenRow {
    id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    oauth_access_token_id: Option<Uuid>,
    oauth_session_id: Uuid,
    next_oauth_refresh_token_id: Option<Uuid>,
    chain_root_oauth_refresh_token_id: Uuid,
    chain_created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

impl TryFrom<OAuthRefreshTokenRow> for RefreshToken {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: OAuthRefreshTokenRow) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let state = match (
            value.revoked_at,
            value.consumed_at,
            value.next_oauth_refresh_token_id,
        ) {
            (Some(revoked_at), ..) => RefreshTokenState::Revoked { revoked_at },
            (None, None, None) => RefreshTokenState::Valid,
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
            chain_root_id: value.chain_root_oauth_refresh_token_id.into(),
            chain_created_at: value.chain_created_at,
            last_seen_at: value.last_seen_at,
            access_token_id: value.oauth_access_token_id.map(Ulid::from),
        })
    }
}

/// Insertable row for creating a new refresh token
#[derive(Insertable)]
#[diesel(table_name = oauth_refresh_tokens)]
struct NewOAuthRefreshToken {
    id: Uuid,
    oauth_session_id: Uuid,
    oauth_access_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    chain_root_oauth_refresh_token_id: Uuid,
    chain_created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

/// Row type for cleanup query results via raw SQL
#[derive(Debug, QueryableByName)]
struct CleanupResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_ts: Option<DateTime<Utc>>,
}

/// Row type for chain revoke count results via raw SQL
#[derive(Debug, QueryableByName)]
struct ChainRevokeResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    refresh_tokens: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    access_tokens: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    session_grants: i64,
}

#[async_trait]
impl coauth_data::oauth::OAuthRefreshTokenRepository for PgOAuthRefreshTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth_refresh_token.lookup",
        skip_all,
        fields(refresh_token.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error> {
        let res = oauth_refresh_tokens::table
            .find(Uuid::from(id))
            .select(OAuthRefreshTokenRow::as_select())
            .first::<OAuthRefreshTokenRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(name = "db.oauth_refresh_token.find_by_token", skip_all, err)]
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error> {
        let res = oauth_refresh_tokens::table
            .filter(oauth_refresh_tokens::refresh_token.eq(refresh_token))
            .select(OAuthRefreshTokenRow::as_select())
            .first::<OAuthRefreshTokenRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth_refresh_token.add",
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

        let new_row = NewOAuthRefreshToken {
            id: Uuid::from(id),
            oauth_session_id: Uuid::from(session.id),
            oauth_access_token_id: Uuid::from(access_token.id),
            refresh_token: refresh_token.clone(),
            created_at,
            chain_root_oauth_refresh_token_id: Uuid::from(id),
            chain_created_at: created_at,
            last_seen_at: created_at,
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
            chain_root_id: id,
            chain_created_at: created_at,
            last_seen_at: created_at,
        })
    }

    #[tracing::instrument(
        name = "db.oauth_refresh_token.consume",
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
        let rows_affected = diesel::update(
            oauth_refresh_tokens::table
                .find(Uuid::from(refresh_token.id))
                .filter(oauth_refresh_tokens::consumed_at.is_null())
                .filter(oauth_refresh_tokens::revoked_at.is_null())
                .filter(oauth_refresh_tokens::next_oauth_refresh_token_id.is_null()),
        )
        .set((
            oauth_refresh_tokens::consumed_at.eq(Some(consumed_at)),
            oauth_refresh_tokens::last_seen_at.eq(consumed_at),
            oauth_refresh_tokens::next_oauth_refresh_token_id.eq(Some(Uuid::from(replaced_by.id))),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        let rows_affected = diesel::update(
            oauth_refresh_tokens::table
                .find(Uuid::from(replaced_by.id))
                .filter(
                    oauth_refresh_tokens::chain_root_oauth_refresh_token_id
                        .eq(Uuid::from(replaced_by.id)),
                ),
        )
        .set((
            oauth_refresh_tokens::chain_root_oauth_refresh_token_id
                .eq(Uuid::from(refresh_token.chain_root_id)),
            oauth_refresh_tokens::chain_created_at.eq(refresh_token.chain_created_at),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        refresh_token
            .consume(consumed_at, replaced_by)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth_refresh_token.revoke",
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

    #[tracing::instrument(
        name = "db.oauth_refresh_token.revoke_chain_by_root",
        skip_all,
        fields(refresh_token.chain_root_id = %chain_root_id),
        err,
    )]
    async fn revoke_chain_by_root(
        &mut self,
        clock: &dyn Clock,
        chain_root_id: Ulid,
    ) -> Result<RefreshTokenChainRevokeOutcome, Self::Error> {
        let revoked_at = clock.now();

        let res: ChainRevokeResult = diesel::sql_query(
            r"
                WITH
                    chain AS (
                        SELECT id, oauth_access_token_id, oauth_session_id
                        FROM oauth_refresh_tokens
                        WHERE chain_root_oauth_refresh_token_id = $1::uuid
                        FOR UPDATE
                    ),
                    revoked_refresh_tokens AS (
                        UPDATE oauth_refresh_tokens
                        SET revoked_at = $2::timestamptz
                        FROM chain
                        WHERE oauth_refresh_tokens.id = chain.id
                          AND oauth_refresh_tokens.revoked_at IS NULL
                        RETURNING oauth_refresh_tokens.id
                    ),
                    revoked_access_tokens AS (
                        UPDATE oauth_access_tokens
                        SET revoked_at = $2::timestamptz
                        FROM chain
                        WHERE oauth_access_tokens.id = chain.oauth_access_token_id
                          AND oauth_access_tokens.revoked_at IS NULL
                        RETURNING oauth_access_tokens.id
                    ),
                    revoked_session_grants AS (
                        UPDATE oauth_session_grants
                        SET revoked_at = $2::timestamptz
                        FROM oauth_sessions
                        JOIN chain ON chain.oauth_session_id = oauth_sessions.id
                        WHERE oauth_sessions.user_session_id IS NOT NULL
                          AND oauth_session_grants.user_session_id = oauth_sessions.user_session_id
                          AND oauth_session_grants.revoked_at IS NULL
                        RETURNING oauth_session_grants.id
                    )
                SELECT
                    (SELECT COUNT(*) FROM revoked_refresh_tokens) AS refresh_tokens,
                    (SELECT COUNT(*) FROM revoked_access_tokens) AS access_tokens,
                    (SELECT COUNT(*) FROM revoked_session_grants) AS session_grants
            ",
        )
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(chain_root_id))
        .bind::<diesel::sql_types::Timestamptz, _>(revoked_at)
        .get_result(self.conn)
        .await?;

        Ok(RefreshTokenChainRevokeOutcome {
            refresh_tokens: res.refresh_tokens.try_into().unwrap_or(usize::MAX),
            access_tokens: res.access_tokens.try_into().unwrap_or(usize::MAX),
            session_grants: res.session_grants.try_into().unwrap_or(usize::MAX),
        })
    }

    #[tracing::instrument(name = "db.oauth_refresh_token.cleanup_revoked", skip_all, err)]
    async fn cleanup_revoked(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        let res: CleanupResult = diesel::sql_query(
            r"
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
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(limit_i64)
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }

    #[tracing::instrument(name = "db.oauth_refresh_token.cleanup_consumed", skip_all, err)]
    async fn cleanup_consumed(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        let res: CleanupResult = diesel::sql_query(
            r"
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
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(limit_i64)
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }
}
