use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coauth_data::{AccessToken, AccessTokenState, Clock, Session, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, schema::oauth2_access_tokens};

/// An implementation of [`OAuth2AccessTokenRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2AccessTokenRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuth2AccessTokenRepository<'c> {
    /// Create a new [`PgOAuth2AccessTokenRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading access tokens from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth2_access_tokens)]
struct OAuth2AccessTokenRow {
    id: Uuid,
    oauth2_session_id: Uuid,
    access_token: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    first_used_at: Option<DateTime<Utc>>,
}

impl From<OAuth2AccessTokenRow> for AccessToken {
    fn from(value: OAuth2AccessTokenRow) -> Self {
        let state = match value.revoked_at {
            None => AccessTokenState::Valid,
            Some(revoked_at) => AccessTokenState::Revoked { revoked_at },
        };

        Self {
            id: value.id.into(),
            state,
            session_id: value.oauth2_session_id.into(),
            access_token: value.access_token,
            created_at: value.created_at,
            expires_at: value.expires_at,
            first_used_at: value.first_used_at,
        }
    }
}

/// Insertable row for creating a new access token
#[derive(Insertable)]
#[diesel(table_name = oauth2_access_tokens)]
struct NewOAuth2AccessToken {
    id: Uuid,
    oauth2_session_id: Uuid,
    access_token: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
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
impl coauth_data::oauth2::OAuth2AccessTokenRepository for PgOAuth2AccessTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_access_token.lookup",
        skip_all,
        fields(access_token.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<AccessToken>, Self::Error> {
        let res = oauth2_access_tokens::table
            .find(Uuid::from(id))
            .select(OAuth2AccessTokenRow::as_select())
            .first::<OAuth2AccessTokenRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(AccessToken::from))
    }

    #[tracing::instrument(name = "db.oauth2_access_token.find_by_token", skip_all, err)]
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<AccessToken>, Self::Error> {
        let res = oauth2_access_tokens::table
            .filter(oauth2_access_tokens::access_token.eq(access_token))
            .select(OAuth2AccessTokenRow::as_select())
            .first::<OAuth2AccessTokenRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(AccessToken::from))
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.add",
        skip_all,
        fields(
            %session.id,
            client.id = %session.client_id,
            access_token.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: String,
        expires_after: Option<Duration>,
    ) -> Result<AccessToken, Self::Error> {
        let created_at = clock.now();
        let expires_at = expires_after.map(|d| created_at + d);
        let id = new_id(created_at, rng);

        tracing::Span::current().record("access_token.id", tracing::field::display(id));

        let new_row = NewOAuth2AccessToken {
            id: Uuid::from(id),
            oauth2_session_id: Uuid::from(session.id),
            access_token: access_token.clone(),
            created_at,
            expires_at,
        };

        diesel::insert_into(oauth2_access_tokens::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(AccessToken {
            id,
            state: AccessTokenState::default(),
            access_token,
            session_id: session.id,
            created_at,
            expires_at,
            first_used_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.revoke",
        skip_all,
        fields(
            session.id = %access_token.session_id,
            %access_token.id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error> {
        let revoked_at = clock.now();
        let rows_affected =
            diesel::update(oauth2_access_tokens::table.find(Uuid::from(access_token.id)))
                .set(oauth2_access_tokens::revoked_at.eq(Some(revoked_at)))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        access_token
            .revoke(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.mark_used",
        skip_all,
        fields(
            session.id = %access_token.session_id,
            %access_token.id,
        ),
        err,
    )]
    async fn mark_used(
        &mut self,
        clock: &dyn Clock,
        mut access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error> {
        let now = clock.now();
        let rows_affected =
            diesel::update(oauth2_access_tokens::table.find(Uuid::from(access_token.id)))
                .set(oauth2_access_tokens::first_used_at.eq(Some(now)))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        access_token.first_used_at = Some(now);

        Ok(access_token)
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.cleanup_revoked",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
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
                        FROM oauth2_access_tokens
                        WHERE revoked_at IS NOT NULL
                          AND ($1::timestamptz IS NULL OR revoked_at >= $1::timestamptz)
                          AND revoked_at < $2::timestamptz
                        ORDER BY revoked_at ASC
                        LIMIT $3
                        FOR UPDATE
                    ),

                    deleted AS (
                        DELETE FROM oauth2_access_tokens
                        USING to_delete
                        WHERE oauth2_access_tokens.id = to_delete.id
                        RETURNING oauth2_access_tokens.revoked_at
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

    #[tracing::instrument(
        name = "db.oauth2_access_token.cleanup_expired",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup_expired(
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
                        FROM oauth2_access_tokens
                        WHERE expires_at IS NOT NULL
                          AND ($1::timestamptz IS NULL OR expires_at >= $1::timestamptz)
                          AND expires_at < $2::timestamptz
                        ORDER BY expires_at ASC
                        LIMIT $3
                        FOR UPDATE
                    ),

                    deleted AS (
                        DELETE FROM oauth2_access_tokens
                        USING to_delete
                        WHERE oauth2_access_tokens.id = to_delete.id
                        RETURNING oauth2_access_tokens.expires_at
                    )

                SELECT
                    COUNT(*) as count,
                    MAX(expires_at) as last_ts
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
