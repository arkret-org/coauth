use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::personal::session::PersonalSession;
use coauth_data::personal::{PersonalAccessToken, PersonalAccessTokenRepository};
use coauth_data::{Clock, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::personal_access_tokens;

/// An implementation of [`PersonalAccessTokenRepository`] for a PostgreSQL
/// connection
pub struct PgPersonalAccessTokenRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgPersonalAccessTokenRepository<'c> {
    /// Create a new [`PgPersonalAccessTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading personal access tokens from the database
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = personal_access_tokens)]
struct PersonalAccessTokenRow {
    id: Uuid,
    personal_session_id: Uuid,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<PersonalAccessTokenRow> for PersonalAccessToken {
    fn from(value: PersonalAccessTokenRow) -> Self {
        Self {
            id: Ulid::from(value.id),
            session_id: Ulid::from(value.personal_session_id),
            created_at: value.created_at,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        }
    }
}

/// Insertable row for creating a new personal access token
#[derive(Insertable)]
#[diesel(table_name = personal_access_tokens)]
struct NewPersonalAccessToken {
    id: Uuid,
    personal_session_id: Uuid,
    access_token_sha256: Vec<u8>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl PersonalAccessTokenRepository for PgPersonalAccessTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.personal_access_token.lookup",
        skip_all,
        fields(
            personal_access_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalAccessToken>, Self::Error> {
        let res = personal_access_tokens::table
            .find(Uuid::from(id))
            .select(PersonalAccessTokenRow::as_select())
            .first::<PersonalAccessTokenRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(PersonalAccessToken::from))
    }

    #[tracing::instrument(name = "db.personal_access_token.find_by_token", skip_all, err)]
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<PersonalAccessToken>, Self::Error> {
        let token_sha256 = Sha256::digest(access_token.as_bytes()).to_vec();

        let res = personal_access_tokens::table
            .filter(personal_access_tokens::access_token_sha256.eq(token_sha256))
            .select(PersonalAccessTokenRow::as_select())
            .first::<PersonalAccessTokenRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(PersonalAccessToken::from))
    }

    #[tracing::instrument(
        name = "db.personal_access_token.find_active_for_session",
        skip_all,
        err
    )]
    async fn find_active_for_session(
        &mut self,
        session: &PersonalSession,
    ) -> Result<Option<PersonalAccessToken>, Self::Error> {
        let res = personal_access_tokens::table
            .filter(personal_access_tokens::personal_session_id.eq(Uuid::from(session.id)))
            .filter(personal_access_tokens::revoked_at.is_null())
            .select(PersonalAccessTokenRow::as_select())
            .first::<PersonalAccessTokenRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(PersonalAccessToken::from))
    }

    #[tracing::instrument(
        name = "db.personal_access_token.add",
        skip_all,
        fields(
            personal_access_token.id,
            %session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &PersonalSession,
        access_token: &str,
        expires_after: Option<chrono::Duration>,
    ) -> Result<PersonalAccessToken, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("personal_access_token.id", tracing::field::display(id));

        let token_sha256 = Sha256::digest(access_token.as_bytes()).to_vec();
        let expires_at = expires_after.map(|expires_after| created_at + expires_after);

        let new_token = NewPersonalAccessToken {
            id: Uuid::from(id),
            personal_session_id: Uuid::from(session.id),
            access_token_sha256: token_sha256,
            created_at,
            expires_at,
        };

        diesel::insert_into(personal_access_tokens::table)
            .values(&new_token)
            .execute(self.conn)
            .await?;

        Ok(PersonalAccessToken {
            id,
            session_id: session.id,
            created_at,
            expires_at,
            revoked_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.personal_access_token.revoke",
        skip_all,
        fields(
            %access_token.id,
            personal_session.id = %access_token.session_id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        mut access_token: PersonalAccessToken,
    ) -> Result<PersonalAccessToken, Self::Error> {
        let revoked_at = clock.now();
        let rows_affected =
            diesel::update(personal_access_tokens::table.find(Uuid::from(access_token.id)))
                .set(personal_access_tokens::revoked_at.eq(Some(revoked_at)))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        access_token.revoked_at = Some(revoked_at);
        Ok(access_token)
    }
}
