use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::user::PrincipalDidRepository;
use coauth_data::{Clock, PrincipalDidUpdateKey, User, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::principal_did_update_keys;

/// PostgreSQL implementation of [`PrincipalDidRepository`].
pub struct PgPrincipalDidRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgPrincipalDidRepository<'c> {
    /// Create a new [`PgPrincipalDidRepository`] from an active PostgreSQL
    /// connection.
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = principal_did_update_keys)]
struct PrincipalDidLookup {
    id: Uuid,
    user_id: Uuid,
    audience: String,
    did: String,
    did_public_key_multibase: String,
    update_public_key_multibase: String,
    update_secret_b64: String,
    key_log_head: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<PrincipalDidLookup> for PrincipalDidUpdateKey {
    fn from(row: PrincipalDidLookup) -> Self {
        Self {
            id: Ulid::from(row.id),
            user_id: Ulid::from(row.user_id),
            audience: row.audience,
            did: row.did,
            did_public_key_multibase: row.did_public_key_multibase,
            update_public_key_multibase: row.update_public_key_multibase,
            update_secret_b64: row.update_secret_b64,
            key_log_head: row.key_log_head,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = principal_did_update_keys)]
struct NewPrincipalDid {
    id: Uuid,
    user_id: Uuid,
    audience: String,
    did: String,
    did_public_key_multibase: String,
    update_public_key_multibase: String,
    update_secret_b64: String,
    key_log_head: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl PrincipalDidRepository for PgPrincipalDidRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.principal_did.get_for_user_and_audience",
        skip_all,
        fields(%user.id, %user.localpart, audience = audience),
        err,
    )]
    async fn get_for_user_and_audience(
        &mut self,
        user: &User,
        audience: &str,
    ) -> Result<Option<PrincipalDidUpdateKey>, Self::Error> {
        let row = principal_did_update_keys::table
            .filter(principal_did_update_keys::user_id.eq(Uuid::from(user.id)))
            .filter(principal_did_update_keys::audience.eq(audience))
            .select(PrincipalDidLookup::as_select())
            .first::<PrincipalDidLookup>(self.conn)
            .await
            .optional()?;
        Ok(row.map(Into::into))
    }

    #[tracing::instrument(
        name = "db.principal_did.get_by_did",
        skip_all,
        fields(did = did),
        err,
    )]
    async fn get_by_did(
        &mut self,
        did: &str,
    ) -> Result<Option<PrincipalDidUpdateKey>, Self::Error> {
        let row = principal_did_update_keys::table
            .filter(principal_did_update_keys::did.eq(did))
            .select(PrincipalDidLookup::as_select())
            .first::<PrincipalDidLookup>(self.conn)
            .await
            .optional()?;
        Ok(row.map(Into::into))
    }

    #[tracing::instrument(
        name = "db.principal_did.add",
        skip_all,
        fields(%user.id, %user.localpart, audience = audience, principal_did.id),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        audience: String,
        did: String,
        did_public_key_multibase: String,
        update_public_key_multibase: String,
        update_secret_b64: String,
        key_log_head: Option<String>,
    ) -> Result<PrincipalDidUpdateKey, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("principal_did.id", tracing::field::display(id));

        let new_row = NewPrincipalDid {
            id: Uuid::from(id),
            user_id: Uuid::from(user.id),
            audience: audience.clone(),
            did: did.clone(),
            did_public_key_multibase: did_public_key_multibase.clone(),
            update_public_key_multibase: update_public_key_multibase.clone(),
            update_secret_b64: update_secret_b64.clone(),
            key_log_head: key_log_head.clone(),
            created_at,
            updated_at: created_at,
        };

        diesel::insert_into(principal_did_update_keys::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(PrincipalDidUpdateKey {
            id,
            user_id: user.id,
            audience,
            did,
            did_public_key_multibase,
            update_public_key_multibase,
            update_secret_b64,
            key_log_head,
            created_at,
            updated_at: created_at,
        })
    }
}
