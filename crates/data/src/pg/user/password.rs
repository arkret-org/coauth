use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{Clock, Password, User, new_id, user::UserPasswordRepository};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, schema::user_passwords};

/// An implementation of [`UserPasswordRepository`] for a PostgreSQL connection
pub struct PgUserPasswordRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserPasswordRepository<'c> {
    /// Create a new [`PgUserPasswordRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = user_passwords)]
struct UserPasswordLookup {
    id: Uuid,
    hashed_password: String,
    version: i32,
    upgraded_from_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = user_passwords)]
struct NewUserPassword {
    id: Uuid,
    user_id: Uuid,
    hashed_password: String,
    version: i32,
    upgraded_from_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UserPasswordRepository for PgUserPasswordRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_password.active",
        skip_all,
        fields(
            %user.id,
            %user.handle,
        ),
        err,
    )]
    async fn active(&mut self, user: &User) -> Result<Option<Password>, Self::Error> {
        let res = user_passwords::table
            .filter(user_passwords::user_id.eq(Uuid::from(user.id)))
            .select(UserPasswordLookup::as_select())
            .order(user_passwords::created_at.desc())
            .first::<UserPasswordLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        let id = Ulid::from(res.id);

        let version = res.version.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("user_passwords")
                .column("version")
                .row(id)
                .source(e)
        })?;

        let upgraded_from_id = res.upgraded_from_id.map(Ulid::from);
        let created_at = res.created_at;
        let hashed_password = res.hashed_password;

        Ok(Some(Password {
            id,
            hashed_password,
            version,
            upgraded_from_id,
            created_at,
        }))
    }

    #[tracing::instrument(
        name = "db.user_password.add",
        skip_all,
        fields(
            %user.id,
            %user.handle,
            user_password.id,
            user_password.version = version,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        version: u16,
        hashed_password: String,
        upgraded_from: Option<&Password>,
    ) -> Result<Password, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_password.id", tracing::field::display(id));

        let upgraded_from_id = upgraded_from.map(|p| p.id);

        let new_password = NewUserPassword {
            id: Uuid::from(id),
            user_id: Uuid::from(user.id),
            hashed_password: hashed_password.clone(),
            version: i32::from(version),
            upgraded_from_id: upgraded_from_id.map(Uuid::from),
            created_at,
        };

        diesel::insert_into(user_passwords::table)
            .values(&new_password)
            .execute(self.conn)
            .await?;

        Ok(Password {
            id,
            hashed_password,
            version,
            upgraded_from_id,
            created_at,
        })
    }
}
