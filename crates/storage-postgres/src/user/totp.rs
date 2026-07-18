use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::user::UserTotpRepository;
use coauth_data::{Clock, User, UserTotpConfig, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::user_totp_configs;

/// An implementation of [`UserTotpRepository`] for a PostgreSQL connection
pub struct PgUserTotpRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserTotpRepository<'c> {
    /// Create a new [`PgUserTotpRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = user_totp_configs)]
struct UserTotpLookup {
    id: Uuid,
    user_id: Uuid,
    secret: String,
    algorithm: String,
    digits: i32,
    period: i32,
    confirmed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = user_totp_configs)]
struct NewUserTotpConfig {
    id: Uuid,
    user_id: Uuid,
    secret: String,
    algorithm: String,
    digits: i32,
    period: i32,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UserTotpRepository for PgUserTotpRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_totp.get_for_user",
        skip_all,
        fields(
            %user.id,
            %user.localpart,
        ),
        err,
    )]
    async fn get_for_user(&mut self, user: &User) -> Result<Option<UserTotpConfig>, Self::Error> {
        let res = user_totp_configs::table
            .filter(user_totp_configs::user_id.eq(Uuid::from(user.id)))
            .select(UserTotpLookup::as_select())
            .first::<UserTotpLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(UserTotpConfig {
            id: Ulid::from(res.id),
            user_id: Ulid::from(res.user_id),
            secret: res.secret,
            algorithm: res.algorithm,
            digits: res.digits,
            period: res.period,
            confirmed_at: res.confirmed_at,
            created_at: res.created_at,
        }))
    }

    #[tracing::instrument(
        name = "db.user_totp.add",
        skip_all,
        fields(
            %user.id,
            %user.localpart,
            user_totp.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        secret: String,
    ) -> Result<UserTotpConfig, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_totp.id", tracing::field::display(id));

        let new_config = NewUserTotpConfig {
            id: Uuid::from(id),
            user_id: Uuid::from(user.id),
            secret: secret.clone(),
            algorithm: "SHA1".to_owned(),
            digits: 6,
            period: 30,
            created_at,
        };

        diesel::insert_into(user_totp_configs::table)
            .values(&new_config)
            .execute(self.conn)
            .await?;

        Ok(UserTotpConfig {
            id,
            user_id: user.id,
            secret,
            algorithm: "SHA1".to_owned(),
            digits: 6,
            period: 30,
            confirmed_at: None,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_totp.confirm",
        skip_all,
        fields(
            user_totp.id = %config.id,
        ),
        err,
    )]
    async fn confirm(
        &mut self,
        clock: &dyn Clock,
        config: UserTotpConfig,
    ) -> Result<UserTotpConfig, Self::Error> {
        let confirmed_at = clock.now();

        let rows_affected = diesel::update(user_totp_configs::table.find(Uuid::from(config.id)))
            .set(user_totp_configs::confirmed_at.eq(Some(confirmed_at)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(UserTotpConfig {
            confirmed_at: Some(confirmed_at),
            ..config
        })
    }

    #[tracing::instrument(
        name = "db.user_totp.remove",
        skip_all,
        fields(
            user_totp.id = %config.id,
        ),
        err,
    )]
    async fn remove(&mut self, config: UserTotpConfig) -> Result<(), Self::Error> {
        let rows_affected = diesel::delete(user_totp_configs::table.find(Uuid::from(config.id)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }
}
