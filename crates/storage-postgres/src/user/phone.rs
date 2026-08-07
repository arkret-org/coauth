use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::user::UserPhoneRepository;
use coauth_data::{
    Clock, User, UserPhone, UserPhoneAuthentication, UserPhoneAuthenticationCode, UserRegistration,
    new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::{user_phone_authentication_codes, user_phone_authentications, user_phones};

/// An implementation of [`UserPhoneRepository`] for a PostgreSQL connection
pub struct PgUserPhoneRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserPhoneRepository<'c> {
    /// Create a new [`PgUserPhoneRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading user phones from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_phones)]
struct UserPhoneRow {
    id: Uuid,
    user_id: Uuid,
    phone: String,
    created_at: DateTime<Utc>,
}

impl From<UserPhoneRow> for UserPhone {
    fn from(row: UserPhoneRow) -> UserPhone {
        UserPhone {
            id: row.id.into(),
            user_id: row.user_id.into(),
            phone: row.phone,
            created_at: row.created_at,
        }
    }
}

/// Insertable row for creating a new user phone
#[derive(Insertable)]
#[diesel(table_name = user_phones)]
struct NewUserPhone {
    id: Uuid,
    user_id: Uuid,
    phone: String,
    created_at: DateTime<Utc>,
}

/// Row type for loading user phone authentications from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_phone_authentications)]
struct UserPhoneAuthenticationRow {
    id: Uuid,
    user_registration_id: Option<Uuid>,
    phone: String,
    completed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<UserPhoneAuthenticationRow> for UserPhoneAuthentication {
    fn from(row: UserPhoneAuthenticationRow) -> Self {
        UserPhoneAuthentication {
            id: row.id.into(),
            user_registration_id: row.user_registration_id.map(Ulid::from),
            phone: row.phone,
            created_at: row.created_at,
            completed_at: row.completed_at,
        }
    }
}

/// Insertable row for creating a new user phone authentication
#[derive(Insertable)]
#[diesel(table_name = user_phone_authentications)]
struct NewUserPhoneAuthentication {
    id: Uuid,
    user_registration_id: Option<Uuid>,
    phone: String,
    created_at: DateTime<Utc>,
}

/// Row type for loading user phone authentication codes from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_phone_authentication_codes)]
struct UserPhoneAuthenticationCodeRow {
    id: Uuid,
    user_phone_authentication_id: Uuid,
    code: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl From<UserPhoneAuthenticationCodeRow> for UserPhoneAuthenticationCode {
    fn from(row: UserPhoneAuthenticationCodeRow) -> Self {
        UserPhoneAuthenticationCode {
            id: row.id.into(),
            user_phone_authentication_id: row.user_phone_authentication_id.into(),
            code: row.code,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

/// Insertable row for creating a new user phone authentication code
#[derive(Insertable)]
#[diesel(table_name = user_phone_authentication_codes)]
struct NewUserPhoneAuthenticationCode {
    id: Uuid,
    user_phone_authentication_id: Uuid,
    code: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UserPhoneRepository for PgUserPhoneRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_phone.lookup",
        skip_all,
        fields(
            user_phone.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPhone>, Self::Error> {
        let res = user_phones::table
            .find(Uuid::from(id))
            .select(UserPhoneRow::as_select())
            .first::<UserPhoneRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(UserPhone::from))
    }

    #[tracing::instrument(
        name = "db.user_phone.find_by_phone",
        skip_all,
        fields(
            user_phone.phone = phone,
        ),
        err,
    )]
    async fn find_by_phone(&mut self, phone: &str) -> Result<Option<UserPhone>, Self::Error> {
        let res: Vec<UserPhoneRow> = user_phones::table
            .filter(user_phones::phone.eq(phone))
            .select(UserPhoneRow::as_select())
            .load(self.conn)
            .await?;

        if res.len() != 1 {
            return Ok(None);
        }

        let Some(user_phone) = res.into_iter().next() else {
            return Ok(None);
        };

        Ok(Some(user_phone.into()))
    }

    #[tracing::instrument(
        name = "db.user_phone.all",
        skip_all,
        fields(
            %user.id,
        ),
        err,
    )]
    async fn all(&mut self, user: &User) -> Result<Vec<UserPhone>, Self::Error> {
        let res: Vec<UserPhoneRow> = user_phones::table
            .filter(user_phones::user_id.eq(Uuid::from(user.id)))
            .select(UserPhoneRow::as_select())
            .order(user_phones::phone.asc())
            .load(self.conn)
            .await?;

        Ok(res.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(
        name = "db.user_phone.add",
        skip_all,
        fields(
            %user.id,
            user_phone.id,
            user_phone.phone = phone,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        phone: String,
    ) -> Result<UserPhone, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_phone.id", tracing::field::display(id));

        let new_phone = NewUserPhone {
            id: Uuid::from(id),
            user_id: Uuid::from(user.id),
            phone: phone.clone(),
            created_at,
        };

        diesel::insert_into(user_phones::table)
            .values(&new_phone)
            .execute(self.conn)
            .await?;

        Ok(UserPhone {
            id,
            user_id: user.id,
            phone,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_phone.remove",
        skip_all,
        fields(
            user.id = %user_phone.user_id,
            %user_phone.id,
            %user_phone.phone,
        ),
        err,
    )]
    async fn remove(&mut self, user_phone: UserPhone) -> Result<(), Self::Error> {
        let rows_affected = diesel::delete(user_phones::table.find(Uuid::from(user_phone.id)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.user_phone.add_authentication_for_registration",
        skip_all,
        fields(
            %user_registration.id,
            user_phone_authentication.id,
            user_phone_authentication.phone = phone,
        ),
        err,
    )]
    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        phone: String,
        user_registration: &UserRegistration,
    ) -> Result<UserPhoneAuthentication, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current()
            .record("user_phone_authentication.id", tracing::field::display(id));

        let new_auth = NewUserPhoneAuthentication {
            id: Uuid::from(id),
            user_registration_id: Some(Uuid::from(user_registration.id)),
            phone: phone.clone(),
            created_at,
        };

        diesel::insert_into(user_phone_authentications::table)
            .values(&new_auth)
            .execute(self.conn)
            .await?;

        Ok(UserPhoneAuthentication {
            id,
            user_registration_id: Some(user_registration.id),
            phone,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_phone.add_authentication_code",
        skip_all,
        fields(
            %user_phone_authentication.id,
            %user_phone_authentication.phone,
            user_phone_authentication_code.id,
            user_phone_authentication_code.code = code,
        ),
        err,
    )]
    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        user_phone_authentication: &UserPhoneAuthentication,
        code: String,
    ) -> Result<UserPhoneAuthenticationCode, Self::Error> {
        let created_at = clock.now();
        let expires_at = created_at + duration;
        let id = new_id(created_at, rng);
        tracing::Span::current().record(
            "user_phone_authentication_code.id",
            tracing::field::display(id),
        );

        let new_code = NewUserPhoneAuthenticationCode {
            id: Uuid::from(id),
            user_phone_authentication_id: Uuid::from(user_phone_authentication.id),
            code: code.clone(),
            created_at,
            expires_at,
        };

        diesel::insert_into(user_phone_authentication_codes::table)
            .values(&new_code)
            .execute(self.conn)
            .await?;

        Ok(UserPhoneAuthenticationCode {
            id,
            user_phone_authentication_id: user_phone_authentication.id,
            code,
            created_at,
            expires_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_phone.lookup_authentication",
        skip_all,
        fields(
            user_phone_authentication.id = %id,
        ),
        err,
    )]
    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserPhoneAuthentication>, Self::Error> {
        let res = user_phone_authentications::table
            .find(Uuid::from(id))
            .select(UserPhoneAuthenticationRow::as_select())
            .first::<UserPhoneAuthenticationRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(UserPhoneAuthentication::from))
    }

    #[tracing::instrument(
        name = "db.user_phone.find_authentication_by_code",
        skip_all,
        fields(
            %authentication.id,
            user_phone_authentication_code.code = code,
        ),
        err,
    )]
    async fn find_authentication_code(
        &mut self,
        authentication: &UserPhoneAuthentication,
        code: &str,
    ) -> Result<Option<UserPhoneAuthenticationCode>, Self::Error> {
        let res = user_phone_authentication_codes::table
            .filter(
                user_phone_authentication_codes::user_phone_authentication_id
                    .eq(Uuid::from(authentication.id)),
            )
            .filter(user_phone_authentication_codes::code.eq(code))
            .select(UserPhoneAuthenticationCodeRow::as_select())
            .first::<UserPhoneAuthenticationCodeRow>(self.conn)
            .await
            .optional()?;

        Ok(res.map(UserPhoneAuthenticationCode::from))
    }

    #[tracing::instrument(
        name = "db.user_phone.complete_phone_authentication_with_code",
        skip_all,
        fields(
            %user_phone_authentication.id,
            %user_phone_authentication.phone,
            %user_phone_authentication_code.id,
            %user_phone_authentication_code.code,
        ),
        err,
    )]
    async fn complete_authentication_with_code(
        &mut self,
        clock: &dyn Clock,
        mut user_phone_authentication: UserPhoneAuthentication,
        user_phone_authentication_code: &UserPhoneAuthenticationCode,
    ) -> Result<UserPhoneAuthentication, Self::Error> {
        // We technically don't use the authentication code here (other than
        // recording it in the span), but this is to make sure the caller has
        // fetched one before calling this
        let completed_at = clock.now();

        // We'll assume the caller has checked that completed_at is None, so in case
        // they haven't, the update will not affect any rows, which will raise
        // an error
        let rows_affected = diesel::update(
            user_phone_authentications::table
                .find(Uuid::from(user_phone_authentication.id))
                .filter(user_phone_authentications::completed_at.is_null()),
        )
        .set(user_phone_authentications::completed_at.eq(Some(completed_at)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_phone_authentication.completed_at = Some(completed_at);
        Ok(user_phone_authentication)
    }
}
