//! A module containing the PostgreSQL implementation of the user-related
//! repositories

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, Pagination, User, UserPatch, UserProfilePatch, new_id,
    pagination::PaginationDirection,
    user::{UserFilter, UserRepository, UserState},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, schema::users};

mod email;
mod password;
mod phone;
mod recovery;
mod registration;
mod registration_token;
mod session;
mod terms;
mod totp;

#[cfg(test)]
mod tests;

pub use self::{
    email::PgUserEmailRepository, password::PgUserPasswordRepository, phone::PgUserPhoneRepository,
    recovery::PgUserRecoveryRepository, registration::PgUserRegistrationRepository,
    registration_token::PgUserRegistrationTokenRepository, session::PgBrowserSessionRepository,
    terms::PgUserTermsRepository, totp::PgUserTotpRepository,
};

const BOOTSTRAP_ADMIN_LOCK_ID: i64 = 0x7061_7369_6f6e_4144;

/// An implementation of [`UserRepository`] for a PostgreSQL connection
pub struct PgUserRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserRepository<'c> {
    /// Create a new [`PgUserRepository`] from an active PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

macro_rules! select_user_columns {
    () => {
        (
            users::id,
            users::username,
            users::created_at,
            users::updated_at,
            users::locked_at,
            users::deactivated_at,
            users::can_request_admin,
            users::is_guest,
            users::display_name,
            users::avatar_url,
            users::preferred_locale,
            users::starid_backend,
        )
    };
}

/// Insertable row for creating a new user
#[derive(Insertable)]
#[diesel(table_name = users)]
struct NewUser {
    id: Uuid,
    username: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl UserRepository for PgUserRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user.lookup",
        skip_all,
        fields(user.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error> {
        let res = users::table
            .find(Uuid::from(id))
            .select(select_user_columns!())
            .first::<User>(self.conn)
            .await
            .optional()?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.user.find_by_username",
        skip_all,
        fields(user.username = username),
        err,
    )]
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error> {
        use crate::lower;

        let res: Vec<User> = users::table
            .filter(lower(users::username).eq(username.to_lowercase()))
            .select(select_user_columns!())
            .load(self.conn)
            .await?;

        match &res[..] {
            [user] => Ok(Some(user.clone())),
            [] => Ok(None),
            list => {
                if let Some(user) = list.iter().find(|u| u.username == username) {
                    Ok(Some(user.clone()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    #[tracing::instrument(
        name = "db.user.add",
        skip_all,
        fields(user.username = username, user.id),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user.id", tracing::field::display(id));

        let new_user = NewUser {
            id: Uuid::from(id),
            username: username.clone(),
            created_at,
            updated_at: created_at,
        };

        let rows_affected = diesel::insert_into(users::table)
            .values(&new_user)
            .on_conflict(users::username)
            .do_nothing()
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(User {
            id,
            username,
            sub: id.to_string(),
            created_at,
            updated_at: created_at,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: false,
            display_name: None,
            avatar_url: None,
            preferred_locale: None,
            // Defaults to `false`; onboarding flips this to `true`
            // immediately after `StaridRegistry::create_principal_did`
            // succeeds via [`UserRepository::set_starid_backend`].
            starid_backend: false,
        })
    }

    #[tracing::instrument(
        name = "db.user.update_profile",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn update_profile(
        &mut self,
        clock: &dyn Clock,
        user: User,
        patch: UserProfilePatch,
    ) -> Result<User, Self::Error> {
        self.patch(clock, user, patch.into()).await
    }

    #[tracing::instrument(
        name = "db.user.patch",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn patch(
        &mut self,
        clock: &dyn Clock,
        mut user: User,
        patch: UserPatch,
    ) -> Result<User, Self::Error> {
        if patch.is_empty() {
            return Ok(user);
        }

        let mut changed = false;
        let now = clock.now();

        if let Some(display_name) = patch.display_name {
            user.display_name = display_name;
            changed = true;
        }

        if let Some(avatar_url) = patch.avatar_url {
            user.avatar_url = avatar_url;
            changed = true;
        }

        if let Some(preferred_locale) = patch.preferred_locale {
            user.preferred_locale = preferred_locale;
            changed = true;
        }

        if let Some(can_request_admin) = patch.can_request_admin {
            user.can_request_admin = can_request_admin;
            changed = true;
        }

        if let Some(locked) = patch.locked {
            let next_locked_at = if locked {
                user.locked_at.or(Some(now))
            } else {
                None
            };
            if user.locked_at != next_locked_at {
                user.locked_at = next_locked_at;
                changed = true;
            }
        }

        if let Some(deactivated) = patch.deactivated {
            let next_deactivated_at = if deactivated {
                user.deactivated_at.or(Some(now))
            } else {
                None
            };
            if user.deactivated_at != next_deactivated_at {
                user.deactivated_at = next_deactivated_at;
                changed = true;
            }
        }

        if !changed {
            return Ok(user);
        }

        user.updated_at = now;

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::updated_at.eq(user.updated_at),
                users::locked_at.eq(user.locked_at),
                users::deactivated_at.eq(user.deactivated_at),
                users::can_request_admin.eq(user.can_request_admin),
                users::display_name.eq(user.display_name.as_deref()),
                users::avatar_url.eq(user.avatar_url.as_deref()),
                users::preferred_locale.eq(user.preferred_locale.as_deref()),
            ))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.exists",
        skip_all,
        fields(user.username = username),
        err,
    )]
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error> {
        use diesel::dsl::{exists, select};

        use crate::lower;

        let result = select(exists(
            users::table.filter(lower(users::username).eq(username.to_lowercase())),
        ))
        .get_result::<bool>(self.conn)
        .await?;

        Ok(result)
    }

    #[tracing::instrument(
        name = "db.user.lock",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn lock(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_some() {
            return Ok(user);
        }

        self.patch(
            clock,
            user,
            UserPatch {
                locked: Some(true),
                ..UserPatch::default()
            },
        )
        .await
    }

    #[tracing::instrument(
        name = "db.user.unlock",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn unlock(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_none() {
            return Ok(user);
        }
        user.locked_at = None;
        user.updated_at = Utc::now();

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::locked_at.eq(None::<DateTime<Utc>>),
                users::updated_at.eq(user.updated_at),
            ))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.deactivate",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn deactivate(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error> {
        if user.deactivated_at.is_some() {
            return Ok(user);
        }
        self.patch(
            clock,
            user,
            UserPatch {
                deactivated: Some(true),
                ..UserPatch::default()
            },
        )
        .await
    }

    #[tracing::instrument(
        name = "db.user.reactivate",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn reactivate(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.deactivated_at.is_none() {
            return Ok(user);
        }
        user.deactivated_at = None;
        user.updated_at = Utc::now();

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::deactivated_at.eq(None::<DateTime<Utc>>),
                users::updated_at.eq(user.updated_at),
            ))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.set_can_request_admin",
        skip_all,
        fields(%user.id, user.can_request_admin = can_request_admin),
        err,
    )]
    async fn set_can_request_admin(
        &mut self,
        mut user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error> {
        user.can_request_admin = can_request_admin;
        user.updated_at = Utc::now();

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::can_request_admin.eq(can_request_admin),
                users::updated_at.eq(user.updated_at),
            ))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.set_starid_backend",
        skip_all,
        fields(%user.id, user.starid_backend = starid_backend),
        err,
    )]
    async fn set_starid_backend(
        &mut self,
        mut user: User,
        starid_backend: bool,
    ) -> Result<User, Self::Error> {
        user.starid_backend = starid_backend;
        user.updated_at = Utc::now();

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::starid_backend.eq(starid_backend),
                users::updated_at.eq(user.updated_at),
            ))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        Ok(user)
    }

    #[tracing::instrument(name = "db.user.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: UserFilter<'_>,
        pagination: Pagination,
    ) -> Result<coauth_data::Page<User>, Self::Error> {
        let mut query = users::table.select(select_user_columns!()).into_boxed();

        // Apply filters
        if let Some(state) = filter.state() {
            match state {
                UserState::Deactivated => {
                    query = query.filter(users::deactivated_at.is_not_null());
                }
                UserState::Locked => {
                    query = query.filter(users::locked_at.is_not_null());
                }
                UserState::Active => {
                    query = query
                        .filter(users::locked_at.is_null())
                        .filter(users::deactivated_at.is_null());
                }
            }
        }

        if let Some(can_request_admin) = filter.can_request_admin() {
            query = query.filter(users::can_request_admin.eq(can_request_admin));
        }

        if let Some(is_guest) = filter.is_guest() {
            query = query.filter(users::is_guest.eq(is_guest));
        }

        if let Some(search) = filter.search() {
            let pattern = format!("%{search}%");
            query = query.filter(users::username.ilike(pattern));
        }

        // Apply pagination
        if let Some(after) = pagination.after {
            query = query.filter(users::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(users::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(users::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(users::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let rows: Vec<User> = query.load(self.conn).await?;
        let page = pagination.process(rows);
        Ok(page)
    }

    #[tracing::instrument(name = "db.user.count", skip_all, err)]
    async fn count(&mut self, filter: UserFilter<'_>) -> Result<usize, Self::Error> {
        let mut query = users::table.into_boxed();

        if let Some(state) = filter.state() {
            match state {
                UserState::Deactivated => {
                    query = query.filter(users::deactivated_at.is_not_null());
                }
                UserState::Locked => {
                    query = query.filter(users::locked_at.is_not_null());
                }
                UserState::Active => {
                    query = query
                        .filter(users::locked_at.is_null())
                        .filter(users::deactivated_at.is_null());
                }
            }
        }

        if let Some(can_request_admin) = filter.can_request_admin() {
            query = query.filter(users::can_request_admin.eq(can_request_admin));
        }

        if let Some(is_guest) = filter.is_guest() {
            query = query.filter(users::is_guest.eq(is_guest));
        }

        if let Some(search) = filter.search() {
            let pattern = format!("%{search}%");
            query = query.filter(users::username.ilike(pattern));
        }

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.user.acquire_bootstrap_admin_lock", skip_all, err)]
    async fn acquire_bootstrap_admin_lock(&mut self) -> Result<(), Self::Error> {
        diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
            .bind::<diesel::sql_types::BigInt, _>(BOOTSTRAP_ADMIN_LOCK_ID)
            .execute(self.conn)
            .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.user.acquire_lock_for_sync",
        skip_all,
        fields(user.id = %user.id),
        err,
    )]
    async fn acquire_lock_for_sync(&mut self, user: &User) -> Result<(), Self::Error> {
        let lock_id = (u128::from(user.id) & 0xffff_ffff_ffff_ffff) as i64;

        diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
            .bind::<diesel::sql_types::BigInt, _>(lock_id)
            .execute(self.conn)
            .await?;

        Ok(())
    }
}
