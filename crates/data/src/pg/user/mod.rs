//! A module containing the PostgreSQL implementation of the user-related
//! repositories

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::pagination::PaginationDirection;
use coauth_data::user::{UserFilter, UserRepository, UserStatus};
use coauth_data::{Clock, Pagination, User, UserPatch, UserProfilePatch, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::users;

mod email;
mod password;
mod phone;
mod primary_handle;
mod principal_did;
mod recovery;
mod registration;
mod registration_token;
mod session;
mod terms;
mod totp;

#[cfg(test)]
mod tests;

pub use self::email::PgUserEmailRepository;
pub use self::password::PgUserPasswordRepository;
pub use self::phone::PgUserPhoneRepository;
pub use self::primary_handle::PgUserPrimaryHandlePreferenceRepository;
pub use self::principal_did::PgPrincipalDidRepository;
pub use self::recovery::PgUserRecoveryRepository;
pub use self::registration::PgUserRegistrationRepository;
pub use self::registration_token::PgUserRegistrationTokenRepository;
pub use self::session::PgBrowserSessionRepository;
pub use self::terms::PgUserTermsRepository;
pub use self::totp::PgUserTotpRepository;

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

    fn status_from_patch(user: &User, patch: &UserPatch) -> UserStatus {
        let mut status = patch.status.unwrap_or(user.status);

        if let Some(locked) = patch.locked {
            if locked {
                if UserStatus::Locked.is_stricter_than(status) {
                    status = UserStatus::Locked;
                }
            } else if status == UserStatus::Locked {
                status = UserStatus::Active;
            }
        }

        if let Some(deactivated) = patch.deactivated {
            if deactivated {
                if UserStatus::Deactivated.is_stricter_than(status) {
                    status = UserStatus::Deactivated;
                }
            } else if status == UserStatus::Deactivated {
                status = UserStatus::Active;
            }
        }

        status
    }

    fn apply_status_timestamps(user: &mut User, now: DateTime<Utc>) {
        match user.status {
            UserStatus::Active | UserStatus::SoftLoggedOut | UserStatus::Suspended => {
                user.locked_at = None;
                user.deactivated_at = None;
            }
            UserStatus::Locked => {
                user.locked_at = user.locked_at.or(Some(now));
                user.deactivated_at = None;
            }
            UserStatus::Deactivated | UserStatus::ErasurePending => {
                user.deactivated_at = user.deactivated_at.or(Some(now));
            }
        }
    }

    fn validate_status_transition(
        current: UserStatus,
        next: UserStatus,
    ) -> Result<(), DatabaseError> {
        let supersedes_current_projection = next.is_less_strict_than(current);
        current
            .validate_transition_to(next, supersedes_current_projection)
            .map_err(|_| DatabaseError::invalid_operation())
    }
}

macro_rules! select_user_columns {
    () => {
        (
            users::id,
            users::localpart,
            users::created_at,
            users::updated_at,
            users::status,
            users::locked_at,
            users::deactivated_at,
            users::can_request_admin,
            users::is_guest,
            users::display_name,
            users::avatar_url,
            users::preferred_locale,
            users::starid_backend,
            users::handle_aliases,
        )
    };
}

/// Insertable row for creating a new user
#[derive(Insertable)]
#[diesel(table_name = users)]
struct NewUser {
    id: Uuid,
    localpart: String,
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
        name = "db.user.find_by_handle",
        skip_all,
        fields(user.handle = handle),
        err,
    )]
    async fn find_by_handle(&mut self, handle: &str) -> Result<Option<User>, Self::Error> {
        use crate::lower;

        let res: Vec<User> = users::table
            .filter(lower(users::localpart).eq(handle.to_lowercase()))
            .select(select_user_columns!())
            .load(self.conn)
            .await?;

        match &res[..] {
            [user] => Ok(Some(user.clone())),
            [] => Ok(None),
            list => {
                if let Some(user) = list.iter().find(|u| u.localpart == handle) {
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
        fields(user.handle = handle, user.id),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        handle: String,
    ) -> Result<User, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user.id", tracing::field::display(id));

        let new_user = NewUser {
            id: Uuid::from(id),
            localpart: handle.clone(),
            created_at,
            updated_at: created_at,
        };

        // `do_nothing()` inserts zero rows when another concurrent finish has
        // already claimed this localpart (protected by the
        // `users_localpart_key` UNIQUE constraint). Surface that as an explicit
        // `UniqueViolation` so the registration handler can return a clean
        // `handle_taken` rejection instead of a generic repository 500.
        let rows_affected = diesel::insert_into(users::table)
            .values(&new_user)
            .on_conflict(users::localpart)
            .do_nothing()
            .execute(self.conn)
            .await?;

        if rows_affected == 0 {
            return Err(DatabaseError::UniqueViolation);
        }
        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(User {
            id,
            localpart: handle,
            sub: id.to_string(),
            created_at,
            updated_at: created_at,
            status: UserStatus::Active,
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
            handle_aliases: Vec::new(),
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

        if let Some(display_name) = patch.display_name.as_ref() {
            user.display_name = display_name.clone();
            changed = true;
        }

        if let Some(avatar_url) = patch.avatar_url.as_ref() {
            user.avatar_url = avatar_url.clone();
            changed = true;
        }

        if let Some(preferred_locale) = patch.preferred_locale.as_ref() {
            user.preferred_locale = preferred_locale.clone();
            changed = true;
        }

        if let Some(can_request_admin) = patch.can_request_admin {
            user.can_request_admin = can_request_admin;
            changed = true;
        }

        let next_status = Self::status_from_patch(&user, &patch);
        if user.status != next_status {
            Self::validate_status_transition(user.status, next_status)?;
            user.status = next_status;
            Self::apply_status_timestamps(&mut user, now);
            changed = true;
        }

        if !changed {
            return Ok(user);
        }

        user.updated_at = now;

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::updated_at.eq(user.updated_at),
                users::status.eq(user.status.as_str()),
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
        name = "db.user.set_account_lifecycle_state",
        skip_all,
        fields(%user.id, account.status = status.as_str()),
        err,
    )]
    async fn set_account_lifecycle_state(
        &mut self,
        clock: &dyn Clock,
        user: User,
        status: UserStatus,
    ) -> Result<User, Self::Error> {
        self.patch(
            clock,
            user,
            UserPatch {
                status: Some(status),
                ..UserPatch::default()
            },
        )
        .await
    }

    #[tracing::instrument(
        name = "db.user.exists",
        skip_all,
        fields(user.handle = handle),
        err,
    )]
    async fn exists(&mut self, handle: &str) -> Result<bool, Self::Error> {
        use diesel::dsl::{exists, select};

        use crate::lower;

        let result = select(exists(
            users::table.filter(lower(users::localpart).eq(handle.to_lowercase())),
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
        if user.status == UserStatus::Locked {
            return Ok(user);
        }

        self.set_account_lifecycle_state(clock, user, UserStatus::Locked)
            .await
    }

    #[tracing::instrument(
        name = "db.user.unlock",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn unlock(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.status != UserStatus::Locked {
            return Ok(user);
        }
        Self::validate_status_transition(user.status, UserStatus::Active)?;
        user.status = UserStatus::Active;
        user.locked_at = None;
        #[allow(clippy::disallowed_methods)] // trait signature doesn't expose a Clock
        {
            user.updated_at = Utc::now();
        }

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::status.eq(user.status.as_str()),
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
        if user.status == UserStatus::Deactivated {
            return Ok(user);
        }
        self.set_account_lifecycle_state(clock, user, UserStatus::Deactivated)
            .await
    }

    #[tracing::instrument(
        name = "db.user.reactivate",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn reactivate(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.status == UserStatus::Active {
            return Ok(user);
        }
        Self::validate_status_transition(user.status, UserStatus::Active)?;
        user.status = UserStatus::Active;
        user.deactivated_at = None;
        user.locked_at = None;
        #[allow(clippy::disallowed_methods)] // trait signature doesn't expose a Clock
        {
            user.updated_at = Utc::now();
        }

        let rows_affected = diesel::update(users::table.find(Uuid::from(user.id)))
            .set((
                users::status.eq(user.status.as_str()),
                users::locked_at.eq(None::<DateTime<Utc>>),
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
        #[allow(clippy::disallowed_methods)] // trait signature doesn't expose a Clock
        {
            user.updated_at = Utc::now();
        }

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
        #[allow(clippy::disallowed_methods)] // trait signature doesn't expose a Clock
        {
            user.updated_at = Utc::now();
        }

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
        if let Some(state) = filter.status() {
            query = query.filter(users::status.eq(state.as_str()));
        }

        if let Some(can_request_admin) = filter.can_request_admin() {
            query = query.filter(users::can_request_admin.eq(can_request_admin));
        }

        if let Some(search) = filter.search() {
            let pattern = format!("%{search}%");
            query = query.filter(users::localpart.ilike(pattern));
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

        if let Some(state) = filter.status() {
            query = query.filter(users::status.eq(state.as_str()));
        }

        if let Some(can_request_admin) = filter.can_request_admin() {
            query = query.filter(users::can_request_admin.eq(can_request_admin));
        }

        if let Some(search) = filter.search() {
            let pattern = format!("%{search}%");
            query = query.filter(users::localpart.ilike(pattern));
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
