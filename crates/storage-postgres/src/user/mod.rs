//! A module containing the PostgreSQL implementation of the user-related
//! repositories

use arkret_locale::UiLocale;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::user::{UserFilter, UserRepository};
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

    fn status_from_patch(user: &User, patch: &UserPatch) -> AccountStatus {
        let mut status = patch.status.unwrap_or(user.status);

        if let Some(locked) = patch.locked {
            if locked {
                if AccountStatus::Locked.is_stricter_than(status) {
                    status = AccountStatus::Locked;
                }
            } else if status == AccountStatus::Locked {
                status = AccountStatus::Active;
            }
        }

        if let Some(deactivated) = patch.deactivated {
            if deactivated {
                if AccountStatus::Deactivated.is_stricter_than(status) {
                    status = AccountStatus::Deactivated;
                }
            } else if status == AccountStatus::Deactivated {
                status = AccountStatus::Active;
            }
        }

        status
    }

    fn apply_status_timestamps(user: &mut User, now: DateTime<Utc>) {
        match user.status {
            AccountStatus::Active | AccountStatus::SoftLoggedOut | AccountStatus::Suspended => {
                user.locked_at = None;
                user.deactivated_at = None;
            }
            AccountStatus::Locked => {
                user.locked_at = user.locked_at.or(Some(now));
                user.deactivated_at = None;
            }
            AccountStatus::Deactivated | AccountStatus::ErasurePending => {
                user.deactivated_at = user.deactivated_at.or(Some(now));
            }
        }
    }

    fn validate_status_transition(
        current: AccountStatus,
        next: AccountStatus,
    ) -> Result<(), DatabaseError> {
        current
            .validate_transition_to(next)
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
            users::display_name,
            users::avatar_url,
            users::preferred_locale,
            users::handle_aliases,
        )
    };
}

#[derive(Debug, Clone, Queryable)]
pub(crate) struct UserRow {
    id: Uuid,
    localpart: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    status: String,
    locked_at: Option<DateTime<Utc>>,
    deactivated_at: Option<DateTime<Utc>>,
    can_request_admin: bool,
    display_name: Option<String>,
    avatar_url: Option<String>,
    preferred_locale: Option<String>,
    handle_aliases: Vec<String>,
}

impl TryFrom<UserRow> for User {
    type Error = DatabaseError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(row.id);
        let status = AccountStatus::from_wire(&row.status).ok_or_else(|| {
            DatabaseError::to_invalid_operation(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown account status {:?}", row.status),
            ))
        })?;

        Ok(Self {
            id,
            localpart: row.localpart,
            sub: id.to_string(),
            created_at: row.created_at,
            updated_at: row.updated_at,
            status,
            locked_at: row.locked_at,
            deactivated_at: row.deactivated_at,
            can_request_admin: row.can_request_admin,
            display_name: row.display_name,
            avatar_url: row.avatar_url,
            // The column is `TEXT` with a CHECK restricting it to the shipped
            // set, so this is the type conversion at the storage boundary. It
            // parses rather than unwraps on purpose: if a value ever does get
            // past the constraint, falling through to the next resolution tier
            // is better than pinning the UI to a language no catalogue exists
            // for.
            preferred_locale: row.preferred_locale.as_deref().and_then(UiLocale::from_tag),
            handle_aliases: row.handle_aliases,
        })
    }
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
            .first::<UserRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()?;

        Ok(res)
    }

    async fn lookup_for_gate(&mut self, id: Ulid) -> Result<Option<User>, Self::Error> {
        users::table
            .find(Uuid::from(id))
            .select(select_user_columns!())
            .for_update()
            .first::<UserRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()
    }

    #[tracing::instrument(
        name = "db.user.find_by_handle",
        skip_all,
        fields(user.handle = handle),
        err,
    )]
    async fn find_by_handle(&mut self, handle: &str) -> Result<Option<User>, Self::Error> {
        let handle = arkret_wire::prepare_handle_localpart(handle)
            .map_err(DatabaseError::to_invalid_operation)?;

        let row = users::table
            .filter(users::localpart.eq(handle))
            .select(select_user_columns!())
            .first::<UserRow>(self.conn)
            .await
            .optional()?
            .map(TryInto::try_into)
            .transpose()?;

        Ok(row)
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
        let handle = arkret_wire::prepare_handle_localpart(&handle)
            .map_err(DatabaseError::to_invalid_operation)?;
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
            status: AccountStatus::Active,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            display_name: None,
            avatar_url: None,
            preferred_locale: None,
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
            user.preferred_locale = *preferred_locale;
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
                users::preferred_locale.eq(user.preferred_locale.map(UiLocale::code)),
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
        status: AccountStatus,
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

        let handle = arkret_wire::prepare_handle_localpart(handle)
            .map_err(DatabaseError::to_invalid_operation)?;

        let result = select(exists(users::table.filter(users::localpart.eq(handle))))
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
        if user.status == AccountStatus::Locked {
            return Ok(user);
        }

        self.set_account_lifecycle_state(clock, user, AccountStatus::Locked)
            .await
    }

    #[tracing::instrument(
        name = "db.user.unlock",
        skip_all,
        fields(%user.id),
        err,
    )]
    async fn unlock(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.status != AccountStatus::Locked {
            return Ok(user);
        }
        Self::validate_status_transition(user.status, AccountStatus::Active)?;
        user.status = AccountStatus::Active;
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
        if user.status == AccountStatus::Deactivated {
            return Ok(user);
        }
        self.set_account_lifecycle_state(clock, user, AccountStatus::Deactivated)
            .await
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

        query = crate::paginate_by_id!(query, pagination, users::id);

        let rows: Vec<User> = query
            .load::<UserRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, DatabaseError>>()?;
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
