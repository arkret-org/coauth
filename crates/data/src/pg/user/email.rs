use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::pagination::{Node, PaginationDirection};
use coauth_data::user::{UserEmailFilter, UserEmailRepository};
use coauth_data::{
    BrowserSession, Clock, Page, Pagination, UpstreamOAuthAuthorizationSession, User, UserEmail,
    UserEmailAuthentication, UserEmailAuthenticationCode, UserEmailPatch, UserRegistration, new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::schema::{user_email_authentication_codes, user_email_authentications, user_emails};

/// An implementation of [`UserEmailRepository`] for a PostgreSQL connection
pub struct PgUserEmailRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserEmailRepository<'c> {
    /// Create a new [`PgUserEmailRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_emails)]
struct UserEmailLookup {
    id: Uuid,
    user_id: Uuid,
    email: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    confirmed_at: Option<DateTime<Utc>>,
    is_primary: bool,
}

impl Node<Ulid> for UserEmailLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl From<UserEmailLookup> for UserEmail {
    fn from(e: UserEmailLookup) -> UserEmail {
        UserEmail {
            id: e.id.into(),
            user_id: e.user_id.into(),
            email: e.email,
            created_at: e.created_at,
            updated_at: e.updated_at,
            confirmed_at: e.confirmed_at,
            is_primary: e.is_primary,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_email_authentications)]
struct UserEmailAuthenticationLookup {
    id: Uuid,
    user_session_id: Option<Uuid>,
    user_registration_id: Option<Uuid>,
    email: String,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<UserEmailAuthenticationLookup> for UserEmailAuthentication {
    fn from(value: UserEmailAuthenticationLookup) -> Self {
        UserEmailAuthentication {
            id: value.id.into(),
            user_session_id: value.user_session_id.map(Ulid::from),
            user_registration_id: value.user_registration_id.map(Ulid::from),
            email: value.email,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_email_authentication_codes)]
struct UserEmailAuthenticationCodeLookup {
    id: Uuid,
    user_email_authentication_id: Uuid,
    code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<UserEmailAuthenticationCodeLookup> for UserEmailAuthenticationCode {
    fn from(value: UserEmailAuthenticationCodeLookup) -> Self {
        UserEmailAuthenticationCode {
            id: value.id.into(),
            user_email_authentication_id: value.user_email_authentication_id.into(),
            code: value.code,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

/// Insertable row for creating a new user email
#[derive(Insertable)]
#[diesel(table_name = user_emails)]
struct NewUserEmail {
    id: Uuid,
    user_id: Uuid,
    email: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    confirmed_at: Option<DateTime<Utc>>,
    is_primary: bool,
}

/// Insertable row for creating a new user email authentication
#[derive(Insertable)]
#[diesel(table_name = user_email_authentications)]
struct NewUserEmailAuthentication {
    id: Uuid,
    user_session_id: Option<Uuid>,
    user_registration_id: Option<Uuid>,
    email: String,
    created_at: DateTime<Utc>,
}

/// Insertable row for creating a new user email authentication code
#[derive(Insertable)]
#[diesel(table_name = user_email_authentication_codes)]
struct NewUserEmailAuthenticationCode {
    id: Uuid,
    user_email_authentication_id: Uuid,
    code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[async_trait]
impl UserEmailRepository for PgUserEmailRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_email.lookup",
        skip_all,
        fields(
            user_email.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserEmail>, Self::Error> {
        let res = user_emails::table
            .find(Uuid::from(id))
            .select(UserEmailLookup::as_select())
            .first::<UserEmailLookup>(self.conn)
            .await
            .optional()?;

        Ok(res.map(UserEmail::from))
    }

    #[tracing::instrument(
        name = "db.user_email.find",
        skip_all,
        fields(
            %user.id,
            user_email.email = email,
        ),
        err,
    )]
    async fn find(&mut self, user: &User, email: &str) -> Result<Option<UserEmail>, Self::Error> {
        use crate::lower;

        let res = user_emails::table
            .filter(user_emails::user_id.eq(Uuid::from(user.id)))
            .filter(lower(user_emails::email).eq(email.to_lowercase()))
            .select(UserEmailLookup::as_select())
            .first::<UserEmailLookup>(self.conn)
            .await
            .optional()?;

        Ok(res.map(UserEmail::from))
    }

    #[tracing::instrument(
        name = "db.user_email.find_by_email",
        skip_all,
        fields(
            user_email.email = email,
        ),
        err,
    )]
    async fn find_by_email(&mut self, email: &str) -> Result<Option<UserEmail>, Self::Error> {
        use crate::lower;

        let res: Vec<UserEmailLookup> = user_emails::table
            .filter(lower(user_emails::email).eq(email.to_lowercase()))
            .select(UserEmailLookup::as_select())
            .load(self.conn)
            .await?;

        if res.len() != 1 {
            return Ok(None);
        }

        let Some(user_email) = res.into_iter().next() else {
            return Ok(None);
        };

        Ok(Some(user_email.into()))
    }

    #[tracing::instrument(
        name = "db.user_email.all",
        skip_all,
        fields(
            %user.id,
        ),
        err,
    )]
    async fn all(&mut self, user: &User) -> Result<Vec<UserEmail>, Self::Error> {
        let res: Vec<UserEmailLookup> = user_emails::table
            .filter(user_emails::user_id.eq(Uuid::from(user.id)))
            .select(UserEmailLookup::as_select())
            .order(user_emails::email.asc())
            .load(self.conn)
            .await?;

        Ok(res.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(name = "db.user_email.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: UserEmailFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserEmail>, DatabaseError> {
        use crate::lower;

        let mut query = user_emails::table
            .select(UserEmailLookup::as_select())
            .into_boxed();

        // Apply filters
        if let Some(user) = filter.user() {
            query = query.filter(user_emails::user_id.eq(Uuid::from(user.id)));
        }

        if let Some(email) = filter.email() {
            query = query.filter(lower(user_emails::email).eq(email.to_lowercase()));
        }

        // Apply pagination
        if let Some(after) = pagination.after {
            query = query.filter(user_emails::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(user_emails::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(user_emails::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(user_emails::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let edges: Vec<UserEmailLookup> = query.load(self.conn).await?;
        let page = pagination.process(edges).map(UserEmail::from);

        Ok(page)
    }

    #[tracing::instrument(name = "db.user_email.count", skip_all, err)]
    async fn count(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error> {
        use crate::lower;

        let mut query = user_emails::table.into_boxed();

        if let Some(user) = filter.user() {
            query = query.filter(user_emails::user_id.eq(Uuid::from(user.id)));
        }

        if let Some(email) = filter.email() {
            query = query.filter(lower(user_emails::email).eq(email.to_lowercase()));
        }

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.user_email.add",
        skip_all,
        fields(
            %user.id,
            user_email.id,
            user_email.email = email,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        email: String,
    ) -> Result<UserEmail, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_email.id", tracing::field::display(id));
        let existing_count: i64 = user_emails::table
            .filter(user_emails::user_id.eq(Uuid::from(user.id)))
            .count()
            .get_result(self.conn)
            .await?;
        let is_primary = existing_count == 0;

        let new_row = NewUserEmail {
            id: Uuid::from(id),
            user_id: Uuid::from(user.id),
            email: email.clone(),
            created_at,
            updated_at: created_at,
            confirmed_at: Some(created_at),
            is_primary,
        };

        diesel::insert_into(user_emails::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(UserEmail {
            id,
            user_id: user.id,
            email,
            created_at,
            updated_at: created_at,
            confirmed_at: Some(created_at),
            is_primary,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.patch",
        skip_all,
        fields(
            user.id = %user_email.user_id,
            %user_email.id,
        ),
        err,
    )]
    async fn patch(
        &mut self,
        clock: &dyn Clock,
        mut user_email: UserEmail,
        patch: UserEmailPatch,
    ) -> Result<UserEmail, Self::Error> {
        if patch.is_empty() {
            return Ok(user_email);
        }

        let mut changed = false;

        if let Some(email) = patch.email {
            user_email.email = email;
            changed = true;
        }

        if let Some(confirmed) = patch.confirmed {
            let next = if confirmed {
                user_email.confirmed_at.or(Some(clock.now()))
            } else {
                None
            };
            if user_email.confirmed_at != next {
                user_email.confirmed_at = next;
                changed = true;
            }
        }

        if let Some(is_primary) = patch.is_primary
            && user_email.is_primary != is_primary
        {
            user_email.is_primary = is_primary;
            changed = true;
        }

        if !changed {
            return Ok(user_email);
        }

        user_email.updated_at = clock.now();

        if user_email.is_primary {
            diesel::update(
                user_emails::table
                    .filter(user_emails::user_id.eq(Uuid::from(user_email.user_id)))
                    .filter(user_emails::id.ne(Uuid::from(user_email.id))),
            )
            .set((
                user_emails::is_primary.eq(false),
                user_emails::updated_at.eq(user_email.updated_at),
            ))
            .execute(self.conn)
            .await?;
        }

        let rows_affected = diesel::update(user_emails::table.find(Uuid::from(user_email.id)))
            .set((
                user_emails::email.eq(&user_email.email),
                user_emails::updated_at.eq(user_email.updated_at),
                user_emails::confirmed_at.eq(user_email.confirmed_at),
                user_emails::is_primary.eq(user_email.is_primary),
            ))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        Ok(user_email)
    }

    #[tracing::instrument(
        name = "db.user_email.remove",
        skip_all,
        fields(
            user.id = %user_email.user_id,
            %user_email.id,
            %user_email.email,
        ),
        err,
    )]
    async fn remove(&mut self, user_email: UserEmail) -> Result<(), Self::Error> {
        let rows_affected = diesel::delete(user_emails::table.find(Uuid::from(user_email.id)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(name = "db.user_email.remove_bulk", skip_all, err)]
    async fn remove_bulk(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error> {
        use crate::lower;

        // Build a boxed select with the filter conditions, then use it as a
        // subselect for the delete
        let mut target = user_emails::table.into_boxed();

        if let Some(user) = filter.user() {
            target = target.filter(user_emails::user_id.eq(Uuid::from(user.id)));
        }

        if let Some(email) = filter.email() {
            target = target.filter(lower(user_emails::email).eq(email.to_lowercase()));
        }

        let matching_ids: Vec<Uuid> = target.select(user_emails::id).load(self.conn).await?;

        if matching_ids.is_empty() {
            return Ok(0);
        }

        let rows_affected =
            diesel::delete(user_emails::table.filter(user_emails::id.eq_any(matching_ids)))
                .execute(self.conn)
                .await?;

        Ok(rows_affected)
    }

    #[tracing::instrument(
        name = "db.user_email.add_authentication_for_session",
        skip_all,
        fields(
            %session.id,
            user_email_authentication.id,
            user_email_authentication.email = email,
        ),
        err,
    )]
    async fn add_authentication_for_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        session: &BrowserSession,
    ) -> Result<UserEmailAuthentication, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current()
            .record("user_email_authentication.id", tracing::field::display(id));

        let new_row = NewUserEmailAuthentication {
            id: Uuid::from(id),
            user_session_id: Some(Uuid::from(session.id)),
            user_registration_id: None,
            email: email.clone(),
            created_at,
        };

        diesel::insert_into(user_email_authentications::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(UserEmailAuthentication {
            id,
            user_session_id: Some(session.id),
            user_registration_id: None,
            email,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.add_authentication_for_registration",
        skip_all,
        fields(
            %user_registration.id,
            user_email_authentication.id,
            user_email_authentication.email = email,
        ),
        err,
    )]
    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        user_registration: &UserRegistration,
    ) -> Result<UserEmailAuthentication, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current()
            .record("user_email_authentication.id", tracing::field::display(id));

        let new_row = NewUserEmailAuthentication {
            id: Uuid::from(id),
            user_session_id: None,
            user_registration_id: Some(Uuid::from(user_registration.id)),
            email: email.clone(),
            created_at,
        };

        diesel::insert_into(user_email_authentications::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(UserEmailAuthentication {
            id,
            user_session_id: None,
            user_registration_id: Some(user_registration.id),
            email,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.add_authentication_code",
        skip_all,
        fields(
            %user_email_authentication.id,
            %user_email_authentication.email,
            user_email_authentication_code.id,
            user_email_authentication_code.code = code,
        ),
        err,
    )]
    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        user_email_authentication: &UserEmailAuthentication,
        code: String,
    ) -> Result<UserEmailAuthenticationCode, Self::Error> {
        let created_at = clock.now();
        let expires_at = created_at + duration;
        let id = new_id(created_at, rng);
        tracing::Span::current().record(
            "user_email_authentication_code.id",
            tracing::field::display(id),
        );

        let new_row = NewUserEmailAuthenticationCode {
            id: Uuid::from(id),
            user_email_authentication_id: Uuid::from(user_email_authentication.id),
            code: code.clone(),
            created_at,
            expires_at,
        };

        diesel::insert_into(user_email_authentication_codes::table)
            .values(&new_row)
            .execute(self.conn)
            .await?;

        Ok(UserEmailAuthenticationCode {
            id,
            user_email_authentication_id: user_email_authentication.id,
            code,
            created_at,
            expires_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.lookup_authentication",
        skip_all,
        fields(
            user_email_authentication.id = %id,
        ),
        err,
    )]
    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserEmailAuthentication>, Self::Error> {
        let res = user_email_authentications::table
            .find(Uuid::from(id))
            .select(UserEmailAuthenticationLookup::as_select())
            .first::<UserEmailAuthenticationLookup>(self.conn)
            .await
            .optional()?;

        Ok(res.map(UserEmailAuthentication::from))
    }

    #[tracing::instrument(
        name = "db.user_email.find_authentication_by_code",
        skip_all,
        fields(
            %authentication.id,
            user_email_authentication_code.code = code,
        ),
        err,
    )]
    async fn find_authentication_code(
        &mut self,
        authentication: &UserEmailAuthentication,
        code: &str,
    ) -> Result<Option<UserEmailAuthenticationCode>, Self::Error> {
        let res = user_email_authentication_codes::table
            .filter(
                user_email_authentication_codes::user_email_authentication_id
                    .eq(Uuid::from(authentication.id)),
            )
            .filter(user_email_authentication_codes::code.eq(code))
            .select(UserEmailAuthenticationCodeLookup::as_select())
            .first::<UserEmailAuthenticationCodeLookup>(self.conn)
            .await
            .optional()?;

        Ok(res.map(UserEmailAuthenticationCode::from))
    }

    #[tracing::instrument(
        name = "db.user_email.complete_email_authentication_with_code",
        skip_all,
        fields(
            %user_email_authentication.id,
            %user_email_authentication.email,
            %user_email_authentication_code.id,
            %user_email_authentication_code.code,
        ),
        err,
    )]
    async fn complete_authentication_with_code(
        &mut self,
        clock: &dyn Clock,
        mut user_email_authentication: UserEmailAuthentication,
        user_email_authentication_code: &UserEmailAuthenticationCode,
    ) -> Result<UserEmailAuthentication, Self::Error> {
        // We technically don't use the authentication code here (other than
        // recording it in the span), but this is to make sure the caller has
        // fetched one before calling this
        let completed_at = clock.now();

        // We'll assume the caller has checked that completed_at is None, so in case
        // they haven't, the update will not affect any rows, which will raise
        // an error
        let rows_affected = diesel::update(
            user_email_authentications::table
                .find(Uuid::from(user_email_authentication.id))
                .filter(user_email_authentications::completed_at.is_null()),
        )
        .set(user_email_authentications::completed_at.eq(Some(completed_at)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_email_authentication.completed_at = Some(completed_at);
        Ok(user_email_authentication)
    }

    #[tracing::instrument(
        name = "db.user_email.complete_email_authentication_with_upstream",
        skip_all,
        fields(
            %user_email_authentication.id,
            %user_email_authentication.email,
            %upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn complete_authentication_with_upstream(
        &mut self,
        clock: &dyn Clock,
        mut user_email_authentication: UserEmailAuthentication,
        upstream_oauth_authorization_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<UserEmailAuthentication, Self::Error> {
        // We technically don't use the upstream_oauth_authorization_session here (other
        // than recording it in the span), but this is to make sure the caller
        // has fetched one before calling this
        let completed_at = clock.now();

        // We'll assume the caller has checked that completed_at is None, so in case
        // they haven't, the update will not affect any rows, which will raise
        // an error
        let rows_affected = diesel::update(
            user_email_authentications::table
                .find(Uuid::from(user_email_authentication.id))
                .filter(user_email_authentications::completed_at.is_null()),
        )
        .set(user_email_authentications::completed_at.eq(Some(completed_at)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        user_email_authentication.completed_at = Some(completed_at);
        Ok(user_email_authentication)
    }

    #[tracing::instrument(
        name = "db.user_email.cleanup_authentications",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup_authentications(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error> {
        // Use ULID cursor-based pagination. Since ULIDs contain a timestamp,
        // we can efficiently delete old authentications without needing an index.
        // `MAX(uuid)` isn't a thing in Postgres, so we aggregate on the client side.
        let res: Vec<Uuid> = diesel::sql_query(
            r"
                WITH
                  to_delete AS (
                    SELECT id
                    FROM user_email_authentications
                    WHERE ($1::uuid IS NULL OR id > $1)
                      AND id <= $2
                    ORDER BY id
                    LIMIT $3
                  ),
                  deleted_codes AS (
                    DELETE FROM user_email_authentication_codes
                    USING to_delete
                    WHERE user_email_authentication_codes.user_email_authentication_id = to_delete.id
                    RETURNING user_email_authentication_codes.id
                  )
                DELETE FROM user_email_authentications
                USING to_delete
                WHERE user_email_authentications.id = to_delete.id
                RETURNING user_email_authentications.id
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(since.map(Uuid::from))
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(until))
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load::<UuidRow>(self.conn)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();

        let count = res.len();
        let max_id = res.into_iter().max();

        Ok((count, max_id.map(Ulid::from)))
    }
}

/// Helper struct for extracting UUID from raw SQL RETURNING clause
#[derive(QueryableByName)]
struct UuidRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}
