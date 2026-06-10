use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Authentication, AuthenticationMethod, BrowserSession, Clock, Page, Pagination, Password,
    UpstreamOAuthAuthorizationSession, User, new_id,
    pagination::{Node, PaginationDirection},
    user::{BrowserSessionFilter, BrowserSessionRepository},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    schema::{
        upstream_oauth_authorization_sessions, user_session_authentications, user_sessions, users,
    },
};

/// An implementation of [`BrowserSessionRepository`] for a PostgreSQL
/// connection
pub struct PgBrowserSessionRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgBrowserSessionRepository<'c> {
    /// Create a new [`PgBrowserSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading `user_sessions` columns
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_sessions)]
struct UserSessionRow {
    id: Uuid,
    user_id: Uuid,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<ipnetwork::IpNetwork>,
}

macro_rules! select_user_columns {
    () => {
        (
            users::id,
            users::localpart,
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
            users::handle_aliases,
        )
    };
}

/// Combined result from joining `user_sessions` + users.
/// We construct this from the two row types after loading.
#[derive(Debug, Clone)]
struct SessionLookup {
    session: UserSessionRow,
    user: User,
}

impl From<(UserSessionRow, User)> for SessionLookup {
    fn from((session, user): (UserSessionRow, User)) -> Self {
        Self { session, user }
    }
}

impl Node<Ulid> for SessionLookup {
    fn cursor(&self) -> Ulid {
        self.session.id.into()
    }
}

impl From<SessionLookup> for BrowserSession {
    fn from(value: SessionLookup) -> Self {
        BrowserSession {
            id: value.session.id.into(),
            user: value.user,
            created_at: value.session.created_at,
            finished_at: value.session.finished_at,
            user_agent: value.session.user_agent,
            last_active_at: value.session.last_active_at,
            last_active_ip: value.session.last_active_ip.map(|ip| ip.ip()),
        }
    }
}

/// Row type for loading a user session authentication
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_session_authentications)]
struct AuthenticationLookup {
    id: Uuid,
    created_at: DateTime<Utc>,
    user_password_id: Option<Uuid>,
    upstream_oauth_authorization_session_id: Option<Uuid>,
}

impl TryFrom<AuthenticationLookup> for Authentication {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AuthenticationLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let authentication_method = match (
            value.user_password_id.map(Into::into),
            value
                .upstream_oauth_authorization_session_id
                .map(Into::into),
        ) {
            (Some(user_password_id), None) => AuthenticationMethod::Password { user_password_id },
            (None, Some(upstream_oauth_session_id)) => AuthenticationMethod::UpstreamOAuth {
                upstream_oauth_session_id,
            },
            (None, None) => AuthenticationMethod::Unknown,
            _ => {
                return Err(DatabaseInconsistencyError::on("user_session_authentications").row(id));
            }
        };

        Ok(Authentication {
            id,
            created_at: value.created_at,
            authentication_method,
        })
    }
}

/// Insertable row for creating a new browser session
#[derive(Insertable)]
#[diesel(table_name = user_sessions)]
struct NewUserSession {
    id: Uuid,
    user_id: Uuid,
    created_at: DateTime<Utc>,
    user_agent: Option<String>,
}

/// Insertable row for creating a new session authentication (password)
#[derive(Insertable)]
#[diesel(table_name = user_session_authentications)]
struct NewSessionAuthenticationPassword {
    id: Uuid,
    user_session_id: Uuid,
    created_at: DateTime<Utc>,
    user_password_id: Option<Uuid>,
}

/// Insertable row for creating a new session authentication (upstream)
#[derive(Insertable)]
#[diesel(table_name = user_session_authentications)]
struct NewSessionAuthenticationUpstream {
    id: Uuid,
    user_session_id: Uuid,
    created_at: DateTime<Utc>,
    upstream_oauth_authorization_session_id: Option<Uuid>,
}

/// Result row for cleanup/batch queries using raw SQL
#[derive(Debug, QueryableByName)]
struct CleanupResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_ts: Option<DateTime<Utc>>,
}

/// Apply the common [`BrowserSessionFilter`] conditions to any diesel
/// query that supports `.filter()` on `user_sessions` columns.
macro_rules! apply_session_filter {
    ($query:expr, $filter:expr) => {{
        let mut q = $query;
        if let Some(user) = $filter.user() {
            q = q.filter(user_sessions::user_id.eq(Uuid::from(user.id)));
        }
        if let Some(state) = $filter.state() {
            if state.is_active() {
                q = q.filter(user_sessions::finished_at.is_null());
            } else {
                q = q.filter(user_sessions::finished_at.is_not_null());
            }
        }
        if let Some(last_active_after) = $filter.last_active_after() {
            q = q.filter(user_sessions::last_active_at.gt(last_active_after));
        }
        if let Some(last_active_before) = $filter.last_active_before() {
            q = q.filter(user_sessions::last_active_at.lt(last_active_before));
        }
        if let Some(upstream_filter) = $filter.authenticated_by_upstream_sessions() {
            let mut sub = user_session_authentications::table
                .inner_join(
                    upstream_oauth_authorization_sessions::table.on(
                        user_session_authentications::upstream_oauth_authorization_session_id
                            .eq(upstream_oauth_authorization_sessions::id.nullable()),
                    ),
                )
                .select(user_session_authentications::user_session_id)
                .into_boxed();

            if let Some(provider) = upstream_filter.provider() {
                sub = sub.filter(
                    upstream_oauth_authorization_sessions::upstream_oauth_provider_id
                        .eq(Uuid::from(provider.id)),
                );
            }
            q = q.filter(user_sessions::id.eq_any(sub));
        }
        q
    }};
}

/// Load the session + user join using raw SQL to avoid diesel tuple
/// compatibility issues. Returns the session row for the given ID or None.
async fn load_session_lookup(
    conn: &mut diesel_async::AsyncPgConnection,
    session_id: Uuid,
) -> Result<Option<SessionLookup>, DatabaseError> {
    let session_row = user_sessions::table
        .filter(user_sessions::id.eq(session_id))
        .select(UserSessionRow::as_select())
        .first::<UserSessionRow>(conn)
        .await
        .optional()?;

    let Some(session_row) = session_row else {
        return Ok(None);
    };

    let user_row = users::table
        .filter(users::id.eq(session_row.user_id))
        .select(select_user_columns!())
        .first::<User>(conn)
        .await
        .optional()?;

    let Some(user_row) = user_row else {
        return Ok(None);
    };

    Ok(Some(SessionLookup {
        session: session_row,
        user: user_row,
    }))
}

#[async_trait]
impl BrowserSessionRepository for PgBrowserSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.browser_session.lookup",
        skip_all,
        fields(
            user_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<BrowserSession>, Self::Error> {
        let res = load_session_lookup(self.conn, Uuid::from(id)).await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.browser_session.add",
        skip_all,
        fields(
            %user.id,
            user_session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        user_agent: Option<String>,
    ) -> Result<BrowserSession, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("user_session.id", tracing::field::display(id));

        let new_session = NewUserSession {
            id: Uuid::from(id),
            user_id: Uuid::from(user.id),
            created_at,
            user_agent: user_agent.clone(),
        };

        diesel::insert_into(user_sessions::table)
            .values(&new_session)
            .execute(self.conn)
            .await?;

        let session = BrowserSession {
            id,
            // The session row links back to the user by id; the full `User`
            // struct is embedded here so callers don't need a second lookup.
            user: user.clone(),
            created_at,
            finished_at: None,
            user_agent,
            last_active_at: None,
            last_active_ip: None,
        };

        Ok(session)
    }

    #[tracing::instrument(
        name = "db.browser_session.finish",
        skip_all,
        fields(
            %user_session.id,
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        mut user_session: BrowserSession,
    ) -> Result<BrowserSession, Self::Error> {
        let finished_at = clock.now();
        let rows_affected = diesel::update(
            user_sessions::table.filter(user_sessions::id.eq(Uuid::from(user_session.id))),
        )
        .set(user_sessions::finished_at.eq(Some(finished_at)))
        .execute(self.conn)
        .await?;

        user_session.finished_at = Some(finished_at);

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(user_session)
    }

    #[tracing::instrument(name = "db.browser_session.finish_bulk", skip_all, err)]
    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: BrowserSessionFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let finished_at = clock.now();

        let update = diesel::update(user_sessions::table).into_boxed();
        let update = apply_session_filter!(update, filter);

        let rows_affected = update
            .set(user_sessions::finished_at.eq(Some(finished_at)))
            .execute(self.conn)
            .await?;

        Ok(rows_affected)
    }

    #[tracing::instrument(name = "db.browser_session.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: BrowserSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error> {
        // First, query the session IDs with filter + pagination
        let query = user_sessions::table
            .select(UserSessionRow::as_select())
            .into_boxed();

        let mut query = apply_session_filter!(query, filter);

        // Apply pagination cursors
        if let Some(after) = pagination.after {
            query = query.filter(user_sessions::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(user_sessions::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(user_sessions::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(user_sessions::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let session_rows: Vec<UserSessionRow> = query.load(self.conn).await?;

        // Collect unique user IDs and fetch the user rows
        let user_ids: Vec<Uuid> = session_rows
            .iter()
            .map(|s| s.user_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let user_rows: Vec<User> = users::table
            .filter(users::id.eq_any(&user_ids))
            .select(select_user_columns!())
            .load(self.conn)
            .await?;

        let user_map: std::collections::HashMap<Uuid, User> = user_rows
            .into_iter()
            .map(|u| (Uuid::from(u.id), u))
            .collect();

        // Combine into SessionLookup entries
        let edges: Vec<SessionLookup> = session_rows
            .into_iter()
            .filter_map(|session| {
                let user = user_map.get(&session.user_id)?.clone();
                Some(SessionLookup { session, user })
            })
            .collect();

        let page = pagination.process(edges).map(BrowserSession::from);

        Ok(page)
    }

    #[tracing::instrument(name = "db.browser_session.count", skip_all, err)]
    async fn count(&mut self, filter: BrowserSessionFilter<'_>) -> Result<usize, Self::Error> {
        let query = user_sessions::table.into_boxed();
        let query = apply_session_filter!(query, filter);

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.browser_session.authenticate_with_password",
        skip_all,
        fields(
            %user_session.id,
            %user_password.id,
            user_session_authentication.id,
        ),
        err,
    )]
    async fn authenticate_with_password(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: &BrowserSession,
        user_password: &Password,
    ) -> Result<Authentication, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record(
            "user_session_authentication.id",
            tracing::field::display(id),
        );

        let new_auth = NewSessionAuthenticationPassword {
            id: Uuid::from(id),
            user_session_id: Uuid::from(user_session.id),
            created_at,
            user_password_id: Some(Uuid::from(user_password.id)),
        };

        diesel::insert_into(user_session_authentications::table)
            .values(&new_auth)
            .execute(self.conn)
            .await?;

        Ok(Authentication {
            id,
            created_at,
            authentication_method: AuthenticationMethod::Password {
                user_password_id: user_password.id,
            },
        })
    }

    #[tracing::instrument(
        name = "db.browser_session.authenticate_with_upstream",
        skip_all,
        fields(
            %user_session.id,
            %upstream_oauth_session.id,
            user_session_authentication.id,
        ),
        err,
    )]
    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: &BrowserSession,
        upstream_oauth_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<Authentication, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record(
            "user_session_authentication.id",
            tracing::field::display(id),
        );

        let new_auth = NewSessionAuthenticationUpstream {
            id: Uuid::from(id),
            user_session_id: Uuid::from(user_session.id),
            created_at,
            upstream_oauth_authorization_session_id: Some(Uuid::from(upstream_oauth_session.id)),
        };

        diesel::insert_into(user_session_authentications::table)
            .values(&new_auth)
            .execute(self.conn)
            .await?;

        Ok(Authentication {
            id,
            created_at,
            authentication_method: AuthenticationMethod::UpstreamOAuth {
                upstream_oauth_session_id: upstream_oauth_session.id,
            },
        })
    }

    #[tracing::instrument(
        name = "db.browser_session.get_last_authentication",
        skip_all,
        fields(
            %user_session.id,
        ),
        err,
    )]
    async fn get_last_authentication(
        &mut self,
        user_session: &BrowserSession,
    ) -> Result<Option<Authentication>, Self::Error> {
        let authentication = user_session_authentications::table
            .filter(user_session_authentications::user_session_id.eq(Uuid::from(user_session.id)))
            .select(AuthenticationLookup::as_select())
            .order(user_session_authentications::created_at.desc())
            .first::<AuthenticationLookup>(self.conn)
            .await
            .optional()?;

        let Some(authentication) = authentication else {
            return Ok(None);
        };

        let authentication = Authentication::try_from(authentication)?;
        Ok(Some(authentication))
    }

    #[tracing::instrument(name = "db.browser_session.record_batch_activity", skip_all, err)]
    async fn record_batch_activity(
        &mut self,
        mut activities: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error> {
        // Sort the activity by ID, so that when batching the updates, Postgres
        // locks the rows in a stable order, preventing deadlocks
        activities.sort_unstable();
        let mut ids = Vec::with_capacity(activities.len());
        let mut last_activities = Vec::with_capacity(activities.len());
        let mut ips: Vec<Option<ipnetwork::IpNetwork>> = Vec::with_capacity(activities.len());

        for (id, last_activity, ip) in activities {
            ids.push(Uuid::from(id));
            last_activities.push(last_activity);
            ips.push(ip.map(ipnetwork::IpNetwork::from));
        }

        let expected = ids.len();

        let rows_affected = diesel::sql_query(
            r"
                UPDATE user_sessions
                SET last_active_at = GREATEST(t.last_active_at, user_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, user_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[])
                        AS t(user_session_id, last_active_at, last_active_ip)
                ) AS t
                WHERE user_sessions.id = t.user_session_id
            ",
        )
        .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(&ids)
        .bind::<diesel::sql_types::Array<diesel::sql_types::Timestamptz>, _>(&last_activities)
        .bind::<diesel::sql_types::Array<diesel::sql_types::Nullable<diesel::sql_types::Inet>>, _>(
            &ips,
        )
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, expected)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.browser_session.cleanup_finished",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup_finished(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let res: CleanupResult = diesel::sql_query(
            r"
                WITH
                    to_delete AS (
                        SELECT us.id AS user_session_id, us.finished_at
                        FROM user_sessions us
                        WHERE us.finished_at IS NOT NULL
                          AND ($1::timestamptz IS NULL OR us.finished_at >= $1)
                          AND us.finished_at < $2
                          -- Only delete if no oauth_sessions reference this user_session
                          AND NOT EXISTS (
                              SELECT 1 FROM oauth_sessions os
                              WHERE os.user_session_id = us.id
                          )
                        ORDER BY us.finished_at ASC
                        LIMIT $3
                        FOR UPDATE OF us
                    ),
                    deleted_authentications AS (
                        DELETE FROM user_session_authentications USING to_delete
                        WHERE user_session_authentications.user_session_id = to_delete.user_session_id
                    ),
                    deleted_sessions AS (
                        DELETE FROM user_sessions USING to_delete
                        WHERE user_sessions.id = to_delete.user_session_id
                        RETURNING user_sessions.finished_at
                    )
                SELECT COUNT(*) AS count, MAX(finished_at) AS last_ts FROM deleted_sessions
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }

    #[tracing::instrument(
        name = "db.browser_session.cleanup_inactive_ips",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            threshold = %threshold,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup_inactive_ips(
        &mut self,
        since: Option<DateTime<Utc>>,
        threshold: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let res: CleanupResult = diesel::sql_query(
            r"
                WITH to_update AS (
                    SELECT id AS user_session_id, last_active_at
                    FROM user_sessions
                    WHERE last_active_ip IS NOT NULL
                      AND last_active_at IS NOT NULL
                      AND ($1::timestamptz IS NULL OR last_active_at >= $1)
                      AND last_active_at < $2
                    ORDER BY last_active_at ASC
                    LIMIT $3
                    FOR UPDATE
                ),
                updated AS (
                    UPDATE user_sessions
                    SET last_active_ip = NULL
                    FROM to_update
                    WHERE user_sessions.id = to_update.user_session_id
                    RETURNING user_sessions.last_active_at
                )
                SELECT COUNT(*) AS count, MAX(last_active_at) AS last_ts FROM updated
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(threshold)
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }
}
