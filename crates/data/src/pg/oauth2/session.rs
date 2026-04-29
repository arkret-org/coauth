use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    BrowserSession, Client, Clock, Page, Pagination, Session, SessionState, User, new_id,
    oauth2::{OAuth2SessionFilter, OAuth2SessionRepository},
    pagination::{Node, PaginationDirection},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ipnetwork::IpNetwork;
use oauth2_types::scope::{Scope, ScopeToken};
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    schema::{oauth2_clients, oauth2_sessions, user_sessions},
};

/// An implementation of [`OAuth2SessionRepository`] for a PostgreSQL connection
pub struct PgOAuth2SessionRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuth2SessionRepository<'c> {
    /// Create a new [`PgOAuth2SessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading OAuth2 sessions from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth2_sessions)]
struct OAuthSessionLookup {
    id: Uuid,
    user_id: Option<Uuid>,
    user_session_id: Option<Uuid>,
    oauth2_client_id: Uuid,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<IpNetwork>,
    human_name: Option<String>,
}

impl Node<Ulid> for OAuthSessionLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<OAuthSessionLookup> for Session {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: OAuthSessionLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let scope: Result<Scope, _> = value
            .scope_list
            .iter()
            .map(|s| s.parse::<ScopeToken>())
            .collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_sessions")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match value.finished_at {
            None => SessionState::Valid,
            Some(finished_at) => SessionState::Finished { finished_at },
        };

        Ok(Session {
            id,
            state,
            created_at: value.created_at,
            client_id: value.oauth2_client_id.into(),
            user_id: value.user_id.map(Ulid::from),
            user_session_id: value.user_session_id.map(Ulid::from),
            scope,
            user_agent: value.user_agent,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip.map(|ip| ip.ip()),
            human_name: value.human_name,
        })
    }
}

/// Insertable row for creating a new OAuth2 session
#[derive(Insertable)]
#[diesel(table_name = oauth2_sessions)]
struct NewOAuthSession {
    id: Uuid,
    user_id: Option<Uuid>,
    user_session_id: Option<Uuid>,
    oauth2_client_id: Uuid,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
}

/// Result row for cleanup CTE queries using raw SQL
#[derive(Debug, QueryableByName)]
struct CleanupResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_ts: Option<DateTime<Utc>>,
}

/// Macro to apply the common [`OAuth2SessionFilter`] conditions to a diesel
/// query (works with any query type that supports `.filter()`).
macro_rules! apply_session_filter {
    ($query:expr, $filter:expr) => {{
        let mut q = $query;

        if let Some(user) = $filter.user() {
            q = q.filter(oauth2_sessions::user_id.eq(Uuid::from(user.id)));
        }

        if let Some(client) = $filter.client() {
            q = q.filter(oauth2_sessions::oauth2_client_id.eq(Uuid::from(client.id)));
        }

        if let Some(client_kind) = $filter.client_kind() {
            let static_client_ids = oauth2_clients::table
                .select(oauth2_clients::id)
                .filter(oauth2_clients::is_static.eq(true));

            if client_kind.is_static() {
                q = q.filter(oauth2_sessions::oauth2_client_id.eq_any(static_client_ids));
            } else {
                q = q.filter(oauth2_sessions::oauth2_client_id.ne_all(static_client_ids));
            }
        }

        if let Some(device) = $filter.device() {
            let stable = format!("urn:matrix:client:device:{device}");
            let unstable = format!("urn:matrix:org.matrix.msc2967.client:device:{device}");
            q = q.filter(
                oauth2_sessions::scope_list
                    .contains(vec![stable])
                    .or(oauth2_sessions::scope_list.contains(vec![unstable])),
            );
        }

        if let Some(browser_session) = $filter.browser_session() {
            q = q.filter(oauth2_sessions::user_session_id.eq(Uuid::from(browser_session.id)));
        }

        if let Some(browser_session_filter) = $filter.browser_session_filter() {
            let mut subquery = user_sessions::table
                .select(user_sessions::id.nullable())
                .into_boxed();

            if let Some(user) = browser_session_filter.user() {
                subquery = subquery.filter(user_sessions::user_id.eq(Uuid::from(user.id)));
            }

            if let Some(state) = browser_session_filter.state() {
                if state.is_active() {
                    subquery = subquery.filter(user_sessions::finished_at.is_null());
                } else {
                    subquery = subquery.filter(user_sessions::finished_at.is_not_null());
                }
            }

            if let Some(last_active_before) = browser_session_filter.last_active_before() {
                subquery = subquery.filter(user_sessions::last_active_at.lt(last_active_before));
            }

            if let Some(last_active_after) = browser_session_filter.last_active_after() {
                subquery = subquery.filter(user_sessions::last_active_at.gt(last_active_after));
            }

            q = q.filter(oauth2_sessions::user_session_id.eq_any(subquery));
        }

        if let Some(state) = $filter.state() {
            if state.is_active() {
                q = q.filter(oauth2_sessions::finished_at.is_null());
            } else {
                q = q.filter(oauth2_sessions::finished_at.is_not_null());
            }
        }

        if let Some(scope) = $filter.scope() {
            let scope: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();
            q = q.filter(oauth2_sessions::scope_list.contains(scope));
        }

        if let Some(any_user) = $filter.any_user() {
            if any_user {
                q = q.filter(oauth2_sessions::user_id.is_not_null());
            } else {
                q = q.filter(oauth2_sessions::user_id.is_null());
            }
        }

        if let Some(last_active_after) = $filter.last_active_after() {
            q = q.filter(oauth2_sessions::last_active_at.gt(last_active_after));
        }

        if let Some(last_active_before) = $filter.last_active_before() {
            q = q.filter(oauth2_sessions::last_active_at.lt(last_active_before));
        }

        q
    }};
}

#[async_trait]
impl OAuth2SessionRepository for PgOAuth2SessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_session.lookup",
        skip_all,
        fields(
            session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error> {
        let res = oauth2_sessions::table
            .find(Uuid::from(id))
            .select(OAuthSessionLookup::as_select())
            .first::<OAuthSessionLookup>(self.conn)
            .await
            .optional()?;

        let Some(session) = res else { return Ok(None) };

        Ok(Some(session.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_session.add",
        skip_all,
        fields(
            %client.id,
            session.id,
            session.scope = %scope,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user: Option<&User>,
        user_session: Option<&BrowserSession>,
        scope: Scope,
    ) -> Result<Session, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("session.id", tracing::field::display(id));

        let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();

        let new_session = NewOAuthSession {
            id: Uuid::from(id),
            user_id: user.map(|u| Uuid::from(u.id)),
            user_session_id: user_session.map(|s| Uuid::from(s.id)),
            oauth2_client_id: Uuid::from(client.id),
            scope_list,
            created_at,
        };

        diesel::insert_into(oauth2_sessions::table)
            .values(&new_session)
            .execute(self.conn)
            .await?;

        Ok(Session {
            id,
            state: SessionState::Valid,
            created_at,
            user_id: user.map(|u| u.id),
            user_session_id: user_session.map(|s| s.id),
            client_id: client.id,
            scope,
            user_agent: None,
            last_active_at: None,
            last_active_ip: None,
            human_name: None,
        })
    }

    #[tracing::instrument(name = "db.oauth2_session.finish_bulk", skip_all, err)]
    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: OAuth2SessionFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let finished_at = clock.now();

        // Build a filtered subquery to get the IDs to update
        let filtered_ids = apply_session_filter!(
            oauth2_sessions::table
                .select(oauth2_sessions::id)
                .into_boxed(),
            filter
        );

        let rows_affected =
            diesel::update(oauth2_sessions::table.filter(oauth2_sessions::id.eq_any(filtered_ids)))
                .set(oauth2_sessions::finished_at.eq(Some(finished_at)))
                .execute(self.conn)
                .await?;

        Ok(rows_affected)
    }

    #[tracing::instrument(
        name = "db.oauth2_session.finish",
        skip_all,
        fields(
            %session.id,
            %session.scope,
            client.id = %session.client_id,
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        session: Session,
    ) -> Result<Session, Self::Error> {
        let finished_at = clock.now();
        let rows_affected = diesel::update(oauth2_sessions::table.find(Uuid::from(session.id)))
            .set(oauth2_sessions::finished_at.eq(Some(finished_at)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.oauth2_session.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: OAuth2SessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error> {
        let mut query = apply_session_filter!(
            oauth2_sessions::table
                .select(OAuthSessionLookup::as_select())
                .into_boxed(),
            filter
        );

        // Apply pagination
        if let Some(after) = pagination.after {
            query = query.filter(oauth2_sessions::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(oauth2_sessions::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(oauth2_sessions::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(oauth2_sessions::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let edges: Vec<OAuthSessionLookup> = query.load(self.conn).await?;

        let page = pagination.process(edges).try_map(Session::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(name = "db.oauth2_session.count", skip_all, err)]
    async fn count(&mut self, filter: OAuth2SessionFilter<'_>) -> Result<usize, Self::Error> {
        let query = apply_session_filter!(oauth2_sessions::table.into_boxed(), filter);

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.oauth2_session.record_batch_activity", skip_all, err)]
    async fn record_batch_activity(
        &mut self,
        mut activities: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error> {
        // Sort the activity by ID, so that when batching the updates, Postgres
        // locks the rows in a stable order, preventing deadlocks
        activities.sort_unstable();
        let mut ids = Vec::with_capacity(activities.len());
        let mut last_activities = Vec::with_capacity(activities.len());
        let mut ips = Vec::with_capacity(activities.len());

        for (id, last_activity, ip) in activities {
            ids.push(Uuid::from(id));
            last_activities.push(last_activity);
            ips.push(ip.map(IpNetwork::from));
        }

        let expected = ids.len();

        let rows_affected = diesel::sql_query(
            r#"
                UPDATE oauth2_sessions
                SET last_active_at = GREATEST(t.last_active_at, oauth2_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, oauth2_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[])
                        AS t(id, last_active_at, last_active_ip)
                ) AS t
                WHERE oauth2_sessions.id = t.id
            "#,
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
        name = "db.oauth2_session.record_user_agent",
        skip_all,
        fields(
            %session.id,
            %session.scope,
            client.id = %session.client_id,
            session.user_agent = user_agent,
        ),
        err,
    )]
    async fn record_user_agent(
        &mut self,
        mut session: Session,
        user_agent: String,
    ) -> Result<Session, Self::Error> {
        let rows_affected = diesel::update(oauth2_sessions::table.find(Uuid::from(session.id)))
            .set(oauth2_sessions::user_agent.eq(&user_agent))
            .execute(self.conn)
            .await?;

        session.user_agent = Some(user_agent);

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(session)
    }

    #[tracing::instrument(
        name = "repository.oauth2_session.set_human_name",
        skip(self),
        fields(
            client.id = %session.client_id,
            session.human_name = ?human_name,
        ),
        err,
    )]
    async fn set_human_name(
        &mut self,
        mut session: Session,
        human_name: Option<String>,
    ) -> Result<Session, Self::Error> {
        let rows_affected = diesel::update(oauth2_sessions::table.find(Uuid::from(session.id)))
            .set(oauth2_sessions::human_name.eq(human_name.as_deref()))
            .execute(self.conn)
            .await?;

        session.human_name = human_name;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(session)
    }

    #[tracing::instrument(
        name = "db.oauth2_session.cleanup_finished",
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
            r#"
                WITH
                    to_delete AS (
                        SELECT id, finished_at
                        FROM oauth2_sessions
                        WHERE finished_at IS NOT NULL
                          AND ($1::timestamptz IS NULL OR finished_at >= $1)
                          AND finished_at < $2
                        ORDER BY finished_at ASC
                        LIMIT $3
                        FOR UPDATE
                    ),
                    deleted_refresh_tokens AS (
                        DELETE FROM oauth2_refresh_tokens USING to_delete
                        WHERE oauth2_refresh_tokens.oauth2_session_id = to_delete.id
                    ),
                    deleted_access_tokens AS (
                        DELETE FROM oauth2_access_tokens USING to_delete
                        WHERE oauth2_access_tokens.oauth2_session_id = to_delete.id
                    ),
                    deleted_sessions AS (
                        DELETE FROM oauth2_sessions USING to_delete
                        WHERE oauth2_sessions.id = to_delete.id
                        RETURNING oauth2_sessions.finished_at
                    )
                SELECT COUNT(*) as count, MAX(finished_at) as last_ts FROM deleted_sessions
            "#,
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }

    #[tracing::instrument(
        name = "db.oauth2_session.cleanup_inactive_ips",
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
            r#"
                WITH to_update AS (
                    SELECT id, last_active_at
                    FROM oauth2_sessions
                    WHERE last_active_ip IS NOT NULL
                      AND last_active_at IS NOT NULL
                      AND ($1::timestamptz IS NULL OR last_active_at >= $1)
                      AND last_active_at < $2
                    ORDER BY last_active_at ASC
                    LIMIT $3
                    FOR UPDATE
                ),
                updated AS (
                    UPDATE oauth2_sessions
                    SET last_active_ip = NULL
                    FROM to_update
                    WHERE oauth2_sessions.id = to_update.id
                    RETURNING oauth2_sessions.last_active_at
                )
                SELECT COUNT(*) AS count, MAX(last_active_at) AS last_ts FROM updated
            "#,
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(threshold)
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }
}
