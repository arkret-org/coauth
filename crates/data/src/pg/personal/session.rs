use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, Page, Pagination, User, new_id,
    pagination::{Node, PaginationDirection},
    personal::{
        PersonalAccessToken, PersonalSessionFilter, PersonalSessionRepository,
        PersonalSessionState,
        session::{PersonalSession, PersonalSessionOwner, SessionState},
    },
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use oauth_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError,
    pg::errors::DatabaseInconsistencyError,
    schema::{personal_access_tokens, personal_sessions},
};

/// An implementation of [`PersonalSessionRepository`] for a PostgreSQL
/// connection
pub struct PgPersonalSessionRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgPersonalSessionRepository<'c> {
    /// Create a new [`PgPersonalSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading a personal session from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = personal_sessions)]
struct PersonalSessionRow {
    id: Uuid,
    owner_user_id: Option<Uuid>,
    owner_oauth_client_id: Option<Uuid>,
    actor_user_id: Uuid,
    human_name: String,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<ipnetwork::IpNetwork>,
}

impl Node<Ulid> for PersonalSessionRow {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<PersonalSessionRow> for PersonalSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: PersonalSessionRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let scope: Result<Scope, _> = value.scope_list.iter().map(|s| s.parse()).collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("personal_sessions")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match value.revoked_at {
            None => SessionState::Valid,
            Some(revoked_at) => SessionState::Revoked { revoked_at },
        };

        let owner = match (value.owner_user_id, value.owner_oauth_client_id) {
            (Some(owner_user_id), None) => PersonalSessionOwner::User(Ulid::from(owner_user_id)),
            (None, Some(owner_oauth_client_id)) => {
                PersonalSessionOwner::OAuthClient(Ulid::from(owner_oauth_client_id))
            }
            _ => {
                return Err(DatabaseInconsistencyError::on("personal_sessions")
                    .column("owner_user_id, owner_oauth_client_id")
                    .row(id));
            }
        };

        Ok(PersonalSession {
            id,
            state,
            owner,
            actor_user_id: Ulid::from(value.actor_user_id),
            human_name: value.human_name,
            scope,
            created_at: value.created_at,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip.map(|ip| ip.ip()),
        })
    }
}

/// Row type for loading a personal session joined with its active access token
#[derive(Debug, Clone, Queryable)]
struct PersonalSessionAndAccessTokenRow {
    // personal_sessions fields
    id: Uuid,
    owner_user_id: Option<Uuid>,
    owner_oauth_client_id: Option<Uuid>,
    actor_user_id: Uuid,
    human_name: String,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<ipnetwork::IpNetwork>,
    // personal_access_tokens fields (nullable because LEFT JOIN)
    personal_access_token_id: Option<Uuid>,
    token_created_at: Option<DateTime<Utc>>,
    token_expires_at: Option<DateTime<Utc>>,
}

impl Node<Ulid> for PersonalSessionAndAccessTokenRow {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<PersonalSessionAndAccessTokenRow> for (PersonalSession, Option<PersonalAccessToken>) {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: PersonalSessionAndAccessTokenRow) -> Result<Self, Self::Error> {
        let session = PersonalSession::try_from(PersonalSessionRow {
            id: value.id,
            owner_user_id: value.owner_user_id,
            owner_oauth_client_id: value.owner_oauth_client_id,
            actor_user_id: value.actor_user_id,
            human_name: value.human_name,
            scope_list: value.scope_list,
            created_at: value.created_at,
            revoked_at: value.revoked_at,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        })?;

        let token_opt = if let Some(id) = value.personal_access_token_id {
            let id = Ulid::from(id);
            Some(PersonalAccessToken {
                id,
                session_id: session.id,
                created_at: value.token_created_at.ok_or(
                    DatabaseInconsistencyError::on("personal_sessions")
                        .column("created_at")
                        .row(id),
                )?,
                expires_at: value.token_expires_at,
                revoked_at: None,
            })
        } else {
            None
        };

        Ok((session, token_opt))
    }
}

/// Insertable row for creating a new personal session
#[derive(Insertable)]
#[diesel(table_name = personal_sessions)]
struct NewPersonalSession {
    id: Uuid,
    owner_user_id: Option<Uuid>,
    owner_oauth_client_id: Option<Uuid>,
    actor_user_id: Uuid,
    human_name: String,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
}

/// Build the tuple of columns selected from the LEFT JOIN of
/// personal_sessions with personal_access_tokens.
fn session_with_token_select() -> (
    personal_sessions::id,
    personal_sessions::owner_user_id,
    personal_sessions::owner_oauth_client_id,
    personal_sessions::actor_user_id,
    personal_sessions::human_name,
    personal_sessions::scope_list,
    personal_sessions::created_at,
    personal_sessions::revoked_at,
    personal_sessions::last_active_at,
    personal_sessions::last_active_ip,
    diesel::dsl::Nullable<personal_access_tokens::id>,
    diesel::dsl::Nullable<personal_access_tokens::created_at>,
    diesel::dsl::Nullable<personal_access_tokens::expires_at>,
) {
    (
        personal_sessions::id,
        personal_sessions::owner_user_id,
        personal_sessions::owner_oauth_client_id,
        personal_sessions::actor_user_id,
        personal_sessions::human_name,
        personal_sessions::scope_list,
        personal_sessions::created_at,
        personal_sessions::revoked_at,
        personal_sessions::last_active_at,
        personal_sessions::last_active_ip,
        personal_access_tokens::id.nullable(),
        personal_access_tokens::created_at.nullable(),
        personal_access_tokens::expires_at.nullable(),
    )
}

#[async_trait]
impl PersonalSessionRepository for PgPersonalSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.personal_session.lookup",
        skip_all,
        fields(
            session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalSession>, Self::Error> {
        let res = personal_sessions::table
            .find(Uuid::from(id))
            .select(PersonalSessionRow::as_select())
            .first::<PersonalSessionRow>(self.conn)
            .await
            .optional()?;

        let Some(session) = res else { return Ok(None) };

        Ok(Some(session.try_into()?))
    }

    #[tracing::instrument(
        name = "db.personal_session.add",
        skip_all,
        fields(
            session.id,
            session.scope = %scope,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        owner: PersonalSessionOwner,
        actor_user: &User,
        human_name: String,
        scope: Scope,
    ) -> Result<PersonalSession, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("session.id", tracing::field::display(id));

        let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();

        let (owner_user_id, owner_oauth_client_id) = match owner {
            PersonalSessionOwner::User(ulid) => (Some(Uuid::from(ulid)), None),
            PersonalSessionOwner::OAuthClient(ulid) => (None, Some(Uuid::from(ulid))),
        };

        let new_session = NewPersonalSession {
            id: Uuid::from(id),
            owner_user_id,
            owner_oauth_client_id,
            actor_user_id: Uuid::from(actor_user.id),
            human_name: human_name.clone(),
            scope_list,
            created_at,
        };

        diesel::insert_into(personal_sessions::table)
            .values(&new_session)
            .execute(self.conn)
            .await?;

        Ok(PersonalSession {
            id,
            state: SessionState::Valid,
            owner,
            actor_user_id: actor_user.id,
            human_name,
            scope,
            created_at,
            last_active_at: None,
            last_active_ip: None,
        })
    }

    #[tracing::instrument(
        name = "db.personal_session.revoke",
        skip_all,
        fields(
            %session.id,
            %session.scope,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        session: PersonalSession,
    ) -> Result<PersonalSession, Self::Error> {
        let revoked_at = clock.now();

        // Revoke dependent PATs
        diesel::update(
            personal_access_tokens::table
                .filter(personal_access_tokens::personal_session_id.eq(Uuid::from(session.id)))
                .filter(personal_access_tokens::revoked_at.is_null()),
        )
        .set(personal_access_tokens::revoked_at.eq(Some(revoked_at)))
        .execute(self.conn)
        .await?;

        let rows_affected = diesel::update(personal_sessions::table.find(Uuid::from(session.id)))
            .set(personal_sessions::revoked_at.eq(Some(revoked_at)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        session
            .finish(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.personal_session.revoke_bulk", skip_all, err)]
    async fn revoke_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: PersonalSessionFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let revoked_at = clock.now();

        // Build a subquery to find the session IDs matching the filter.
        // We need a LEFT JOIN to personal_access_tokens for filters that
        // reference token fields (expires_before, expires_after, expires).
        let mut sub = personal_sessions::table
            .left_join(
                personal_access_tokens::table.on(personal_sessions::id
                    .eq(personal_access_tokens::personal_session_id)
                    .and(personal_access_tokens::revoked_at.is_null())),
            )
            .select(personal_sessions::id)
            .into_boxed();

        // Apply session-level filters
        if let Some(user) = filter.owner_user() {
            sub = sub.filter(personal_sessions::owner_user_id.eq(Uuid::from(user.id)));
        }

        if let Some(client) = filter.owner_oauth_client() {
            sub = sub.filter(personal_sessions::owner_oauth_client_id.eq(Uuid::from(client.id)));
        }

        if let Some(user) = filter.actor_user() {
            sub = sub.filter(personal_sessions::actor_user_id.eq(Uuid::from(user.id)));
        }

        if let Some(device) = filter.device() {
            let device_scope = format!("urn:contrix:client:device:{device}");
            sub = sub.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("")
                    .bind::<diesel::sql_types::Text, _>(device_scope)
                    .sql(" = ANY(")
                    .sql("personal_sessions.scope_list")
                    .sql(")"),
            );
        }

        match filter.state() {
            Some(PersonalSessionState::Active) => {
                sub = sub.filter(personal_sessions::revoked_at.is_null());
            }
            Some(PersonalSessionState::Revoked) => {
                sub = sub.filter(personal_sessions::revoked_at.is_not_null());
            }
            None => {}
        }

        if let Some(scope) = filter.scope() {
            let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();
            sub = sub.filter(personal_sessions::scope_list.contains(scope_list));
        }

        if let Some(last_active_before) = filter.last_active_before() {
            sub = sub.filter(personal_sessions::last_active_at.lt(last_active_before));
        }

        if let Some(last_active_after) = filter.last_active_after() {
            sub = sub.filter(personal_sessions::last_active_at.gt(last_active_after));
        }

        // Token-level filters
        if let Some(expires_before) = filter.expires_before() {
            sub = sub.filter(personal_access_tokens::expires_at.lt(expires_before));
        }

        if let Some(expires_after) = filter.expires_after() {
            sub = sub.filter(personal_access_tokens::expires_at.gt(expires_after));
        }

        if let Some(expires) = filter.expires() {
            if expires {
                sub = sub.filter(personal_access_tokens::expires_at.is_not_null());
            } else {
                sub = sub.filter(personal_access_tokens::expires_at.is_null());
            }
        }

        let rows_affected =
            diesel::update(personal_sessions::table.filter(personal_sessions::id.eq_any(sub)))
                .set(personal_sessions::revoked_at.eq(Some(revoked_at)))
                .execute(self.conn)
                .await?;

        Ok(rows_affected)
    }

    #[tracing::instrument(name = "db.personal_session.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: PersonalSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<(PersonalSession, Option<PersonalAccessToken>)>, Self::Error> {
        let mut query = personal_sessions::table
            .left_join(
                personal_access_tokens::table.on(personal_sessions::id
                    .eq(personal_access_tokens::personal_session_id)
                    .and(personal_access_tokens::revoked_at.is_null())),
            )
            .select(session_with_token_select())
            .into_boxed();

        // Apply session-level filters
        if let Some(user) = filter.owner_user() {
            query = query.filter(personal_sessions::owner_user_id.eq(Uuid::from(user.id)));
        }

        if let Some(client) = filter.owner_oauth_client() {
            query =
                query.filter(personal_sessions::owner_oauth_client_id.eq(Uuid::from(client.id)));
        }

        if let Some(user) = filter.actor_user() {
            query = query.filter(personal_sessions::actor_user_id.eq(Uuid::from(user.id)));
        }

        if let Some(device) = filter.device() {
            let device_scope = format!("urn:contrix:client:device:{device}");
            query = query.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("")
                    .bind::<diesel::sql_types::Text, _>(device_scope)
                    .sql(" = ANY(")
                    .sql("personal_sessions.scope_list")
                    .sql(")"),
            );
        }

        match filter.state() {
            Some(PersonalSessionState::Active) => {
                query = query.filter(personal_sessions::revoked_at.is_null());
            }
            Some(PersonalSessionState::Revoked) => {
                query = query.filter(personal_sessions::revoked_at.is_not_null());
            }
            None => {}
        }

        if let Some(scope) = filter.scope() {
            let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();
            query = query.filter(personal_sessions::scope_list.contains(scope_list));
        }

        if let Some(last_active_before) = filter.last_active_before() {
            query = query.filter(personal_sessions::last_active_at.lt(last_active_before));
        }

        if let Some(last_active_after) = filter.last_active_after() {
            query = query.filter(personal_sessions::last_active_at.gt(last_active_after));
        }

        // Token-level filters
        if let Some(expires_before) = filter.expires_before() {
            query = query.filter(personal_access_tokens::expires_at.lt(expires_before));
        }

        if let Some(expires_after) = filter.expires_after() {
            query = query.filter(personal_access_tokens::expires_at.gt(expires_after));
        }

        if let Some(expires) = filter.expires() {
            if expires {
                query = query.filter(personal_access_tokens::expires_at.is_not_null());
            } else {
                query = query.filter(personal_access_tokens::expires_at.is_null());
            }
        }

        // Apply pagination
        if let Some(after) = pagination.after {
            query = query.filter(personal_sessions::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(personal_sessions::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(personal_sessions::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(personal_sessions::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let edges: Vec<PersonalSessionAndAccessTokenRow> = query.load(self.conn).await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(name = "db.personal_session.count", skip_all, err)]
    async fn count(&mut self, filter: PersonalSessionFilter<'_>) -> Result<usize, Self::Error> {
        let mut query = personal_sessions::table
            .left_join(
                personal_access_tokens::table.on(personal_sessions::id
                    .eq(personal_access_tokens::personal_session_id)
                    .and(personal_access_tokens::revoked_at.is_null())),
            )
            .select(diesel::dsl::count(personal_sessions::id))
            .into_boxed();

        // Apply session-level filters
        if let Some(user) = filter.owner_user() {
            query = query.filter(personal_sessions::owner_user_id.eq(Uuid::from(user.id)));
        }

        if let Some(client) = filter.owner_oauth_client() {
            query =
                query.filter(personal_sessions::owner_oauth_client_id.eq(Uuid::from(client.id)));
        }

        if let Some(user) = filter.actor_user() {
            query = query.filter(personal_sessions::actor_user_id.eq(Uuid::from(user.id)));
        }

        if let Some(device) = filter.device() {
            let device_scope = format!("urn:contrix:client:device:{device}");
            query = query.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("")
                    .bind::<diesel::sql_types::Text, _>(device_scope)
                    .sql(" = ANY(")
                    .sql("personal_sessions.scope_list")
                    .sql(")"),
            );
        }

        match filter.state() {
            Some(PersonalSessionState::Active) => {
                query = query.filter(personal_sessions::revoked_at.is_null());
            }
            Some(PersonalSessionState::Revoked) => {
                query = query.filter(personal_sessions::revoked_at.is_not_null());
            }
            None => {}
        }

        if let Some(scope) = filter.scope() {
            let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();
            query = query.filter(personal_sessions::scope_list.contains(scope_list));
        }

        if let Some(last_active_before) = filter.last_active_before() {
            query = query.filter(personal_sessions::last_active_at.lt(last_active_before));
        }

        if let Some(last_active_after) = filter.last_active_after() {
            query = query.filter(personal_sessions::last_active_at.gt(last_active_after));
        }

        // Token-level filters
        if let Some(expires_before) = filter.expires_before() {
            query = query.filter(personal_access_tokens::expires_at.lt(expires_before));
        }

        if let Some(expires_after) = filter.expires_after() {
            query = query.filter(personal_access_tokens::expires_at.gt(expires_after));
        }

        if let Some(expires) = filter.expires() {
            if expires {
                query = query.filter(personal_access_tokens::expires_at.is_not_null());
            } else {
                query = query.filter(personal_access_tokens::expires_at.is_null());
            }
        }

        let count: i64 = query.get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.personal_session.record_batch_activity", skip_all, err)]
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
            ips.push(ip.map(ipnetwork::IpNetwork::from));
        }

        let expected = ids.len();

        let rows_affected = diesel::sql_query(
            r#"
                UPDATE personal_sessions
                SET last_active_at = GREATEST(t.last_active_at, personal_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, personal_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[])
                        AS t(personal_session_id, last_active_at, last_active_ip)
                ) AS t
                WHERE personal_sessions.id = t.personal_session_id
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
}
