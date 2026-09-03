use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::pagination::Node;
use coauth_data::upstream_oauth::{UpstreamOAuthSessionFilter, UpstreamOAuthSessionRepository};
use coauth_data::{
    BrowserSession, Clock, Page, Pagination, UpstreamOAuthAuthorizationSession,
    UpstreamOAuthAuthorizationSessionState, UpstreamOAuthLink, UpstreamOAuthProvider, new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::upstream_oauth_authorization_sessions;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// An implementation of [`UpstreamOAuthSessionRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthSessionRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUpstreamOAuthSessionRepository<'c> {
    /// Create a new [`PgUpstreamOAuthSessionRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = upstream_oauth_authorization_sessions)]
struct SessionLookup {
    id: Uuid,
    upstream_oauth_provider_id: Uuid,
    upstream_oauth_link_id: Option<Uuid>,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: Option<String>,
    id_token: Option<String>,
    id_token_claims: Option<serde_json::Value>,
    userinfo: Option<serde_json::Value>,
    completed_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    extra_callback_parameters: Option<serde_json::Value>,
    unlinked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl Node<Ulid> for SessionLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<SessionLookup> for UpstreamOAuthAuthorizationSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionLookup) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let state = match (
            value.upstream_oauth_link_id,
            value.id_token,
            value.id_token_claims,
            value.extra_callback_parameters,
            value.userinfo,
            value.completed_at,
            value.consumed_at,
            value.unlinked_at,
        ) {
            (None, None, None, None, None, None, None, None) => {
                UpstreamOAuthAuthorizationSessionState::Pending
            }
            (
                Some(link_id),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
                Some(completed_at),
                None,
                None,
            ) => UpstreamOAuthAuthorizationSessionState::Completed {
                completed_at,
                link_id: link_id.into(),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
            },
            (
                Some(link_id),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
                Some(completed_at),
                Some(consumed_at),
                None,
            ) => UpstreamOAuthAuthorizationSessionState::Consumed {
                completed_at,
                link_id: link_id.into(),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
                consumed_at,
            },
            (
                _,
                id_token,
                id_token_claims,
                _,
                _,
                Some(completed_at),
                consumed_at,
                Some(unlinked_at),
            ) => UpstreamOAuthAuthorizationSessionState::Unlinked {
                completed_at,
                id_token,
                id_token_claims,
                consumed_at,
                unlinked_at,
            },
            _ => {
                return Err(DatabaseInconsistencyError::on(
                    "upstream_oauth_authorization_sessions",
                )
                .row(id));
            }
        };

        Ok(Self {
            id,
            provider_id: value.upstream_oauth_provider_id.into(),
            state_str: value.state,
            nonce: value.nonce,
            code_challenge_verifier: value.code_challenge_verifier,
            created_at: value.created_at,
            state,
        })
    }
}

/// Insertable row for creating a new upstream OAuth authorization session
#[derive(Insertable)]
#[diesel(table_name = upstream_oauth_authorization_sessions)]
struct NewSession {
    id: Uuid,
    upstream_oauth_provider_id: Uuid,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: Option<String>,
    completed_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    id_token: Option<String>,
    userinfo: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UpstreamOAuthSessionRepository for PgUpstreamOAuthSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.lookup",
        skip_all,
        fields(
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UpstreamOAuthAuthorizationSession>, Self::Error> {
        let res = upstream_oauth_authorization_sessions::table
            .find(Uuid::from(id))
            .select(SessionLookup::as_select())
            .first::<SessionLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.add",
        skip_all,
        fields(
            %upstream_oauth_provider.id,
            upstream_oauth_provider.oidc_issuer_uri = upstream_oauth_provider.oidc_issuer_uri,
            %upstream_oauth_provider.client_id,
            upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        state_str: String,
        code_challenge_verifier: Option<String>,
        nonce: Option<String>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record(
            "upstream_oauth_authorization_session.id",
            tracing::field::display(id),
        );

        let new_session = NewSession {
            id: Uuid::from(id),
            upstream_oauth_provider_id: Uuid::from(upstream_oauth_provider.id),
            state: state_str.clone(),
            code_challenge_verifier: code_challenge_verifier.clone(),
            nonce: nonce.clone(),
            created_at,
            completed_at: None,
            consumed_at: None,
            id_token: None,
            userinfo: None,
        };

        diesel::insert_into(upstream_oauth_authorization_sessions::table)
            .values(&new_session)
            .execute(self.conn)
            .await?;

        Ok(UpstreamOAuthAuthorizationSession {
            id,
            state: UpstreamOAuthAuthorizationSessionState::default(),
            provider_id: upstream_oauth_provider.id,
            state_str,
            code_challenge_verifier,
            nonce,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.complete_with_link",
        skip_all,
        fields(
            %upstream_oauth_authorization_session.id,
            %upstream_oauth_link.id,
        ),
        err,
    )]
    async fn complete_with_link(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
        id_token_claims: Option<serde_json::Value>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let completed_at = clock.now();

        diesel::update(
            upstream_oauth_authorization_sessions::table
                .find(Uuid::from(upstream_oauth_authorization_session.id)),
        )
        .set((
            upstream_oauth_authorization_sessions::upstream_oauth_link_id
                .eq(Some(Uuid::from(upstream_oauth_link.id))),
            upstream_oauth_authorization_sessions::completed_at.eq(Some(completed_at)),
            upstream_oauth_authorization_sessions::id_token.eq(&id_token),
            upstream_oauth_authorization_sessions::id_token_claims.eq(&id_token_claims),
            upstream_oauth_authorization_sessions::extra_callback_parameters
                .eq(&extra_callback_parameters),
            upstream_oauth_authorization_sessions::userinfo.eq(&userinfo),
        ))
        .execute(self.conn)
        .await?;

        let upstream_oauth_authorization_session = upstream_oauth_authorization_session
            .complete(
                completed_at,
                upstream_oauth_link,
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
            )
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(upstream_oauth_authorization_session)
    }

    /// Mark a session as consumed
    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.consume",
        skip_all,
        fields(
            %upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        browser_session: &BrowserSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let consumed_at = clock.now();

        diesel::update(
            upstream_oauth_authorization_sessions::table
                .find(Uuid::from(upstream_oauth_authorization_session.id)),
        )
        .set((
            upstream_oauth_authorization_sessions::consumed_at.eq(Some(consumed_at)),
            upstream_oauth_authorization_sessions::user_session_id
                .eq(Some(Uuid::from(browser_session.id))),
        ))
        .execute(self.conn)
        .await?;

        let upstream_oauth_authorization_session = upstream_oauth_authorization_session
            .consume(consumed_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(upstream_oauth_authorization_session)
    }

    #[tracing::instrument(name = "db.upstream_oauth_authorization_session.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: UpstreamOAuthSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthAuthorizationSession>, Self::Error> {
        let mut query = upstream_oauth_authorization_sessions::table
            .select(SessionLookup::as_select())
            .into_boxed();

        // Apply filters
        if let Some(provider) = filter.provider() {
            query = query.filter(
                upstream_oauth_authorization_sessions::upstream_oauth_provider_id
                    .eq(Uuid::from(provider.id)),
            );
        }

        if let Some(sub) = filter.sub_claim() {
            // Filter by the "sub" field in id_token_claims JSONB column using a
            // bound parameter (never string-interpolated) to keep the claim
            // value out of the SQL text.
            query = query.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("id_token_claims->>'sub' = ")
                    .bind::<diesel::sql_types::Text, _>(sub),
            );
        }

        if let Some(sid) = filter.sid_claim() {
            // Filter by the "sid" field in id_token_claims JSONB column.
            query = query.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("id_token_claims->>'sid' = ")
                    .bind::<diesel::sql_types::Text, _>(sid),
            );
        }

        query =
            crate::paginate_by_id!(query, pagination, upstream_oauth_authorization_sessions::id);

        let edges: Vec<SessionLookup> = query.load(self.conn).await?;

        let page = pagination
            .process(edges)
            .try_map(UpstreamOAuthAuthorizationSession::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(name = "db.upstream_oauth_authorization_session.count", skip_all, err)]
    async fn count(
        &mut self,
        filter: UpstreamOAuthSessionFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let mut query = upstream_oauth_authorization_sessions::table.into_boxed();

        if let Some(provider) = filter.provider() {
            query = query.filter(
                upstream_oauth_authorization_sessions::upstream_oauth_provider_id
                    .eq(Uuid::from(provider.id)),
            );
        }

        if let Some(sub) = filter.sub_claim() {
            query = query.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("id_token_claims->>'sub' = ")
                    .bind::<diesel::sql_types::Text, _>(sub),
            );
        }

        if let Some(sid) = filter.sid_claim() {
            query = query.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("id_token_claims->>'sid' = ")
                    .bind::<diesel::sql_types::Text, _>(sid),
            );
        }

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.cleanup",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup_orphaned(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error> {
        // Use raw SQL for the CTE-based cleanup query since diesel doesn't
        // natively support CTEs with DELETE ... USING ... RETURNING.
        let res: Vec<Uuid> = diesel::sql_query(
            r"
                WITH to_delete AS (
                    SELECT id
                    FROM upstream_oauth_authorization_sessions
                    WHERE ($1::uuid IS NULL OR id > $1)
                      AND id <= $2
                      AND user_session_id IS NULL
                    ORDER BY id
                    LIMIT $3
                )
                DELETE FROM upstream_oauth_authorization_sessions
                USING to_delete
                WHERE upstream_oauth_authorization_sessions.id = to_delete.id
                RETURNING upstream_oauth_authorization_sessions.id
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(since.map(Uuid::from))
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(until))
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load::<CleanupResult>(self.conn)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();

        let count = res.len();
        let max_id = res.into_iter().max();

        Ok((count, max_id.map(Ulid::from)))
    }
}

/// Helper struct for the `cleanup_orphaned` query result
#[derive(QueryableByName)]
struct CleanupResult {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}
