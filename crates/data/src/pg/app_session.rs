//! A module containing PostgreSQL implementation of repositories for sessions

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::app_session::{
    AppSession, AppSessionFilter, AppSessionRepository, AppSessionState,
};
use coauth_data::pagination::PaginationDirection;
use coauth_data::{Clock, Page, Pagination, Session, SessionState, User};
use coauth_oauth_types::scope::{Scope, ScopeToken};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::pg::errors::DatabaseInconsistencyError;
use crate::schema::oauth_sessions;

/// An implementation of [`AppSessionRepository`] for a PostgreSQL connection
pub struct PgAppSessionRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgAppSessionRepository<'c> {
    /// Create a new [`PgAppSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading an OAuth session as an app session
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_sessions)]
struct AppSessionLookup {
    id: Uuid,
    oauth_client_id: Uuid,
    user_session_id: Option<Uuid>,
    user_id: Option<Uuid>,
    scope_list: Vec<String>,
    human_name: Option<String>,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<ipnetwork::IpNetwork>,
}

impl coauth_data::pagination::Node<Ulid> for AppSessionLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<AppSessionLookup> for AppSession {
    type Error = DatabaseError;

    fn try_from(value: AppSessionLookup) -> Result<Self, Self::Error> {
        let id: Ulid = value.id.into();

        let scope: Result<Scope, _> = value
            .scope_list
            .iter()
            .map(|s| s.parse::<ScopeToken>())
            .collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("oauth_sessions")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match value.finished_at {
            None => SessionState::Valid,
            Some(finished_at) => SessionState::Finished { finished_at },
        };

        let session = Session {
            id,
            state,
            created_at: value.created_at,
            client_id: value.oauth_client_id.into(),
            user_id: value.user_id.map(Ulid::from),
            user_session_id: value.user_session_id.map(Ulid::from),
            scope,
            user_agent: value.user_agent,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip.map(|ip| ip.ip()),
            human_name: value.human_name,
        };

        Ok(AppSession::OAuth(Box::new(session)))
    }
}

/// Apply the [`AppSessionFilter`] to a boxed select query on `oauth_sessions`.
macro_rules! apply_app_session_filter {
    ($query:expr, $filter:expr) => {{
        let mut query = $query;
        let filter = $filter;

        if let Some(user) = filter.user() {
            query = query.filter(oauth_sessions::user_id.eq(Uuid::from(user.id)));
        }

        match filter.state() {
            Some(AppSessionState::Active) => {
                query = query.filter(oauth_sessions::finished_at.is_null());
            }
            Some(AppSessionState::Finished) => {
                query = query.filter(oauth_sessions::finished_at.is_not_null());
            }
            None => {}
        }

        if let Some(device) = filter.device() {
            let device_scope = format!("urn:arkret:client:device:{device}");
            query = query.filter(
                diesel::dsl::sql::<diesel::sql_types::Bool>("")
                    .bind::<diesel::sql_types::Text, _>(device_scope)
                    .sql(" = ANY(")
                    .sql("oauth_sessions.scope_list")
                    .sql(")"),
            );
        }

        if let Some(browser_session) = filter.browser_session() {
            query =
                query.filter(oauth_sessions::user_session_id.eq(Uuid::from(browser_session.id)));
        }

        if let Some(last_active_before) = filter.last_active_before() {
            query = query.filter(oauth_sessions::last_active_at.lt(last_active_before));
        }

        if let Some(last_active_after) = filter.last_active_after() {
            query = query.filter(oauth_sessions::last_active_at.gt(last_active_after));
        }

        query
    }};
}

#[async_trait]
impl AppSessionRepository for PgAppSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.app_session.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: AppSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<AppSession>, Self::Error> {
        let mut query = oauth_sessions::table
            .select(AppSessionLookup::as_select())
            .into_boxed();

        query = apply_app_session_filter!(query, filter);

        // Apply pagination
        if let Some(after) = pagination.after {
            query = query.filter(oauth_sessions::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(oauth_sessions::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(oauth_sessions::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(oauth_sessions::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let edges: Vec<AppSessionLookup> = query.load(self.conn).await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(name = "db.app_session.count", skip_all, err)]
    async fn count(&mut self, filter: AppSessionFilter<'_>) -> Result<usize, Self::Error> {
        let query = oauth_sessions::table.into_boxed();
        let query = apply_app_session_filter!(query, filter);

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.app_session.finish_sessions_to_replace_device",
        skip_all,
        fields(
            %user.id,
            %device
        ),
        err,
    )]
    async fn finish_sessions_to_replace_device(
        &mut self,
        clock: &dyn Clock,
        user: &User,
        device: &str,
    ) -> Result<bool, Self::Error> {
        let finished_at = clock.now();
        let device_scope = format!("urn:arkret:client:device:{device}");

        let oauth_affected = diesel::sql_query(
            "UPDATE oauth_sessions
             SET finished_at = $3
             WHERE user_id = $1
               AND $2 = ANY(scope_list)
               AND finished_at IS NULL",
        )
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(user.id))
        .bind::<diesel::sql_types::Text, _>(&device_scope)
        .bind::<diesel::sql_types::Timestamptz, _>(finished_at)
        .execute(self.conn)
        .await?;

        Ok(oauth_affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::app_session::{AppSession, AppSessionFilter};
    use coauth_data::clock::MockClock;
    use coauth_data::oauth::OAuthSessionRepository;
    use coauth_data::{Pagination, RepositoryAccess as _, RepositoryFactory as _};
    use coauth_oauth_types::requests::GrantType;
    use coauth_oauth_types::scope::{OPENID, Scope};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::PgRepositoryFactory;

    #[tokio::test]
    async fn test_app_repo() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        let all = AppSessionFilter::new().for_user(&user);
        let active = all.active_only();
        let finished = all.finished_only();
        let pagination = Pagination::first(10);

        assert_eq!(repo.app_session().count(all).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 0);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert!(full_list.edges.is_empty());
        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert!(finished_list.edges.is_empty());

        // Start an OAuth session
        let client = repo
            .oauth_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("First client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        let device_id = "AABBCCDDEE";
        let stable_scope = format!("urn:arkret:client:device:{device_id}");
        let scope: Scope = [OPENID]
            .into_iter()
            .chain([stable_scope.parse().unwrap()])
            .collect();

        // We're moving the clock forward by 1 minute between each session to ensure
        // we're getting consistent ordering in lists.
        clock.advance(Duration::try_minutes(1).unwrap());

        let oauth_session = repo
            .oauth_session()
            .add(&mut rng, &clock, &client, Some(&user), None, scope)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 0);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(
            full_list.edges[0].node,
            AppSession::OAuth(Box::new(oauth_session.clone()))
        );

        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert_eq!(active_list.edges.len(), 1);
        assert_eq!(
            active_list.edges[0].node,
            AppSession::OAuth(Box::new(oauth_session.clone()))
        );

        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert!(finished_list.edges.is_empty());

        // Finish the session
        let oauth_session = repo
            .oauth_session()
            .finish(&clock, oauth_session)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 1);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(
            full_list.edges[0].node,
            AppSession::OAuth(Box::new(oauth_session.clone()))
        );

        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());

        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert_eq!(finished_list.edges.len(), 1);
        assert_eq!(
            finished_list.edges[0].node,
            AppSession::OAuth(Box::new(oauth_session.clone()))
        );

        // Query by device
        let filter = AppSessionFilter::new().for_device(device_id);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 1);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(
            list.edges[0].node,
            AppSession::OAuth(Box::new(oauth_session.clone()))
        );

        // Create a second user
        let user2 = repo
            .user()
            .add(&mut rng, &clock, "alice".to_owned())
            .await
            .unwrap();

        // If we list/count for this user, we should get nothing
        let filter = AppSessionFilter::new().for_user(&user2);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 0);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert!(list.edges.is_empty());
    }
}
