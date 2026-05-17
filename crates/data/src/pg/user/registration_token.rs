use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, Page, Pagination, UserRegistrationToken, new_id,
    pagination::{Node, PaginationDirection},
    user::{UserRegistrationTokenFilter, UserRegistrationTokenRepository},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseInconsistencyError, pg::errors::DatabaseError, schema::user_registration_tokens,
};

/// An implementation of
/// [`coauth_data::user::UserRegistrationTokenRepository`] for a PostgreSQL
/// connection
pub struct PgUserRegistrationTokenRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUserRegistrationTokenRepository<'c> {
    /// Create a new [`PgUserRegistrationTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Row type for loading user registration tokens from the database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = user_registration_tokens)]
struct UserRegistrationTokenRow {
    id: Uuid,
    token: String,
    usage_limit: Option<i32>,
    times_used: i32,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl Node<Ulid> for UserRegistrationTokenRow {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<UserRegistrationTokenRow> for UserRegistrationToken {
    type Error = DatabaseInconsistencyError;

    fn try_from(res: UserRegistrationTokenRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(res.id);

        let usage_limit = res
            .usage_limit
            .map(u32::try_from)
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("user_registration_tokens")
                    .column("usage_limit")
                    .row(id)
                    .source(e)
            })?;

        let times_used = res.times_used.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("user_registration_tokens")
                .column("times_used")
                .row(id)
                .source(e)
        })?;

        Ok(UserRegistrationToken {
            id,
            token: res.token,
            usage_limit,
            times_used,
            created_at: res.created_at,
            last_used_at: res.last_used_at,
            expires_at: res.expires_at,
            revoked_at: res.revoked_at,
        })
    }
}

/// Insertable row for creating a new user registration token
#[derive(Insertable)]
#[diesel(table_name = user_registration_tokens)]
struct NewUserRegistrationToken {
    id: Uuid,
    token: String,
    usage_limit: Option<i32>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

/// Apply [`UserRegistrationTokenFilter`] to a boxed query.
///
/// This is a macro-like helper since the filter logic is identical for both
/// `list` (which has a custom SELECT) and `count` (default SELECT), but those
/// two produce different concrete boxed query types.  We use a generic function
/// bounded on `BoxedDsl` output to avoid duplicating the filter code.
macro_rules! apply_token_filter {
    ($query:expr, $filter:expr) => {{
        let mut query = $query;

        if let Some(has_been_used) = $filter.has_been_used() {
            if has_been_used {
                query = query.filter(user_registration_tokens::times_used.gt(0));
            } else {
                query = query.filter(user_registration_tokens::times_used.eq(0));
            }
        }

        if let Some(is_revoked) = $filter.is_revoked() {
            if is_revoked {
                query = query.filter(user_registration_tokens::revoked_at.is_not_null());
            } else {
                query = query.filter(user_registration_tokens::revoked_at.is_null());
            }
        }

        if let Some(is_expired) = $filter.is_expired() {
            let now = $filter.now();
            if is_expired {
                query = query.filter(
                    user_registration_tokens::expires_at
                        .is_not_null()
                        .and(user_registration_tokens::expires_at.lt(now)),
                );
            } else {
                query = query.filter(
                    user_registration_tokens::expires_at
                        .is_null()
                        .or(user_registration_tokens::expires_at.ge(now)),
                );
            }
        }

        if let Some(is_valid) = $filter.is_valid() {
            let now = $filter.now();
            // A token is valid if:
            // 1. usage_limit IS NULL OR times_used < usage_limit
            // 2. revoked_at IS NULL
            // 3. expires_at IS NULL OR expires_at >= now
            if is_valid {
                query = query
                    .filter(
                        user_registration_tokens::usage_limit
                            .is_null()
                            .or(user_registration_tokens::times_used
                                .lt(user_registration_tokens::usage_limit.assume_not_null())),
                    )
                    .filter(user_registration_tokens::revoked_at.is_null())
                    .filter(
                        user_registration_tokens::expires_at
                            .is_null()
                            .or(user_registration_tokens::expires_at.ge(now)),
                    );
            } else {
                // Not valid: at least one validity condition fails
                query = query.filter(
                    (user_registration_tokens::usage_limit.is_not_null().and(
                        user_registration_tokens::times_used
                            .ge(user_registration_tokens::usage_limit.assume_not_null()),
                    ))
                    .or(user_registration_tokens::revoked_at.is_not_null())
                    .or(user_registration_tokens::expires_at
                        .is_not_null()
                        .and(user_registration_tokens::expires_at.lt(now))),
                );
            }
        }

        query
    }};
}

#[async_trait]
impl UserRegistrationTokenRepository for PgUserRegistrationTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.user_registration_token.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: UserRegistrationTokenFilter,
        pagination: Pagination,
    ) -> Result<Page<UserRegistrationToken>, Self::Error> {
        let query = user_registration_tokens::table
            .select(UserRegistrationTokenRow::as_select())
            .into_boxed();

        let mut query = apply_token_filter!(query, filter);

        // Apply pagination cursors
        if let Some(after) = pagination.after {
            query = query.filter(user_registration_tokens::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(user_registration_tokens::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(user_registration_tokens::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(user_registration_tokens::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let rows: Vec<UserRegistrationTokenRow> = query.load(self.conn).await?;
        let page = pagination
            .process(rows)
            .try_map(UserRegistrationToken::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.count",
        skip_all,
        fields(
            user_registration_token.filter = ?filter,
        ),
        err,
    )]
    async fn count(&mut self, filter: UserRegistrationTokenFilter) -> Result<usize, Self::Error> {
        let query = user_registration_tokens::table.into_boxed();
        let query = apply_token_filter!(query, filter);

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.lookup",
        skip_all,
        fields(
            user_registration_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistrationToken>, Self::Error> {
        let res = user_registration_tokens::table
            .find(Uuid::from(id))
            .select(UserRegistrationTokenRow::as_select())
            .first::<UserRegistrationTokenRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else {
            return Ok(None);
        };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration_token.find_by_token",
        skip_all,
        fields(
            token = %token,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        token: &str,
    ) -> Result<Option<UserRegistrationToken>, Self::Error> {
        let res = user_registration_tokens::table
            .filter(user_registration_tokens::token.eq(token))
            .select(UserRegistrationTokenRow::as_select())
            .first::<UserRegistrationTokenRow>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else {
            return Ok(None);
        };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration_token.add",
        skip_all,
        fields(
            user_registration_token.token = %token,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        token: String,
        usage_limit: Option<u32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);

        let usage_limit_i32 = usage_limit
            .map(i32::try_from)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let new_token = NewUserRegistrationToken {
            id: Uuid::from(id),
            token: token.clone(),
            usage_limit: usage_limit_i32,
            created_at,
            expires_at,
        };

        diesel::insert_into(user_registration_tokens::table)
            .values(&new_token)
            .execute(self.conn)
            .await?;

        Ok(UserRegistrationToken {
            id,
            token,
            usage_limit,
            times_used: 0,
            created_at,
            last_used_at: None,
            expires_at,
            revoked_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_registration_token.use_token",
        skip_all,
        fields(
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn use_token(
        &mut self,
        clock: &dyn Clock,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let now = clock.now();

        // Use raw SQL for the UPDATE ... RETURNING pattern with an expression
        // (times_used = times_used + 1), since diesel's update builder does not
        // directly support incrementing a column and returning in one step
        // without a custom expression.
        let new_times_used: i32 = diesel::sql_query(
            "UPDATE user_registration_tokens \
             SET times_used = times_used + 1, \
                 last_used_at = $2 \
             WHERE id = $1 AND revoked_at IS NULL \
             RETURNING times_used",
        )
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(token.id))
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .get_result::<TimesUsedRow>(self.conn)
        .await
        .map(|r| r.times_used)?;

        let new_times_used = new_times_used
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(UserRegistrationToken {
            times_used: new_times_used,
            last_used_at: Some(now),
            ..token
        })
    }

    #[tracing::instrument(
        name = "db.user_registration_token.revoke",
        skip_all,
        fields(
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        mut token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let revoked_at = clock.now();
        let rows_affected =
            diesel::update(user_registration_tokens::table.find(Uuid::from(token.id)))
                .set(user_registration_tokens::revoked_at.eq(Some(revoked_at)))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        token.revoked_at = Some(revoked_at);

        Ok(token)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.unrevoke",
        skip_all,
        fields(
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn unrevoke(
        &mut self,
        mut token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let rows_affected =
            diesel::update(user_registration_tokens::table.find(Uuid::from(token.id)))
                .set(user_registration_tokens::revoked_at.eq(None::<DateTime<Utc>>))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        token.revoked_at = None;

        Ok(token)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.set_expiry",
        skip_all,
        fields(
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn set_expiry(
        &mut self,
        mut token: UserRegistrationToken,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let rows_affected =
            diesel::update(user_registration_tokens::table.find(Uuid::from(token.id)))
                .set(user_registration_tokens::expires_at.eq(expires_at))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        token.expires_at = expires_at;

        Ok(token)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.set_usage_limit",
        skip_all,
        fields(
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn set_usage_limit(
        &mut self,
        mut token: UserRegistrationToken,
        usage_limit: Option<u32>,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let usage_limit_i32 = usage_limit
            .map(i32::try_from)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let rows_affected =
            diesel::update(user_registration_tokens::table.find(Uuid::from(token.id)))
                .set(user_registration_tokens::usage_limit.eq(usage_limit_i32))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        token.usage_limit = usage_limit;

        Ok(token)
    }
}

/// Helper row type for extracting `times_used` from a RETURNING clause.
#[derive(Debug, Clone, QueryableByName)]
struct TimesUsedRow {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    times_used: i32,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::{
        Clock as _, Pagination, RepositoryAccess as _, RepositoryFactory as _, clock::MockClock,
        user::UserRegistrationTokenFilter,
    };
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::PgRepositoryFactory;

    #[tokio::test]
    async fn test_unrevoke() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        // Create a token
        let token = repo
            .user_registration_token()
            .add(&mut rng, &clock, "test_token".to_owned(), None, None)
            .await
            .unwrap();

        // Revoke the token
        let revoked_token = repo
            .user_registration_token()
            .revoke(&clock, token)
            .await
            .unwrap();

        // Verify it's revoked
        assert!(revoked_token.revoked_at.is_some());

        // Unrevoke the token
        let unrevoked_token = repo
            .user_registration_token()
            .unrevoke(revoked_token)
            .await
            .unwrap();

        // Verify it's no longer revoked
        assert!(unrevoked_token.revoked_at.is_none());

        // Check that we can find it with the non-revoked filter
        let non_revoked_filter = UserRegistrationTokenFilter::new(clock.now()).with_revoked(false);
        let page = repo
            .user_registration_token()
            .list(non_revoked_filter, Pagination::first(10))
            .await
            .unwrap();

        assert!(page.edges.iter().any(|t| t.node.id == unrevoked_token.id));
    }

    #[tokio::test]
    async fn test_set_expiry() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        // Create a token without expiry
        let token = repo
            .user_registration_token()
            .add(&mut rng, &clock, "test_token_expiry".to_owned(), None, None)
            .await
            .unwrap();

        // Verify it has no expiration
        assert!(token.expires_at.is_none());

        // Set an expiration
        let future_time = clock.now() + Duration::days(30);
        let updated_token = repo
            .user_registration_token()
            .set_expiry(token, Some(future_time))
            .await
            .unwrap();

        // Verify expiration is set
        assert_eq!(updated_token.expires_at, Some(future_time));

        // Remove the expiration
        let final_token = repo
            .user_registration_token()
            .set_expiry(updated_token, None)
            .await
            .unwrap();

        // Verify expiration is removed
        assert!(final_token.expires_at.is_none());
    }

    #[tokio::test]
    async fn test_set_usage_limit() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        // Create a token without usage limit
        let token = repo
            .user_registration_token()
            .add(&mut rng, &clock, "test_token_limit".to_owned(), None, None)
            .await
            .unwrap();

        // Verify it has no usage limit
        assert!(token.usage_limit.is_none());

        // Set a usage limit
        let updated_token = repo
            .user_registration_token()
            .set_usage_limit(token, Some(5))
            .await
            .unwrap();

        // Verify usage limit is set
        assert_eq!(updated_token.usage_limit, Some(5));

        // Change the usage limit
        let changed_token = repo
            .user_registration_token()
            .set_usage_limit(updated_token, Some(10))
            .await
            .unwrap();

        // Verify usage limit is changed
        assert_eq!(changed_token.usage_limit, Some(10));

        // Remove the usage limit
        let final_token = repo
            .user_registration_token()
            .set_usage_limit(changed_token, None)
            .await
            .unwrap();

        // Verify usage limit is removed
        assert!(final_token.usage_limit.is_none());
    }

    #[tokio::test]
    async fn test_list_and_count() {
        let Some(pool) = crate::test_utils::setup_test_pool().await else {
            return;
        };
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepositoryFactory::new(pool.clone())
            .create()
            .await
            .unwrap();

        // Create different types of tokens
        // 1. A regular token
        let _token1 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token1".to_owned(), None, None)
            .await
            .unwrap();

        // 2. A token that has been used
        let token2 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token2".to_owned(), None, None)
            .await
            .unwrap();
        let token2 = repo
            .user_registration_token()
            .use_token(&clock, token2)
            .await
            .unwrap();

        // 3. A token that is expired
        let past_time = clock.now() - Duration::days(1);
        let token3 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token3".to_owned(), None, Some(past_time))
            .await
            .unwrap();

        // 4. A token that is revoked
        let token4 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token4".to_owned(), None, None)
            .await
            .unwrap();
        let token4 = repo
            .user_registration_token()
            .revoke(&clock, token4)
            .await
            .unwrap();

        // Test list with empty filter
        let empty_filter = UserRegistrationTokenFilter::new(clock.now());
        let page = repo
            .user_registration_token()
            .list(empty_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 4);

        // Test count with empty filter
        let count = repo
            .user_registration_token()
            .count(empty_filter)
            .await
            .unwrap();
        assert_eq!(count, 4);

        // Test has_been_used filter
        let used_filter = UserRegistrationTokenFilter::new(clock.now()).with_been_used(true);
        let page = repo
            .user_registration_token()
            .list(used_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node.id, token2.id);

        // Test unused filter
        let unused_filter = UserRegistrationTokenFilter::new(clock.now()).with_been_used(false);
        let page = repo
            .user_registration_token()
            .list(unused_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 3);

        // Test is_expired filter
        let expired_filter = UserRegistrationTokenFilter::new(clock.now()).with_expired(true);
        let page = repo
            .user_registration_token()
            .list(expired_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node.id, token3.id);

        let not_expired_filter = UserRegistrationTokenFilter::new(clock.now()).with_expired(false);
        let page = repo
            .user_registration_token()
            .list(not_expired_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 3);

        // Test is_revoked filter
        let revoked_filter = UserRegistrationTokenFilter::new(clock.now()).with_revoked(true);
        let page = repo
            .user_registration_token()
            .list(revoked_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node.id, token4.id);

        let not_revoked_filter = UserRegistrationTokenFilter::new(clock.now()).with_revoked(false);
        let page = repo
            .user_registration_token()
            .list(not_revoked_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 3);

        // Test is_valid filter
        let valid_filter = UserRegistrationTokenFilter::new(clock.now()).with_valid(true);
        let page = repo
            .user_registration_token()
            .list(valid_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 2);

        let invalid_filter = UserRegistrationTokenFilter::new(clock.now()).with_valid(false);
        let page = repo
            .user_registration_token()
            .list(invalid_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 2);

        // Test combined filters
        let combined_filter = UserRegistrationTokenFilter::new(clock.now())
            .with_been_used(false)
            .with_revoked(true);
        let page = repo
            .user_registration_token()
            .list(combined_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node.id, token4.id);

        // Test pagination
        let page = repo
            .user_registration_token()
            .list(empty_filter, Pagination::first(2))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 2);
    }
}
