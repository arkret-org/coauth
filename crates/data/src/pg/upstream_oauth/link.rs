use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, Page, Pagination, UpstreamOAuthLink, UpstreamOAuthLinkPatch, UpstreamOAuthProvider,
    User, new_id,
    pagination::{Node, PaginationDirection},
    upstream_oauth::{UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository},
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError,
    schema::{upstream_oauth_links, upstream_oauth_providers},
};

/// An implementation of [`UpstreamOAuthLinkRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthLinkRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUpstreamOAuthLinkRepository<'c> {
    /// Create a new [`PgUpstreamOAuthLinkRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = upstream_oauth_links)]
struct LinkLookup {
    id: Uuid,
    upstream_oauth_provider_id: Uuid,
    user_id: Option<Uuid>,
    subject: String,
    human_account_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Node<Ulid> for LinkLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl From<LinkLookup> for UpstreamOAuthLink {
    fn from(value: LinkLookup) -> Self {
        UpstreamOAuthLink {
            id: Ulid::from(value.id),
            provider_id: Ulid::from(value.upstream_oauth_provider_id),
            user_id: value.user_id.map(Ulid::from),
            subject: value.subject,
            human_account_name: value.human_account_name,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

/// Insertable row for creating a new upstream OAuth link
#[derive(Insertable)]
#[diesel(table_name = upstream_oauth_links)]
struct NewLink {
    id: Uuid,
    upstream_oauth_provider_id: Uuid,
    user_id: Option<Uuid>,
    subject: String,
    human_account_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl UpstreamOAuthLinkRepository for PgUpstreamOAuthLinkRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_link.lookup",
        skip_all,
        fields(
            upstream_oauth_link.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLink>, Self::Error> {
        let res = upstream_oauth_links::table
            .find(Uuid::from(id))
            .select(LinkLookup::as_select())
            .first::<LinkLookup>(self.conn)
            .await
            .optional()?
            .map(Into::into);

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.find_by_subject",
        skip_all,
        fields(
            upstream_oauth_link.subject = subject,
            %upstream_oauth_provider.id,
            upstream_oauth_provider.issuer = upstream_oauth_provider.issuer,
            %upstream_oauth_provider.client_id,
        ),
        err,
    )]
    async fn find_by_subject(
        &mut self,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: &str,
    ) -> Result<Option<UpstreamOAuthLink>, Self::Error> {
        let res = upstream_oauth_links::table
            .filter(
                upstream_oauth_links::upstream_oauth_provider_id
                    .eq(Uuid::from(upstream_oauth_provider.id)),
            )
            .filter(upstream_oauth_links::subject.eq(subject))
            .select(LinkLookup::as_select())
            .first::<LinkLookup>(self.conn)
            .await
            .optional()?
            .map(Into::into);

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.add",
        skip_all,
        fields(
            upstream_oauth_link.id,
            upstream_oauth_link.subject = subject,
            upstream_oauth_link.human_account_name = human_account_name,
            %upstream_oauth_provider.id,
            upstream_oauth_provider.issuer = upstream_oauth_provider.issuer,
            %upstream_oauth_provider.client_id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: String,
        human_account_name: Option<String>,
    ) -> Result<UpstreamOAuthLink, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("upstream_oauth_link.id", tracing::field::display(id));

        let new_link = NewLink {
            id: Uuid::from(id),
            upstream_oauth_provider_id: Uuid::from(upstream_oauth_provider.id),
            user_id: None,
            subject: subject.clone(),
            human_account_name: human_account_name.clone(),
            created_at,
            updated_at: created_at,
        };

        diesel::insert_into(upstream_oauth_links::table)
            .values(&new_link)
            .execute(self.conn)
            .await?;

        Ok(UpstreamOAuthLink {
            id,
            provider_id: upstream_oauth_provider.id,
            user_id: None,
            subject,
            human_account_name,
            created_at,
            updated_at: created_at,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.associate_to_user",
        skip_all,
        fields(
            %upstream_oauth_link.id,
            %upstream_oauth_link.subject,
            %user.id,
            %user.handle,
        ),
        err,
    )]
    async fn associate_to_user(
        &mut self,
        upstream_oauth_link: &UpstreamOAuthLink,
        user: &User,
    ) -> Result<(), Self::Error> {
        // The repository trait doesn't pass a clock for this method;
        // use the wall clock until the trait signature is reworked.
        #[allow(clippy::disallowed_methods)]
        let now = Utc::now();
        diesel::update(upstream_oauth_links::table.find(Uuid::from(upstream_oauth_link.id)))
            .set((
                upstream_oauth_links::user_id.eq(Some(Uuid::from(user.id))),
                upstream_oauth_links::updated_at.eq(now),
            ))
            .execute(self.conn)
            .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.patch",
        skip_all,
        fields(%upstream_oauth_link.id),
        err,
    )]
    async fn patch(
        &mut self,
        clock: &dyn Clock,
        mut upstream_oauth_link: UpstreamOAuthLink,
        patch: UpstreamOAuthLinkPatch,
    ) -> Result<UpstreamOAuthLink, Self::Error> {
        if patch.is_empty() {
            return Ok(upstream_oauth_link);
        }

        let mut changed = false;

        if let Some(user_id) = patch.user_id
            && upstream_oauth_link.user_id != user_id {
                upstream_oauth_link.user_id = user_id;
                changed = true;
            }

        if let Some(subject) = patch.subject
            && upstream_oauth_link.subject != subject
        {
            upstream_oauth_link.subject = subject;
            changed = true;
        }

        if let Some(human_account_name) = patch.human_account_name
            && upstream_oauth_link.human_account_name != human_account_name
        {
            upstream_oauth_link.human_account_name = human_account_name;
            changed = true;
        }

        if !changed {
            return Ok(upstream_oauth_link);
        }

        upstream_oauth_link.updated_at = clock.now();

        let rows_affected =
            diesel::update(upstream_oauth_links::table.find(Uuid::from(upstream_oauth_link.id)))
                .set((
                    upstream_oauth_links::user_id.eq(upstream_oauth_link.user_id.map(Uuid::from)),
                    upstream_oauth_links::subject.eq(&upstream_oauth_link.subject),
                    upstream_oauth_links::human_account_name
                        .eq(upstream_oauth_link.human_account_name.as_deref()),
                    upstream_oauth_links::updated_at.eq(upstream_oauth_link.updated_at),
                ))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
        Ok(upstream_oauth_link)
    }

    #[tracing::instrument(name = "db.upstream_oauth_link.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: UpstreamOAuthLinkFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthLink>, DatabaseError> {
        let mut query = upstream_oauth_links::table
            .select(LinkLookup::as_select())
            .into_boxed();

        // Apply filters
        if let Some(user) = filter.user() {
            query = query.filter(upstream_oauth_links::user_id.eq(Uuid::from(user.id)));
        }

        if let Some(provider) = filter.provider() {
            query = query.filter(
                upstream_oauth_links::upstream_oauth_provider_id.eq(Uuid::from(provider.id)),
            );
        }

        if let Some(enabled) = filter.provider_enabled() {
            // Subquery to find provider IDs matching the enabled/disabled condition.
            // We use `into_boxed()` so that both branches have the same type.
            let subquery = if enabled {
                upstream_oauth_providers::table
                    .filter(upstream_oauth_providers::disabled_at.is_null())
                    .select(upstream_oauth_providers::id)
                    .into_boxed()
            } else {
                upstream_oauth_providers::table
                    .filter(upstream_oauth_providers::disabled_at.is_not_null())
                    .select(upstream_oauth_providers::id)
                    .into_boxed()
            };

            query = query.filter(upstream_oauth_links::upstream_oauth_provider_id.eq_any(subquery));
        }

        if let Some(subject) = filter.subject() {
            query = query.filter(upstream_oauth_links::subject.eq(subject));
        }

        // Apply pagination
        if let Some(after) = pagination.after {
            query = query.filter(upstream_oauth_links::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(upstream_oauth_links::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(upstream_oauth_links::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(upstream_oauth_links::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let edges: Vec<LinkLookup> = query.load(self.conn).await?;

        let page = pagination.process(edges).map(UpstreamOAuthLink::from);

        Ok(page)
    }

    #[tracing::instrument(name = "db.upstream_oauth_link.count", skip_all, err)]
    async fn count(&mut self, filter: UpstreamOAuthLinkFilter<'_>) -> Result<usize, Self::Error> {
        let mut query = upstream_oauth_links::table.into_boxed();

        if let Some(user) = filter.user() {
            query = query.filter(upstream_oauth_links::user_id.eq(Uuid::from(user.id)));
        }

        if let Some(provider) = filter.provider() {
            query = query.filter(
                upstream_oauth_links::upstream_oauth_provider_id.eq(Uuid::from(provider.id)),
            );
        }

        if let Some(enabled) = filter.provider_enabled() {
            let subquery = if enabled {
                upstream_oauth_providers::table
                    .filter(upstream_oauth_providers::disabled_at.is_null())
                    .select(upstream_oauth_providers::id)
                    .into_boxed()
            } else {
                upstream_oauth_providers::table
                    .filter(upstream_oauth_providers::disabled_at.is_not_null())
                    .select(upstream_oauth_providers::id)
                    .into_boxed()
            };

            query = query.filter(upstream_oauth_links::upstream_oauth_provider_id.eq_any(subquery));
        }

        if let Some(subject) = filter.subject() {
            query = query.filter(upstream_oauth_links::subject.eq(subject));
        }

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.remove",
        skip_all,
        fields(
            upstream_oauth_link.id,
            upstream_oauth_link.provider_id,
            %upstream_oauth_link.subject,
        ),
        err,
    )]
    async fn remove(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_link: UpstreamOAuthLink,
    ) -> Result<(), Self::Error> {
        use crate::schema::upstream_oauth_authorization_sessions;

        // Unlink the authorization sessions first, as they have a foreign key
        // constraint on the links.
        diesel::update(
            upstream_oauth_authorization_sessions::table.filter(
                upstream_oauth_authorization_sessions::upstream_oauth_link_id
                    .eq(Uuid::from(upstream_oauth_link.id)),
            ),
        )
        .set((
            upstream_oauth_authorization_sessions::upstream_oauth_link_id.eq(None::<Uuid>),
            upstream_oauth_authorization_sessions::unlinked_at.eq(Some(clock.now())),
        ))
        .execute(self.conn)
        .await?;

        // Then delete the link itself
        let rows_affected =
            diesel::delete(upstream_oauth_links::table.find(Uuid::from(upstream_oauth_link.id)))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link.cleanup_orphaned",
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
                WITH
                  to_delete AS (
                    SELECT id
                    FROM upstream_oauth_links
                    WHERE user_id IS NULL
                    AND ($1::uuid IS NULL OR id > $1)
                    AND id <= $2
                    ORDER BY id
                    LIMIT $3
                  ),
                  deleted_sessions AS (
                    DELETE FROM upstream_oauth_authorization_sessions
                    USING to_delete
                    WHERE upstream_oauth_authorization_sessions.upstream_oauth_link_id = to_delete.id
                  )
                DELETE FROM upstream_oauth_links
                USING to_delete
                WHERE upstream_oauth_links.id = to_delete.id
                RETURNING upstream_oauth_links.id
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
