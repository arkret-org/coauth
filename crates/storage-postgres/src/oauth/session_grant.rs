use arkret_identifiers::{EventId, IdentifierError, SessionGrantId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::oauth::{NewSessionGrant, SessionGrantFilter, SessionGrantRepository};
use coauth_data::pagination::{Node, PaginationDirection};
use coauth_data::{Clock, Page, Pagination, SessionGrant, new_id};
use coauth_oauth_types::scope::{Scope, ScopeToken};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{oauth_session_grants, user_sessions};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`SessionGrantRepository`].
pub struct PgOAuthSessionGrantRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuthSessionGrantRepository<'c> {
    /// Create a repository backed by the provided PostgreSQL connection.
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

fn session_grant_id_from_bytes(value: &[u8]) -> Result<SessionGrantId, IdentifierError> {
    let token: [u8; 33] = value.try_into().map_err(|_| {
        IdentifierError::InvalidId("SessionGrantId storage token must be 33 bytes".to_owned())
    })?;
    EventId::from_token_bytes(token).map(|event_id| SessionGrantId::from_event_id(&event_id))
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_session_grants)]
struct SessionGrantLookup {
    id: Uuid,
    grant_id: Vec<u8>,
    user_session_id: Option<Uuid>,
    issuer: String,
    subject: String,
    device_id: Option<String>,
    applet_id: Option<String>,
    effective_scope: Option<Value>,
    registration_epoch: Option<String>,
    service_id: Option<String>,
    capability_grant_refs: Vec<String>,
    audience: String,
    scope_list: Vec<String>,
    grant_jwt: String,
    session_public_key: String,
    credential_class: String,
    recovery_session_id: Option<String>,
    recovery_policy_id: Option<String>,
    recovery_policy_version: Option<i64>,
    device_authorization_event_id: Option<String>,
    model_generation_ref: Option<Value>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl Node<Ulid> for SessionGrantLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<SessionGrantLookup> for SessionGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionGrantLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let grant_id = session_grant_id_from_bytes(&value.grant_id).map_err(|error| {
            DatabaseInconsistencyError::on("oauth_session_grants")
                .column("grant_id")
                .row(id)
                .source(error)
        })?;
        let scope: Result<Scope, _> = value
            .scope_list
            .iter()
            .map(|s| s.parse::<ScopeToken>())
            .collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("oauth_session_grants")
                .column("scope_list")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            grant_id,
            browser_session_id: value.user_session_id.map(Into::into),
            issuer: value.issuer,
            subject: value.subject,
            device_id: value.device_id,
            applet_id: value.applet_id,
            effective_scope: value.effective_scope,
            registration_epoch: value.registration_epoch,
            service_id: value.service_id,
            capability_grant_refs: value.capability_grant_refs,
            audience: value.audience,
            scope,
            grant_jwt: value.grant_jwt,
            session_public_key: value.session_public_key,
            credential_class: value.credential_class,
            recovery_session_id: value.recovery_session_id,
            recovery_policy_id: value.recovery_policy_id,
            recovery_policy_version: value.recovery_policy_version,
            device_authorization_event_id: value.device_authorization_event_id,
            model_generation_ref: value.model_generation_ref,
            created_at: value.created_at,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = oauth_session_grants)]
struct NewSessionGrantRow<'a> {
    id: Uuid,
    grant_id: Vec<u8>,
    user_session_id: Option<Uuid>,
    issuer: &'a str,
    subject: &'a str,
    device_id: Option<&'a str>,
    applet_id: Option<&'a str>,
    effective_scope: Option<Value>,
    registration_epoch: Option<&'a str>,
    service_id: Option<&'a str>,
    capability_grant_refs: Vec<String>,
    audience: &'a str,
    scope_list: Vec<String>,
    grant_jwt: &'a str,
    session_public_key: &'a str,
    credential_class: &'a str,
    recovery_session_id: Option<&'a str>,
    recovery_policy_id: Option<&'a str>,
    recovery_policy_version: Option<i64>,
    device_authorization_event_id: Option<&'a str>,
    model_generation_ref: Option<Value>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

macro_rules! apply_session_grant_filter {
    ($query:expr, $filter:expr) => {{
        let mut q = $query;

        if let Some(user_session_id) = $filter.browser_session_id() {
            q = q.filter(
                oauth_session_grants::user_session_id.eq(Some(Uuid::from(user_session_id))),
            );
        }

        if let Some(account_id) = $filter.account_id() {
            // Owning account is the `user_id` of the browser session the grant
            // is bound to. Push the ownership check down as a subquery on
            // `user_sessions` instead of paging the whole table and resolving
            // each owner in memory. Grants with `user_session_id IS NULL` are
            // excluded because the subquery never yields NULL.
            let owned_sessions = user_sessions::table
                .filter(user_sessions::user_id.eq(Uuid::from(account_id)))
                .select(user_sessions::id.nullable());
            q = q.filter(oauth_session_grants::user_session_id.eq_any(owned_sessions));
        }

        if let Some(subject) = $filter.subject() {
            q = q.filter(oauth_session_grants::subject.eq(subject));
        }

        if let Some(device_id) = $filter.device_id() {
            q = q.filter(oauth_session_grants::device_id.eq(device_id));
        }

        if let Some(applet_id) = $filter.applet_id() {
            q = q.filter(oauth_session_grants::applet_id.eq(applet_id));
        }

        if let Some(effective_scope) = $filter.effective_scope() {
            q = q.filter(oauth_session_grants::effective_scope.eq(effective_scope));
        }

        if let Some(registration_epoch) = $filter.registration_epoch() {
            q = q.filter(oauth_session_grants::registration_epoch.eq(registration_epoch));
        }

        if let Some(service_id) = $filter.service_id() {
            q = q.filter(oauth_session_grants::service_id.eq(service_id));
        }

        if let Some(audience) = $filter.audience() {
            q = q.filter(oauth_session_grants::audience.eq(audience));
        }

        if let Some(active_at) = $filter.active_at_value() {
            q = q
                .filter(oauth_session_grants::revoked_at.is_null())
                .filter(oauth_session_grants::expires_at.gt(active_at));
        }

        q
    }};
}

#[async_trait]
impl SessionGrantRepository for PgOAuthSessionGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.oauth_session_grant.add", skip_all, err)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        grant: NewSessionGrant<'_>,
    ) -> Result<SessionGrant, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        let scope_list: Vec<String> = grant
            .scope
            .iter()
            .map(|token| token.as_str().to_owned())
            .collect();

        let row = NewSessionGrantRow {
            id: Uuid::from(id),
            grant_id: grant.grant_id.token_bytes().to_vec(),
            user_session_id: grant.browser_session_id.map(Uuid::from),
            issuer: grant.issuer,
            subject: grant.subject,
            device_id: grant.device_id,
            applet_id: grant.applet_id,
            effective_scope: grant.effective_scope.clone(),
            registration_epoch: grant.registration_epoch,
            service_id: grant.service_id,
            capability_grant_refs: grant.capability_grant_refs.clone(),
            audience: grant.audience,
            scope_list,
            grant_jwt: grant.grant_jwt,
            session_public_key: grant.session_public_key,
            credential_class: grant.credential_class,
            recovery_session_id: grant.recovery_session_id,
            recovery_policy_id: grant.recovery_policy_id,
            recovery_policy_version: grant.recovery_policy_version,
            device_authorization_event_id: grant.device_authorization_event_id,
            model_generation_ref: grant.model_generation_ref.clone(),
            created_at,
            expires_at: grant.expires_at,
        };

        diesel::insert_into(oauth_session_grants::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(SessionGrant {
            id,
            grant_id: grant.grant_id,
            browser_session_id: grant.browser_session_id,
            issuer: grant.issuer.to_owned(),
            subject: grant.subject.to_owned(),
            device_id: grant.device_id.map(ToOwned::to_owned),
            applet_id: grant.applet_id.map(ToOwned::to_owned),
            effective_scope: grant.effective_scope,
            registration_epoch: grant.registration_epoch.map(ToOwned::to_owned),
            service_id: grant.service_id.map(ToOwned::to_owned),
            capability_grant_refs: grant.capability_grant_refs,
            audience: grant.audience.to_owned(),
            scope: grant.scope,
            grant_jwt: grant.grant_jwt.to_owned(),
            session_public_key: grant.session_public_key.to_owned(),
            credential_class: grant.credential_class.to_owned(),
            recovery_session_id: grant.recovery_session_id.map(ToOwned::to_owned),
            recovery_policy_id: grant.recovery_policy_id.map(ToOwned::to_owned),
            recovery_policy_version: grant.recovery_policy_version,
            device_authorization_event_id: grant
                .device_authorization_event_id
                .map(ToOwned::to_owned),
            model_generation_ref: grant.model_generation_ref,
            created_at,
            expires_at: grant.expires_at,
            revoked_at: None,
        })
    }

    #[tracing::instrument(name = "db.oauth_session_grant.lookup", skip_all, err)]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<SessionGrant>, Self::Error> {
        let row = oauth_session_grants::table
            .find(Uuid::from(id))
            .select(SessionGrantLookup::as_select())
            .first::<SessionGrantLookup>(self.conn)
            .await
            .optional()?;

        row.map(SessionGrant::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.lookup_by_grant_id", skip_all, err)]
    async fn lookup_by_grant_id(
        &mut self,
        grant_id: &SessionGrantId,
    ) -> Result<Option<SessionGrant>, Self::Error> {
        let row = oauth_session_grants::table
            .filter(oauth_session_grants::grant_id.eq(grant_id.token_bytes().to_vec()))
            .select(SessionGrantLookup::as_select())
            .first::<SessionGrantLookup>(self.conn)
            .await
            .optional()?;

        row.map(SessionGrant::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.lookup_by_grant_jwt", skip_all, err)]
    async fn lookup_by_grant_jwt(
        &mut self,
        grant_jwt: &str,
    ) -> Result<Option<SessionGrant>, Self::Error> {
        let row = oauth_session_grants::table
            .filter(oauth_session_grants::grant_jwt.eq(grant_jwt))
            .select(SessionGrantLookup::as_select())
            .first::<SessionGrantLookup>(self.conn)
            .await
            .optional()?;

        row.map(SessionGrant::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: SessionGrantFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<SessionGrant>, Self::Error> {
        let mut query = apply_session_grant_filter!(
            oauth_session_grants::table
                .select(SessionGrantLookup::as_select())
                .into_boxed(),
            filter
        );

        if let Some(after) = pagination.after {
            query = query.filter(oauth_session_grants::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(oauth_session_grants::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(oauth_session_grants::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(oauth_session_grants::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let edges = query.load::<SessionGrantLookup>(self.conn).await?;
        pagination
            .process(edges)
            .try_map(SessionGrant::try_from)
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.revoke", skip_all, err)]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        grant: SessionGrant,
    ) -> Result<SessionGrant, Self::Error> {
        let revoked_at = clock.now();
        let rows_affected = diesel::update(oauth_session_grants::table.find(Uuid::from(grant.id)))
            .set(oauth_session_grants::revoked_at.eq(Some(revoked_at)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        grant
            .revoke(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.revoke_if_active", skip_all, err)]
    async fn revoke_if_active(&mut self, clock: &dyn Clock, id: Ulid) -> Result<bool, Self::Error> {
        let revoked_at = clock.now();
        // Conditional consume: the `revoked_at IS NULL` predicate makes this a
        // compare-and-swap. Under READ COMMITTED the UPDATE takes a row lock,
        // so a concurrent rotation of the same parent blocks here and then
        // re-evaluates the predicate against the committed row — seeing
        // `revoked_at` already set and matching 0 rows. Exactly one winner.
        let rows_affected = diesel::update(
            oauth_session_grants::table
                .filter(oauth_session_grants::id.eq(Uuid::from(id)))
                .filter(oauth_session_grants::revoked_at.is_null()),
        )
        .set(oauth_session_grants::revoked_at.eq(Some(revoked_at)))
        .execute(self.conn)
        .await?;

        Ok(rows_affected == 1)
    }

    #[tracing::instrument(
        name = "db.oauth_session_grant.cleanup_expired",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup_expired(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let res: SessionGrantCleanupResult = diesel::sql_query(
            r"
                WITH to_delete AS (
                    SELECT id, expires_at
                    FROM oauth_session_grants
                    WHERE ($1::timestamptz IS NULL OR expires_at >= $1)
                      AND expires_at < $2
                    ORDER BY expires_at ASC
                    LIMIT $3
                    FOR UPDATE
                ),
                deleted AS (
                    DELETE FROM oauth_session_grants USING to_delete
                    WHERE oauth_session_grants.id = to_delete.id
                    RETURNING oauth_session_grants.expires_at
                )
                SELECT COUNT(*) as count, MAX(expires_at) as last_ts FROM deleted
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }
}

#[derive(Debug, diesel::QueryableByName)]
struct SessionGrantCleanupResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_ts: Option<DateTime<Utc>>,
}
