use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::oauth::{OAuthDeviceCodeGrantParams, OAuthDeviceCodeGrantRepository};
use coauth_data::{BrowserSession, Clock, DeviceCodeGrant, DeviceCodeGrantState, Session, new_id};
use coauth_oauth_types::scope::Scope;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use ipnetwork::IpNetwork;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::DatabaseError;
use crate::pg::errors::DatabaseInconsistencyError;
use crate::schema::oauth_device_code_grant;

/// An implementation of [`OAuthDeviceCodeGrantRepository`] for a PostgreSQL
/// connection
pub struct PgOAuthDeviceCodeGrantRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuthDeviceCodeGrantRepository<'c> {
    /// Create a new [`PgOAuthDeviceCodeGrantRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_device_code_grant)]
struct OAuthDeviceGrantLookup {
    id: Uuid,
    oauth_client_id: Uuid,
    scope: String,
    device_code: String,
    user_code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    fulfilled_at: Option<DateTime<Utc>>,
    rejected_at: Option<DateTime<Utc>>,
    exchanged_at: Option<DateTime<Utc>>,
    user_session_id: Option<Uuid>,
    oauth_session_id: Option<Uuid>,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
}

impl TryFrom<OAuthDeviceGrantLookup> for DeviceCodeGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(
        OAuthDeviceGrantLookup {
            id,
            oauth_client_id,
            scope,
            device_code,
            user_code,
            created_at,
            expires_at,
            fulfilled_at,
            rejected_at,
            exchanged_at,
            user_session_id,
            oauth_session_id,
            ip_address,
            user_agent,
        }: OAuthDeviceGrantLookup,
    ) -> Result<Self, Self::Error> {
        let id = Ulid::from(id);
        let client_id = Ulid::from(oauth_client_id);

        let scope: Scope = scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth_device_code_grant")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match (
            fulfilled_at,
            rejected_at,
            exchanged_at,
            user_session_id,
            oauth_session_id,
        ) {
            (None, None, None, None, None) => DeviceCodeGrantState::Pending,

            (Some(fulfilled_at), None, None, Some(user_session_id), None) => {
                DeviceCodeGrantState::Fulfilled {
                    browser_session_id: Ulid::from(user_session_id),
                    fulfilled_at,
                }
            }

            (None, Some(rejected_at), None, Some(user_session_id), None) => {
                DeviceCodeGrantState::Rejected {
                    browser_session_id: Ulid::from(user_session_id),
                    rejected_at,
                }
            }

            (
                Some(fulfilled_at),
                None,
                Some(exchanged_at),
                Some(user_session_id),
                Some(oauth_session_id),
            ) => DeviceCodeGrantState::Exchanged {
                browser_session_id: Ulid::from(user_session_id),
                session_id: Ulid::from(oauth_session_id),
                fulfilled_at,
                exchanged_at,
            },

            _ => return Err(DatabaseInconsistencyError::on("oauth_device_code_grant").row(id)),
        };

        Ok(DeviceCodeGrant {
            id,
            state,
            client_id,
            scope,
            user_code,
            device_code,
            created_at,
            expires_at,
            ip_address: ip_address.map(|ip| ip.ip()),
            user_agent,
        })
    }
}

/// Insertable row for creating a new device code grant
#[derive(Insertable)]
#[diesel(table_name = oauth_device_code_grant)]
struct NewDeviceCodeGrant {
    id: Uuid,
    oauth_client_id: Uuid,
    scope: String,
    device_code: String,
    user_code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
}

#[async_trait]
impl OAuthDeviceCodeGrantRepository for PgOAuthDeviceCodeGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.add",
        skip_all,
        fields(
            oauth_device_code.id,
            oauth_device_code.scope = %params.scope,
            oauth_client.id = %params.client.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: OAuthDeviceCodeGrantParams<'_>,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let now = clock.now();
        let id = new_id(now, rng);
        tracing::Span::current().record("oauth_device_code.id", tracing::field::display(id));

        let created_at = now;
        let expires_at = now + params.expires_in;
        let client_id = params.client.id;

        let new_grant = NewDeviceCodeGrant {
            id: Uuid::from(id),
            oauth_client_id: Uuid::from(client_id),
            scope: params.scope.to_string(),
            device_code: params.device_code.clone(),
            user_code: params.user_code.clone(),
            created_at,
            expires_at,
            ip_address: params.ip_address.map(IpNetwork::from),
            user_agent: params.user_agent.clone(),
        };

        diesel::insert_into(oauth_device_code_grant::table)
            .values(&new_grant)
            .execute(self.conn)
            .await?;

        Ok(DeviceCodeGrant {
            id,
            state: DeviceCodeGrantState::Pending,
            client_id,
            scope: params.scope,
            user_code: params.user_code,
            device_code: params.device_code,
            created_at,
            expires_at,
            ip_address: params.ip_address,
            user_agent: params.user_agent,
        })
    }

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.lookup",
        skip_all,
        fields(
            oauth_device_code.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = oauth_device_code_grant::table
            .find(Uuid::from(id))
            .select(OAuthDeviceGrantLookup::as_select())
            .first::<OAuthDeviceGrantLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.find_by_user_code",
        skip_all,
        fields(
            oauth_device_code.user_code = %user_code,
        ),
        err,
    )]
    async fn find_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = oauth_device_code_grant::table
            .filter(oauth_device_code_grant::user_code.eq(user_code))
            .select(OAuthDeviceGrantLookup::as_select())
            .first::<OAuthDeviceGrantLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.find_by_device_code",
        skip_all,
        fields(
            oauth_device_code.device_code = %device_code,
        ),
        err,
    )]
    async fn find_by_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = oauth_device_code_grant::table
            .filter(oauth_device_code_grant::device_code.eq(device_code))
            .select(OAuthDeviceGrantLookup::as_select())
            .first::<OAuthDeviceGrantLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.fulfill",
        skip_all,
        fields(
            oauth_device_code.id = %device_code_grant.id,
            oauth_client.id = %device_code_grant.client_id,
            browser_session.id = %browser_session.id,
            user.id = %browser_session.user.id,
        ),
        err,
    )]
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let device_code_grant = device_code_grant
            .fulfill(browser_session, fulfilled_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let rows_affected =
            diesel::update(oauth_device_code_grant::table.find(Uuid::from(device_code_grant.id)))
                .set((
                    oauth_device_code_grant::fulfilled_at.eq(Some(fulfilled_at)),
                    oauth_device_code_grant::user_session_id
                        .eq(Some(Uuid::from(browser_session.id))),
                ))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.reject",
        skip_all,
        fields(
            oauth_device_code.id = %device_code_grant.id,
            oauth_client.id = %device_code_grant.client_id,
            browser_session.id = %browser_session.id,
            user.id = %browser_session.user.id,
        ),
        err,
    )]
    async fn reject(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let device_code_grant = device_code_grant
            .reject(browser_session, fulfilled_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let rows_affected =
            diesel::update(oauth_device_code_grant::table.find(Uuid::from(device_code_grant.id)))
                .set((
                    oauth_device_code_grant::rejected_at.eq(Some(fulfilled_at)),
                    oauth_device_code_grant::user_session_id
                        .eq(Some(Uuid::from(browser_session.id))),
                ))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.exchange",
        skip_all,
        fields(
            oauth_device_code.id = %device_code_grant.id,
            oauth_client.id = %device_code_grant.client_id,
            oauth_session.id = %session.id,
        ),
        err,
    )]
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        session: &Session,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let exchanged_at = clock.now();
        let device_code_grant = device_code_grant
            .exchange(session, exchanged_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let rows_affected =
            diesel::update(oauth_device_code_grant::table.find(Uuid::from(device_code_grant.id)))
                .set((
                    oauth_device_code_grant::exchanged_at.eq(Some(exchanged_at)),
                    oauth_device_code_grant::oauth_session_id.eq(Some(Uuid::from(session.id))),
                ))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth_device_code_grant.cleanup",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error> {
        // `MAX(uuid)` isn't a thing in Postgres, so we can't just re-select the
        // deleted rows and do a MAX on the `id`.
        // Instead, we do the aggregation on the client side, which is a little
        // less efficient, but good enough.
        let res: Vec<Uuid> = diesel::sql_query(
            r"
                WITH to_delete AS (
                    SELECT id
                    FROM oauth_device_code_grant
                    WHERE ($1::uuid IS NULL OR id > $1)
                    AND id <= $2
                    ORDER BY id
                    LIMIT $3
                )
                DELETE FROM oauth_device_code_grant
                USING to_delete
                WHERE oauth_device_code_grant.id = to_delete.id
                RETURNING oauth_device_code_grant.id
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(since.map(Uuid::from))
        .bind::<diesel::sql_types::Uuid, _>(Uuid::from(until))
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load::<DeviceCodeGrantUuidRow>(self.conn)
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();

        let count = res.len();
        let max_id = res.into_iter().max();

        Ok((count, max_id.map(Ulid::from)))
    }
}

/// Helper struct for loading UUID results from raw SQL queries
#[derive(QueryableByName)]
struct DeviceCodeGrantUuidRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}
