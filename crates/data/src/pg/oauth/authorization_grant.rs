use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, Clock, Pkce, Session,
    new_id, oauth::OAuthAuthorizationGrantRepository,
};
use coauth_iana::oauth::PkceCodeChallengeMethod;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use oauth_types::{requests::ResponseMode, scope::Scope};
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, schema::oauth_authorization_grants};

/// An implementation of [`OAuthAuthorizationGrantRepository`] for a PostgreSQL
/// connection
pub struct PgOAuthAuthorizationGrantRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuthAuthorizationGrantRepository<'c> {
    /// Create a new [`PgOAuthAuthorizationGrantRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_authorization_grants)]
struct GrantLookup {
    id: Uuid,
    created_at: DateTime<Utc>,
    cancelled_at: Option<DateTime<Utc>>,
    fulfilled_at: Option<DateTime<Utc>>,
    exchanged_at: Option<DateTime<Utc>>,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    redirect_uri: String,
    response_mode: String,
    response_type_code: bool,
    response_type_id_token: bool,
    authorization_code: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    login_hint: Option<String>,
    locale: Option<String>,
    oauth_client_id: Uuid,
    oauth_session_id: Option<Uuid>,
}

impl TryFrom<GrantLookup> for AuthorizationGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: GrantLookup) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let scope: Scope = value.scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth_authorization_grants")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let stage = match (
            value.fulfilled_at,
            value.exchanged_at,
            value.cancelled_at,
            value.oauth_session_id,
        ) {
            (None, None, None, None) => AuthorizationGrantStage::Pending,
            (Some(fulfilled_at), None, None, Some(session_id)) => {
                AuthorizationGrantStage::Fulfilled {
                    session_id: session_id.into(),
                    fulfilled_at,
                }
            }
            (Some(fulfilled_at), Some(exchanged_at), None, Some(session_id)) => {
                AuthorizationGrantStage::Exchanged {
                    session_id: session_id.into(),
                    fulfilled_at,
                    exchanged_at,
                }
            }
            (None, None, Some(cancelled_at), None) => {
                AuthorizationGrantStage::Cancelled { cancelled_at }
            }
            _ => {
                return Err(DatabaseInconsistencyError::on("oauth_authorization_grants")
                    .column("stage")
                    .row(id));
            }
        };

        let pkce = match (value.code_challenge, value.code_challenge_method) {
            (Some(challenge), Some(challenge_method)) if challenge_method == "plain" => {
                Some(Pkce {
                    challenge_method: PkceCodeChallengeMethod::Plain,
                    challenge,
                })
            }
            (Some(challenge), Some(challenge_method)) if challenge_method == "S256" => Some(Pkce {
                challenge_method: PkceCodeChallengeMethod::S256,
                challenge,
            }),
            (None, None) => None,
            _ => {
                return Err(DatabaseInconsistencyError::on("oauth_authorization_grants")
                    .column("code_challenge_method")
                    .row(id));
            }
        };

        let code: Option<AuthorizationCode> =
            match (value.response_type_code, value.authorization_code, pkce) {
                (false, None, None) => None,
                (true, Some(code), pkce) => Some(AuthorizationCode { code, pkce }),
                _ => {
                    return Err(DatabaseInconsistencyError::on("oauth_authorization_grants")
                        .column("authorization_code")
                        .row(id));
                }
            };

        let redirect_uri = value.redirect_uri.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth_authorization_grants")
                .column("redirect_uri")
                .row(id)
                .source(e)
        })?;

        let response_mode = value.response_mode.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth_authorization_grants")
                .column("response_mode")
                .row(id)
                .source(e)
        })?;

        Ok(AuthorizationGrant {
            id,
            stage,
            client_id: value.oauth_client_id.into(),
            code,
            scope,
            state: value.state,
            nonce: value.nonce,
            response_mode,
            redirect_uri,
            created_at: value.created_at,
            response_type_id_token: value.response_type_id_token,
            login_hint: value.login_hint,
            locale: value.locale,
        })
    }
}

/// Insertable row for creating a new authorization grant
#[derive(Insertable)]
#[diesel(table_name = oauth_authorization_grants)]
struct NewAuthorizationGrant {
    id: Uuid,
    oauth_client_id: Uuid,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    response_mode: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_type_code: bool,
    response_type_id_token: bool,
    authorization_code: Option<String>,
    login_hint: Option<String>,
    locale: Option<String>,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl OAuthAuthorizationGrantRepository for PgOAuthAuthorizationGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth_authorization_grant.add",
        skip_all,
        fields(
            grant.id,
            grant.scope = %scope,
            %client.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        redirect_uri: Url,
        scope: Scope,
        code: Option<AuthorizationCode>,
        state: Option<String>,
        nonce: Option<String>,
        response_mode: ResponseMode,
        response_type_id_token: bool,
        login_hint: Option<String>,
        locale: Option<String>,
    ) -> Result<AuthorizationGrant, Self::Error> {
        let code_challenge = code
            .as_ref()
            .and_then(|c| c.pkce.as_ref())
            .map(|p| p.challenge.clone());
        let code_challenge_method = code
            .as_ref()
            .and_then(|c| c.pkce.as_ref())
            .map(|p| p.challenge_method.to_string());
        let code_str = code.as_ref().map(|c| c.code.clone());

        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("grant.id", tracing::field::display(id));

        let new_grant = NewAuthorizationGrant {
            id: Uuid::from(id),
            oauth_client_id: Uuid::from(client.id),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            state: state.clone(),
            nonce: nonce.clone(),
            response_mode: response_mode.to_string(),
            code_challenge,
            code_challenge_method,
            response_type_code: code.is_some(),
            response_type_id_token,
            authorization_code: code_str,
            login_hint: login_hint.clone(),
            locale: locale.clone(),
            created_at,
        };

        diesel::insert_into(oauth_authorization_grants::table)
            .values(&new_grant)
            .execute(self.conn)
            .await?;

        Ok(AuthorizationGrant {
            id,
            stage: AuthorizationGrantStage::Pending,
            code,
            redirect_uri,
            client_id: client.id,
            scope,
            state,
            nonce,
            response_mode,
            created_at,
            response_type_id_token,
            login_hint,
            locale,
        })
    }

    #[tracing::instrument(
        name = "db.oauth_authorization_grant.lookup",
        skip_all,
        fields(
            grant.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<AuthorizationGrant>, Self::Error> {
        let res = oauth_authorization_grants::table
            .find(Uuid::from(id))
            .select(GrantLookup::as_select())
            .first::<GrantLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(name = "db.oauth_authorization_grant.find_by_code", skip_all, err)]
    async fn find_by_code(
        &mut self,
        code: &str,
    ) -> Result<Option<AuthorizationGrant>, Self::Error> {
        let res = oauth_authorization_grants::table
            .filter(oauth_authorization_grants::authorization_code.eq(code))
            .select(GrantLookup::as_select())
            .first::<GrantLookup>(self.conn)
            .await
            .optional()?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth_authorization_grant.fulfill",
        skip_all,
        fields(
            %grant.id,
            client.id = %grant.client_id,
            %session.id,
        ),
        err,
    )]
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        session: &Session,
        grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let rows_affected =
            diesel::update(oauth_authorization_grants::table.find(Uuid::from(grant.id)))
                .set((
                    oauth_authorization_grants::fulfilled_at.eq(Some(fulfilled_at)),
                    oauth_authorization_grants::oauth_session_id.eq(Some(Uuid::from(session.id))),
                ))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        // XXX: check affected rows & new methods
        let grant = grant
            .fulfill(fulfilled_at, session)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(grant)
    }

    #[tracing::instrument(
        name = "db.oauth_authorization_grant.exchange",
        skip_all,
        fields(
            %grant.id,
            client.id = %grant.client_id,
        ),
        err,
    )]
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error> {
        let exchanged_at = clock.now();
        let rows_affected =
            diesel::update(oauth_authorization_grants::table.find(Uuid::from(grant.id)))
                .set(oauth_authorization_grants::exchanged_at.eq(Some(exchanged_at)))
                .execute(self.conn)
                .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        let grant = grant
            .exchange(exchanged_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(grant)
    }

    #[tracing::instrument(
        name = "db.oauth_authorization_grant.cleanup",
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
                    FROM oauth_authorization_grants
                    WHERE ($1::uuid IS NULL OR id > $1)
                    AND id <= $2
                    ORDER BY id
                    LIMIT $3
                )
                DELETE FROM oauth_authorization_grants
                USING to_delete
                WHERE oauth_authorization_grants.id = to_delete.id
                RETURNING oauth_authorization_grants.id
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

/// Helper struct for loading UUID results from raw SQL queries
#[derive(QueryableByName)]
struct UuidRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}
