use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::pagination::Node;
use coauth_data::upstream_oauth::{
    UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
    provider,
};
use coauth_data::{Clock, Page, Pagination, UpstreamOAuthProvider, new_id};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::upstream_oauth_providers;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// An implementation of [`UpstreamOAuthProviderRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthProviderRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgUpstreamOAuthProviderRepository<'c> {
    /// Create a new [`PgUpstreamOAuthProviderRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = upstream_oauth_providers)]
struct ProviderLookup {
    id: Uuid,
    oidc_issuer_uri: Option<String>,
    human_name: Option<String>,
    brand_name: Option<String>,
    scope: String,
    client_id: String,
    encrypted_client_secret: Option<String>,
    token_endpoint_signing_alg: Option<String>,
    token_endpoint_auth_method: String,
    id_token_signed_response_alg: String,
    fetch_userinfo: bool,
    userinfo_signed_response_alg: Option<String>,
    disabled_at: Option<DateTime<Utc>>,
    claims_imports: Option<serde_json::Value>,
    jwks_uri_override: Option<String>,
    authorization_endpoint_override: Option<String>,
    token_endpoint_override: Option<String>,
    userinfo_endpoint_override: Option<String>,
    discovery_mode: String,
    pkce_mode: String,
    response_mode: Option<String>,
    additional_parameters: Option<serde_json::Value>,
    forward_login_hint: bool,
    on_backchannel_logout: Option<String>,
    source: String,
    created_at: DateTime<Utc>,
}

impl Node<Ulid> for ProviderLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<ProviderLookup> for UpstreamOAuthProvider {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: ProviderLookup) -> Result<Self, Self::Error> {
        let id = value.id.into();
        let scope = value.scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("scope")
                .row(id)
                .source(e)
        })?;
        let token_endpoint_auth_method = value.token_endpoint_auth_method.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("token_endpoint_auth_method")
                .row(id)
                .source(e)
        })?;
        let token_endpoint_signing_alg = value
            .token_endpoint_signing_alg
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("token_endpoint_signing_alg")
                    .row(id)
                    .source(e)
            })?;
        let id_token_signed_response_alg =
            value.id_token_signed_response_alg.parse().map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("id_token_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_signed_response_alg = value
            .userinfo_signed_response_alg
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("userinfo_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let authorization_endpoint_override = value
            .authorization_endpoint_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("authorization_endpoint_override")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_override = value
            .token_endpoint_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("token_endpoint_override")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_endpoint_override = value
            .userinfo_endpoint_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("userinfo_endpoint_override")
                    .row(id)
                    .source(e)
            })?;

        let jwks_uri_override = value
            .jwks_uri_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("jwks_uri_override")
                    .row(id)
                    .source(e)
            })?;

        let discovery_mode = value.discovery_mode.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("discovery_mode")
                .row(id)
                .source(e)
        })?;

        let pkce_mode = value.pkce_mode.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("pkce_mode")
                .row(id)
                .source(e)
        })?;

        let response_mode = value
            .response_mode
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("response_mode")
                    .row(id)
                    .source(e)
            })?;

        let additional_authorization_parameters: Vec<(String, String)> = value
            .additional_parameters
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        let claims_imports: provider::ClaimsImports = value
            .claims_imports
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        let on_backchannel_logout = value
            .on_backchannel_logout
            .unwrap_or_else(|| "do_nothing".to_owned())
            .parse()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("on_backchannel_logout")
                    .row(id)
                    .source(e)
            })?;

        let source = value.source.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("source")
                .row(id)
                .source(e)
        })?;

        Ok(UpstreamOAuthProvider {
            id,
            oidc_issuer_uri: value.oidc_issuer_uri,
            human_name: value.human_name,
            brand_name: value.brand_name,
            scope,
            client_id: value.client_id,
            encrypted_client_secret: value.encrypted_client_secret,
            token_endpoint_auth_method,
            token_endpoint_signing_alg,
            id_token_signed_response_alg,
            fetch_userinfo: value.fetch_userinfo,
            userinfo_signed_response_alg,
            created_at: value.created_at,
            disabled_at: value.disabled_at,
            claims_imports,
            authorization_endpoint_override,
            token_endpoint_override,
            userinfo_endpoint_override,
            jwks_uri_override,
            discovery_mode,
            pkce_mode,
            response_mode,
            additional_authorization_parameters,
            forward_login_hint: value.forward_login_hint,
            on_backchannel_logout,
            source,
        })
    }
}

/// Insertable row for creating a new upstream OAuth provider
#[derive(Insertable)]
#[diesel(table_name = upstream_oauth_providers)]
struct NewProvider {
    id: Uuid,
    oidc_issuer_uri: Option<String>,
    human_name: Option<String>,
    brand_name: Option<String>,
    scope: String,
    client_id: String,
    encrypted_client_secret: Option<String>,
    token_endpoint_signing_alg: Option<String>,
    token_endpoint_auth_method: String,
    id_token_signed_response_alg: String,
    fetch_userinfo: bool,
    userinfo_signed_response_alg: Option<String>,
    claims_imports: Option<serde_json::Value>,
    jwks_uri_override: Option<String>,
    authorization_endpoint_override: Option<String>,
    token_endpoint_override: Option<String>,
    userinfo_endpoint_override: Option<String>,
    discovery_mode: String,
    pkce_mode: String,
    response_mode: Option<String>,
    additional_parameters: Option<serde_json::Value>,
    forward_login_hint: bool,
    ui_order: i32,
    on_backchannel_logout: Option<String>,
    source: String,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl UpstreamOAuthProviderRepository for PgUpstreamOAuthProviderRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.lookup",
        skip_all,
        fields(
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error> {
        let res = upstream_oauth_providers::table
            .find(Uuid::from(id))
            .select(ProviderLookup::as_select())
            .first::<ProviderLookup>(self.conn)
            .await
            .optional()?;

        let res = res
            .map(UpstreamOAuthProvider::try_from)
            .transpose()
            .map_err(DatabaseError::from)?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.add",
        skip_all,
        fields(
            upstream_oauth_provider.id,
            upstream_oauth_provider.oidc_issuer_uri = params.oidc_issuer_uri,
            upstream_oauth_provider.client_id = %params.client_id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: UpstreamOAuthProviderParams,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("upstream_oauth_provider.id", tracing::field::display(id));

        let new_provider = NewProvider {
            id: Uuid::from(id),
            oidc_issuer_uri: params.oidc_issuer_uri.clone(),
            human_name: params.human_name.clone(),
            brand_name: params.brand_name.clone(),
            scope: params.scope.to_string(),
            client_id: params.client_id.clone(),
            encrypted_client_secret: params.encrypted_client_secret.clone(),
            token_endpoint_signing_alg: params
                .token_endpoint_signing_alg
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_auth_method: params.token_endpoint_auth_method.to_string(),
            id_token_signed_response_alg: params.id_token_signed_response_alg.to_string(),
            fetch_userinfo: params.fetch_userinfo,
            userinfo_signed_response_alg: params
                .userinfo_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            claims_imports: serde_json::to_value(&params.claims_imports).ok(),
            jwks_uri_override: params.jwks_uri_override.as_ref().map(ToString::to_string),
            authorization_endpoint_override: params
                .authorization_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_override: params
                .token_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            userinfo_endpoint_override: params
                .userinfo_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            discovery_mode: params.discovery_mode.as_str().to_owned(),
            pkce_mode: params.pkce_mode.as_str().to_owned(),
            response_mode: params.response_mode.as_ref().map(ToString::to_string),
            additional_parameters: None,
            forward_login_hint: params.forward_login_hint,
            ui_order: 0,
            on_backchannel_logout: Some(params.on_backchannel_logout.as_str().to_owned()),
            created_at,
            source: params.source.as_str().to_owned(),
        };

        diesel::insert_into(upstream_oauth_providers::table)
            .values(&new_provider)
            .execute(self.conn)
            .await?;

        Ok(UpstreamOAuthProvider {
            id,
            oidc_issuer_uri: params.oidc_issuer_uri,
            human_name: params.human_name,
            brand_name: params.brand_name,
            scope: params.scope,
            client_id: params.client_id,
            encrypted_client_secret: params.encrypted_client_secret,
            token_endpoint_signing_alg: params.token_endpoint_signing_alg,
            token_endpoint_auth_method: params.token_endpoint_auth_method,
            id_token_signed_response_alg: params.id_token_signed_response_alg,
            fetch_userinfo: params.fetch_userinfo,
            userinfo_signed_response_alg: params.userinfo_signed_response_alg,
            created_at,
            disabled_at: None,
            claims_imports: params.claims_imports,
            authorization_endpoint_override: params.authorization_endpoint_override,
            token_endpoint_override: params.token_endpoint_override,
            userinfo_endpoint_override: params.userinfo_endpoint_override,
            jwks_uri_override: params.jwks_uri_override,
            discovery_mode: params.discovery_mode,
            pkce_mode: params.pkce_mode,
            response_mode: params.response_mode,
            additional_authorization_parameters: params.additional_authorization_parameters,
            forward_login_hint: params.forward_login_hint,
            on_backchannel_logout: params.on_backchannel_logout,
            source: params.source,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.delete_by_id",
        skip_all,
        fields(
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error> {
        use crate::schema::{upstream_oauth_authorization_sessions, upstream_oauth_links};

        // Delete the authorization sessions first, as they have a foreign key
        // constraint on the links and the providers.
        diesel::delete(upstream_oauth_authorization_sessions::table.filter(
            upstream_oauth_authorization_sessions::upstream_oauth_provider_id.eq(Uuid::from(id)),
        ))
        .execute(self.conn)
        .await?;

        // Delete the links next, as they have a foreign key constraint on the
        // providers.
        diesel::delete(
            upstream_oauth_links::table
                .filter(upstream_oauth_links::upstream_oauth_provider_id.eq(Uuid::from(id))),
        )
        .execute(self.conn)
        .await?;

        let rows_affected = diesel::delete(upstream_oauth_providers::table.find(Uuid::from(id)))
            .execute(self.conn)
            .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.upsert",
        skip_all,
        fields(
            upstream_oauth_provider.id = %id,
            upstream_oauth_provider.oidc_issuer_uri = params.oidc_issuer_uri,
            upstream_oauth_provider.client_id = %params.client_id,
        ),
        err,
    )]
    async fn upsert(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        params: UpstreamOAuthProviderParams,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let created_at = clock.now();

        let new_provider = NewProvider {
            id: Uuid::from(id),
            oidc_issuer_uri: params.oidc_issuer_uri.clone(),
            human_name: params.human_name.clone(),
            brand_name: params.brand_name.clone(),
            scope: params.scope.to_string(),
            client_id: params.client_id.clone(),
            encrypted_client_secret: params.encrypted_client_secret.clone(),
            token_endpoint_signing_alg: params
                .token_endpoint_signing_alg
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_auth_method: params.token_endpoint_auth_method.to_string(),
            id_token_signed_response_alg: params.id_token_signed_response_alg.to_string(),
            fetch_userinfo: params.fetch_userinfo,
            userinfo_signed_response_alg: params
                .userinfo_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            claims_imports: serde_json::to_value(&params.claims_imports).ok(),
            jwks_uri_override: params.jwks_uri_override.as_ref().map(ToString::to_string),
            authorization_endpoint_override: params
                .authorization_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_override: params
                .token_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            userinfo_endpoint_override: params
                .userinfo_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            discovery_mode: params.discovery_mode.as_str().to_owned(),
            pkce_mode: params.pkce_mode.as_str().to_owned(),
            response_mode: params.response_mode.as_ref().map(ToString::to_string),
            additional_parameters: serde_json::to_value(
                &params.additional_authorization_parameters,
            )
            .ok(),
            forward_login_hint: params.forward_login_hint,
            ui_order: params.ui_order,
            on_backchannel_logout: Some(params.on_backchannel_logout.as_str().to_owned()),
            created_at,
            source: params.source.as_str().to_owned(),
        };

        let created_at: DateTime<Utc> = diesel::insert_into(upstream_oauth_providers::table)
            .values(&new_provider)
            .on_conflict(upstream_oauth_providers::id)
            .do_update()
            .set((
                upstream_oauth_providers::oidc_issuer_uri.eq(params.oidc_issuer_uri.as_deref()),
                upstream_oauth_providers::human_name.eq(params.human_name.as_deref()),
                upstream_oauth_providers::brand_name.eq(params.brand_name.as_deref()),
                upstream_oauth_providers::scope.eq(params.scope.to_string()),
                upstream_oauth_providers::token_endpoint_auth_method
                    .eq(params.token_endpoint_auth_method.to_string()),
                upstream_oauth_providers::token_endpoint_signing_alg.eq(params
                    .token_endpoint_signing_alg
                    .as_ref()
                    .map(ToString::to_string)),
                upstream_oauth_providers::id_token_signed_response_alg
                    .eq(params.id_token_signed_response_alg.to_string()),
                upstream_oauth_providers::fetch_userinfo.eq(params.fetch_userinfo),
                upstream_oauth_providers::userinfo_signed_response_alg.eq(params
                    .userinfo_signed_response_alg
                    .as_ref()
                    .map(ToString::to_string)),
                // NOTE: do not touch `disabled_at` here. Admin-driven disables
                // must survive subsequent `config_sync` runs (see sync.rs and
                // the source-aware admin endpoints).
                upstream_oauth_providers::client_id.eq(&params.client_id),
                upstream_oauth_providers::encrypted_client_secret
                    .eq(params.encrypted_client_secret.as_deref()),
                upstream_oauth_providers::claims_imports
                    .eq(serde_json::to_value(&params.claims_imports).ok()),
                upstream_oauth_providers::authorization_endpoint_override.eq(params
                    .authorization_endpoint_override
                    .as_ref()
                    .map(ToString::to_string)),
                upstream_oauth_providers::token_endpoint_override.eq(params
                    .token_endpoint_override
                    .as_ref()
                    .map(ToString::to_string)),
                upstream_oauth_providers::userinfo_endpoint_override.eq(params
                    .userinfo_endpoint_override
                    .as_ref()
                    .map(ToString::to_string)),
                upstream_oauth_providers::jwks_uri_override
                    .eq(params.jwks_uri_override.as_ref().map(ToString::to_string)),
                upstream_oauth_providers::discovery_mode.eq(params.discovery_mode.as_str()),
                upstream_oauth_providers::pkce_mode.eq(params.pkce_mode.as_str()),
                upstream_oauth_providers::response_mode
                    .eq(params.response_mode.as_ref().map(ToString::to_string)),
                upstream_oauth_providers::additional_parameters
                    .eq(serde_json::to_value(&params.additional_authorization_parameters).ok()),
                upstream_oauth_providers::forward_login_hint.eq(params.forward_login_hint),
                upstream_oauth_providers::ui_order.eq(params.ui_order),
                upstream_oauth_providers::on_backchannel_logout
                    .eq(Some(params.on_backchannel_logout.as_str())),
                upstream_oauth_providers::source.eq(params.source.as_str()),
            ))
            .returning(upstream_oauth_providers::created_at)
            .get_result(self.conn)
            .await?;

        Ok(UpstreamOAuthProvider {
            id,
            oidc_issuer_uri: params.oidc_issuer_uri,
            human_name: params.human_name,
            brand_name: params.brand_name,
            scope: params.scope,
            client_id: params.client_id,
            encrypted_client_secret: params.encrypted_client_secret,
            token_endpoint_signing_alg: params.token_endpoint_signing_alg,
            token_endpoint_auth_method: params.token_endpoint_auth_method,
            id_token_signed_response_alg: params.id_token_signed_response_alg,
            fetch_userinfo: params.fetch_userinfo,
            userinfo_signed_response_alg: params.userinfo_signed_response_alg,
            created_at,
            disabled_at: None,
            claims_imports: params.claims_imports,
            authorization_endpoint_override: params.authorization_endpoint_override,
            token_endpoint_override: params.token_endpoint_override,
            userinfo_endpoint_override: params.userinfo_endpoint_override,
            jwks_uri_override: params.jwks_uri_override,
            discovery_mode: params.discovery_mode,
            pkce_mode: params.pkce_mode,
            response_mode: params.response_mode,
            additional_authorization_parameters: params.additional_authorization_parameters,
            forward_login_hint: params.forward_login_hint,
            on_backchannel_logout: params.on_backchannel_logout,
            source: params.source,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.disable",
        skip_all,
        fields(
            %upstream_oauth_provider.id,
        ),
        err,
    )]
    async fn disable(
        &mut self,
        clock: &dyn Clock,
        mut upstream_oauth_provider: UpstreamOAuthProvider,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let disabled_at = clock.now();
        let rows_affected = diesel::update(
            upstream_oauth_providers::table.find(Uuid::from(upstream_oauth_provider.id)),
        )
        .set(upstream_oauth_providers::disabled_at.eq(Some(disabled_at)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        upstream_oauth_provider.disabled_at = Some(disabled_at);

        Ok(upstream_oauth_provider)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.enable",
        skip_all,
        fields(
            %upstream_oauth_provider.id,
        ),
        err,
    )]
    async fn enable(
        &mut self,
        mut upstream_oauth_provider: UpstreamOAuthProvider,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let rows_affected = diesel::update(
            upstream_oauth_providers::table.find(Uuid::from(upstream_oauth_provider.id)),
        )
        .set(upstream_oauth_providers::disabled_at.eq(None::<DateTime<Utc>>))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        upstream_oauth_provider.disabled_at = None;

        Ok(upstream_oauth_provider)
    }

    #[tracing::instrument(name = "db.upstream_oauth_provider.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error> {
        let mut query = upstream_oauth_providers::table
            .select(ProviderLookup::as_select())
            .into_boxed();

        // Apply filters
        if let Some(enabled) = filter.enabled() {
            if enabled {
                query = query.filter(upstream_oauth_providers::disabled_at.is_null());
            } else {
                query = query.filter(upstream_oauth_providers::disabled_at.is_not_null());
            }
        }
        if let Some(source) = filter.source() {
            query = query.filter(upstream_oauth_providers::source.eq(source.as_str()));
        }

        query = crate::paginate_by_id!(query, pagination, upstream_oauth_providers::id);

        let edges: Vec<ProviderLookup> = query.load(self.conn).await?;

        let page = pagination
            .process(edges)
            .try_map(UpstreamOAuthProvider::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(name = "db.upstream_oauth_provider.count", skip_all, err)]
    async fn count(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let mut query = upstream_oauth_providers::table.into_boxed();

        if let Some(enabled) = filter.enabled() {
            if enabled {
                query = query.filter(upstream_oauth_providers::disabled_at.is_null());
            } else {
                query = query.filter(upstream_oauth_providers::disabled_at.is_not_null());
            }
        }
        if let Some(source) = filter.source() {
            query = query.filter(upstream_oauth_providers::source.eq(source.as_str()));
        }

        let count: i64 = query.count().get_result(self.conn).await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.upstream_oauth_provider.all_enabled", skip_all, err)]
    async fn all_enabled(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error> {
        let res: Vec<ProviderLookup> = upstream_oauth_providers::table
            .filter(upstream_oauth_providers::disabled_at.is_null())
            .order((
                upstream_oauth_providers::ui_order.asc(),
                upstream_oauth_providers::id.asc(),
            ))
            .select(ProviderLookup::as_select())
            .load(self.conn)
            .await?;

        let res: Result<Vec<_>, _> = res.into_iter().map(TryInto::try_into).collect();
        Ok(res?)
    }
}
