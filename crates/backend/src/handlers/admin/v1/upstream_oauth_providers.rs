// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use coauth_data::audit::AdminOperation;
use coauth_data::upstream_oauth::{
    UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
};
use coauth_data::{
    RepositoryAccess, UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
    UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
    UpstreamOAuthProviderResponseMode, UpstreamOAuthProviderSource,
    UpstreamOAuthProviderTokenAuthMethod,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_oauth_types::scope::Scope;
use salvo::http::StatusCode;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use url::Url;

use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::{Resource, UpstreamOAuthProvider, to_upstream_oauth_provider};
use crate::handlers::admin::params::{IncludeCount, extract_pagination, extract_ulid_param};
use crate::handlers::admin::response::{
    PaginatedOutcome, SingleOutcome, paginated_response_for_count_only, paginated_response_for_page,
};
use crate::handlers::common::DepotExt as _;
use crate::{AppError, AppResult, CreatedJsonResult, JsonResult};

/// Fetch a single upstream OAuth provider by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.get", skip_all)]
pub async fn get_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let provider_id = extract_ulid_param(req)?;

    let entry = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    Ok(Json(SingleOutcome::new_canonical(
        to_upstream_oauth_provider(entry),
    )))
}

/// Query-string filters for the provider list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UpstreamOAuthProviderFilter")]
pub struct FilterParams {
    /// When set, only return providers matching this enabled/disabled state
    #[serde(rename = "filter[enabled]")]
    enabled: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delimiter = '?';

        if let Some(flag) = self.enabled {
            write!(f, "{delimiter}filter[enabled]={flag}")?;
            delimiter = '&';
        }

        let _ = delimiter;
        Ok(())
    }
}

/// List upstream OAuth providers with optional filtering and pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.list", skip_all)]
pub async fn list_providers(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedOutcome<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = UpstreamOAuthProvider::PATH);
    let base_url = include_count.add_to_base(&base_url);
    let mut filter = UpstreamOAuthProviderFilter::new();

    // Apply the enabled/disabled constraint when requested
    filter = match params.enabled {
        Some(true) => filter.enabled_only(),
        Some(false) => filter.disabled_only(),
        None => filter,
    };

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(to_upstream_oauth_provider);
            let total = repo.upstream_oauth_provider().count(filter).await?;
            paginated_response_for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(to_upstream_oauth_provider);
            paginated_response_for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.upstream_oauth_provider().count(filter).await?;
            paginated_response_for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

/// JSON request body for creating or updating an upstream OAuth provider.
///
/// Mirrors [`UpstreamOAuthProviderParams`] but accepts the client secret in
/// plaintext (the server encrypts it before persisting) and accepts enums as
/// strings to keep the API stable across data-layer refactors.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "UpstreamOAuthProviderRequest")]
pub struct ProviderRequestBody {
    issuer: Option<String>,
    human_name: Option<String>,
    brand_name: Option<String>,
    /// Space-separated OAuth scope, e.g. "openid email profile"
    scope: String,
    /// One of: none, `client_secret_basic`, `client_secret_post`,
    /// `client_secret_jwt`, `private_key_jwt`, `sign_in_with_apple`,
    /// `qq_connect`, feishu, lark, dingtalk, wechat, wecom
    token_endpoint_auth_method: String,
    token_endpoint_signing_alg: Option<String>,
    /// JWS algorithm name, e.g. "RS256"
    id_token_signed_response_alg: String,
    #[serde(default)]
    fetch_userinfo: bool,
    userinfo_signed_response_alg: Option<String>,
    client_id: String,
    /// Plaintext client secret. Encrypted server-side before being persisted.
    client_secret: Option<String>,
    /// Claims-import configuration as JSON. See
    /// [`UpstreamOAuthProviderClaimsImports`].
    #[serde(default)]
    #[schemars(with = "serde_json::Value")]
    claims_imports: serde_json::Value,
    authorization_endpoint_override: Option<Url>,
    token_endpoint_override: Option<Url>,
    userinfo_endpoint_override: Option<Url>,
    jwks_uri_override: Option<Url>,
    /// One of: oidc, insecure, disabled
    #[serde(default = "default_discovery_mode")]
    discovery_mode: String,
    /// One of: auto, s256, disabled
    #[serde(default = "default_pkce_mode")]
    pkce_mode: String,
    /// One of: query, `form_post`
    response_mode: Option<String>,
    #[serde(default)]
    additional_authorization_parameters: Vec<(String, String)>,
    #[serde(default)]
    forward_login_hint: bool,
    #[serde(default)]
    ui_order: i32,
    /// One of: `do_nothing`, `logout_browser_only`, `logout_all`
    #[serde(default = "default_on_backchannel_logout")]
    on_backchannel_logout: String,
}

fn default_discovery_mode() -> String {
    "oidc".to_owned()
}
fn default_pkce_mode() -> String {
    "auto".to_owned()
}
fn default_on_backchannel_logout() -> String {
    "do_nothing".to_owned()
}

fn parse_request(
    body: ProviderRequestBody,
    encrypter: &coauth_keystore::Encrypter,
    source: UpstreamOAuthProviderSource,
) -> Result<UpstreamOAuthProviderParams, AppError> {
    let scope: Scope = body
        .scope
        .parse()
        .map_err(|e| AppError::bad_request(format!("scope: {e}")))?;
    let token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod = body
        .token_endpoint_auth_method
        .parse()
        .map_err(|e| AppError::bad_request(format!("token_endpoint_auth_method: {e}")))?;
    let token_endpoint_signing_alg = body
        .token_endpoint_signing_alg
        .map(|s| s.parse::<JsonWebSignatureAlg>())
        .transpose()
        .map_err(|e| AppError::bad_request(format!("token_endpoint_signing_alg: {e}")))?;
    let id_token_signed_response_alg: JsonWebSignatureAlg = body
        .id_token_signed_response_alg
        .parse()
        .map_err(|e| AppError::bad_request(format!("id_token_signed_response_alg: {e}")))?;
    let userinfo_signed_response_alg = body
        .userinfo_signed_response_alg
        .map(|s| s.parse::<JsonWebSignatureAlg>())
        .transpose()
        .map_err(|e| AppError::bad_request(format!("userinfo_signed_response_alg: {e}")))?;
    let discovery_mode: UpstreamOAuthProviderDiscoveryMode = body
        .discovery_mode
        .parse()
        .map_err(|e| AppError::bad_request(format!("discovery_mode: {e}")))?;
    let pkce_mode: UpstreamOAuthProviderPkceMode = body
        .pkce_mode
        .parse()
        .map_err(|e| AppError::bad_request(format!("pkce_mode: {e}")))?;
    let response_mode = body
        .response_mode
        .map(|s| s.parse::<UpstreamOAuthProviderResponseMode>())
        .transpose()
        .map_err(|e| AppError::bad_request(format!("response_mode: {e}")))?;
    let on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout = body
        .on_backchannel_logout
        .parse()
        .map_err(|e| AppError::bad_request(format!("on_backchannel_logout: {e}")))?;
    let claims_imports: UpstreamOAuthProviderClaimsImports = if body.claims_imports.is_null() {
        UpstreamOAuthProviderClaimsImports::default()
    } else {
        serde_json::from_value(body.claims_imports)
            .map_err(|e| AppError::bad_request(format!("claims_imports: {e}")))?
    };

    let encrypted_client_secret = body
        .client_secret
        .map(|secret| encrypter.encrypt_to_string(secret.as_bytes()))
        .transpose()
        .map_err(AppError::internal)?;

    Ok(UpstreamOAuthProviderParams {
        issuer: body.issuer,
        human_name: body.human_name,
        brand_name: body.brand_name,
        scope,
        token_endpoint_auth_method,
        token_endpoint_signing_alg,
        id_token_signed_response_alg,
        fetch_userinfo: body.fetch_userinfo,
        userinfo_signed_response_alg,
        client_id: body.client_id,
        encrypted_client_secret,
        claims_imports,
        authorization_endpoint_override: body.authorization_endpoint_override,
        token_endpoint_override: body.token_endpoint_override,
        userinfo_endpoint_override: body.userinfo_endpoint_override,
        jwks_uri_override: body.jwks_uri_override,
        discovery_mode,
        pkce_mode,
        response_mode,
        additional_authorization_parameters: body.additional_authorization_parameters,
        forward_login_hint: body.forward_login_hint,
        ui_order: body.ui_order,
        on_backchannel_logout,
        source,
    })
}

/// Create a new upstream OAuth provider. Always created with `source=manual`.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.add", skip_all)]
pub async fn add_provider(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleOutcome<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let encrypter = depot.encrypter().map_err(AppError::internal)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: ProviderRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    let params = parse_request(body, &encrypter, UpstreamOAuthProviderSource::Manual)?;

    let provider = repo
        .upstream_oauth_provider()
        .add(&mut rng, &clock, params)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({
            "action": "create",
            "source": provider.source.as_str(),
            "client_id": provider.client_id,
        }),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleOutcome::new_canonical(to_upstream_oauth_provider(provider)),
    ))
}

/// Update an existing upstream OAuth provider. Only allowed for
/// `source=manual`.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.update", skip_all)]
pub async fn update_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let encrypter = depot.encrypter().map_err(AppError::internal)?;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: ProviderRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    let existing = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    if existing.source == UpstreamOAuthProviderSource::Config {
        return Err(AppError::conflict(
            "Provider is managed by the configuration file. Edit the config file and run \
             `coauth config sync` instead.",
        ));
    }

    let params = parse_request(body, &encrypter, UpstreamOAuthProviderSource::Manual)?;

    let provider = repo
        .upstream_oauth_provider()
        .upsert(&clock, id, params)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({"action": "update"}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(
        to_upstream_oauth_provider(provider),
    )))
}

/// Delete an upstream OAuth provider.
///
/// `source=manual` rows can always be deleted. `source=config` rows can only
/// be deleted once they are also disabled — the expected workflow being:
/// remove the entry from the config file, restart the server (the next sync
/// run soft-disables the orphaned row), then call DELETE here to clean up.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.delete", skip_all)]
pub async fn delete_provider(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let provider = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    if provider.source == UpstreamOAuthProviderSource::Config && provider.enabled() {
        return Err(AppError::conflict(
            "Provider is managed by the configuration file. Remove it from the config file and \
             restart the server first; once it shows as disabled it can be deleted.",
        ));
    }

    repo.upstream_oauth_provider().delete_by_id(id).await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(id),
        serde_json::json!({"action": "delete", "source": provider.source.as_str()}),
    )
    .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Disable a provider (sets `disabled_at`). Allowed for both sources.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.disable", skip_all)]
pub async fn disable_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let provider = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    let provider = repo
        .upstream_oauth_provider()
        .disable(&clock, provider)
        .await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({"action": "disable"}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(
        to_upstream_oauth_provider(provider),
    )))
}

/// Re-enable a previously disabled provider. Allowed for both sources.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.enable", skip_all)]
pub async fn enable_provider(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UpstreamOAuthProvider>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let provider = repo
        .upstream_oauth_provider()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found("Provider not found"))?;

    let provider = repo.upstream_oauth_provider().enable(provider).await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamProviderModified,
        "upstream_oauth_provider",
        Some(provider.id),
        serde_json::json!({"action": "enable"}),
    )
    .await?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(
        to_upstream_oauth_provider(provider),
    )))
}

#[cfg(test)]
mod tests {
    use coauth_data::upstream_oauth::{
        UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
    };
    use coauth_data::{
        RepositoryAccess, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
    };
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_oauth_types::scope::{OPENID, Scope};
    use hyper::{Request, StatusCode};
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_test_provider(state: &mut TestState) -> UpstreamOAuthProvider {
        let mut repo = state.repository().await.unwrap();

        let params = UpstreamOAuthProviderParams {
            issuer: Some("https://accounts.google.com".to_owned()),
            human_name: Some("Google".to_owned()),
            brand_name: Some("google".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "google-client-id".to_owned(),
            encrypted_client_secret: Some("encrypted-secret".to_owned()),
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            scope: Scope::from_iter([OPENID]),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            ui_order: 0,
            source: coauth_data::UpstreamOAuthProviderSource::Config,
        };

        let provider = repo
            .upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, params)
            .await
            .unwrap();

        Box::new(repo).save().await.unwrap();

        provider
    }

    #[tokio::test]
    async fn test_get_provider() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        let provider = create_test_provider(&mut state).await;

        let request = Request::get(format!(
            "/_coauth/admin/upstream-oauth-providers/{}",
            provider.id
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        assert_eq!(body["data"]["type"], "upstream-oauth-provider");
        assert_eq!(body["data"]["id"], provider.id.to_string());
        assert_eq!(body["data"]["attributes"]["human_name"], "Google");

        insta::assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-provider",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "issuer": "https://accounts.google.com",
              "human_name": "Google",
              "brand_name": "google",
              "created_at": "2022-01-16T14:40:00.000Z",
              "disabled_at": null
            },
            "links": {
              "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;

        let provider_id = Ulid::nil();
        let request = Request::get(format!(
            "/_coauth/admin/upstream-oauth-providers/{provider_id}"
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    async fn create_test_providers(state: &mut TestState) {
        let mut repo = state.repository().await.unwrap();

        // Create an enabled provider
        let enabled_params = UpstreamOAuthProviderParams {
            issuer: Some("https://accounts.google.com".to_owned()),
            human_name: Some("Google".to_owned()),
            brand_name: Some("google".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "google-client-id".to_owned(),
            encrypted_client_secret: Some("encrypted-secret".to_owned()),
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            scope: Scope::from_iter([OPENID]),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            ui_order: 0,
            source: coauth_data::UpstreamOAuthProviderSource::Config,
        };

        repo.upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, enabled_params)
            .await
            .unwrap();

        // Create a disabled provider
        let disabled_params = UpstreamOAuthProviderParams {
            issuer: Some("https://appleid.apple.com".to_owned()),
            human_name: Some("Apple ID".to_owned()),
            brand_name: Some("apple".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::S256,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "apple-client-id".to_owned(),
            encrypted_client_secret: Some("encrypted-secret".to_owned()),
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            scope: Scope::from_iter([OPENID]),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            ui_order: 1,
            source: coauth_data::UpstreamOAuthProviderSource::Config,
        };

        let disabled_provider = repo
            .upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, disabled_params)
            .await
            .unwrap();

        // Disable the provider
        repo.upstream_oauth_provider()
            .disable(&state.clock, disabled_provider)
            .await
            .unwrap();

        // Create another enabled provider
        let another_enabled_params = UpstreamOAuthProviderParams {
            issuer: Some("https://login.microsoftonline.com/common/v2.0".to_owned()),
            human_name: Some("Microsoft".to_owned()),
            brand_name: Some("microsoft".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "microsoft-client-id".to_owned(),
            encrypted_client_secret: Some("encrypted-secret".to_owned()),
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            scope: Scope::from_iter([OPENID]),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            ui_order: 2,
            source: coauth_data::UpstreamOAuthProviderSource::Config,
        };

        repo.upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, another_enabled_params)
            .await
            .unwrap();

        Box::new(repo).save().await.unwrap();
    }

    #[tokio::test]
    async fn test_list_all_providers() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/_coauth/admin/upstream-oauth-providers")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        // Should return all providers
        assert_eq!(body["data"].as_array().unwrap().len(), 3);

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-providers?page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-providers?page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_enabled_true() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/_coauth/admin/upstream-oauth-providers?filter[enabled]=true")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=true&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=true&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=true&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_enabled_false() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/_coauth/admin/upstream-oauth-providers?filter[enabled]=false")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=false&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=false&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_pagination() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        create_test_providers(&mut state).await;

        // Test first page with limit of 2
        let request = Request::get("/_coauth/admin/upstream-oauth-providers?page[first]=2")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?page[first]=2",
            "first": "/_coauth/admin/upstream-oauth-providers?page[first]=2",
            "last": "/_coauth/admin/upstream-oauth-providers?page[last]=2",
            "next": "/_coauth/admin/upstream-oauth-providers?page[after]=01FSHN9AG09AVTNSQFMSR34AJC&page[first]=2"
          }
        }
        "#);

        // Extract the ID of the last item for pagination
        let last_item_id = body["data"][1]["id"].as_str().unwrap();
        let request = Request::get(format!(
            "/_coauth/admin/upstream-oauth-providers?page[first]=2&page[after]={last_item_id}",
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?page[after]=01FSHN9AG09AVTNSQFMSR34AJC&page[first]=2",
            "first": "/_coauth/admin/upstream-oauth-providers?page[first]=2",
            "last": "/_coauth/admin/upstream-oauth-providers?page[last]=2"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_invalid_filter() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;

        let request =
            Request::get("/_coauth/admin/upstream-oauth-providers?filter[enabled]=invalid")
                .bearer(&admin_token)
                .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_count_parameter() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:coauth:admin").await;
        create_test_providers(&mut state).await;

        // Test count=false
        let request = Request::get("/_coauth/admin/upstream-oauth-providers?count=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": "2022-01-16T14:40:00.000Z"
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?count=false&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-providers?count=false&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-providers?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/_coauth/admin/upstream-oauth-providers?count=only")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?count=only"
          }
        }
        "#);

        // Test count=false with filtering
        let request = Request::get(
            "/_coauth/admin/upstream-oauth-providers?count=false&filter[enabled]=true",
        )
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "issuer": "https://accounts.google.com",
                "human_name": "Google",
                "brand_name": "google",
                "created_at": "2022-01-16T14:40:00.000Z",
                "disabled_at": null
              },
              "links": {
                "self": "/_coauth/admin/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=true&count=false&page[first]=10",
            "first": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=true&count=false&page[first]=10",
            "last": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=true&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get(
            "/_coauth/admin/upstream-oauth-providers?count=only&filter[enabled]=false",
        )
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/_coauth/admin/upstream-oauth-providers?filter[enabled]=false&count=only"
          }
        }
        "#);
    }
}
