//! OIDC browser-bridge and exchange surfaces for the account API.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use coauth_data::{RepositoryAccess, UpstreamOAuthProviderDiscoveryMode};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use http::header::ACCEPT;
use mime::APPLICATION_JSON;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{
        AccessTokenRequest, AccessTokenResponse,
        AuthorizationCodeGrant as OAuthAuthorizationCodeGrant,
    },
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use ulid::Ulid;

use super::{
    DepotExt, LoginResponse, NodeType, RouteError, SessionGrantInfo, SessionGrantKind,
    SessionGrantPrincipalServerInfo, ViewerInfo, make_clock, make_rng,
};
use crate::{
    handlers::contrix, oidc_client::requests::discovery,
    oidc_client::types::client_credentials::ClientCredentials,
    services::upstream_oidc::UpstreamOidcExchangeMode,
};

#[derive(Deserialize, ToSchema)]
pub struct OidcCodeExchangeRequest {
    pub authorization_code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub issuer: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub login_hint: String,
    pub device_id: String,
    #[serde(default)]
    pub principal_audience: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub expected_state: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct OidcBrowserBridgeSessionRequest {
    pub redirect_uri: String,
    pub login_hint: String,
    pub device_id: String,
    #[serde(default)]
    pub principal_audience: Option<String>,
    #[serde(default)]
    pub client_id_hint: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AuthBridgeDescribeResponse {
    pub contract: &'static str,
    pub version: &'static str,
    pub api_base_path: &'static str,
    pub oauth: AuthBridgeOAuthDescriptor,
    pub contrix: AuthBridgeContrixDescriptor,
    pub admin: AuthBridgeAdminDescriptor,
    pub todos: Vec<&'static str>,
}

#[derive(Serialize, ToSchema)]
pub struct AuthBridgeOAuthDescriptor {
    pub discovery_path: &'static str,
    pub browser_bridge_session_path: &'static str,
    pub exchange_describe_path: &'static str,
    pub exchange_path: &'static str,
    pub supported_flows: Vec<&'static str>,
    pub redirect_uri_modes: Vec<&'static str>,
    pub client_selection_mode: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct AuthBridgeContrixDescriptor {
    pub login_path: &'static str,
    pub logout_path: &'static str,
    pub providers_path: &'static str,
    pub session_grants_path: &'static str,
    pub session_grants_introspect_path: &'static str,
    pub session_grant_scope: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct AuthBridgeAdminDescriptor {
    pub accounts_path: &'static str,
    pub account_detail_path_template: &'static str,
    pub account_dids_path_template: &'static str,
    pub risk_action_path_template: &'static str,
    pub risk_action_current_path_template: &'static str,
    pub risk_action_history_path_template: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationManifestResponse {
    pub contract: &'static str,
    pub version: &'static str,
    pub service: &'static str,
    pub service_kind: &'static str,
    pub api_base_path: &'static str,
    pub describe_path: &'static str,
    pub dependencies: Vec<IntegrationManifestDependency>,
    pub surfaces: Vec<IntegrationManifestSurface>,
    pub examples: serde_json::Value,
    pub todos: Vec<&'static str>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationManifestDependency {
    pub service: &'static str,
    pub purpose: &'static str,
    pub required_contract: &'static str,
    pub discovery_path: &'static str,
    pub mode: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationManifestSurface {
    pub name: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub contract: &'static str,
    pub stability: &'static str,
    pub todo: &'static str,
}
#[derive(Serialize, ToSchema)]
pub struct OidcBrowserBridgeSessionResponse {
    pub contract: &'static str,
    pub version: &'static str,
    pub authorize_url: String,
    pub callback_uri: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub code_challenge_method: &'static str,
    pub principal_audience: String,
    pub todo: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct OidcExchangeDescribeResponse {
    pub contract: &'static str,
    pub version: &'static str,
    pub exchange_path: &'static str,
    pub upstream_boundary_mode: &'static str,
    pub upstream_modes_supported: Vec<&'static str>,
    pub required_fields: Vec<&'static str>,
    pub validation_layers: Vec<&'static str>,
    pub failure_codes: Vec<&'static str>,
    pub example_request: serde_json::Value,
    pub todos: Vec<&'static str>,
}

fn pkce_s256_challenge(code_verifier: &str) -> String {
    Base64UrlUnpadded::encode_string(&Sha256::digest(code_verifier.as_bytes()))
}

fn login_hint_matches_user(
    url_builder: &coauth_data::UrlBuilder,
    contrix_config: &coauth_config::ContrixConfig,
    user: &coauth_data::User,
    login_hint: &str,
) -> bool {
    let login_hint = login_hint.trim();
    login_hint == user.username
        || login_hint == contrix::user_did_for(url_builder, contrix_config, user)
        || login_hint == contrix::user_handle(url_builder, user)
}

/// OIDC authorization-code exchange bridge that now validates the incoming
/// authorization code against coauth's local OAuth2 authorization-grant store
/// before minting a temporary audience-bound Contrix session grant.
#[endpoint]
pub async fn oidc_code_exchange(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let mut rng = make_rng();
    let clock = make_clock();
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let encrypter = depot.encrypter()?;
    let upstream_oidc = depot.upstream_oidc_service()?;
    let homeserver = depot.homeserver()?;
    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .cloned()
        .map_err(|_| {
            RouteError::Internal(Box::new(std::io::Error::other(
                "http_client not found in depot",
            )))
        })?;
    let service_activity_tracker = depot
        .get::<crate::handlers::ActivityTracker>("activity_tracker")
        .cloned()
        .map_err(|_| {
            RouteError::Internal(Box::new(std::io::Error::other(
                "activity_tracker not found in depot",
            )))
        })?;
    let mut repo = depot.repo().await?;

    let input: OidcCodeExchangeRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    if input.code_verifier.trim().is_empty() {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("pkce_required"),
            viewer: None,
            session_grant: None,
            warnings: vec![
                "code_verifier is required and the authorization_code must have been issued with PKCE"
                    .to_owned(),
            ],
        }));
        return Ok(());
    }

    if input.authorization_code.trim().is_empty()
        || input.redirect_uri.trim().is_empty()
        || input.issuer.trim().is_empty()
        || input.token_endpoint.trim().is_empty()
        || input.userinfo_endpoint.trim().is_empty()
        || input.client_id.trim().is_empty()
        || input.login_hint.trim().is_empty()
        || input.device_id.trim().is_empty()
    {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_request"),
            viewer: None,
            session_grant: None,
            warnings: vec![
                "authorization_code, redirect_uri, issuer, token_endpoint, userinfo_endpoint, client_id, login_hint, and device_id are required"
                    .to_owned(),
            ],
        }));
        return Ok(());
    }

    let redirect_uri = match url::Url::parse(input.redirect_uri.trim()) {
        Ok(uri) => uri,
        Err(_) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_redirect_uri"),
                viewer: None,
                session_grant: None,
                warnings: vec!["redirect_uri must be a valid absolute URI".to_owned()],
            }));
            return Ok(());
        }
    };
    let issuer = match url::Url::parse(input.issuer.trim()) {
        Ok(uri) => uri,
        Err(_) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_issuer"),
                viewer: None,
                session_grant: None,
                warnings: vec!["issuer must be a valid absolute URI".to_owned()],
            }));
            return Ok(());
        }
    };
    let token_endpoint = match url::Url::parse(input.token_endpoint.trim()) {
        Ok(uri) => uri,
        Err(_) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_token_endpoint"),
                viewer: None,
                session_grant: None,
                warnings: vec!["token_endpoint must be a valid absolute URI".to_owned()],
            }));
            return Ok(());
        }
    };
    let userinfo_endpoint = match url::Url::parse(input.userinfo_endpoint.trim()) {
        Ok(uri) => uri,
        Err(_) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_userinfo_endpoint"),
                viewer: None,
                session_grant: None,
                warnings: vec!["userinfo_endpoint must be a valid absolute URI".to_owned()],
            }));
            return Ok(());
        }
    };
    let expected_issuer = url_builder.oidc_issuer();

    let enabled_upstream_providers = repo.upstream_oauth_provider().all_enabled().await?;
    let exchange_mode = match upstream_oidc.exchange_mode_for_issuer(
        &url_builder,
        &enabled_upstream_providers,
        &issuer,
        input.client_id.trim(),
    ) {
        Ok(mode) => mode,
        Err(message) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_issuer"),
                viewer: None,
                session_grant: None,
                warnings: vec![message],
            }));
            return Ok(());
        }
    };

    if matches!(exchange_mode, UpstreamOidcExchangeMode::LocalCoauth) {
        if issuer.scheme() != token_endpoint.scheme()
            || issuer.domain() != token_endpoint.domain()
            || issuer.port_or_known_default() != token_endpoint.port_or_known_default()
        {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_discovery_binding"),
                viewer: None,
                session_grant: None,
                warnings: vec![
                    "local issuer and token_endpoint must resolve to the same origin for local OIDC exchange"
                        .to_owned(),
                ],
            }));
            return Ok(());
        }
        if issuer.scheme() != userinfo_endpoint.scheme()
            || issuer.domain() != userinfo_endpoint.domain()
            || issuer.port_or_known_default() != userinfo_endpoint.port_or_known_default()
        {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_discovery_binding"),
                viewer: None,
                session_grant: None,
                warnings: vec![
                    "local issuer and userinfo_endpoint must resolve to the same origin for local OIDC exchange"
                        .to_owned(),
                ],
            }));
            return Ok(());
        }
    }

    let discovery_result = match &exchange_mode {
        UpstreamOidcExchangeMode::LocalCoauth => {
            if issuer.scheme() == "https" {
                discovery::discover(&http_client, issuer.as_str()).await
            } else {
                discovery::insecure_discover(&http_client, issuer.as_str()).await
            }
        }
        UpstreamOidcExchangeMode::Federated { provider } => match provider.discovery_mode {
            UpstreamOAuthProviderDiscoveryMode::Oidc => {
                discovery::discover(&http_client, issuer.as_str()).await
            }
            UpstreamOAuthProviderDiscoveryMode::Insecure => {
                discovery::insecure_discover(&http_client, issuer.as_str()).await
            }
            UpstreamOAuthProviderDiscoveryMode::Disabled => {
                res.render(Json(LoginResponse {
                    status: "error",
                    error: Some("invalid_discovery_binding"),
                    viewer: None,
                    session_grant: None,
                    warnings: vec![
                        "federated OIDC exchange requires discovery-enabled upstream provider metadata"
                            .to_owned(),
                    ],
                }));
                return Ok(());
            }
        },
    };
    let discovered_metadata = match discovery_result {
        Ok(metadata) => metadata,
        Err(error) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_discovery_binding"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "OIDC exchange could not fetch live discovery metadata for issuer={issuer}: {error}"
                )],
            }));
            return Ok(());
        }
    };
    if let Err(message) = upstream_oidc.validate_exchange_endpoints(
        &url_builder,
        &exchange_mode,
        &discovered_metadata,
        &token_endpoint,
        &userinfo_endpoint,
    ) {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_discovery_binding"),
            viewer: None,
            session_grant: None,
            warnings: vec![message],
        }));
        return Ok(());
    }

    if let Some(expected_state) = input.expected_state.as_deref() {
        let returned_state = input.state.as_deref().unwrap_or_default();
        if returned_state.is_empty() {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_state"),
                viewer: None,
                session_grant: None,
                warnings: vec![
                    "callback state is required when expected_state is supplied".to_owned(),
                ],
            }));
            return Ok(());
        }
        if returned_state != expected_state {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_state"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "callback state mismatch: expected {expected_state} but received {returned_state}"
                )],
            }));
            return Ok(());
        }
    }

    if let UpstreamOidcExchangeMode::Federated { provider } = exchange_mode {
        let jwks_uri = provider
            .jwks_uri_override
            .clone()
            .unwrap_or_else(|| discovered_metadata.jwks_uri().clone());
        let federated_exchange = match upstream_oidc
            .exchange_federated_authorization_code(
                &http_client,
                &key_store,
                &encrypter,
                &provider,
                &issuer,
                &token_endpoint,
                &userinfo_endpoint,
                &jwks_uri,
                input.authorization_code.trim(),
                redirect_uri.clone(),
                input.code_verifier.trim(),
                clock.now(),
                &mut rng,
            )
            .await
        {
            Ok(exchange) => exchange,
            Err(error) => {
                res.render(Json(LoginResponse {
                    status: "error",
                    error: Some("invalid_authorization_code"),
                    viewer: None,
                    session_grant: None,
                    warnings: vec![format!("federated upstream OIDC exchange failed: {error}")],
                }));
                return Ok(());
            }
        };
        let upstream_subject = federated_exchange.userinfo.sub.clone();
        let Some(upstream_link) = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, upstream_subject.as_str())
            .await?
        else {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("upstream_link_required"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "federated upstream subject={} is not linked to a local account for provider={}",
                    upstream_subject,
                    provider
                        .human_name
                        .as_deref()
                        .unwrap_or(provider.client_id.as_str())
                )],
            }));
            return Ok(());
        };
        let Some(user_id) = upstream_link.user_id else {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("upstream_link_required"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "federated upstream subject={} has an unassociated upstream link; complete account linking before oidc/exchange",
                    upstream_subject
                )],
            }));
            return Ok(());
        };
        let Some(user) = repo.user().lookup(user_id).await? else {
            return Err(RouteError::Internal(Box::new(std::io::Error::other(
                format!(
                    "federated upstream link={} points to missing user={user_id}",
                    upstream_link.id
                ),
            ))));
        };
        if !user.is_valid() {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("account_unavailable"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "linked local account username={} is locked or deactivated",
                    user.username
                )],
            }));
            return Ok(());
        }
        if !login_hint_matches_user(
            &url_builder,
            &contrix_config,
            &user,
            input.login_hint.trim(),
        ) {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_login_hint"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "login_hint={} does not match linked local account username={}",
                    input.login_hint.trim(),
                    user.username
                )],
            }));
            return Ok(());
        }

        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &*clock, &user, user_agent)
            .await?;
        let device_id = input.device_id.trim().to_owned();
        let grant_target = match upstream_oidc.session_grant_target_for_requested_audience(
            &url_builder,
            &contrix_config,
            input.principal_audience.as_deref(),
        ) {
            Ok(target) => target,
            Err(message) => {
                res.render(Json(LoginResponse {
                    status: "error",
                    error: Some("invalid_audience"),
                    viewer: None,
                    session_grant: None,
                    warnings: vec![message],
                }));
                return Ok(());
            }
        };
        let session_grant = contrix::issue_session_grant_for_audience(
            &mut rng,
            &*clock,
            &url_builder,
            &contrix_config,
            &key_store,
            &browser_session,
            grant_target.audience.clone(),
            vec![contrix::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
        )
        .map_err(|error| RouteError::Internal(Box::new(error)))?;

        let persisted_session_grant = contrix::persist_session_grant(
            &mut repo,
            &mut rng,
            &*clock,
            &browser_session,
            &session_grant,
        )
        .await?;
        repo.save().await?;

        let display_name = match homeserver.query_user(&user.username).await {
            Ok(info) => info.displayname,
            Err(_) => None,
        };

        res.render(Json(LoginResponse {
            status: "success",
            error: None,
            viewer: Some(ViewerInfo {
                id: NodeType::User.serialize(user.id),
                username: user.username.clone(),
                did: contrix::user_did_for(&url_builder, &contrix_config, &user),
                handle: contrix::user_handle(&url_builder, &user),
                mxid: homeserver.mxid(&user.username),
                display_name,
            }),
            session_grant: Some(SessionGrantInfo {
                kind: SessionGrantKind::PrincipalSession,
                id: persisted_session_grant.id.to_string(),
                grant_jwt: session_grant.grant_jwt,
                session_public_key: session_grant.session_public_key,
                session_private_key_pem: session_grant.session_private_key_pem,
                expires_at: session_grant.expires_at,
                audience: session_grant.audience,
                scopes: session_grant.scopes,
                principal_server: grant_target
                    .principal_server_name
                    .zip(grant_target.principal_server_endpoint)
                    .map(|(name, endpoint)| SessionGrantPrincipalServerInfo { name, endpoint }),
            }),
            warnings: vec![
                "oidc_exchange_mode=federated".to_owned(),
                format!("device_id={device_id}"),
                format!("redirect_uri={}", redirect_uri),
                format!("issuer={issuer}"),
                format!("token_endpoint={token_endpoint}"),
                format!("userinfo_endpoint={userinfo_endpoint}"),
                format!("client_id={}", provider.client_id),
                format!("upstream_provider_id={}", provider.id),
                format!("upstream_link_id={}", upstream_link.id),
                format!("upstream_subject={upstream_subject}"),
                format!("browser_session_id={}", browser_session.id),
                format!(
                    "upstream_oauth_scope={}",
                    federated_exchange
                        .token_response
                        .scope
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "missing".to_owned())
                ),
                "authorization_code_exchanged_via_federated_token_endpoint=true".to_owned(),
                "oauth_access_token_validated_via_federated_userinfo=true".to_owned(),
                format!(
                    "oauth_userinfo_response_signed={}",
                    federated_exchange.userinfo_response_signed
                ),
                format!(
                    "oauth_refresh_token_issued={}",
                    federated_exchange.token_response.refresh_token.is_some()
                ),
                format!(
                    "oauth_id_token_issued={}",
                    federated_exchange.token_response.id_token.is_some()
                ),
                format!(
                    "oauth_id_token_subject={}",
                    federated_exchange
                        .id_token_subject
                        .as_deref()
                        .unwrap_or("missing")
                ),
                format!("oauth_userinfo_subject={upstream_subject}"),
                format!("callback_state_checked={}", input.expected_state.is_some()),
            ],
        }));
        return Ok(());
    }

    let Some(authz_grant) = repo
        .oauth2_authorization_grant()
        .find_by_code(input.authorization_code.trim())
        .await?
    else {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![
                "authorization_code was not issued by this coauth OAuth2 authorization server"
                    .to_owned(),
            ],
        }));
        return Ok(());
    };
    let Some(authz_code) = authz_grant.code.as_ref() else {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![
                "authorization_code grant does not contain an authorization_code payload"
                    .to_owned(),
            ],
        }));
        return Ok(());
    };
    let Some(pkce) = authz_code.pkce.as_ref() else {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("pkce_required"),
            viewer: None,
            session_grant: None,
            warnings: vec![
                "authorization_code was not issued with PKCE; browser OIDC exchange requires S256 PKCE"
                    .to_owned(),
            ],
        }));
        return Ok(());
    };
    if let Err(error) = pkce.verify(input.code_verifier.trim()) {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_code_verifier"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "PKCE verifier did not match authorization_code challenge: {error}"
            )],
        }));
        return Ok(());
    }

    let exchangeable_oauth2_session_id = match &authz_grant.stage {
        coauth_data::AuthorizationGrantStage::Fulfilled { session_id, .. } => Some(*session_id),
        _ => None,
    };

    if authz_grant.redirect_uri != redirect_uri {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_redirect_uri"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "authorization_code was issued for redirect_uri={} rather than {}",
                authz_grant.redirect_uri, redirect_uri
            )],
        }));
        return Ok(());
    }

    if let Some(expected_login_hint) = authz_grant.login_hint.as_deref()
        && expected_login_hint != input.login_hint.trim()
    {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_login_hint"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "authorization_code was issued for login_hint={} rather than {}",
                expected_login_hint,
                input.login_hint.trim()
            )],
        }));
        return Ok(());
    }

    let Some(oauth2_client) = repo.oauth2_client().lookup(authz_grant.client_id).await? else {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "authorization_code references missing oauth2_client={}",
                authz_grant.client_id
            )],
        }));
        return Ok(());
    };
    if !oauth2_client
        .redirect_uris
        .iter()
        .any(|registered_redirect_uri| registered_redirect_uri == &redirect_uri)
    {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_redirect_uri"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "authorization_code client={} no longer allows redirect_uri={}",
                oauth2_client.client_id, redirect_uri
            )],
        }));
        return Ok(());
    }
    if oauth2_client.client_id != input.client_id.trim() {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_client"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "authorization_code was issued for client_id={} rather than {}",
                oauth2_client.client_id,
                input.client_id.trim()
            )],
        }));
        return Ok(());
    }
    if oauth2_client.token_endpoint_auth_method.as_ref()
        != Some(&OAuthClientAuthenticationMethod::None)
    {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_client"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "authorization_code client_id={} requires token_endpoint_auth_method={}; the browser OIDC bridge only supports public clients with token_endpoint_auth_method=none",
                oauth2_client.client_id,
                oauth2_client
                    .token_endpoint_auth_method
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "missing".to_owned())
            )],
        }));
        return Ok(());
    }

    let oauth_code_grant = OAuthAuthorizationCodeGrant {
        code: input.authorization_code.trim().to_owned(),
        redirect_uri: Some(redirect_uri.clone()),
        code_verifier: Some(input.code_verifier.trim().to_owned()),
    };
    let oauth_token_request = AccessTokenRequest::AuthorizationCode(oauth_code_grant.clone());
    let local_token_credentials = ClientCredentials::None {
        client_id: oauth2_client.client_id.clone(),
    };
    let oauth_token_http_request = local_token_credentials
        .authenticated_form(
            http_client
                .post(token_endpoint.as_str())
                .header(ACCEPT, APPLICATION_JSON.as_ref()),
            &oauth_token_request,
            clock.now(),
            &mut rng,
        )
        .map_err(|error| RouteError::Internal(Box::new(error)))?;
    let oauth_token_http_response = oauth_token_http_request
        .send()
        .await
        .map_err(|error| RouteError::Internal(Box::new(error)))?;
    if !oauth_token_http_response.status().is_success() {
        let status = oauth_token_http_response.status();
        let token_error = oauth_token_http_response.json::<ClientError>().await;
        if status.is_server_error() {
            return Err(RouteError::Internal(Box::new(std::io::Error::other(
                match token_error {
                    Ok(error) => {
                        format!("local OAuth2 token endpoint returned server_error: {error:?}")
                    }
                    Err(error) => format!(
                        "local OAuth2 token endpoint returned {status} and its error body could not be decoded: {error}"
                    ),
                },
            ))));
        }
        match token_error {
            Ok(error) => {
                let error_description = error
                    .error_description
                    .as_deref()
                    .unwrap_or(
                        "local OAuth2 token endpoint rejected the authorization_code exchange",
                    )
                    .to_owned();
                let lower_description = error_description.to_ascii_lowercase();
                let (code, error_kind) = match error.error {
                    ClientErrorCode::InvalidGrant if lower_description.contains("pkce") => (
                        "invalid_code_verifier",
                        format!("pkce verification failed: {error_description}"),
                    ),
                    ClientErrorCode::InvalidGrant => {
                        ("invalid_authorization_code", error_description)
                    }
                    ClientErrorCode::InvalidClient | ClientErrorCode::UnauthorizedClient => {
                        ("invalid_client", error_description)
                    }
                    ClientErrorCode::InvalidRequest => ("invalid_request", error_description),
                    _ => ("invalid_authorization_code", error_description),
                };
                res.render(Json(LoginResponse {
                    status: "error",
                    error: Some(code),
                    viewer: None,
                    session_grant: None,
                    warnings: vec![format!(
                        "local OAuth2 token endpoint rejected the authorization_code exchange: {error_kind}"
                    )],
                }));
                return Ok(());
            }
            Err(error) => {
                return Err(RouteError::Internal(Box::new(std::io::Error::other(
                    format!(
                        "local OAuth2 token endpoint returned {status} and its error body could not be decoded: {error}"
                    ),
                ))));
            }
        }
    }
    let oauth_token_reply: AccessTokenResponse = oauth_token_http_response
        .json()
        .await
        .map_err(|error| RouteError::Internal(Box::new(error)))?;
    repo.cancel().await?;
    let mut repo = depot.repo().await?;

    let oauth2_session_id = exchangeable_oauth2_session_id.ok_or_else(|| {
        RouteError::Internal(Box::new(std::io::Error::other(
            "authorization_code exchanged successfully without a fulfilled oauth2 session id",
        )))
    })?;
    let Some(oauth2_session) = repo.oauth2_session().lookup(oauth2_session_id).await? else {
        return Err(RouteError::Internal(Box::new(std::io::Error::other(
            format!(
                "authorization_code exchange succeeded but oauth2_session={oauth2_session_id} could not be loaded",
            ),
        ))));
    };
    if oauth2_session.client_id != authz_grant.client_id {
        return Err(RouteError::Internal(Box::new(std::io::Error::other(
            format!(
                "authorization_code exchange succeeded with mismatched client binding: grant client={} session client={}",
                authz_grant.client_id, oauth2_session.client_id
            ),
        ))));
    }

    let Some(user_session_id) = oauth2_session.user_session_id else {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec!["authorization_code is not bound to a browser user session".to_owned()],
        }));
        return Ok(());
    };

    let Some(browser_session) = repo.browser_session().lookup(user_session_id).await? else {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "authorization_code references missing browser_session={user_session_id}"
            )],
        }));
        return Ok(());
    };
    let expected_subject =
        contrix::user_did_for(&url_builder, &contrix_config, &browser_session.user);
    let oauth_introspection = match crate::handlers::oauth2::introspection_service::introspect_token(
        &mut repo,
        &clock,
        &url_builder,
        &contrix_config,
        &service_activity_tracker,
        &oauth_token_reply.access_token,
        Some(coauth_iana::oauth::OAuthTokenTypeHint::AccessToken),
    )
    .await
    {
        Ok(reply) => reply,
        Err(
            crate::handlers::oauth2::introspection_service::IntrospectionError::Repository(_)
            | crate::handlers::oauth2::introspection_service::IntrospectionError::CantLoadOAuthSession(_)
            | crate::handlers::oauth2::introspection_service::IntrospectionError::CantLoadPersonalSession(_)
            | crate::handlers::oauth2::introspection_service::IntrospectionError::CantLoadUser(_)
            | crate::handlers::oauth2::introspection_service::IntrospectionError::CantLoadOAuth2Client(_),
        ) => {
            return Err(RouteError::Internal(Box::new(std::io::Error::other(
                "fresh OAuth token could not be introspected because local session state could not be loaded",
            ))));
        }
        Err(error) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_authorization_code"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "fresh OAuth access token failed local introspection: {error}"
                )],
            }));
            return Ok(());
        }
    };
    if !oauth_introspection.active {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![
                "fresh OAuth access token was minted but not reported active by local introspection"
                    .to_owned(),
            ],
        }));
        return Ok(());
    }
    if oauth_introspection.iss.as_deref() != Some(expected_issuer.as_str()) {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_discovery_binding"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth access token issuer mismatch: expected {} but introspection returned {}",
                expected_issuer,
                oauth_introspection.iss.as_deref().unwrap_or("missing")
            )],
        }));
        return Ok(());
    }
    if oauth_introspection.sub.as_deref() != Some(expected_subject.as_str()) {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth access token subject mismatch: expected {} but introspection returned {}",
                expected_subject,
                oauth_introspection.sub.as_deref().unwrap_or("missing")
            )],
        }));
        return Ok(());
    }
    let expected_oauth_client_id = oauth2_session.client_id.to_string();
    if oauth_introspection.client_id.as_deref() != Some(expected_oauth_client_id.as_str()) {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_client"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth access token client mismatch: expected {} but introspection returned {}",
                expected_oauth_client_id,
                oauth_introspection.client_id.as_deref().unwrap_or("missing")
            )],
        }));
        return Ok(());
    }
    let expected_oauth_session_id = oauth2_session_id.to_string();
    if oauth_introspection.contrix_session_id.as_deref() != Some(expected_oauth_session_id.as_str())
    {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth access token session mismatch: expected {} but introspection returned {}",
                expected_oauth_session_id,
                oauth_introspection
                    .contrix_session_id
                    .as_deref()
                    .unwrap_or("missing")
            )],
        }));
        return Ok(());
    }
    let (oauth_userinfo, userinfo_response_signed) = match upstream_oidc
        .fetch_local_oidc_userinfo(
            &http_client,
            &key_store,
            &userinfo_endpoint,
            &expected_issuer,
            &oauth_token_reply.access_token,
            &oauth2_client.client_id,
            oauth2_client.userinfo_signed_response_alg.as_ref(),
        )
        .await
    {
        Ok(reply) => reply,
        Err(error) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_authorization_code"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!(
                    "fresh OAuth access token failed local userinfo validation: {error}"
                )],
            }));
            return Ok(());
        }
    };
    if oauth_userinfo.sub != expected_subject {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth userinfo subject mismatch: expected {} but userinfo returned {}",
                expected_subject, oauth_userinfo.sub
            )],
        }));
        return Ok(());
    }
    if oauth_userinfo.principal_did.as_deref() != Some(expected_subject.as_str()) {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth userinfo principal_did mismatch: expected {} but userinfo returned {}",
                expected_subject,
                oauth_userinfo.principal_did.as_deref().unwrap_or("missing")
            )],
        }));
        return Ok(());
    }
    if oauth_userinfo.session_id.as_deref() != Some(expected_oauth_session_id.as_str()) {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth userinfo session mismatch: expected {} but userinfo returned {}",
                expected_oauth_session_id,
                oauth_userinfo.session_id.as_deref().unwrap_or("missing")
            )],
        }));
        return Ok(());
    }

    let device_id = input.device_id.trim().to_owned();
    let grant_target = match upstream_oidc.session_grant_target_for_requested_audience(
        &url_builder,
        &contrix_config,
        input.principal_audience.as_deref(),
    ) {
        Ok(target) => target,
        Err(message) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_audience"),
                viewer: None,
                session_grant: None,
                warnings: vec![message],
            }));
            return Ok(());
        }
    };
    let session_grant = contrix::issue_session_grant_for_audience(
        &mut rng,
        &clock,
        &url_builder,
        &contrix_config,
        &key_store,
        &browser_session,
        grant_target.audience.clone(),
        vec![contrix::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
    )
    .map_err(|error| RouteError::Internal(Box::new(error)))?;

    let persisted_session_grant = contrix::persist_session_grant(
        &mut repo,
        &mut rng,
        &clock,
        &browser_session,
        &session_grant,
    )
    .await?;
    repo.save().await?;

    let user = &browser_session.user;
    let display_name = match homeserver.query_user(&user.username).await {
        Ok(info) => info.displayname,
        Err(_) => None,
    };

    res.render(Json(LoginResponse {
        status: "success",
        error: None,
        viewer: Some(ViewerInfo {
            id: NodeType::User.serialize(user.id),
            username: user.username.clone(),
            did: contrix::user_did_for(&url_builder, &contrix_config, &user),
            handle: contrix::user_handle(&url_builder, &user),
            mxid: homeserver.mxid(&user.username),
            display_name,
        }),
        session_grant: Some(SessionGrantInfo {
            kind: SessionGrantKind::PrincipalSession,
            id: persisted_session_grant.id.to_string(),
            grant_jwt: session_grant.grant_jwt,
            session_public_key: session_grant.session_public_key,
            session_private_key_pem: session_grant.session_private_key_pem,
            expires_at: session_grant.expires_at,
            audience: session_grant.audience,
            scopes: session_grant.scopes,
            principal_server: grant_target
                .principal_server_name
                .zip(grant_target.principal_server_endpoint)
                .map(|(name, endpoint)| SessionGrantPrincipalServerInfo { name, endpoint }),
        }),
        warnings: vec![
            "oidc_exchange_mode=local_coauth".to_owned(),
            format!("device_id={device_id}"),
            format!("redirect_uri={}", redirect_uri),
            format!("issuer={issuer}"),
            format!("token_endpoint={token_endpoint}"),
            format!("userinfo_endpoint={userinfo_endpoint}"),
            format!("client_id={}", oauth2_client.client_id),
            format!("oauth2_session_id={oauth2_session_id}"),
            format!("oauth2_client_id={}", oauth2_client.client_id),
            format!("browser_session_id={user_session_id}"),
            format!(
                "oauth_scope={}",
                oauth_token_reply
                    .scope
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "missing".to_owned())
            ),
            "authorization_code_exchanged_via_local_http_token_endpoint=true".to_owned(),
            "oauth_access_token_issued=true".to_owned(),
            "oauth_access_token_introspected_locally=true".to_owned(),
            "oauth_access_token_validated_via_local_userinfo=true".to_owned(),
            format!("oauth_userinfo_response_signed={userinfo_response_signed}"),
            format!(
                "oauth_refresh_token_issued={}",
                oauth_token_reply.refresh_token.is_some()
            ),
            format!(
                "oauth_id_token_issued={}",
                oauth_token_reply.id_token.is_some()
            ),
            format!(
                "oauth_introspection_subject={}",
                oauth_introspection.sub.as_deref().unwrap_or("missing")
            ),
            format!("oauth_userinfo_subject={}", oauth_userinfo.sub),
            format!("callback_state_checked={}", input.expected_state.is_some()),
        ],
    }));
    Ok(())
}

#[endpoint]
pub async fn oidc_browser_bridge_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<OidcBrowserBridgeSessionResponse>, RouteError> {
    let url_builder = depot.url_builder()?;
    let input: OidcBrowserBridgeSessionRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid browser bridge session payload".to_owned()))?;

    if input.redirect_uri.trim().is_empty()
        || input.login_hint.trim().is_empty()
        || input.device_id.trim().is_empty()
    {
        return Err(RouteError::BadRequest(
            "redirect_uri, login_hint, and device_id are required".to_owned(),
        ));
    }

    let principal_audience = input
        .principal_audience
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "TODO_PRINCIPAL_AUDIENCE".to_owned());
    let client_id = input
        .client_id_hint
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "yougen".to_owned());
    let state = format!("cx-state-{}", Ulid::new().to_string().to_lowercase());
    let nonce = format!("cx-nonce-{}", Ulid::new().to_string().to_lowercase());
    let code_verifier = format!(
        "cx-pkce-verifier-{}",
        Ulid::new().to_string().to_lowercase()
    );
    let code_challenge = pkce_s256_challenge(&code_verifier);
    let mut authorize_url = url_builder.oauth_authorization_endpoint();
    {
        let mut query = authorize_url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client_id.as_str());
        query.append_pair("redirect_uri", input.redirect_uri.trim());
        query.append_pair("scope", "openid profile");
        query.append_pair("state", state.as_str());
        query.append_pair("nonce", nonce.as_str());
        query.append_pair("login_hint", input.login_hint.trim());
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("code_challenge", code_challenge.as_str());
        query.append_pair("resource", principal_audience.as_str());
    }

    Ok(Json(OidcBrowserBridgeSessionResponse {
        contract: "contrix.rest.oidc_browser_bridge_session.v1",
        version: "2026-05-04-scaffold",
        authorize_url: authorize_url.to_string(),
        callback_uri: input.redirect_uri.trim().to_owned(),
        issuer: url_builder.oidc_issuer().to_string(),
        authorization_endpoint: url_builder.oauth_authorization_endpoint().to_string(),
        token_endpoint: url_builder.oauth_token_endpoint().to_string(),
        userinfo_endpoint: url_builder.oidc_userinfo_endpoint().to_string(),
        client_id,
        state,
        nonce,
        code_verifier,
        code_challenge,
        code_challenge_method: "S256",
        principal_audience,
        todo: "TODO: persist browser-bound state/nonce/verifier material and backed OAuth client selection.",
    }))
}

#[endpoint]
pub async fn oidc_exchange_describe() -> Result<Json<OidcExchangeDescribeResponse>, RouteError> {
    Ok(Json(OidcExchangeDescribeResponse {
        contract: "contrix.rest.oidc_exchange.v1",
        version: "2026-05-04-scaffold",
        exchange_path: "/api/v1/auth/oidc/exchange",
        upstream_boundary_mode: "local_coauth_or_federated_oidc_token_plus_userinfo_validation",
        upstream_modes_supported: vec![
            "local_coauth",
            "local_http_token_exchange",
            "local_oauth2_introspection",
            "local_userinfo_http_validation",
            "federated",
            "federated_upstream_token_endpoint",
            "federated_userinfo_http_validation",
            "federated_upstream_link_binding",
        ],
        required_fields: vec![
            "authorization_code",
            "code_verifier",
            "redirect_uri",
            "issuer",
            "token_endpoint",
            "userinfo_endpoint",
            "client_id",
            "login_hint",
            "device_id",
        ],
        validation_layers: vec![
            "callback_state_gate_if_expected_state_present",
            "live_discovery_metadata_match",
            "local_authorization_code_binding",
            "pkce_required_for_authorization_code",
            "public_client_only_for_browser_bridge",
            "local_http_oauth2_token_exchange",
            "local_oauth2_introspection_active_check",
            "local_userinfo_subject_principal_session_binding",
            "federated_configured_provider_issuer_match",
            "federated_token_endpoint_exchange",
            "federated_userinfo_subject_validation",
            "federated_upstream_link_to_local_account",
            "login_hint_to_linked_local_account",
            "configured_principal_audience_match",
            "contrix_session_grant_issuance",
        ],
        failure_codes: vec![
            "invalid_redirect_uri",
            "invalid_issuer",
            "invalid_discovery_binding",
            "invalid_client_id",
            "pkce_required",
            "invalid_code_verifier",
            "invalid_state",
            "invalid_authorization_code",
            "invalid_userinfo_binding",
            "upstream_link_required",
            "account_unavailable",
            "invalid_audience",
            "session_grant_denied",
        ],
        example_request: serde_json::json!({
            "authorization_code": "TODO_AUTHORIZATION_CODE",
            "code_verifier": "TODO_PKCE_CODE_VERIFIER",
            "redirect_uri": "http://localhost:8080/auth/callback",
            "issuer": "https://coauth.example",
            "token_endpoint": "https://coauth.example/oauth2/token",
            "userinfo_endpoint": "https://coauth.example/oauth2/userinfo",
            "client_id": "yougen",
            "login_hint": "did:web:alice.example",
            "device_id": "device-web",
            "principal_audience": "https://soland.example",
            "state": "TODO_CALLBACK_STATE",
            "expected_state": "TODO_EXPECTED_STATE"
        }),
        todos: vec![
            "TODO: publish machine-readable failure taxonomy for discovery drift, pkce failure, and userinfo/session binding mismatch",
            "TODO: bind browser bridge sessions to persisted PKCE and OAuth client records",
        ],
    }))
}

#[endpoint]
pub async fn auth_bridge_describe(
    depot: &Depot,
) -> Result<Json<AuthBridgeDescribeResponse>, RouteError> {
    let _ = depot.url_builder()?;

    Ok(Json(AuthBridgeDescribeResponse {
        contract: "contrix.rest.auth_bridge.v1",
        version: "2026-05-04-scaffold",
        api_base_path: "/api/v1",
        oauth: AuthBridgeOAuthDescriptor {
            discovery_path: "/.well-known/openid-configuration",
            browser_bridge_session_path: "/api/v1/auth/oidc/browser-bridge/session",
            exchange_describe_path: "/api/v1/auth/oidc/exchange/describe",
            exchange_path: "/api/v1/auth/oidc/exchange",
            supported_flows: vec!["authorization_code_pkce_browser"],
            redirect_uri_modes: vec!["browser_origin_callback", "native_urn_callback"],
            client_selection_mode: "public_authorization_code_client_with_exact_redirect_match",
        },
        contrix: AuthBridgeContrixDescriptor {
            login_path: "/api/v1/auth/login",
            logout_path: "/api/v1/auth/logout",
            providers_path: "/api/v1/auth/providers",
            session_grants_path: "/api/v1/session-grants",
            session_grants_introspect_path: "/api/v1/session-grants/introspect",
            session_grant_scope: contrix::PRINCIPAL_SERVER_SESSION_BIND_SCOPE,
        },
        admin: AuthBridgeAdminDescriptor {
            accounts_path: "/api/admin/v1/accounts",
            account_detail_path_template: "/api/admin/v1/accounts/{account_id}",
            account_dids_path_template: "/api/admin/v1/accounts/{account_id}/dids",
            risk_action_path_template: "/api/admin/v1/accounts/{account_id}/risk-action",
            risk_action_current_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/current",
            risk_action_history_path_template: "/api/admin/v1/accounts/{account_id}/risk-action/history",
        },
        todos: vec![
            "TODO: replace audit-derived risk-action lifecycle with persisted proposal/approval/execute state records",
            "TODO: publish formal OpenAPI examples for browser callback, PKCE exchange, and session-grant bridge flows",
        ],
    }))
}

#[endpoint]
pub async fn integration_describe() -> Result<Json<IntegrationManifestResponse>, RouteError> {
    Ok(Json(IntegrationManifestResponse {
        contract: "contrix.rest.integration_manifest.v1",
        version: "2026-05-04-scaffold",
        service: "coauth",
        service_kind: "account_authority",
        api_base_path: "/api/v1",
        describe_path: "/api/v1/integration/describe",
        dependencies: vec![
            IntegrationManifestDependency {
                service: "soland",
                purpose: "principal_server_session_exchange",
                required_contract: "contrix.rest.principal_bridge.v1",
                discovery_path: "/api/v1/auth/bridge/describe",
                mode: "remote_service_contract",
            },
            IntegrationManifestDependency {
                service: "public_did_resolver",
                purpose: "principal_did_resolution",
                required_contract: "did_method_resolution",
                discovery_path: "TODO: external resolver metadata",
                mode: "remote_public_resolver",
            },
        ],
        surfaces: vec![
            IntegrationManifestSurface {
                name: "auth_bridge",
                method: "GET",
                path: "/api/v1/auth/bridge/describe",
                contract: "contrix.rest.auth_bridge.v1",
                stability: "scaffold",
                todo: "TODO: keep browser bridge, exchange contract, and downstream grant metadata aligned with real OIDC/passkey flows.",
            },
            IntegrationManifestSurface {
                name: "oidc_browser_bridge_session",
                method: "POST",
                path: "/api/v1/auth/oidc/browser-bridge/session",
                contract: "contrix.rest.oidc_browser_bridge_session.v1",
                stability: "scaffold",
                todo: "TODO: persist browser-bound PKCE/session state.",
            },
            IntegrationManifestSurface {
                name: "oidc_exchange_describe",
                method: "GET",
                path: "/api/v1/auth/oidc/exchange/describe",
                contract: "contrix.rest.oidc_exchange.v1",
                stability: "scaffold",
                todo: "TODO: publish upstream-boundary verification modes and failure taxonomy as final contract states.",
            },
            IntegrationManifestSurface {
                name: "oidc_exchange",
                method: "POST",
                path: "/api/v1/auth/oidc/exchange",
                contract: "contrix.rest.oidc_exchange.v1",
                stability: "scaffold",
                todo: "TODO: publish final failure taxonomy and examples for local_coauth and federated modes.",
            },
            IntegrationManifestSurface {
                name: "admin_bridge",
                method: "GET",
                path: "/api/admin/v1/bridge/describe",
                contract: "contrix.rest.coauth_admin_bridge.v1",
                stability: "scaffold",
                todo: "TODO: replace audit-derived risk-action lifecycle with persisted proposal/approval/execute state records.",
            },
            IntegrationManifestSurface {
                name: "account_claims",
                method: "GET",
                path: "/api/admin/v1/accounts/{account_id}/claims",
                contract: "contrix.rest.coauth_account_claims.v1",
                stability: "scaffold",
                todo: "TODO: replace scaffold claim inventory with real issuer-backed claim sources and verification state.",
            },
            IntegrationManifestSurface {
                name: "account_session_grants",
                method: "GET",
                path: "/api/admin/v1/accounts/{account_id}/session-grants",
                contract: "contrix.rest.coauth_account_session_grants.v1",
                stability: "scaffold",
                todo: "TODO: expose durable grant inventory, revocation state, and audience binding beyond preview records.",
            },
        ],
        examples: serde_json::json!({
            "compose_flow": {
                "step_1": {
                    "service": "coauth",
                    "path": "/api/v1/auth/oidc/browser-bridge/session",
                    "method": "POST"
                },
                "step_2": {
                    "service": "coauth",
                    "path": "/api/v1/auth/oidc/exchange",
                    "method": "POST"
                },
                "step_3": {
                    "service": "soland",
                    "path": "/api/v1/auth/session-grant/exchange",
                    "method": "POST"
                },
                "step_4": {
                    "service": "soland",
                    "path": "/api/v1/push/register-device",
                    "method": "POST"
                }
            }
        }),
        todos: vec![
            "TODO: persist browser bridge session state, PKCE material, and approval/risk-action lifecycle records.",
            "TODO: publish OpenAPI examples that match the integration manifest surfaces exactly.",
        ],
    }))
}
