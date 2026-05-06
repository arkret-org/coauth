//! REST API endpoints for authentication flows (login, logout, providers).
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. Session cookies are set/cleared as side effects.

use std::sync::LazyLock;

use http::header::ACCEPT;
use mime::APPLICATION_JSON;
use coauth_data::{RepositoryAccess, UrlBuilder};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use opentelemetry::{Key, KeyValue, metrics::Counter};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{
        AccessTokenRequest, AccessTokenResponse,
        AuthorizationCodeGrant as OAuthAuthorizationCodeGrant,
    },
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{DepotExt, NodeType, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::{
    routing::{
        METER, RequesterFingerprint,
        account::service::access::{
            PasswordLoginOutcome, PasswordLoginRequest, load_enabled_upstream_providers,
            login_with_password, logout_browser_session,
        },
        contrix,
    },
    oidc_client::requests::discovery,
    oidc_client::requests::jose::{JwtVerificationData, verify_signed_jwt},
    oidc_client::types::client_credentials::ClientCredentials,
    salvo_utils::session::SessionInfoExt,
};

// ── Metrics ────────────────────────────────────────────────────

static PASSWORD_LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.rest.password_login_attempt")
        .with_description("Number of REST API password login attempts")
        .with_unit("{attempt}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

// ── Request / Response types ───────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer: Option<ViewerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<SessionGrantInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

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
pub struct ViewerInfo {
    pub id: String,
    pub username: String,
    pub did: String,
    pub handle: String,
    pub mxid: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct OidcUserinfoClaims {
    sub: String,
    #[serde(rename = "org.contrix.principal_did")]
    principal_did: String,
    #[serde(rename = "org.contrix.session_id")]
    session_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct SessionGrantInfo {
    pub kind: &'static str,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub session_private_key_pem: String,
    pub expires_at: String,
    pub audience: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_server: Option<SessionGrantPrincipalServerInfo>,
}

#[derive(Serialize, ToSchema)]
pub struct SessionGrantPrincipalServerInfo {
    pub name: String,
    pub endpoint: String,
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
    #[salvo(schema(value_type = Object))]
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
pub struct LogoutResponse {
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct ProvidersResponse {
    pub providers: Vec<ProviderInfo>,
    pub password_login_enabled: bool,
    pub password_registration_enabled: bool,
    pub account_recovery_allowed: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ProviderInfo {
    pub id: String,
    pub human_name: Option<String>,
    pub brand_name: Option<String>,
    pub authorize_url: String,
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

// ── POST /api/v1/auth/login ────────────────────────────────────

/// Authenticate a user with username and password, returning viewer info,
/// setting a session cookie on success, and minting a temporary scaffold
/// session grant for the configured principal-server bridge.
#[endpoint]
pub async fn login(req: &mut Request, depot: &Depot, res: &mut Response) -> Result<(), RouteError> {
    let mut rng = make_rng();
    let clock = make_clock();
    let password_manager = depot.password_manager()?;
    let site_config = depot.site_config()?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let limiter = depot.limiter()?;
    let homeserver = depot.homeserver()?;
    let repo = depot.repo().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());

    let input: LoginRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    // Validate fields
    if input.username.is_empty() || input.password.is_empty() {
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_credentials"),
            viewer: None,
            session_grant: None,
            warnings: Vec::new(),
        }));
        return Ok(());
    }

    match login_with_password(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        &limiter,
        homeserver.as_ref(),
        &url_builder,
        &contrix_config,
        &site_config,
        PasswordLoginRequest {
            username_or_email: input.username,
            password: zeroize::Zeroizing::new(input.password),
            user_agent,
            requester,
        },
    )
    .await
    .map_err(|error| match error {
        crate::routing::account::service::access::PasswordLoginError::Repository(error) => {
            RouteError::from(error)
        }
        crate::routing::account::service::access::PasswordLoginError::Password(error) => {
            RouteError::Internal(error.into())
        }
    })? {
        PasswordLoginOutcome::Disabled => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("password_login_disabled"),
                viewer: None,
                session_grant: None,
                warnings: Vec::new(),
            }));
            Ok(())
        }
        PasswordLoginOutcome::InvalidCredentials => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_credentials"),
                viewer: None,
                session_grant: None,
                warnings: Vec::new(),
            }));
            Ok(())
        }
        PasswordLoginOutcome::RateLimited => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("rate_limited"),
                viewer: None,
                session_grant: None,
                warnings: Vec::new(),
            }));
            Ok(())
        }
        PasswordLoginOutcome::AccountDeactivated { .. } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("account_deactivated"),
                viewer: None,
                session_grant: None,
                warnings: Vec::new(),
            }));
            Ok(())
        }
        PasswordLoginOutcome::AccountLocked { .. } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("account_locked"),
                viewer: None,
                session_grant: None,
                warnings: Vec::new(),
            }));
            Ok(())
        }
        PasswordLoginOutcome::Authenticated { user, user_session } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

            activity_tracker
                .record_browser_session(&clock, &user_session)
                .await;

            let cookie_jar = cookie_jar.set_session(&user_session);
            let display_name = match homeserver.query_user(&user.username).await {
                Ok(info) => info.displayname,
                Err(_) => None,
            };
            let grant_target =
                contrix::password_login_session_grant_target(&url_builder, &contrix_config);
            // TODO(contrix): replace password bootstrap minting with the real
            // coauth-owned OIDC/passkey exchange and proof-bound grant issuance.
            let session_grant = contrix::issue_session_grant_for_audience(
                &mut rng,
                &clock,
                &url_builder,
                &contrix_config,
                &key_store,
                &user_session,
                grant_target.audience.clone(),
                vec![contrix::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
            )
            .map_err(|error| RouteError::Internal(Box::new(error)))?;

            let mut grant_repo = depot.repo().await?;
            contrix::persist_session_grant(
                &mut grant_repo,
                &mut rng,
                &clock,
                &user_session,
                &session_grant,
            )
            .await?;
            grant_repo.save().await?;

            cookie_jar.finalize(
                res,
                Json(LoginResponse {
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
                        kind: "cx.session_grant",
                        grant_jwt: session_grant.grant_jwt,
                        session_public_key: session_grant.session_public_key,
                        session_private_key_pem: session_grant.session_private_key_pem,
                        expires_at: session_grant.expires_at,
                        audience: session_grant.audience,
                        scopes: session_grant.scopes,
                        principal_server: grant_target
                            .principal_server_name
                            .zip(grant_target.principal_server_endpoint)
                            .map(|(name, endpoint)| SessionGrantPrincipalServerInfo {
                                name,
                                endpoint,
                            }),
                    }),
                    warnings: Vec::new(),
                }),
            );
            Ok(())
        }
    }
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
        .get::<crate::routing::ActivityTracker>("activity_tracker")
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

    if input.authorization_code.trim().is_empty()
        || input.code_verifier.trim().is_empty()
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
                "authorization_code, code_verifier, redirect_uri, issuer, token_endpoint, userinfo_endpoint, client_id, login_hint, and device_id are required"
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
                "issuer and token_endpoint must resolve to the same origin for the OIDC exchange scaffold".to_owned(),
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
                "issuer and userinfo_endpoint must resolve to the same origin for the OIDC exchange scaffold".to_owned(),
            ],
        }));
        return Ok(());
    }
    let expected_issuer = url_builder.oidc_issuer();
    let expected_token_endpoint = url_builder.oauth_token_endpoint();
    let expected_userinfo_endpoint = url_builder.oidc_userinfo_endpoint();
    let discovered_metadata = match if issuer.scheme() == "https" {
        discovery::discover(&http_client, issuer.as_str()).await
    } else {
        discovery::insecure_discover(&http_client, issuer.as_str()).await
    } {
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
    if discovered_metadata.issuer() != issuer.as_str()
        || discovered_metadata.token_endpoint() != &token_endpoint
        || discovered_metadata.userinfo_endpoint() != &userinfo_endpoint
    {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_discovery_binding"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "OIDC exchange metadata does not match live discovery for issuer={}: discovered token_endpoint={} userinfo_endpoint={} but received token_endpoint={} userinfo_endpoint={}",
                discovered_metadata.issuer(),
                discovered_metadata.token_endpoint(),
                discovered_metadata.userinfo_endpoint(),
                token_endpoint,
                userinfo_endpoint
            )],
        }));
        return Ok(());
    }
    if issuer != expected_issuer
        || token_endpoint != expected_token_endpoint
        || userinfo_endpoint != expected_userinfo_endpoint
    {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_discovery_binding"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "OIDC exchange metadata does not match this coauth issuer/token/userinfo surface: expected issuer={} token_endpoint={} userinfo_endpoint={} but received issuer={} token_endpoint={} userinfo_endpoint={}",
                expected_issuer, expected_token_endpoint, expected_userinfo_endpoint, issuer, token_endpoint, userinfo_endpoint
            )],
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
            warnings: vec![
                format!(
                    "authorization_code was issued for login_hint={} rather than {}",
                    expected_login_hint,
                    input.login_hint.trim()
                ),
            ],
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
                    Ok(error) => format!("local OAuth2 token endpoint returned server_error: {error:?}"),
                    Err(error) => format!("local OAuth2 token endpoint returned {status} and its error body could not be decoded: {error}"),
                },
            ))));
        }
        match token_error {
            Ok(error) => {
                let error_description = error
                    .error_description
                    .as_deref()
                    .unwrap_or("local OAuth2 token endpoint rejected the authorization_code exchange")
                    .to_owned();
                let lower_description = error_description.to_ascii_lowercase();
                let (code, error_kind) = match error.error {
                    ClientErrorCode::InvalidGrant if lower_description.contains("pkce") => {
                        ("invalid_code_verifier", format!("pkce verification failed: {error_description}"))
                    }
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
        return Err(RouteError::Internal(Box::new(std::io::Error::other(format!(
            "authorization_code exchange succeeded but oauth2_session={oauth2_session_id} could not be loaded",
        )))));
    };
    if oauth2_session.client_id != authz_grant.client_id {
        return Err(RouteError::Internal(Box::new(std::io::Error::other(format!(
            "authorization_code exchange succeeded with mismatched client binding: grant client={} session client={}",
            authz_grant.client_id, oauth2_session.client_id
        )))));
    }

    let Some(user_session_id) = oauth2_session.user_session_id else {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![
                "authorization_code is not bound to a browser user session".to_owned(),
            ],
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
    let expected_subject = contrix::user_did_for(&url_builder, &contrix_config, &browser_session.user);
    let oauth_introspection = match crate::routing::oauth2::introspection_service::introspect_token(
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
            crate::routing::oauth2::introspection_service::IntrospectionError::Repository(_)
            | crate::routing::oauth2::introspection_service::IntrospectionError::CantLoadOAuthSession(_)
            | crate::routing::oauth2::introspection_service::IntrospectionError::CantLoadPersonalSession(_)
            | crate::routing::oauth2::introspection_service::IntrospectionError::CantLoadUser(_)
            | crate::routing::oauth2::introspection_service::IntrospectionError::CantLoadOAuth2Client(_),
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
    if oauth_introspection.contrix_session_id.as_deref()
        != Some(expected_oauth_session_id.as_str())
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
    let (oauth_userinfo, userinfo_response_signed) = match fetch_local_oidc_userinfo(
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
    if oauth_userinfo.principal_did != expected_subject {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth userinfo principal_did mismatch: expected {} but userinfo returned {}",
                expected_subject, oauth_userinfo.principal_did
            )],
        }));
        return Ok(());
    }
    if oauth_userinfo.session_id != expected_oauth_session_id {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_authorization_code"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "fresh OAuth userinfo session mismatch: expected {} but userinfo returned {}",
                expected_oauth_session_id, oauth_userinfo.session_id
            )],
        }));
        return Ok(());
    }

    let device_id = input.device_id.trim().to_owned();
    let grant_target = session_grant_target_for_requested_audience(
        &url_builder,
        &contrix_config,
        input.principal_audience.as_deref(),
    );
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

    contrix::persist_session_grant(
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
            kind: "cx.session_grant",
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
            "TODO(contrix): replace the local OAuth2 HTTP token bridge with a full upstream token endpoint exchange or proof/introspection validation before treating this flow as production-grade.".to_owned(),
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
            format!("oauth_id_token_issued={}", oauth_token_reply.id_token.is_some()),
            format!(
                "oauth_introspection_subject={}",
                oauth_introspection
                    .sub
                    .as_deref()
                    .unwrap_or("missing")
            ),
            format!("oauth_userinfo_subject={}", oauth_userinfo.sub),
            format!(
                "callback_state_checked={}",
                input.expected_state.is_some()
            ),
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
    let code_verifier = format!("cx-pkce-verifier-{}", Ulid::new().to_string().to_lowercase());
    let code_challenge = format!("TODO-S256-{}", Ulid::new().to_string().to_lowercase());
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
        todo: "TODO: replace scaffold state/nonce/verifier generation with true browser-bound PKCE material and backed OAuth client selection.",
    }))
}

#[endpoint]
pub async fn oidc_exchange_describe() -> Result<Json<OidcExchangeDescribeResponse>, RouteError> {
    Ok(Json(OidcExchangeDescribeResponse {
        contract: "contrix.rest.oidc_exchange.v1",
        version: "2026-05-04-scaffold",
        exchange_path: "/api/v1/auth/oidc/exchange",
        upstream_boundary_mode:
            "local_http_token_plus_local_introspection_plus_local_userinfo_with_todo_upstream_validation",
        upstream_modes_supported: vec![
            "local_http_token_exchange",
            "local_oauth2_introspection",
            "local_userinfo_http_validation",
            "todo_upstream_token_endpoint",
            "todo_upstream_introspection",
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
            "public_client_only_for_browser_bridge",
            "local_http_oauth2_token_exchange",
            "local_oauth2_introspection_active_check",
            "local_userinfo_subject_principal_session_binding",
            "contrix_session_grant_issuance",
        ],
        failure_codes: vec![
            "invalid_redirect_uri",
            "invalid_issuer",
            "invalid_discovery_binding",
            "invalid_client_id",
            "invalid_code_verifier",
            "invalid_state",
            "invalid_authorization_code",
            "invalid_userinfo_binding",
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
            "TODO: replace local-only token/introspection/userinfo validation chain with explicit upstream-boundary verification modes",
            "TODO: publish machine-readable failure taxonomy for discovery drift, pkce failure, and userinfo/session binding mismatch",
            "TODO: bind browser bridge sessions to persisted PKCE and OAuth client records instead of deterministic scaffold material",
        ],
    }))
}

#[endpoint]
pub async fn auth_bridge_describe(depot: &Depot) -> Result<Json<AuthBridgeDescribeResponse>, RouteError> {
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
            risk_action_current_path_template:
                "/api/admin/v1/accounts/{account_id}/risk-action/current",
            risk_action_history_path_template:
                "/api/admin/v1/accounts/{account_id}/risk-action/history",
        },
        todos: vec![
            "TODO: replace local OAuth bridge validation with true upstream token endpoint and/or upstream introspection verification",
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
                todo: "TODO: replace deterministic scaffold material with persisted browser-bound PKCE/session state.",
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
                todo: "TODO: replace local-only HTTP token/introspection/userinfo chain with explicit upstream verification modes.",
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
            "TODO: finalize a single upstream verification mode story for OIDC bridge exchange.",
            "TODO: persist browser bridge session state, PKCE material, and approval/risk-action lifecycle records.",
            "TODO: publish OpenAPI examples that match the integration manifest surfaces exactly.",
        ],
    }))
}

// ── POST /api/v1/auth/logout ───────────────────────────────────

/// End the current browser session and clear the session cookie.
#[endpoint]
pub async fn logout(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let repo = depot.repo().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);

    let (session_info, cookie_jar) = cookie_jar.session_info();

    if let Some(session) =
        logout_browser_session(repo, &clock, session_info.current_session_id()).await?
    {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;
    }

    // Clear the session cookie
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    cookie_jar.finalize(res, Json(LogoutResponse { status: "success" }));
    Ok(())
}

// ── GET /api/v1/auth/providers ─────────────────────────────────

/// List all enabled upstream OAuth providers and site configuration flags
/// relevant to the login/registration UI.
#[endpoint]
pub async fn providers(depot: &Depot) -> Result<Json<ProvidersResponse>, RouteError> {
    let site_config = depot.site_config()?;
    let mut repo = depot.repo().await?;

    let upstream_providers = load_enabled_upstream_providers(&mut repo).await?;

    let provider_list: Vec<ProviderInfo> = upstream_providers
        .into_iter()
        .map(|p| {
            let authorize_url = format!("/upstream/authorize/{}", p.id);
            ProviderInfo {
                id: p.id.to_string(),
                human_name: p.human_name,
                brand_name: p.brand_name,
                authorize_url,
            }
        })
        .collect();

    repo.cancel().await?;

    Ok(Json(ProvidersResponse {
        providers: provider_list,
        password_login_enabled: site_config.password_login_enabled,
        password_registration_enabled: site_config.password_registration_enabled,
        account_recovery_allowed: site_config.account_recovery_allowed,
    }))
}

fn session_grant_target_for_requested_audience(
    url_builder: &UrlBuilder,
    contrix_config: &coauth_config::ContrixConfig,
    requested_audience: Option<&str>,
) -> contrix::SessionGrantTarget {
    if let Some(requested_audience) = requested_audience.map(str::trim).filter(|value| !value.is_empty())
    {
        if let Some(server) = contrix_config
            .principal_servers
            .iter()
            .find(|server| server.audience == requested_audience)
        {
            return contrix::SessionGrantTarget {
                audience: server.audience.clone(),
                principal_server_name: Some(server.name.clone()),
                principal_server_endpoint: Some(server.endpoint.to_string()),
            };
        }

        return contrix::SessionGrantTarget {
            audience: requested_audience.to_owned(),
            principal_server_name: None,
            principal_server_endpoint: None,
        };
    }

    contrix::password_login_session_grant_target(url_builder, contrix_config)
}

async fn fetch_local_oidc_userinfo(
    http_client: &reqwest::Client,
    key_store: &coauth_keystore::Keystore,
    userinfo_endpoint: &url::Url,
    issuer: &url::Url,
    access_token: &str,
    expected_client_id: &String,
    expected_signed_alg: Option<&coauth_iana::jose::JsonWebSignatureAlg>,
) -> Result<(OidcUserinfoClaims, bool), String> {
    let response = http_client
        .get(userinfo_endpoint.clone())
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| format!("userinfo endpoint request failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("userinfo endpoint returned error status: {error}"))?;

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();

    if content_type.starts_with("application/jwt") {
        let expected_alg = expected_signed_alg.ok_or_else(|| {
            "userinfo endpoint returned a signed JWT but the selected client does not advertise a signed userinfo response".to_owned()
        })?;
        let jwt_body = response
            .text()
            .await
            .map_err(|error| format!("failed to read signed userinfo response: {error}"))?;
        let jwks = key_store.public_jwks();
        let jwt = verify_signed_jwt(
            jwt_body.as_str(),
            JwtVerificationData {
                issuer: Some(issuer.as_str()),
                jwks: &jwks,
                client_id: expected_client_id,
                signing_algorithm: expected_alg,
            },
        )
        .map_err(|error| format!("userinfo JWT verification failed: {error}"))?;
        let claims = serde_json::from_value::<OidcUserinfoClaims>(serde_json::json!(
            jwt.payload().clone()
        ))
            .map_err(|error| format!("failed to decode signed userinfo claims: {error}"))?;
        return Ok((claims, true));
    }

    if expected_signed_alg.is_some() {
        return Err(
            "userinfo endpoint returned JSON but the selected client expects a signed JWT response"
                .to_owned(),
        );
    }

    let claims = response
        .json::<OidcUserinfoClaims>()
        .await
        .map_err(|error| format!("failed to decode JSON userinfo response: {error}"))?;
    Ok((claims, false))
}
