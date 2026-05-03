//! REST API endpoints for authentication flows (login, logout, providers).
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. Session cookies are set/cleared as side effects.

use std::sync::LazyLock;

use coauth_data::{RepositoryAccess, UrlBuilder};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use oauth2_types::requests::AuthorizationCodeGrant as OAuthAuthorizationCodeGrant;
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{DepotExt, NodeType, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::{
    handlers::{
        METER, RequesterFingerprint,
        account::service::access::{
            PasswordLoginOutcome, PasswordLoginRequest, load_enabled_upstream_providers,
            login_with_password, logout_browser_session,
        },
        contrix,
    },
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

#[derive(Serialize, ToSchema)]
pub struct ViewerInfo {
    pub id: String,
    pub username: String,
    pub did: String,
    pub handle: String,
    pub mxid: String,
    pub display_name: Option<String>,
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
        crate::handlers::account::service::access::PasswordLoginError::Repository(error) => {
            RouteError::from(error)
        }
        crate::handlers::account::service::access::PasswordLoginError::Password(error) => {
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
    let site_config = depot.site_config()?;
    let url_builder = depot.url_builder()?;
    let contrix_config = depot.contrix_config()?;
    let key_store = depot.key_store()?;
    let templates = depot.templates()?;
    let homeserver = depot.homeserver()?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
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
                "authorization_code, code_verifier, redirect_uri, issuer, token_endpoint, client_id, login_hint, and device_id are required"
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
    let expected_issuer = url_builder.oidc_issuer();
    let expected_token_endpoint = url_builder.oauth_token_endpoint();
    if issuer != expected_issuer || token_endpoint != expected_token_endpoint {
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_discovery_binding"),
            viewer: None,
            session_grant: None,
            warnings: vec![format!(
                "OIDC exchange metadata does not match this coauth issuer/token surface: expected issuer={} token_endpoint={} but received issuer={} token_endpoint={}",
                expected_issuer, expected_token_endpoint, issuer, token_endpoint
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

    let oauth_code_grant = OAuthAuthorizationCodeGrant {
        code: input.authorization_code.trim().to_owned(),
        redirect_uri: Some(redirect_uri.clone()),
        code_verifier: Some(input.code_verifier.trim().to_owned()),
    };
    let oauth_token_reply = match crate::handlers::oauth2::token_service::exchange_authorization_code(
        &mut rng,
        &clock,
        &activity_tracker,
        &oauth_code_grant,
        &oauth2_client,
        &key_store,
        &url_builder,
        &contrix_config,
        &site_config,
        repo,
        &homeserver,
        &templates,
        user_agent,
    )
    .await
    {
        Ok((reply, next_repo)) => {
            repo = next_repo;
            reply
        }
        Err(
            crate::handlers::oauth2::token_service::AuthorizationCodeExchangeError::GrantNotFound
            | crate::handlers::oauth2::token_service::AuthorizationCodeExchangeError::InvalidGrant(_),
        ) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_authorization_code"),
                viewer: None,
                session_grant: None,
                warnings: vec![
                    "authorization_code could not be exchanged through the local OAuth2 token service"
                        .to_owned(),
                ],
            }));
            return Ok(());
        }
        Err(
            crate::handlers::oauth2::token_service::AuthorizationCodeExchangeError::UnauthorizedClient(_)
            | crate::handlers::oauth2::token_service::AuthorizationCodeExchangeError::UnexpectedClient { .. },
        ) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_client"),
                viewer: None,
                session_grant: None,
                warnings: vec![
                    "authorization_code is not bound to the requested OAuth2 client".to_owned(),
                ],
            }));
            return Ok(());
        }
        Err(crate::handlers::oauth2::token_service::AuthorizationCodeExchangeError::PkceVerification(error)) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_code_verifier"),
                viewer: None,
                session_grant: None,
                warnings: vec![format!("pkce verification failed: {error}")],
            }));
            return Ok(());
        }
        Err(crate::handlers::oauth2::token_service::AuthorizationCodeExchangeError::BadRequest) => {
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_request"),
                viewer: None,
                session_grant: None,
                warnings: vec![
                    "authorization_code exchange request was rejected by the local OAuth2 token service"
                        .to_owned(),
                ],
            }));
            return Ok(());
        }
        Err(error) => {
            return Err(RouteError::Internal(Box::new(error)));
        }
    };

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
            "TODO(contrix): replace the local OAuth2 token-service bridge with a full upstream token endpoint exchange or proof/introspection validation before treating this flow as production-grade.".to_owned(),
            format!("device_id={device_id}"),
            format!("redirect_uri={}", redirect_uri),
            format!("issuer={issuer}"),
            format!("token_endpoint={token_endpoint}"),
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
            "authorization_code_exchanged_via_local_token_service=true".to_owned(),
            "oauth_access_token_issued=true".to_owned(),
            format!(
                "oauth_refresh_token_issued={}",
                oauth_token_reply.refresh_token.is_some()
            ),
            format!("oauth_id_token_issued={}", oauth_token_reply.id_token.is_some()),
            format!(
                "callback_state_checked={}",
                input.expected_state.is_some()
            ),
        ],
    }));
    Ok(())
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
