//! REST API endpoints for authentication flows (login, logout, providers).
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. Session cookies are set/cleared as side effects.

pub mod oidc_bridge;
pub mod passkey;

pub use oidc_bridge::{
    auth_bridge_describe, integration_describe, oidc_browser_bridge_session, oidc_code_exchange,
    oidc_exchange_describe,
};
pub use passkey::{
    auth_finish as passkey_auth_finish, auth_start as passkey_auth_start,
    register_finish as passkey_register_finish, register_start as passkey_register_start,
};

use std::sync::LazyLock;

use coauth_data::UrlBuilder;
use opentelemetry::{Key, KeyValue, metrics::Counter};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};

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
    services::dpop::{DpopError, DpopVerifier, dpop_header_from_request, dpop_htu},
};

/// Extract a DPoP proof from the "kickoff" request — i.e. the initial
/// auth-side request that mints a session grant (login or
/// `oidc/exchange`). When no `DPoP` header is present we return
/// `Ok(None)` so the grant is issued unbound (legacy clients keep
/// working); when the header is present but malformed we surface the
/// failure so the caller can emit `invalid_dpop_proof` rather than
/// silently degrade.
///
/// On these kickoff endpoints we do NOT require an `ath` claim — there
/// is no access token to bind to yet; the proof's `jkt` becomes the
/// `cnf.jkt` of the newly issued grant.
pub(crate) async fn extract_dpop_jkt_for_kickoff(
    req: &salvo::Request,
    url_builder: &UrlBuilder,
) -> Result<Option<String>, DpopError> {
    let Some(header) = dpop_header_from_request(req) else {
        return Ok(None);
    };
    let verifier = DpopVerifier::shared();
    let now = chrono::Utc::now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(Some(&public_base), req);
    let result = verifier.verify(&header, &htm, &htu, now, None).await?;
    Ok(Some(result.jkt))
}

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
pub struct LoginReqBody {
    pub handle: String,
    pub password: String,
    /// Audience the client wants the issued session grant to be bound to.
    /// Must exactly match a configured principal-server audience. When
    /// omitted, the caller is implicitly accepting the deployment's only
    /// configured `server_name`; deployments with zero or multiple
    /// principal servers will reject the request.
    #[serde(default)]
    pub audience: Option<String>,
    /// Solved CAPTCHA token, supplied when the deployment has a CAPTCHA
    /// provider configured (`site.captcha`). The token is verified with
    /// the configured provider before the credentials are checked.
    #[serde(default)]
    pub captcha_token: Option<String>,
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

#[derive(Serialize, ToSchema)]
pub struct ViewerInfo {
    pub id: String,
    pub handle: String,
    pub did: String,
    pub federated_handle: String,
    pub principal_id: String,
    pub display_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantKind {
    PrincipalSession,
    PushRegister,
    DevicePairing,
    AdminBridge,
}

#[derive(Serialize, ToSchema)]
pub struct SessionGrantInfo {
    pub kind: SessionGrantKind,
    pub id: String,
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
    let principal_server = depot.principal_server()?;
    let repo = depot.repo().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(std::borrow::ToOwned::to_owned);

    // Same DPoP extraction as `oidc_code_exchange`: a present-but-broken
    // proof must reject the login outright; absence is allowed for the
    // legacy password-bootstrap path.
    let dpop_jkt = match extract_dpop_jkt_for_kickoff(req, &url_builder).await {
        Ok(jkt) => jkt,
        Err(error) => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_dpop_proof"),
                viewer: None,
                session_grant: None,
                warnings: vec![error.to_string()],
            }));
            return Ok(());
        }
    };

    let input: LoginReqBody = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    // Validate fields
    if input.handle.is_empty() || input.password.is_empty() {
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

    if site_config.captcha.is_some() {
        let http_client = depot.http_client()?;
        if let Err(error) = crate::handlers::captcha::verify_token(
            activity_tracker.ip(),
            &http_client,
            url_builder.public_hostname(),
            site_config.captcha.as_ref(),
            input.captcha_token.as_deref(),
        )
        .await
        {
            tracing::warn!(error = %error, "CAPTCHA verification failed on login");
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("captcha_failed"),
                viewer: None,
                session_grant: None,
                warnings: Vec::new(),
            }));
            return Ok(());
        }
    }

    let requested_audience = input.audience.clone();

    match login_with_password(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        &limiter,
        principal_server.as_ref(),
        &url_builder,
        &contrix_config,
        &site_config,
        PasswordLoginRequest {
            username_or_email: input.handle,
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
            let display_name = match principal_server.query_user(&user.handle).await {
                Ok(info) => info.displayname,
                Err(_) => None,
            };
            let grant_target = match contrix::password_login_session_grant_target(
                &url_builder,
                &contrix_config,
                requested_audience.as_deref(),
            ) {
                Ok(target) => target,
                Err(error) => {
                    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(LoginResponse {
                        status: "error",
                        error: Some("invalid_audience"),
                        viewer: None,
                        session_grant: None,
                        warnings: vec![error.to_string()],
                    }));
                    return Ok(());
                }
            };
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
                None,
                dpop_jkt.clone(),
            )
            .map_err(|error| RouteError::Internal(Box::new(error)))?;

            let mut grant_repo = depot.repo().await?;
            let persisted_session_grant = contrix::persist_session_grant(
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
                        handle: user.handle.clone(),
                        did: contrix::user_did_for(&url_builder, &contrix_config, &user),
                        federated_handle: contrix::user_handle(&url_builder, &user),
                        principal_id: principal_server.principal_id(&user.handle),
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
