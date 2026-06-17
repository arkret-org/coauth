//! REST API endpoints for authentication strands (login, logout, providers).
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. Session cookies are set/cleared as side effects.

pub mod oidc_bridge;
pub mod passkey;

use std::sync::LazyLock;

use coauth_data::UrlBuilder;
use coauth_jose::jwk::PublicJsonWebKey;
pub use oidc_bridge::integration_describe;
use opentelemetry::metrics::Counter;
use opentelemetry::{Key, KeyValue};
pub use passkey::{
    auth_finish as passkey_auth_finish, auth_start as passkey_auth_start,
    register_finish as passkey_register_finish, register_start as passkey_register_start,
};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{DepotExt, NodeType, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::handlers::account::service::access::{
    PasswordLoginOutcome, PasswordLoginRequestBody, load_enabled_upstream_providers,
    login_with_password, logout_browser_session,
};
use crate::handlers::{METER, RequesterFingerprint, cokret};
use crate::salvo_utils::session::SessionInfoExt;
use crate::services::dpop::{DpopError, DpopVerifier, dpop_header_from_request, dpop_htu};

#[derive(Clone)]
pub(crate) struct DpopSessionBinding {
    pub jkt: String,
    pub public_jwk: PublicJsonWebKey,
}

/// Extract a DPoP proof from the "kickoff" request — i.e. the initial
/// auth-side request that mints a session grant (login or
/// `oidc/exchange`). When no `DPoP` header is present we return
/// `Ok(None)` so the grant is issued unbound; when the header is present
/// but malformed we surface the failure so the caller can emit
/// `invalid_dpop_proof` rather than silently degrade.
///
/// On these kickoff endpoints we do NOT require an `ath` claim — there
/// is no access token to bind to yet; the proof's `jkt` becomes the
/// `cnf.jkt` of the newly issued grant.
pub(crate) async fn extract_dpop_binding_for_kickoff(
    req: &salvo::Request,
    url_builder: &UrlBuilder,
) -> Result<Option<DpopSessionBinding>, DpopError> {
    let Some(header) = dpop_header_from_request(req) else {
        return Ok(None);
    };
    let verifier = DpopVerifier::shared();
    let now = chrono::Utc::now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let result = verifier.verify(&header, &htm, &htu, now, None).await?;
    Ok(Some(DpopSessionBinding {
        jkt: result.jkt,
        public_jwk: result.jwk,
    }))
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
pub struct LoginOutcome {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer: Option<ViewerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_grant: Option<SessionGrantOneShotInfo>,
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
pub struct SessionGrantOneShotInfo {
    pub kind: SessionGrantKind,
    pub id: String,
    pub grant_jwt: String,
    pub session_public_key: String,
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
pub struct LogoutOutcome {
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct ProvidersOutcome {
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
// ── POST /_coauth/gate/account/auth/login ────────────────────────────────────

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
    let cokret_config = depot.cokret_config()?;
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
    // proof rejects the login outright, and session-grant issuance below
    // requires a verified proof-bound public key.
    let dpop_binding = match extract_dpop_binding_for_kickoff(req, &url_builder).await {
        Ok(jkt) => jkt,
        Err(error) => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(LoginOutcome {
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
        res.render(Json(LoginOutcome {
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
            res.render(Json(LoginOutcome {
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
        &cokret_config,
        &site_config,
        PasswordLoginRequestBody {
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
            res.render(Json(LoginOutcome {
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
            res.render(Json(LoginOutcome {
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
            res.render(Json(LoginOutcome {
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
            res.render(Json(LoginOutcome {
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
            res.render(Json(LoginOutcome {
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
            let display_name = match principal_server.query_user(&user.localpart).await {
                Ok(info) => info.displayname,
                Err(_) => None,
            };
            if !cokret_config.password_login_session_grants_enabled {
                cookie_jar.finalize(
                    res,
                    Json(LoginOutcome {
                        status: "success",
                        error: None,
                        viewer: Some(ViewerInfo {
                            id: NodeType::User.serialize(user.id),
                            handle: user.localpart.clone(),
                            did: cokret::user_did_for(&url_builder, &cokret_config, &user),
                            federated_handle: cokret::user_handle(&url_builder, &user),
                            principal_id: principal_server.principal_id(&user.localpart),
                            display_name,
                        }),
                        session_grant: None,
                        warnings: vec![
                            "password_login_session_grants_disabled; use the OIDC/passkey bridge"
                                .to_owned(),
                        ],
                    }),
                );
                return Ok(());
            }
            let Some(dpop_binding) = dpop_binding else {
                PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(LoginOutcome {
                    status: "error",
                    error: Some("invalid_dpop_proof"),
                    viewer: None,
                    session_grant: None,
                    warnings: vec![
                        "password login session grants require a valid DPoP proof".to_owned(),
                    ],
                }));
                return Ok(());
            };
            let grant_target = match cokret::password_login_session_grant_target(
                &url_builder,
                &cokret_config,
                requested_audience.as_deref(),
            ) {
                Ok(target) => target,
                Err(error) => {
                    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(LoginOutcome {
                        status: "error",
                        error: Some("invalid_audience"),
                        viewer: None,
                        session_grant: None,
                        warnings: vec![error.to_string()],
                    }));
                    return Ok(());
                }
            };
            // TODO(cokret): replace password bootstrap minting with the real
            // coauth-owned OIDC/passkey exchange and proof-bound grant issuance.
            //
            // STATUS: scaffold — disabled by default; NOT for production.
            // CATEGORY: P0 / auth-issuance.
            // RISK: this path mints a principal-server session grant
            //   directly from a password login without the canonical
            //   OIDC `authorize -> token` ceremony. It bypasses
            //   per-grant scope negotiation, PKCE binding, and the
            //   proof-of-possession strand that real deployments
            //   require. Acceptable for the bring-up phase because it
            //   keeps the development loop short, but MUST be replaced
            //   before any external relying party trusts these grants. The
            //   handler now requires
            //   `cokret.password_login_session_grants_enabled=true` and a
            //   valid DPoP proof before this branch can run.
            // PRE-PROD CHECKLIST:
            //   - swap to passkey / OIDC exchange via
            //     `crate::handlers::account::auth::oidc_bridge`.
            //   - bind the grant `cnf.jkt` to a DPoP proof carried on the actual exchange request
            //     (not the kickoff one).
            //   - enforce policy on scopes the caller may request.
            //   (TODO scaffold — pre-production checklist above.)
            //
            // Subject parity with the OIDC bridge: the grant subject (and
            // `viewer.did`) MUST be the soland-minted `did:webvh:…` principal
            // DID, not the coauth-local `user_did_for` fallback. The fallback
            // anchors the actor identity on coauth's own host
            // (`did:web:<coauth-host>:users:<ulid>`), which diverges from the
            // principal DID the bridge mints for the same user — every event
            // the client then writes is attributed to a DID that no DID
            // service resolves under the principal server's authority.
            let http_client = depot.http_client()?;
            let encrypter = depot.encrypter()?;
            let mut grant_repo = depot.repo().await?;
            let principal_did = match oidc_bridge::ensure_principal_did_for_user(
                &mut grant_repo,
                &mut rng,
                &clock,
                &encrypter,
                &http_client,
                &url_builder,
                &cokret_config,
                &user,
                &grant_target.audience,
            )
            .await
            {
                Ok(did) => did,
                Err(message) => {
                    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                    res.render(Json(LoginOutcome {
                        status: "error",
                        error: Some("principal_did_minting_failed"),
                        viewer: None,
                        session_grant: None,
                        warnings: vec![message],
                    }));
                    return Ok(());
                }
            };
            let account_handle = oidc_bridge::registration_handle_for_audience(
                &grant_target.audience,
                &user.localpart,
            );
            if let Err(message) = oidc_bridge::ensure_soland_account_registered(
                &http_client,
                grant_target.principal_server_endpoint.as_deref(),
                &principal_did,
                account_handle.as_deref(),
                display_name.as_deref(),
                None,
            )
            .await
            {
                PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                res.render(Json(LoginOutcome {
                    status: "error",
                    error: Some("principal_account_registration_failed"),
                    viewer: None,
                    session_grant: None,
                    warnings: vec![message],
                }));
                return Ok(());
            }
            let session_grant = cokret::issue_session_grant_for_audience(
                &clock,
                &url_builder,
                &cokret_config,
                &key_store,
                &user_session,
                dpop_binding.public_jwk,
                grant_target.audience.clone(),
                vec![cokret::PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned()],
                Some(&principal_did),
                Some(dpop_binding.jkt),
            )
            .map_err(|error| RouteError::Internal(Box::new(error)))?;

            let persisted_session_grant = cokret::persist_session_grant(
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
                Json(LoginOutcome {
                    status: "success",
                    error: None,
                    viewer: Some(ViewerInfo {
                        id: NodeType::User.serialize(user.id),
                        handle: user.localpart.clone(),
                        did: principal_did,
                        federated_handle: cokret::user_handle(&url_builder, &user),
                        principal_id: principal_server.principal_id(&user.localpart),
                        display_name,
                    }),
                    session_grant: Some(SessionGrantOneShotInfo {
                        kind: SessionGrantKind::PrincipalSession,
                        id: persisted_session_grant.id.to_string(),
                        grant_jwt: session_grant.grant_jwt,
                        session_public_key: session_grant.session_public_key,
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

// ── POST /_coauth/gate/account/auth/logout ───────────────────────────────────

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

    cookie_jar.finalize(res, Json(LogoutOutcome { status: "success" }));
    Ok(())
}

// ── GET /_coauth/gate/account/auth/providers ─────────────────────────────────

/// List all enabled upstream OAuth providers and site configuration flags
/// relevant to the login/registration UI.
#[endpoint]
pub async fn providers(depot: &Depot) -> Result<Json<ProvidersOutcome>, RouteError> {
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

    Ok(Json(ProvidersOutcome {
        providers: provider_list,
        password_login_enabled: site_config.password_login_enabled,
        password_registration_enabled: site_config.password_registration_enabled,
        account_recovery_allowed: site_config.account_recovery_allowed,
    }))
}
