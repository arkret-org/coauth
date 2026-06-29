//! REST API endpoints for authentication strands (login, logout, providers).
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. Session cookies are set/cleared as side effects.

pub mod oidc_bridge;
pub mod passkey;

use std::sync::LazyLock;

use coauth_account_types::{
    CurrentAccountInfo, LoginOutcome, LoginReqBody, LogoutOutcome, ProviderInfo, ProvidersOutcome,
    SessionGrantKind, SessionGrantOneShotInfo, SessionGrantPrincipalServerInfo, ViewerInfo,
};
use coauth_data::oauth::{LoginHint, OAuthAuthorizationGrantRepository};
use coauth_data::{AuthorizationGrant, PostAuthAction, SiteConfig, UrlBuilder};
use coauth_jose::jwk::PublicJsonWebKey;
pub use oidc_bridge::integration_describe;
use opentelemetry::metrics::Counter;
use opentelemetry::{Key, KeyValue};
pub use passkey::{
    auth_finish as passkey_auth_finish, auth_start as passkey_auth_start,
    register_finish as passkey_register_finish, register_start as passkey_register_start,
};
use salvo::prelude::*;
use serde::Deserialize;

use super::{
    DepotExt, NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    make_clock, make_rng,
};
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
    depot: &Depot,
    url_builder: &UrlBuilder,
) -> Result<Option<DpopSessionBinding>, DpopError> {
    let Some(header) = dpop_header_from_request(req) else {
        return Ok(None);
    };
    let verifier = depot
        .dpop_verifier()
        .unwrap_or_else(|_| DpopVerifier::shared());
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

#[derive(Deserialize, Default)]
struct ProvidersQuery {
    #[serde(flatten)]
    post_auth_action: Option<PostAuthAction>,
}

// ── POST /_coauth/account/auth/login ────────────────────────────────────

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
    let dpop_binding = match extract_dpop_binding_for_kickoff(req, depot, &url_builder).await {
        Ok(jkt) => jkt,
        Err(error) => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(
                LoginOutcome::error("invalid_dpop_proof").with_warnings(vec![error.to_string()]),
            ));
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
        res.render(Json(LoginOutcome::error("invalid_credentials")));
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
            res.render(Json(LoginOutcome::error("captcha_failed")));
            return Ok(());
        }
    }

    let requested_audience = input.audience.clone();
    let requested_device_id = input.device_id.clone();

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
            res.render(Json(LoginOutcome::error("password_login_disabled")));
            Ok(())
        }
        PasswordLoginOutcome::InvalidCredentials => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginOutcome::error("invalid_credentials")));
            Ok(())
        }
        PasswordLoginOutcome::RateLimited => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(LoginOutcome::error("rate_limited")));
            Ok(())
        }
        PasswordLoginOutcome::AccountDeactivated { .. } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginOutcome::error("account_deactivated")));
            Ok(())
        }
        PasswordLoginOutcome::AccountLocked { .. } => {
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
            res.render(Json(LoginOutcome::error("account_locked")));
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
                let mut viewer_repo = depot.repo().await?;
                let viewer_did = cokret::published_principal_did_for_user(
                    &mut viewer_repo,
                    &cokret_config,
                    &user,
                )
                .await?;
                viewer_repo.cancel().await.ok();
                cookie_jar.finalize(
                    res,
                    Json(LoginOutcome::success(
                        Some(ViewerInfo {
                            id: NodeType::User.serialize(user.id),
                            handle: user.localpart.clone(),
                            did: viewer_did,
                            federated_handle: cokret::user_handle(&url_builder, &user),
                            principal_id: principal_server.principal_id(&user.localpart),
                            display_name,
                        }),
                        None,
                        vec![
                            "password_login_session_grants_disabled; use the OIDC/passkey bridge"
                                .to_owned(),
                        ],
                    )),
                );
                return Ok(());
            }
            let Some(dpop_binding) = dpop_binding else {
                PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    LoginOutcome::error("invalid_dpop_proof").with_warnings(vec![
                        "password login session grants require a valid DPoP proof".to_owned(),
                    ]),
                ));
                return Ok(());
            };
            let Some(device_id) = requested_device_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    LoginOutcome::error("invalid_device_id").with_warnings(vec![
                        "password login session grants require device_id".to_owned(),
                    ]),
                ));
                return Ok(());
            };
            let device_id = match cokret_core::DeviceId::new(device_id.to_owned()) {
                Ok(device_id) => device_id,
                Err(error) => {
                    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(
                        LoginOutcome::error("invalid_device_id")
                            .with_warnings(vec![format!("device_id is invalid: {error}")]),
                    ));
                    return Ok(());
                }
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
                    res.render(Json(
                        LoginOutcome::error("invalid_audience")
                            .with_warnings(vec![error.to_string()]),
                    ));
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
            let principal_did = match oidc_bridge::ensure_principal_did_for_user_committed(
                depot,
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
                    res.render(Json(
                        LoginOutcome::error("principal_did_minting_failed")
                            .with_warnings(vec![message]),
                    ));
                    return Ok(());
                }
            };
            let account_handle = oidc_bridge::registration_handle_for_principal_endpoint(
                grant_target.principal_server_endpoint.as_deref(),
                &user.localpart,
            );
            let localpart_sync_bearer = oidc_bridge::principal_server_operation_bearer(
                &cokret_config,
                &grant_target.audience,
            );
            if let Err(message) = oidc_bridge::ensure_soland_account_registered(
                &http_client,
                grant_target.principal_server_endpoint.as_deref(),
                &principal_did,
                localpart_sync_bearer,
                Some(&user.localpart),
                account_handle.as_deref(),
                display_name.as_deref(),
                Some(device_id.as_str()),
            )
            .await
            {
                PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
                res.render(Json(
                    LoginOutcome::error("principal_account_registration_failed")
                        .with_warnings(vec![message]),
                ));
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
                oidc_bridge::principal_session_grant_scopes(device_id.as_str()),
                Some(&principal_did),
                Some(dpop_binding.jkt),
            )
            .map_err(|error| RouteError::Internal(Box::new(error)))?;

            let mut grant_repo = depot.repo().await?;
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
                Json(LoginOutcome::success(
                    Some(ViewerInfo {
                        id: NodeType::User.serialize(user.id),
                        handle: user.localpart.clone(),
                        did: Some(principal_did),
                        federated_handle: cokret::user_handle(&url_builder, &user),
                        principal_id: principal_server.principal_id(&user.localpart),
                        display_name,
                    }),
                    Some(SessionGrantOneShotInfo {
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
                    Vec::new(),
                )),
            );
            Ok(())
        }
    }
}

// ── POST /_coauth/account/auth/logout ───────────────────────────────────

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

    cookie_jar.finalize(res, Json(LogoutOutcome::success()));
    Ok(())
}

// ── GET /_coauth/account/auth/providers ─────────────────────────────────

/// List all enabled upstream OAuth providers and site configuration flags
/// relevant to the login/registration UI.
#[endpoint]
pub async fn providers(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ProvidersOutcome>, RouteError> {
    let site_config = depot.site_config()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo().await?;
    let query: ProvidersQuery = req.parse_queries().unwrap_or_else(|err| {
        // A malformed `post_auth_action` query must not silently degrade into a
        // hint-less response with no diagnostic trail; record it at debug level.
        tracing::debug!(error = %err, "failed to parse providers query parameters");
        ProvidersQuery::default()
    });

    let upstream_providers = load_enabled_upstream_providers(&mut repo).await?;
    let login_hint = provider_login_hint(&mut repo, &query, &site_config, &url_builder).await?;
    let current_account = extract_session_info(req, depot)
        .load_active_session(&mut repo)
        .await?
        .map(|session| {
            let user = session.user;
            CurrentAccountInfo {
                id: NodeType::User.serialize(user.id),
                username: user.localpart.clone(),
                handle: cokret::user_handle(&url_builder, &user),
                display_name: user.display_name,
            }
        });

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
        login_hint,
        current_account,
    }))
}

async fn provider_login_hint(
    repo: &mut coauth_data::BoxRepository,
    query: &ProvidersQuery,
    site_config: &SiteConfig,
    url_builder: &UrlBuilder,
) -> Result<Option<String>, RouteError> {
    let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = query.post_auth_action.as_ref()
    else {
        return Ok(None);
    };
    let Some(grant) = repo.oauth_authorization_grant().lookup(*id).await? else {
        return Ok(None);
    };
    // `providers` is an unauthenticated, pre-login endpoint and `lookup` is a
    // bare primary-key fetch with no owner/session binding. The login hint only
    // serves to pre-fill the sign-in form *before* a grant is fulfilled, so we
    // refuse to echo back the hint of any grant that has already progressed past
    // `pending`. This closes the cross-subject PII read surface: a fulfilled or
    // exchanged grant's hint is never disclosed to a fresh anonymous caller.
    if !grant.is_pending() {
        return Ok(None);
    }
    Ok(password_form_login_hint(&grant, site_config, url_builder))
}

fn password_form_login_hint(
    grant: &AuthorizationGrant,
    site_config: &SiteConfig,
    url_builder: &UrlBuilder,
) -> Option<String> {
    match grant.parse_login_hint() {
        LoginHint::Username(username) => Some(username.to_owned()),
        LoginHint::Email(email) if site_config.login_with_email_allowed => Some(email.to_string()),
        _ => grant
            .login_hint
            .as_deref()
            .and_then(|hint| cokret::parse_local_handle(url_builder, hint)),
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::clock::{Clock, MockClock};
    use rand_core::SeedableRng;

    use super::*;
    use crate::handlers::test_utils::test_site_config;

    fn grant_with_hint(login_hint: &str) -> AuthorizationGrant {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        AuthorizationGrant {
            login_hint: Some(login_hint.to_owned()),
            ..AuthorizationGrant::sample(now, &mut rng)
        }
    }

    fn test_url_builder() -> UrlBuilder {
        UrlBuilder::new("https://auth.local.host/".parse().unwrap(), None, None)
    }

    #[test]
    fn password_form_login_hint_accepts_username() {
        let site_config = test_site_config();
        let url_builder = test_url_builder();
        let grant = grant_with_hint("chris");

        assert_eq!(
            password_form_login_hint(&grant, &site_config, &url_builder).as_deref(),
            Some("chris")
        );
    }

    #[test]
    fn password_form_login_hint_converts_local_canonical_handle() {
        let site_config = test_site_config();
        let url_builder = test_url_builder();
        let grant = grant_with_hint("chris:auth.local.host");

        assert_eq!(
            password_form_login_hint(&grant, &site_config, &url_builder).as_deref(),
            Some("chris")
        );
    }

    #[test]
    fn password_form_login_hint_rejects_remote_or_opaque_colon_hint() {
        let site_config = test_site_config();
        let url_builder = test_url_builder();

        assert_eq!(
            password_form_login_hint(
                &grant_with_hint("chris:remote.example"),
                &site_config,
                &url_builder,
            ),
            None
        );
        assert_eq!(
            password_form_login_hint(
                &grant_with_hint("something:anything"),
                &site_config,
                &url_builder
            ),
            None
        );
    }
}
