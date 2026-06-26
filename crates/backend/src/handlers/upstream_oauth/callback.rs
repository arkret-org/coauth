use std::collections::HashMap;
use std::sync::LazyLock;

use coauth_data::upstream_oauth::{
    UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
};
use coauth_data::{
    Clock, UpstreamOAuthProvider, UpstreamOAuthProviderResponseMode,
    UpstreamOAuthProviderTokenAuthMethod,
};
use coauth_jose::claims::TokenHash;
use coauth_templates::FormPostContext;
use oauth_types::errors::ClientErrorCode;
use oauth_types::requests::AccessTokenRequest;
use opentelemetry::metrics::Counter;
use opentelemetry::{Key, KeyValue};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use ulid::Ulid;

use super::cache::LazyProviderInfos;
use super::template::{AttributeMappingContext, environment};
use super::{UpstreamSessionsCookie, client_credentials_for_provider};
use crate::handlers::METER;
use crate::handlers::account::DepotExt;
use crate::oidc_client::requests::jose::JwtVerificationData;
use crate::oidc_client::types::client_credentials::ClientCredentials;
use crate::salvo_utils::cookies::TimedCookie;
use crate::salvo_utils::{GenericError, InternalError};

static CALLBACK_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.upstream_oauth.callback")
        .with_description("Number of requests to the upstream OAuth callback endpoint")
        .build()
});
const PROVIDER: Key = Key::from_static_str("provider");
const RESULT: Key = Key::from_static_str("result");
const ALLOW_NON_STANDARD_UPSTREAM_OAUTH_ENV: &str = "COAUTH_ALLOW_NON_STANDARD_UPSTREAM_OAUTH";

#[derive(Serialize, Deserialize)]
pub struct Params {
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    /// An extra parameter to track whether the POST request was re-made by us
    /// to the same URL to escape Same-Site cookies restrictions
    #[serde(default)]
    did_repost_to_itself: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ClientErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,

    #[serde(flatten)]
    extra_callback_parameters: Option<serde_json::Value>,
}

impl Params {
    /// Returns true if none of the fields are set
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.is_none()
            && self.code.is_none()
            && self.error.is_none()
            && self.error_description.is_none()
            && self.error_uri.is_none()
    }
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Provider not found")]
    ProviderNotFound,

    #[error("Provider mismatch")]
    ProviderMismatch,

    #[error("Session already completed")]
    AlreadyCompleted,

    #[error("State parameter mismatch")]
    StateMismatch,

    #[error("Missing state parameter")]
    MissingState,

    #[error("Missing code parameter")]
    MissingCode,

    #[error("Could not extract subject from ID token")]
    ExtractSubject(#[source] minijinja::Error),

    #[error("Subject is empty")]
    EmptySubject,

    #[error("Error from the provider: {error}")]
    ClientError {
        error: ClientErrorCode,
        error_description: Option<String>,
    },

    #[error("Missing session cookie")]
    MissingCookie,

    #[error("Missing query parameters")]
    MissingQueryParams,

    #[error("Missing form parameters")]
    MissingFormParams,

    #[error("Invalid response mode, expected '{expected}'")]
    InvalidResponseMode {
        expected: UpstreamOAuthProviderResponseMode,
    },

    /// A non-standard provider (QQ / Feishu / Lark / DingTalk / WeChat /
    /// WeCom) MUST contact the upstream over HTTPS. These providers do
    /// not return a signed ID token, so the channel is the only thing
    /// authenticating the userinfo payload — plaintext HTTP would let
    /// an on-path attacker forge identities.
    #[error("Non-standard provider endpoint must be HTTPS (got '{scheme}' for {endpoint})")]
    InsecureUpstreamEndpoint {
        endpoint: &'static str,
        scheme: String,
    },

    #[error(
        "Non-standard upstream OAuth provider '{provider_kind}' is disabled by default; set \
         COAUTH_ALLOW_NON_STANDARD_UPSTREAM_OAUTH=true only after accepting userinfo-only \
         TLS-bound identity risk"
    )]
    NonStandardProviderDisabled { provider_kind: &'static str },

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(coauth_templates::TemplateError);
impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::account::RouteError);
impl_from_error_for_route!(crate::oidc_client::error::DiscoveryError);
impl_from_error_for_route!(crate::oidc_client::error::JwksError);
impl_from_error_for_route!(crate::oidc_client::error::TokenRequestError);
impl_from_error_for_route!(crate::oidc_client::error::IdTokenError);
impl_from_error_for_route!(crate::oidc_client::error::UserInfoError);
impl_from_error_for_route!(super::ProviderCredentialsError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        match self {
            Self::Internal(e) => InternalError::new(e).render(res),
            e @ (Self::ProviderNotFound | Self::SessionNotFound) => {
                GenericError::new(StatusCode::NOT_FOUND, e).render(res);
            }
            e @ Self::NonStandardProviderDisabled { .. } => {
                GenericError::new(StatusCode::FORBIDDEN, e).render(res);
            }
            e => GenericError::new(StatusCode::BAD_REQUEST, e).render(res),
        }
    }
}

/// SECURITY: every endpoint we hit for a non-standard provider MUST
/// be HTTPS. These providers (QQ / Feishu / Lark / DingTalk / WeChat
/// / WeCom) do not return a signed ID token, so the TLS channel is
/// the only thing authenticating the response body. Self-signed
/// certificates are rejected automatically by the platform verifier
/// configured on the shared HTTP client (see
/// `outbound_http::reqwest_client`); this helper guards against a
/// misconfigured override URL that downgrades the scheme to `http`.
fn require_https_endpoint(name: &'static str, url: &::url::Url) -> Result<(), RouteError> {
    if url.scheme().eq_ignore_ascii_case("https") {
        Ok(())
    } else {
        Err(RouteError::InsecureUpstreamEndpoint {
            endpoint: name,
            scheme: url.scheme().to_owned(),
        })
    }
}

fn non_standard_provider_kind(
    method: UpstreamOAuthProviderTokenAuthMethod,
) -> Option<&'static str> {
    match method {
        UpstreamOAuthProviderTokenAuthMethod::QQConnect => Some("qq_connect"),
        UpstreamOAuthProviderTokenAuthMethod::Feishu => Some("feishu"),
        UpstreamOAuthProviderTokenAuthMethod::Lark => Some("lark"),
        UpstreamOAuthProviderTokenAuthMethod::DingTalk => Some("dingtalk"),
        UpstreamOAuthProviderTokenAuthMethod::WeChat => Some("wechat"),
        UpstreamOAuthProviderTokenAuthMethod::WeCom => Some("wecom"),
        _ => None,
    }
}

fn non_standard_upstream_oauth_allowed() -> bool {
    non_standard_upstream_oauth_allowed_from_env(
        std::env::var(ALLOW_NON_STANDARD_UPSTREAM_OAUTH_ENV)
            .ok()
            .as_deref(),
    )
}

fn non_standard_upstream_oauth_allowed_from_env(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let value = value.trim();
        !(value.is_empty()
            || value.eq_ignore_ascii_case("0")
            || value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("no"))
    })
}

/// Emit a structured audit record for each callback that took the
/// non-standard provider path. Used by SIEM / ops to flag strands where
/// the identity payload came from a userinfo-only strand rather than a
/// signed ID token (no JWT signature, no `nonce` binding, no audience
/// check) so that downstream policy can apply extra scrutiny.
///
/// The `provider_kind` label is a short stable identifier (e.g.
/// `"qq_connect"`, `"feishu"`); the `session_had_nonce` flag tells
/// the auditor whether the original `/authorize` request bound a
/// nonce that we ultimately could not verify (because the provider
/// returned no ID token).
fn audit_non_standard_token_source(
    provider_id: ulid::Ulid,
    provider_kind: &'static str,
    session_had_nonce: bool,
) {
    tracing::info!(
        provider.id = %provider_id,
        provider.kind = provider_kind,
        non_standard_token_source = true,
        session_had_nonce,
        nonce_verifiable = false,
        "Upstream OAuth callback completed via non-standard (userinfo-only) strand; \
         identity is bound to TLS chain only — no signed ID token / nonce check possible"
    );
}

#[handler]
#[tracing::instrument(name = "handlers.upstream_oauth.callback.handler", skip_all)]
#[allow(clippy::too_many_arguments)]
pub async fn handler(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let provider_id: Ulid = req
        .param("provider_id")
        .ok_or(RouteError::ProviderNotFound)?;
    let mut rng = crate::handlers::account::make_rng();
    let clock = crate::handlers::account::make_clock();
    let metadata_cache = depot.metadata_cache()?;
    let jwks_cache = depot.jwks_cache()?;
    let mut repo = depot.repo().await?;
    let url_builder = depot.url_builder()?;
    let encrypter = depot.encrypter()?;
    let keystore = depot.key_store()?;
    let client = depot.http_client()?;
    let templates = depot.templates()?;
    let locale = crate::handlers::preferred_language(req, depot);
    let cookie_jar = depot.cookie_jar(req)?;
    let method = req.method().clone();

    // For POST requests, parse from form body; for GET requests, parse from query
    let params: Params = if method == http::Method::POST {
        req.parse_form().await.unwrap_or_else(|_| Params {
            state: None,
            did_repost_to_itself: false,
            code: None,
            error: None,
            error_description: None,
            error_uri: None,
            extra_callback_parameters: None,
        })
    } else {
        req.parse_queries().unwrap_or_else(|_| Params {
            state: None,
            did_repost_to_itself: false,
            code: None,
            error: None,
            error_description: None,
            error_uri: None,
            extra_callback_parameters: None,
        })
    };

    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    if let Some(provider_kind) = non_standard_provider_kind(provider.token_endpoint_auth_method)
        && !non_standard_upstream_oauth_allowed()
    {
        tracing::warn!(
            provider.id = %provider.id,
            provider.kind = provider_kind,
            env = ALLOW_NON_STANDARD_UPSTREAM_OAUTH_ENV,
            "Rejected non-standard upstream OAuth callback because userinfo-only identity strands are disabled by default"
        );
        return Err(RouteError::NonStandardProviderDisabled { provider_kind });
    }

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);

    if params.is_empty() {
        if method == http::Method::GET {
            return Err(RouteError::MissingQueryParams);
        }

        return Err(RouteError::MissingFormParams);
    }

    // The `Form` extractor will use the body of the request for POST requests and
    // the query parameters for GET requests. We need to then look at the method do
    // make sure it matches the expected `response_mode`
    match (provider.response_mode, &method) {
        (Some(UpstreamOAuthProviderResponseMode::FormPost) | None, &http::Method::POST) => {
            // We set the cookies with a `Same-Site` policy set to `Lax`, so because this is
            // usually a cross-site form POST, we need to render a form with the
            // same values, which posts back to the same URL. However, there are
            // other valid reasons for the cookie to be missing, so to track whether we did
            // this POST ourselves, we set a flag.
            if sessions_cookie.is_empty() && !params.did_repost_to_itself {
                let params = Params {
                    did_repost_to_itself: true,
                    ..params
                };
                let context = FormPostContext::new_for_current_url(params).with_language(&locale);
                let html = templates.render_form_post(&context)?;
                res.render(Text::Html(html));
                return Ok(());
            }
        }
        (None, _) | (Some(UpstreamOAuthProviderResponseMode::Query), &http::Method::GET) => {}
        (Some(expected), _) => return Err(RouteError::InvalidResponseMode { expected }),
    }

    if let Some(error) = params.error {
        CALLBACK_COUNTER.add(
            1,
            &[
                KeyValue::new(PROVIDER, provider_id.to_string()),
                KeyValue::new(RESULT, "error"),
            ],
        );

        return Err(RouteError::ClientError {
            error,
            error_description: params.error_description.clone(),
        });
    }

    let Some(state) = params.state else {
        return Err(RouteError::MissingState);
    };

    let (session_id, _post_auth_action) = sessions_cookie
        .find_session(provider_id, &state)
        .map_err(|_| RouteError::MissingCookie)?;

    let session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    if provider.id != session.provider_id {
        // The provider in the session cookie should match the one from the URL
        return Err(RouteError::ProviderMismatch);
    }

    // Constant-time compare (COA-SEC-04): the state binds the upstream callback
    // to the session that initiated it; compare without leaking a
    // matching-prefix timing side channel.
    if !crate::util::constant_time_token_eq(&state, &session.state_str) {
        // The state in the session cookie should match the one from the params
        return Err(RouteError::StateMismatch);
    }

    if !session.is_pending() {
        // The session was already completed
        return Err(RouteError::AlreadyCompleted);
    }

    // Let's extract the code from the params, and return if there was an error
    let Some(code) = params.code else {
        return Err(RouteError::MissingCode);
    };

    CALLBACK_COUNTER.add(
        1,
        &[
            KeyValue::new(PROVIDER, provider_id.to_string()),
            KeyValue::new(RESULT, "success"),
        ],
    );

    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &client);

    // Figure out the client credentials
    let client_credentials = client_credentials_for_provider(
        &provider,
        lazy_metadata.token_endpoint().await?,
        &keystore,
        &encrypter,
    )?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    // Token exchange + claims extraction, branching on provider type
    let (id_token_raw, id_token_claims, context, userinfo) = match &client_credentials {
        // ── QQ Connect ──────────────────────────────────────────────
        ClientCredentials::QQConnect {
            client_id,
            client_secret,
        } => {
            // SECURITY: QQ Connect has no ID token. We enforce HTTPS on
            // the configured token endpoint (the userinfo endpoint URLs
            // are hard-coded in the QQ request module and are HTTPS by
            // construction). Self-signed certificates are rejected by
            // the platform verifier on the shared HTTP client.
            let token_endpoint = lazy_metadata.token_endpoint().await?;
            require_https_endpoint("token", token_endpoint)?;

            // 1. Exchange code for access token
            let token_response = crate::oidc_client::requests::qq_connect::request_access_token(
                &client,
                token_endpoint,
                client_id,
                client_secret,
                &code,
                &redirect_uri,
            )
            .await?;

            // 2. Fetch OpenID (user subject identifier)
            let openid_response = crate::oidc_client::requests::qq_connect::fetch_openid(
                &client,
                &token_response.access_token,
            )
            .await?;

            // 3. Fetch user info
            let mut userinfo_claims = crate::oidc_client::requests::qq_connect::fetch_userinfo(
                &client,
                &token_response.access_token,
                client_id,
                &openid_response.openid,
            )
            .await?;

            // Inject openid as "sub" and "openid" for template access
            userinfo_claims.insert(
                "sub".to_owned(),
                serde_json::Value::String(openid_response.openid.clone()),
            );
            userinfo_claims.insert(
                "openid".to_owned(),
                serde_json::Value::String(openid_response.openid),
            );

            let userinfo_value = serde_json::to_value(&userinfo_claims)
                .expect("serializing a HashMap<String, Value> should never fail");

            let mut context = AttributeMappingContext::new();
            context = context.with_userinfo_claims(userinfo_value.clone());
            if let Some(extra) = params.extra_callback_parameters.clone() {
                context = context.with_extra_callback_parameters(extra);
            }

            audit_non_standard_token_source(provider.id, "qq_connect", session.nonce.is_some());
            (None, None, context.build(), Some(userinfo_value))
        }

        // ── Feishu / Lark ────────────────────────────────────────────
        ClientCredentials::Feishu {
            client_id,
            client_secret,
        }
        | ClientCredentials::Lark {
            client_id,
            client_secret,
        } => {
            // SECURITY: Feishu / Lark have no signed ID token. Enforce
            // HTTPS on the configured token endpoint; the userinfo
            // endpoint comes from discovery / override and is also
            // checked. The hard-coded `app_access_token` endpoints
            // are HTTPS by construction (see `feishu.rs`).
            let token_endpoint = lazy_metadata.token_endpoint().await?;
            require_https_endpoint("token", token_endpoint)?;

            let app_token_endpoint =
                if matches!(&client_credentials, ClientCredentials::Lark { .. }) {
                    crate::oidc_client::requests::feishu::LARK_APP_TOKEN_ENDPOINT
                } else {
                    crate::oidc_client::requests::feishu::FEISHU_APP_TOKEN_ENDPOINT
                };

            // 1. Get app_access_token
            let app_token = crate::oidc_client::requests::feishu::get_app_access_token(
                &client,
                app_token_endpoint,
                client_id,
                client_secret,
            )
            .await?;

            // 2. Exchange code using app_access_token as Bearer
            let feishu_response = crate::oidc_client::requests::feishu::request_access_token(
                &client,
                token_endpoint,
                &app_token,
                &code,
            )
            .await?;

            // 3. Optionally fetch full userinfo
            let userinfo = if provider.fetch_userinfo {
                let userinfo_endpoint = lazy_metadata.userinfo_endpoint().await?;
                require_https_endpoint("userinfo", userinfo_endpoint)?;
                let ui = crate::oidc_client::requests::feishu::fetch_userinfo(
                    &client,
                    userinfo_endpoint,
                    &feishu_response.access_token,
                )
                .await?;
                Some(
                    serde_json::to_value(&ui)
                        .expect("serializing a HashMap<String, Value> should never fail"),
                )
            } else {
                None
            };

            // Token response contains user info (open_id, name, email, etc.)
            let token_claims = feishu_response.to_claims_map();

            let mut context = AttributeMappingContext::new();
            // Token response user data as id_token_claims context
            context = context.with_id_token_claims(token_claims);
            if let Some(ref ui) = userinfo {
                context = context.with_userinfo_claims(ui.clone());
            }
            if let Some(extra) = params.extra_callback_parameters.clone() {
                context = context.with_extra_callback_parameters(extra);
            }

            let kind = if matches!(&client_credentials, ClientCredentials::Lark { .. }) {
                "lark"
            } else {
                "feishu"
            };
            audit_non_standard_token_source(provider.id, kind, session.nonce.is_some());
            (None, None, context.build(), userinfo)
        }

        // ── DingTalk ──────────────────────────────────────────────────
        ClientCredentials::DingTalk {
            client_id,
            client_secret,
        } => {
            // SECURITY: DingTalk has no signed ID token. Enforce HTTPS
            // on the token + userinfo endpoints.
            let token_endpoint = lazy_metadata.token_endpoint().await?;
            require_https_endpoint("token", token_endpoint)?;

            // 1. Exchange code for access token
            let token_response = crate::oidc_client::requests::dingtalk::request_access_token(
                &client,
                token_endpoint,
                client_id,
                client_secret,
                &code,
            )
            .await?;

            // 2. Fetch user info
            let userinfo = if provider.fetch_userinfo {
                let userinfo_endpoint = lazy_metadata.userinfo_endpoint().await?;
                require_https_endpoint("userinfo", userinfo_endpoint)?;
                let ui = crate::oidc_client::requests::dingtalk::fetch_userinfo(
                    &client,
                    userinfo_endpoint,
                    &token_response.access_token,
                )
                .await?;
                Some(
                    serde_json::to_value(&ui)
                        .expect("serializing a HashMap<String, Value> should never fail"),
                )
            } else {
                None
            };

            let token_claims = token_response.to_claims_map();

            let mut context = AttributeMappingContext::new();
            context = context.with_id_token_claims(token_claims);
            if let Some(ref ui) = userinfo {
                context = context.with_userinfo_claims(ui.clone());
            }
            if let Some(extra) = params.extra_callback_parameters.clone() {
                context = context.with_extra_callback_parameters(extra);
            }

            audit_non_standard_token_source(provider.id, "dingtalk", session.nonce.is_some());
            (None, None, context.build(), userinfo)
        }

        // ── WeChat ──────────────────────────────────────────────────
        ClientCredentials::WeChat {
            client_id,
            client_secret,
        } => {
            // SECURITY: WeChat has no signed ID token. Token endpoint
            // must be HTTPS; userinfo endpoint is hard-coded HTTPS in
            // the request module.
            let token_endpoint = lazy_metadata.token_endpoint().await?;
            require_https_endpoint("token", token_endpoint)?;

            // 1. Exchange code for access token (includes openid)
            let token_response = crate::oidc_client::requests::wechat::request_access_token(
                &client,
                token_endpoint,
                client_id,
                client_secret,
                &code,
            )
            .await?;

            // 2. Fetch user info using openid
            let mut userinfo_claims = crate::oidc_client::requests::wechat::fetch_userinfo(
                &client,
                &token_response.access_token,
                &token_response.openid,
            )
            .await?;

            // Inject openid/unionid as "sub" for template access
            userinfo_claims.insert(
                "sub".to_owned(),
                serde_json::Value::String(token_response.openid.clone()),
            );
            userinfo_claims.insert(
                "openid".to_owned(),
                serde_json::Value::String(token_response.openid),
            );
            if let Some(ref unionid) = token_response.unionid {
                userinfo_claims.insert(
                    "unionid".to_owned(),
                    serde_json::Value::String(unionid.clone()),
                );
            }

            let userinfo_value = serde_json::to_value(&userinfo_claims)
                .expect("serializing a HashMap<String, Value> should never fail");

            let mut context = AttributeMappingContext::new();
            context = context.with_userinfo_claims(userinfo_value.clone());
            if let Some(extra) = params.extra_callback_parameters.clone() {
                context = context.with_extra_callback_parameters(extra);
            }

            audit_non_standard_token_source(provider.id, "wechat", session.nonce.is_some());
            (None, None, context.build(), Some(userinfo_value))
        }

        // ── WeCom (企业微信) ────────────────────────────────────────
        ClientCredentials::WeCom {
            client_id,
            client_secret,
        } => {
            // SECURITY: WeCom uses hard-coded HTTPS endpoints in
            // `wecom.rs`; no upstream-overridable URL strands through
            // here, but we still surface the audit marker so the
            // callback is visibly tied to a non-standard provider.
            // 1. Get corp access_token
            let corp_token = crate::oidc_client::requests::wecom::get_corp_access_token(
                &client,
                client_id,
                client_secret,
            )
            .await?;

            // 2. Get user identity from authorization code
            let identity =
                crate::oidc_client::requests::wecom::get_user_identity(&client, &corp_token, &code)
                    .await?;

            // Determine the subject (UserId for members, OpenId for external)
            let subject_id = identity
                .user_id
                .as_deref()
                .or(identity.open_id.as_deref())
                .unwrap_or("")
                .to_owned();

            // 3. Fetch full user profile if we have a userid and userinfo is enabled
            let userinfo = if provider.fetch_userinfo {
                if let Some(ref userid) = identity.user_id {
                    let ui = crate::oidc_client::requests::wecom::fetch_userinfo(
                        &client,
                        &corp_token,
                        userid,
                    )
                    .await?;
                    Some(
                        serde_json::to_value(&ui)
                            .expect("serializing a HashMap<String, Value> should never fail"),
                    )
                } else {
                    None
                }
            } else {
                None
            };

            let mut claims = HashMap::new();
            claims.insert("sub".to_owned(), serde_json::Value::String(subject_id));
            if let Some(ref uid) = identity.user_id {
                claims.insert("userid".to_owned(), serde_json::Value::String(uid.clone()));
            }
            if let Some(ref oid) = identity.open_id {
                claims.insert("openid".to_owned(), serde_json::Value::String(oid.clone()));
            }

            let mut context = AttributeMappingContext::new();
            context = context.with_id_token_claims(claims);
            if let Some(ref ui) = userinfo {
                context = context.with_userinfo_claims(ui.clone());
            }
            if let Some(extra) = params.extra_callback_parameters.clone() {
                context = context.with_extra_callback_parameters(extra);
            }

            audit_non_standard_token_source(provider.id, "wecom", session.nonce.is_some());
            (None, None, context.build(), userinfo)
        }

        // ── Standard OIDC strand ──────────────────────────────────────
        _ => {
            let token_response = crate::oidc_client::requests::token::request_access_token(
                &client,
                client_credentials,
                lazy_metadata.token_endpoint().await?,
                AccessTokenRequest::AuthorizationCode(
                    oauth_types::requests::AuthorizationCodeGrant {
                        code: code.clone(),
                        redirect_uri: Some(redirect_uri),
                        code_verifier: session.code_challenge_verifier.clone(),
                    },
                ),
                clock.now(),
                &mut rng,
            )
            .await?;

            let mut jwks = None;
            let mut id_token_claims = None;

            let mut context = AttributeMappingContext::new();
            if let Some(id_token) = token_response.id_token.as_ref() {
                // Resolve the JWKS URI once, then serve the keyset from the
                // shared cache (falling back to a network fetch on a miss /
                // stale entry). Cloning the URL releases the mutable borrow of
                // `lazy_metadata` so it can be reused for later endpoints.
                let jwks_uri = lazy_metadata.jwks_uri().await?.clone();
                let mut current_jwks = jwks_cache.get_or_fetch(&client, &jwks_uri).await?;

                // Verify the ID token. If verification fails because the
                // signature did not validate against the cached keyset, the
                // upstream may have rotated its signing key: force a single
                // re-fetch (bypassing the cache) and retry verification once
                // before surfacing the error.
                let verified = verify_id_token_with_rotation_retry(
                    &jwks_cache,
                    &client,
                    &jwks_uri,
                    &mut current_jwks,
                    id_token,
                    provider.issuer.as_deref(),
                    &provider.id_token_signed_response_alg,
                    &provider.client_id,
                    clock.now(),
                )
                .await?;

                // `current_jwks` now holds the keyset that actually verified the
                // token (refreshed in place if the upstream had rotated its
                // key); stash it so the userinfo path can reuse it.
                jwks = Some(current_jwks);

                let (_headers, mut claims) = verified.into_parts();

                id_token_claims =
                    Some(serde_json::to_value(&claims).expect(
                        "serializing a HashMap<String, Value> into a Value should never fail",
                    ));

                coauth_jose::claims::AT_HASH
                    .extract_optional_with_options(
                        &mut claims,
                        TokenHash::new(
                            &provider.id_token_signed_response_alg,
                            &token_response.access_token,
                        ),
                    )
                    .map_err(crate::oidc_client::error::IdTokenError::from)?;

                coauth_jose::claims::C_HASH
                    .extract_optional_with_options(
                        &mut claims,
                        TokenHash::new(&provider.id_token_signed_response_alg, &code),
                    )
                    .map_err(crate::oidc_client::error::IdTokenError::from)?;

                if let Some(nonce) = session.nonce.as_deref() {
                    coauth_jose::claims::NONCE
                        .extract_required_with_options(&mut claims, nonce)
                        .map_err(crate::oidc_client::error::IdTokenError::from)?;
                }

                context = context.with_id_token_claims(claims);
            }

            if let Some(extra_callback_parameters) = params.extra_callback_parameters.clone() {
                context = context.with_extra_callback_parameters(extra_callback_parameters);
            }

            let userinfo = if provider.fetch_userinfo {
                Some(json!(match &provider.userinfo_signed_response_alg {
                    Some(signing_algorithm) => {
                        let jwks = match jwks {
                            Some(jwks) => jwks,
                            None => {
                                jwks_cache
                                    .get_or_fetch(&client, lazy_metadata.jwks_uri().await?)
                                    .await?
                            }
                        };

                        crate::oidc_client::requests::userinfo::fetch_userinfo(
                            &client,
                            lazy_metadata.userinfo_endpoint().await?,
                            token_response.access_token.as_str(),
                            Some(JwtVerificationData {
                                issuer: provider.issuer.as_deref(),
                                jwks: &jwks,
                                signing_algorithm,
                                client_id: &provider.client_id,
                            }),
                        )
                        .await?
                    }
                    None => {
                        crate::oidc_client::requests::userinfo::fetch_userinfo(
                            &client,
                            lazy_metadata.userinfo_endpoint().await?,
                            token_response.access_token.as_str(),
                            None,
                        )
                        .await?
                    }
                }))
            } else {
                None
            };

            if let Some(ref ui) = userinfo {
                context = context.with_userinfo_claims(ui.clone());
            }

            (
                token_response.id_token,
                id_token_claims,
                context.build(),
                userinfo,
            )
        }
    };

    let env = environment();

    let template = provider
        .claims_imports
        .subject
        .template
        .as_deref()
        .unwrap_or("{{ user.sub }}");
    let subject = env
        .render_str(template, context.clone())
        .map_err(RouteError::ExtractSubject)?;

    if subject.is_empty() {
        return Err(RouteError::EmptySubject);
    }

    // Look for an existing link
    let maybe_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, &subject)
        .await?;

    let link = if let Some(link) = maybe_link {
        link
    } else {
        // Try to render the human account name if we have one,
        // but just log if it fails
        let human_account_name = provider
            .claims_imports
            .account_name
            .template
            .as_deref()
            .and_then(|template| match env.render_str(template, context) {
                Ok(name) => Some(name),
                Err(e) => {
                    tracing::warn!(
                        error = &e as &dyn std::error::Error,
                        "Failed to render account name"
                    );
                    None
                }
            });

        repo.upstream_oauth_link()
            .add(&mut rng, &clock, &provider, subject, human_account_name)
            .await?
    };

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(
            &clock,
            session,
            &link,
            id_token_raw,
            id_token_claims,
            params.extra_callback_parameters,
            userinfo,
        )
        .await?;

    let cookie_jar = sessions_cookie
        .add_link_to_session(session.id, link.id)?
        .save(cookie_jar, &clock);

    repo.save().await?;

    cookie_jar.finalize(
        res,
        salvo::writing::Redirect::other(
            url_builder.relative_url(&format!("/upstream/link/{}", link.id)),
        ),
    );
    Ok(())
}

/// Verify an ID token against a cached JWKS, transparently recovering from an
/// upstream signing-key rotation.
///
/// The happy path verifies `id_token` against `*current_jwks` (served from the
/// shared [`super::jwks_cache::JwksCache`]). If verification fails *because the
/// signature did not validate* — the symptom of the upstream having rotated its
/// signing key out from under our cached copy — this forces a single
/// cache-bypassing re-fetch via
/// [`super::jwks_cache::JwksCache::force_refresh`], updates `*current_jwks` in
/// place, and retries verification once. Any other failure (expired token,
/// wrong audience, etc.) is returned immediately without a re-fetch, since a
/// fresh keyset would not change the outcome.
///
/// On success `*current_jwks` holds the keyset that actually verified the token
/// (refreshed or not), so the caller can reuse it for downstream userinfo
/// verification.
#[allow(clippy::too_many_arguments)]
async fn verify_id_token_with_rotation_retry<'a>(
    jwks_cache: &super::jwks_cache::JwksCache,
    client: &reqwest::Client,
    jwks_uri: &::url::Url,
    current_jwks: &mut coauth_jose::jwk::PublicJsonWebKeySet,
    id_token: &'a str,
    issuer: Option<&str>,
    signing_algorithm: &coauth_iana::jose::JsonWebSignatureAlg,
    client_id: &String,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<crate::oidc_client::types::IdToken<'a>, RouteError> {
    use crate::oidc_client::error::{IdTokenError, JwtVerificationError};

    let first_attempt = crate::oidc_client::requests::jose::verify_id_token(
        id_token,
        JwtVerificationData {
            issuer,
            jwks: current_jwks,
            signing_algorithm,
            client_id,
        },
        None,
        now,
    );

    match first_attempt {
        Ok(verified) => Ok(verified),
        // Signature did not validate against the cached keyset — the upstream
        // may have rotated its kid. Force a single re-fetch and retry once.
        Err(IdTokenError::Jwt(JwtVerificationError::JwtSignature(_))) => {
            tracing::info!(
                %jwks_uri,
                "ID token signature did not validate against cached JWKS; \
                 forcing a JWKS re-fetch in case the upstream rotated its key"
            );
            let refreshed = jwks_cache.force_refresh(client, jwks_uri).await?;
            *current_jwks = refreshed;

            let verified = crate::oidc_client::requests::jose::verify_id_token(
                id_token,
                JwtVerificationData {
                    issuer,
                    jwks: current_jwks,
                    signing_algorithm,
                    client_id,
                },
                None,
                now,
            )?;
            Ok(verified)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_standard_provider_kind_identifies_userinfo_only_adapters() {
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::QQConnect),
            Some("qq_connect")
        );
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::Feishu),
            Some("feishu")
        );
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::Lark),
            Some("lark")
        );
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::DingTalk),
            Some("dingtalk")
        );
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::WeChat),
            Some("wechat")
        );
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::WeCom),
            Some("wecom")
        );
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost),
            None
        );
        assert_eq!(
            non_standard_provider_kind(UpstreamOAuthProviderTokenAuthMethod::SignInWithApple),
            None
        );
    }

    #[test]
    fn non_standard_provider_gate_is_closed_by_default() {
        for value in [None, Some(""), Some("0"), Some("false"), Some("no")] {
            assert!(!non_standard_upstream_oauth_allowed_from_env(value));
        }
        for value in [Some("1"), Some("true"), Some("yes"), Some("enabled")] {
            assert!(non_standard_upstream_oauth_allowed_from_env(value));
        }
    }
}
