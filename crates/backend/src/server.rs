use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use coauth_config::{HttpBindConfig, HttpResource, HttpTlsConfig, UnixOrTcp};
use coauth_data::UrlBuilder;
use coauth_templates::Templates;
use headers::{CacheControl, HeaderMapExt as _, UserAgent};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, USER_AGENT};
use http::{HeaderValue, Method, StatusCode, Version};
use listenfd::ListenFd;
use opentelemetry_http::HeaderExtractor;
use opentelemetry_semantic_conventions::trace::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, HTTP_ROUTE, NETWORK_PROTOCOL_NAME,
    NETWORK_PROTOCOL_VERSION, URL_PATH, URL_QUERY, URL_SCHEME, USER_AGENT_ORIGINAL,
};
use rustls::ServerConfig;
use salvo::cors::{Any, Cors};
use salvo::prelude::*;
use salvo::serve_static::StaticDir;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::app_state::{AppState, inject_app_state};
use crate::listener::ConnectionInfo;
use crate::listener::unix_or_tcp::UnixOrTcpListener;

/// Scan the Dioxus build output directory for the hashed frontend JS entry
/// point. Returns a URL path like `/assets/coauth-frontend-dxh<hash>.js`.
#[must_use]
pub fn discover_frontend_script(assets_root: &camino::Utf8Path) -> Option<String> {
    let assets_dir = assets_root.join("assets");
    let dir = std::fs::read_dir(&assets_dir).ok()?;
    let mut candidates = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("coauth-frontend-") && name.ends_with(".js") {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            candidates.push((modified, name.into_owned()));
        }
    }

    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    if let Some((_modified, name)) = candidates.into_iter().next() {
        return Some(format!("/assets/{name}"));
    }

    // Fallback: check for non-hashed name
    if assets_dir.join("coauth-frontend.js").exists() {
        return Some("/assets/coauth-frontend.js".into());
    }
    None
}

#[inline]
fn otel_http_method(method: &Method) -> &'static str {
    match method {
        &Method::OPTIONS => "OPTIONS",
        &Method::GET => "GET",
        &Method::POST => "POST",
        &Method::PUT => "PUT",
        &Method::DELETE => "DELETE",
        &Method::HEAD => "HEAD",
        &Method::TRACE => "TRACE",
        &Method::CONNECT => "CONNECT",
        &Method::PATCH => "PATCH",
        _other => "_OTHER",
    }
}

#[inline]
fn otel_net_protocol_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _other => "_OTHER",
    }
}

fn otel_url_scheme(req: &Request) -> &'static str {
    // Check if connection info indicates TLS
    req.extensions()
        .get::<ConnectionInfo>()
        .map_or("http", |conn_info| {
            if conn_info.tls().is_some() {
                "https"
            } else {
                "http"
            }
        })
}

/// Middleware for logging responses
#[handler]
pub async fn log_response_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let user_agent: Option<UserAgent> = req.headers().typed_get();
    let user_agent_str = user_agent.as_ref().map_or("-", |u| u.as_str());
    let method = otel_http_method(req.method());
    let path = req.uri().path().to_owned();
    let version = otel_net_protocol_version(req.version());

    ctrl.call_next(req, depot, res).await;

    let status_code = res.status_code.unwrap_or(StatusCode::OK);
    match status_code.as_u16() {
        100..=399 => tracing::info!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?}",
        ),
        400..=499 => tracing::warn!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?}",
        ),
        500..=599 => tracing::error!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?}",
        ),
        _ => { /* This shouldn't happen */ }
    }
}

/// Middleware for OpenTelemetry tracing
#[handler]
pub async fn tracing_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let method = otel_http_method(req.method());
    let path = req.uri().path().to_owned();
    let version = otel_net_protocol_version(req.version());
    let scheme = otel_url_scheme(req);

    let user_agent = req
        .headers()
        .get(USER_AGENT)
        .and_then(|ua| ua.to_str().ok())
        .map(String::from);

    let query = req.uri().query().map(String::from);

    let span = tracing::info_span!(
        "http.server.request",
        "otel.kind" = "server",
        "otel.name" = format!("{method} {path}"),
        "otel.status_code" = tracing::field::Empty,
        { NETWORK_PROTOCOL_NAME } = "http",
        { NETWORK_PROTOCOL_VERSION } = version,
        { HTTP_REQUEST_METHOD } = method,
        { HTTP_ROUTE } = %path,
        { HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { URL_PATH } = %path,
        { URL_QUERY } = tracing::field::Empty,
        { URL_SCHEME } = scheme,
        { USER_AGENT_ORIGINAL } = tracing::field::Empty,
    );

    if let Some(ref q) = query {
        span.record(URL_QUERY, q.as_str());
    }

    if let Some(ref ua) = user_agent {
        span.record(USER_AGENT_ORIGINAL, ua.as_str());
    }

    // Extract the parent span context from the request headers
    if !span.is_disabled() {
        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            let extractor = HeaderExtractor(req.headers());
            let context = opentelemetry::Context::new();
            propagator.extract_with_context(&context, &extractor)
        });

        if let Err(err) = span.set_parent(parent_context) {
            tracing::error!(
                error = &err as &dyn std::error::Error,
                "Failed to set parent context on span"
            );
        }
    }

    let _guard = span.enter();
    ctrl.call_next(req, depot, res).await;

    let status_code = res.status_code.unwrap_or(StatusCode::OK);
    span.record(HTTP_RESPONSE_STATUS_CODE, status_code.as_u16());
    span.record("otel.status_code", "OK");
}

/// Middleware for Sentry integration
#[handler]
pub async fn sentry_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let path = req.uri().path().to_owned();
    let method = otel_http_method(req.method());

    sentry::configure_scope(|scope| {
        scope.set_transaction(Some(&format!("{method} {path}")));
    });

    ctrl.call_next(req, depot, res).await;
}

/// Cache control middleware for static files
#[handler]
pub async fn cache_control_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    ctrl.call_next(req, depot, res).await;

    let status_code = res.status_code.unwrap_or(StatusCode::OK);
    let cache_control = if status_code == StatusCode::NOT_FOUND {
        // Cache 404s for 5 minutes
        CacheControl::new()
            .with_public()
            .with_max_age(Duration::from_mins(5))
    } else {
        // Cache assets for 1 year
        CacheControl::new()
            .with_public()
            .with_max_age(Duration::from_hours(8760))
            .with_immutable()
    };
    res.headers_mut().typed_insert(cache_control);
}

/// Cap the time a single request handler may run.
///
/// Materialised as a per-request middleware so it composes with cookies,
/// CORS, and auth, and so operators can disable it via
/// `http.request_timeout_seconds = 0`.
#[derive(Clone, Copy)]
struct RequestTimeout {
    duration: Duration,
}

#[salvo::async_trait]
impl Handler for RequestTimeout {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let next = ctrl.call_next(req, depot, res);
        if tokio::time::timeout(self.duration, next).await.is_err() {
            *res = Response::new();
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Text::Plain("request timed out"));
            ctrl.skip_rest();
        }
    }
}

/// Override the deployment-wide `Content-Security-Policy` for the
/// current response. Call this from a handler **before** the security
/// middleware runs its post-flight pass; the middleware uses
/// `entry().or_insert()`, so any value placed on the response wins
/// over the configured default.
///
/// Returns an error only if `value` is not a syntactically valid HTTP
/// header value (control bytes / non-ASCII).
pub fn override_response_csp(
    res: &mut Response,
    value: &str,
) -> Result<(), http::header::InvalidHeaderValue> {
    let header_value = HeaderValue::from_str(value)?;
    res.headers_mut()
        .insert("content-security-policy", header_value);
    Ok(())
}

/// Override the deployment-wide `X-Frame-Options` for the current
/// response. Pre-emptively sets the header so the security middleware's
/// `entry().or_insert()` no-ops. Useful for embed-friendly routes that
/// must allow `SAMEORIGIN` framing.
///
/// Returns an error only if `value` is not a syntactically valid HTTP
/// header value.
pub fn override_response_frame_options(
    res: &mut Response,
    value: &str,
) -> Result<(), http::header::InvalidHeaderValue> {
    let header_value = HeaderValue::from_str(value)?;
    res.headers_mut().insert("x-frame-options", header_value);
    Ok(())
}

/// Apply baseline browser security headers to every response.
///
/// `Strict-Transport-Security` is emitted only when `http.hsts` is set:
/// HSTS has long-lived caching semantics and can lock operators out of an
/// HTTP-only host if sent by mistake.
///
/// `Content-Security-Policy` is emitted only on HTML responses and only
/// when `http.csp_html` is configured (the default is a conservative
/// `'self'`-only policy). Non-HTML responses (JSON APIs, assets) are
/// left untouched so a JSON error envelope cannot accidentally fall
/// under a script-src directive.
///
/// **Per-route overrides** — handlers that need a different policy can
/// pre-set the header on the response before the middleware runs its
/// post-flight pass. The middleware uses `entry().or_insert()`, so any
/// header already on the response is preserved as-is. Use the
/// [`override_response_csp`] / [`override_response_frame_options`]
/// helpers to do this safely.
#[handler]
pub async fn security_headers_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let (hsts_header, csp_html_header) =
        depot
            .get::<AppState>("app_state")
            .ok()
            .map_or((None, None), |state| {
                (
                    state
                        .hsts_header
                        .as_deref()
                        .and_then(|value| HeaderValue::from_str(value).ok()),
                    state
                        .csp_html_header
                        .as_deref()
                        .and_then(|value| HeaderValue::from_str(value).ok()),
                )
            });

    ctrl.call_next(req, depot, res).await;

    let response_is_html = res
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("text/html")
        });

    let headers = res.headers_mut();
    headers
        .entry("x-content-type-options")
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry("x-frame-options")
        .or_insert(HeaderValue::from_static("DENY"));
    headers
        .entry("referrer-policy")
        .or_insert(HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers
        .entry("cross-origin-opener-policy")
        .or_insert(HeaderValue::from_static("same-origin"));
    if let Some(value) = hsts_header {
        headers.entry("strict-transport-security").or_insert(value);
    }
    if response_is_html && let Some(value) = csp_html_header {
        headers.entry("content-security-policy").or_insert(value);
    }
}

/// A Salvo handler that injects [`AppState`] into the depot for every request.
#[derive(Clone)]
struct InjectAppState(AppState);

#[salvo::async_trait]
impl Handler for InjectAppState {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.insert("app_state", self.0.clone());
        ctrl.call_next(req, depot, res).await;
    }
}

#[derive(Clone)]
struct OpenApiYaml {
    yaml: String,
}

impl OpenApiYaml {
    fn from_doc(doc: &salvo::oapi::OpenApi) -> Self {
        Self {
            yaml: serde_yaml::to_string(doc).expect("admin OpenAPI document should serialize"),
        }
    }
}

#[salvo::async_trait]
impl Handler for OpenApiYaml {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/yaml; charset=utf-8"),
        );
        res.render(Text::Plain(self.yaml.clone()));
    }
}

fn public_oidc_browser_cors() -> impl Handler {
    Cors::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            ACCEPT,
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("dpop"),
        ])
        .into_handler()
}

#[handler]
async fn oidc_preflight_handler() -> StatusCode {
    StatusCode::NO_CONTENT
}

const INLINE_FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#1f7a4f"/><text x="32" y="41" text-anchor="middle" font-size="34" font-family="Arial,sans-serif" font-weight="700" fill="white">C</text></svg>"##;

#[handler]
async fn favicon_handler(res: &mut Response) {
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml; charset=utf-8"),
    );
    res.render(Text::Plain(INLINE_FAVICON_SVG));
}

#[must_use]
pub fn build_router(
    state: AppState,
    resources: &[HttpResource],
    prefix: Option<&str>,
    _name: Option<&str>,
) -> Router {
    let templates = state.templates.clone();
    let max_body_bytes = usize::try_from(state.max_body_bytes).unwrap_or(usize::MAX);
    let request_timeout = (state.request_timeout_seconds > 0)
        .then(|| Duration::from_secs(state.request_timeout_seconds));

    // Create the base router with the AppState in depot
    let mut router = Router::new();

    // Add state injection middleware at the top level
    router = router
        .hoop(InjectAppState(state))
        .hoop(salvo::http::request::SecureMaxSize::new(max_body_bytes));

    if let Some(duration) = request_timeout {
        router = router.hoop(RequestTimeout { duration });
    }

    // Build sub-routers for each resource
    use crate::handlers::health;
    use crate::handlers::oauth::{discovery, webfinger};

    for resource in resources {
        router = match resource {
            coauth_config::HttpResource::Health => router
                .push(Router::with_path("/health").get(health::get))
                .push(Router::with_path("/healthz").get(health::get))
                .push(Router::with_path("/readyz").get(health::readyz)),
            coauth_config::HttpResource::Prometheus => {
                router.push(Router::with_path("/metrics").get(crate::telemetry::prometheus_handler))
            }
            coauth_config::HttpResource::Discovery => router
                .push(
                    Router::with_path("/.well-known/openid-configuration")
                        .hoop(public_oidc_browser_cors())
                        .get(discovery::get),
                )
                .push(
                    Router::with_path("/.well-known/webfinger")
                        .hoop(public_oidc_browser_cors())
                        .get(webfinger::get),
                ),
            // NOTE: coauth deliberately hosts NO DID documents
            // (`/.well-known/did.json`, `/did.json`, `/users/{id}/did.json`
            // were removed). DID hosting is the principal server's job —
            // soland's embedded webvh provider (or an external starid) serves
            // `did:webvh` documents under its own authority; coauth only
            // mints/registers against it. coauth-issued artefacts (session
            // grants, handle claims) are verified via the introspection
            // endpoints and the OAuth JWKS, never by resolving a
            // coauth-hosted DID document.
            coauth_config::HttpResource::Human => build_human_router(router, templates.clone()),
            coauth_config::HttpResource::RestApi => build_account_api_router(router),
            coauth_config::HttpResource::Assets { path } => router
                .push(Router::with_path("/favicon.ico").get(favicon_handler))
                .push(
                    Router::with_path("/assets/{**path}")
                        .hoop(cache_control_middleware)
                        .get(
                            StaticDir::new([path.join("assets")])
                                .include_dot_files(false)
                                .auto_list(false),
                        ),
                ),
            coauth_config::HttpResource::OAuth => build_oauth_router(router),
            coauth_config::HttpResource::AdminApi => build_admin_router(router),
            coauth_config::HttpResource::ConnectionInfo => {
                router.push(Router::with_path("/connection-info").get(connection_info_handler))
            }
        }
    }

    // Apply prefix if specified
    let prefix = format!("{}/", prefix.unwrap_or_default().trim_end_matches('/'));
    if !prefix.is_empty() && prefix != "/" {
        let prefixed_router = Router::with_path(&prefix);
        router = prefixed_router.push(router);
    }

    // Add middleware layers
    router
        .hoop(inject_app_state)
        .hoop(security_headers_middleware)
        .hoop(log_response_middleware)
        .hoop(tracing_middleware)
        .hoop(sentry_middleware)
}

fn build_human_router(router: Router, _templates: Templates) -> Router {
    use crate::handlers::oauth::authorization;
    use crate::handlers::{email_webhooks, spa, upstream_oauth};

    router
        .push(Router::with_path("/webhooks/email/{provider}").post(email_webhooks::post))
        // ── OAuth protocol endpoints (server-side redirects) ──
        .push(Router::with_path("/authorize").get(authorization::get))
        // ── Upstream OAuth (server-side redirect & callback) ──
        .push(
            Router::with_path("/upstream/authorize/{provider_id}")
                .get(upstream_oauth::authorize::get),
        )
        .push(
            Router::with_path("/upstream/callback/{provider_id}")
                .get(upstream_oauth::callback::handler)
                .post(upstream_oauth::callback::handler),
        )
        .push(Router::with_path("/upstream/link/{link_id}").get(spa::get))
        .push(
            Router::with_path("/upstream/backchannel-logout/{provider_id}")
                .post(upstream_oauth::backchannel_logout::post),
        )
        // ── Well-known redirect ──
        .push(
            Router::with_path("/.well-known/change-password").get(change_password_redirect_handler),
        )
        // ── SPA shell ──
        // Root & auth pages
        .push(Router::with_path("/").get(spa::get))
        .push(Router::with_path("/login").get(spa::get))
        .push(Router::with_path("/register").get(spa::get))
        .push(Router::with_path("/register/{**rest}").get(spa::get))
        .push(Router::with_path("/recover").get(spa::get))
        .push(Router::with_path("/recover/{**rest}").get(spa::get))
        .push(Router::with_path("/oauth/approval/{**rest}").get(spa::get))
        .push(Router::with_path("/link").get(spa::get))
        .push(Router::with_path("/device/{**rest}").get(spa::get))
        // Account pages (root-level frontend routes)
        .push(Router::with_path("/settings").get(spa::get))
        .push(Router::with_path("/sessions").get(spa::get))
        .push(Router::with_path("/sessions/{**rest}").get(spa::get))
        .push(Router::with_path("/security").get(spa::get))
        .push(Router::with_path("/notifications").get(spa::get))
        .push(Router::with_path("/identities").get(spa::get))
        .push(Router::with_path("/contacts").get(spa::get))
        .push(Router::with_path("/workflows").get(spa::get))
        .push(Router::with_path("/plan").get(spa::get))
        // Standalone pages
        .push(Router::with_path("/password/{**rest}").get(spa::get))
        .push(Router::with_path("/emails/{**rest}").get(spa::get))
        .push(Router::with_path("/clients/{**rest}").get(spa::get))
        .push(Router::with_path("/devices/{**rest}").get(spa::get))
}

fn build_oauth_router(router: Router) -> Router {
    use crate::handlers::oauth::{
        device, introspection, keys, registration, revoke, token, userinfo,
    };

    let cors = || public_oidc_browser_cors();

    router
        .push(
            Router::with_path("/oauth/keys.json")
                .hoop(cors())
                .get(keys::get),
        )
        .push(
            Router::with_path("/oauth/userinfo")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .get(userinfo::get)
                .post(userinfo::get),
        )
        .push(
            Router::with_path("/oauth/introspect")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(introspection::post),
        )
        .push(
            Router::with_path("/oauth/revoke")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(revoke::post),
        )
        .push(
            Router::with_path("/oauth/token")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(token::post),
        )
        .push(
            Router::with_path("/oauth/registration")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(registration::post),
        )
        .push(
            Router::with_path("/oauth/device")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(device::authorize::post),
        )
}

fn build_account_api_router(router: Router) -> Router {
    use crate::handlers::account::{
        agents, approval, auth, avatar, bootstrap_admin_status, emails, flow, invite_accept,
        invite_relay, linked_accounts, notification_prefs, oauth_clients, openapi, password,
        recovery, register, sessions, site_config, upstream_oauth, users, viewer,
    };
    use crate::handlers::{cokret, policy_check};

    let cokret_router = Router::with_path("/_cokret")
        .hoop(public_oidc_browser_cors())
        .push(Router::with_path("describe").get(cokret::server_describe))
        .push(Router::with_path("root/identity/describe").get(cokret::identity_describe))
        .push(Router::with_path("root/identity/resolve").post(cokret::identity_resolve))
        .push(Router::with_path("root/identity/document").get(cokret::identity_document))
        .push(Router::with_path("find/directory/describe").get(cokret::directory_describe))
        .push(
            Router::with_path("find/directory/resolve-handle")
                .post(cokret::directory_resolve_handle),
        )
        .push(Router::with_path("self/policy/check").post(policy_check::post_policy_check));

    let mut coauth_router = Router::with_path("/_coauth")
        .hoop(public_oidc_browser_cors())
        // Product-private surface only. Protocol-standard Cokret endpoints
        // are served solely under `/_cokret` above; the former `/_coauth`
        // protocol mirror (describe, root/identity/{describe,resolve,
        // document}, find/directory/{describe,resolve-handle},
        // self/policy/check) was a backward-compatibility shim and has been
        // removed — clients must use `/_cokret`.
        .push(
            // `root/identity/primary-handle` is a coauth product-private
            // path (not a spec operation), so it legitimately stays here.
            Router::with_path("root/identity/primary-handle")
                .patch(cokret::patch_primary_handle_preference),
        )
        .push(
            Router::with_path("gate/account/session-grants")
                .get(cokret::list_session_grants)
                .push(Router::with_path("introspect").post(cokret::introspect_session_grant))
                .push(Router::with_path("refresh").post(cokret::refresh_session_grant))
                .push(Router::with_path("{id}/revoke").post(cokret::revoke_session_grant)),
        )
        // Viewer
        .push(
            Router::with_path("self/viewer")
                .get(viewer::get_viewer)
                .push(Router::with_path("overview").get(viewer::get_viewer_overview))
                .push(Router::with_path("security").get(viewer::get_security_summary))
                .push(Router::with_path("password").post(password::set_password))
                .push(Router::with_path("profile").patch(users::patch_profile))
                .push(Router::with_path("avatar").post(avatar::upload_avatar))
                .push(Router::with_path("avatar/{user_id}").get(avatar::get_avatar))
                .push(Router::with_path("deactivate").post(users::deactivate_user))
                .push(
                    Router::with_path("preferences")
                        .get(notification_prefs::get_notification_preferences)
                        .patch(notification_prefs::patch_notification_preferences),
                )
                .push(Router::with_path("workflow-inbox").get(viewer::get_workflow_inbox)),
        )
        .push(Router::with_path("self/bootstrap-admin-status").get(bootstrap_admin_status::get))
        // Site config
        .push(Router::with_path("self/site-config").get(site_config::get))
        // Sessions
        .push(Router::with_path("self/sessions/{id}").get(sessions::get_session))
        .push(Router::with_path("self/browser-sessions/{id}").delete(sessions::end_browser_session))
        .push(
            Router::with_path("self/oauth-sessions/{id}")
                .delete(sessions::end_oauth_session)
                .push(Router::with_path("name").put(sessions::set_oauth_session_name)),
        )
        // OAuth clients
        .push(Router::with_path("self/oauth-clients/{id}").get(oauth_clients::get_client))
        // Password recovery
        .push(
            Router::with_path("gate/account/password-recovery")
                .push(Router::with_path("{ticket}").get(password::get_recovery_ticket_status))
                .push(Router::with_path("set").post(password::set_password_by_recovery))
                .push(Router::with_path("resend").post(password::resend_recovery_email)),
        )
        // Email authentication
        .push(
            Router::with_path("gate/account/email-auth")
                .push(Router::with_path("start").post(emails::start_email_auth))
                .push(
                    Router::with_path("{id}")
                        .get(emails::get_email_auth)
                        .push(Router::with_path("complete").post(emails::complete_email_auth))
                        .push(Router::with_path("resend").post(emails::resend_email_auth_code)),
                ),
        )
        // User emails
        .push(Router::with_path("self/user-emails/{id}").delete(emails::remove_email))
        .push(
            Router::with_path("gate/account/integration/describe").get(auth::integration_describe),
        )
        // Auth (login, logout, providers, registration, recovery)
        .push(
            Router::with_path("gate/account/auth")
                .push(Router::with_path("bridge/describe").get(auth::auth_bridge_describe))
                .push(Router::with_path("login").post(auth::login))
                .push(
                    Router::with_path("oidc/browser-bridge/session")
                        .options(oidc_preflight_handler)
                        .post(auth::oidc_browser_bridge_session),
                )
                .push(Router::with_path("oidc/exchange/describe").get(auth::oidc_exchange_describe))
                .push(
                    Router::with_path("oidc/exchange")
                        .options(oidc_preflight_handler)
                        .post(auth::oidc_code_exchange),
                )
                .push(
                    Router::with_path("passkey")
                        .push(
                            Router::with_path("register/start").post(auth::passkey_register_start),
                        )
                        .push(
                            Router::with_path("register/finish")
                                .post(auth::passkey_register_finish),
                        )
                        .push(Router::with_path("auth/start").post(auth::passkey_auth_start))
                        .push(Router::with_path("auth/finish").post(auth::passkey_auth_finish)),
                )
                .push(Router::with_path("logout").post(auth::logout))
                .push(Router::with_path("providers").get(auth::providers))
                // Registration
                .push(
                    Router::with_path("register")
                        .post(register::post_register)
                        .push(
                            Router::with_path("webvh")
                                .push(Router::with_path("start").post(register::post_webvh_start))
                                .push(
                                    Router::with_path("{id}")
                                        .push(
                                            Router::with_path("email")
                                                .post(register::post_webvh_email),
                                        )
                                        .push(
                                            Router::with_path("verify-email")
                                                .post(register::post_webvh_verify_email),
                                        )
                                        .push(
                                            Router::with_path("finish")
                                                .post(register::post_webvh_finish),
                                        ),
                                ),
                        )
                        .push(Router::with_path("did").push(
                            Router::with_path("start").post(register::post_existing_did_start),
                        ))
                        .push(
                            Router::with_path("{id}")
                                .get(register::get_registration)
                                .push(
                                    Router::with_path("verify-email")
                                        .post(register::post_verify_email),
                                )
                                .push(
                                    Router::with_path("verify-phone")
                                        .post(register::post_verify_phone),
                                )
                                .push(
                                    Router::with_path("resend-verification")
                                        .post(register::post_resend_verification),
                                )
                                .push(
                                    Router::with_path("change-email")
                                        .post(register::post_change_email),
                                )
                                .push(
                                    Router::with_path("display-name")
                                        .post(register::post_display_name),
                                )
                                .push(Router::with_path("finish").post(register::post_finish)),
                        ),
                )
                // Account recovery
                .push(
                    Router::with_path("recovery")
                        .push(Router::with_path("start").post(recovery::post_recovery_start))
                        .push(Router::with_path("{id}").get(recovery::get_recovery).push(
                            Router::with_path("resend").post(recovery::post_recovery_resend),
                        )),
                ),
        )
        // OAuth approval
        .push(
            Router::with_path("self/oauth/authorization-grants/{grant_id}/decision")
                .get(approval::oauth_approval_get)
                .post(approval::oauth_approval_post),
        )
        // Invite relay (consent-gated forward to target principal)
        .push(Router::with_path("self/account/invites/relay").post(invite_relay::post_invite_relay))
        // G3.C3: 3PID invite verifier — runs the binding-proof +
        // subject-proof chain in `services::third_party_invite` and
        // returns the verified summary. The actual invite-claim
        // reducer lives on soland; this endpoint is the trusted
        // pre-flight check the claimant runs before submitting
        // `ck.invite.claim`.
        .push(Router::with_path("self/invites/3pid/verify").post(invite_accept::post_verify_invite))
        // Device code link & approval
        .push(Router::with_path("self/device-link").get(approval::device_link_get))
        .push(
            Router::with_path("self/device-grants/{id}/decision")
                .get(approval::device_approval_get)
                .post(approval::device_approval_post),
        )
        // Linked accounts
        .push(
            Router::with_path("self/linked-accounts")
                .get(linked_accounts::list_linked_accounts)
                .push(Router::with_path("{id}").delete(linked_accounts::unlink_account)),
        )
        // Upstream OAuth link
        .push(
            Router::with_path("self/upstream-oauth/link/{id}")
                .get(upstream_oauth::get_link)
                .post(upstream_oauth::post_link),
        )
        // Flow engine
        .push(
            Router::with_path("self/flow")
                .push(Router::with_path("{slug}/start").post(flow::start_flow))
                .push(
                    Router::with_path("session/{id}")
                        .get(flow::get_flow_session)
                        .push(Router::with_path("respond").post(flow::respond_flow)),
                ),
        )
        // CKP-0008 personal-agent controller approval. Internal
        // server-to-server endpoint: accepts only soland / sodmin
        // static bearers. Issues a `accountability_grant` payload
        // referencing the agent principal + capability set.
        .push(
            Router::with_path("self/agents/{id}/accountability-grant")
                .post(agents::post_accountability_grant),
        );

    #[cfg(debug_assertions)]
    if cokret::test_endpoints_enabled() {
        coauth_router = coauth_router.push(
            Router::with_path("gate/account/test/debug/issue-dpop-grant")
                .post(cokret::debug_issue_dpop_grant),
        );
    }

    let docs_router = openapi::build_openapi_router(&coauth_router);

    router
        .push(cokret_router)
        .push(coauth_router)
        .push(docs_router)
}

fn build_admin_router(router: Router) -> Router {
    use crate::handlers::admin::v1::{
        account_dids, accounts, audit_feed, circle_capabilities, claims, connector_health, devices,
        invite_quarantine, notification_channels, notification_templates, oauth_clients,
        oauth_clients_i18n, oauth_clients_register, oauth_sessions, passkeys, personal_sessions,
        policy_checks, policy_data, site_config, upstream_oauth_links, upstream_oauth_providers,
        user_emails, user_registration_tokens, user_sessions, users, version,
    };

    let admin_router = Router::with_path("/_coauth/admin")
        // Version
        .push(Router::with_path("version").get(version::handler))
        // Site config
        .push(Router::with_path("site-config").get(site_config::handler))
        // Operational health
        .push(Router::with_path("connector-health").get(connector_health::handler))
        .push(Router::with_path("notification-channels").get(notification_channels::handler))
        // Notification templates
        .push(
            Router::with_path("notification-templates")
                .get(notification_templates::list_handler)
                .push(Router::with_path("publish").post(notification_templates::publish_handler)),
        )
        // Audit feed
        .push(Router::with_path("audit-feed").get(audit_feed::handler))
        // CKP-0007 ck.circle.* capability grants (P2B.2). Wire shape is in
        // coauth-admin-types::circle_capability_admin; persistence is
        // in-memory until the follow-up migration lands.
        .push(
            Router::with_path("circles/capabilities")
                .get(circle_capabilities::list_handler)
                .post(circle_capabilities::create_handler)
                .push(Router::with_path("{grant_id}").delete(circle_capabilities::revoke_handler)),
        )
        // Invite-quarantine outbox (C10.E §6.1 default-profile path)
        .push(
            Router::with_path("invite-quarantine")
                .get(invite_quarantine::list_invite_quarantine)
                .push(
                    Router::with_path("{id}/resolve")
                        .post(invite_quarantine::resolve_invite_quarantine),
                ),
        )
        // Cokret accounts
        .push(Router::with_path("bridge/describe").get(accounts::admin_bridge_describe))
        .push(
            Router::with_path("accounts")
                .get(accounts::list_accounts)
                .push(
                    Router::with_path("{id}")
                        .get(accounts::get_account)
                        .push(Router::with_path("claims").get(accounts::list_account_claims))
                        .push(
                            Router::with_path("session-grants")
                                .get(accounts::list_account_session_grants),
                        )
                        .push(
                            Router::with_path("risk-action/history")
                                .get(accounts::risk_action::list_history),
                        )
                        .push(
                            Router::with_path("risk-action/current")
                                .get(accounts::risk_action::get_current),
                        )
                        .push(Router::with_path("risk-action").post(accounts::risk_action::propose))
                        .push(
                            Router::with_path("risk-action/{proposal_id}/approve")
                                .post(accounts::risk_action::approve),
                        )
                        .push(
                            Router::with_path("risk-action/{proposal_id}/execute")
                                .post(accounts::risk_action::execute),
                        )
                        .push(Router::with_path("lock").post(accounts::lock_account))
                        .push(Router::with_path("disable").post(accounts::disable_account))
                        .push(Router::with_path("erase").post(accounts::erase_account))
                        .push(Router::with_path("reset-recovery").post(accounts::reset_recovery))
                        .push(
                            Router::with_path("dids")
                                .get(account_dids::list_account_dids)
                                .post(account_dids::add_account_did)
                                .push(
                                    Router::with_path("{did_id}")
                                        .delete(account_dids::remove_account_did),
                                ),
                        )
                        .push(
                            Router::with_path("passkeys")
                                .push(
                                    Router::with_path("register/start")
                                        .post(passkeys::register_start),
                                )
                                .push(
                                    Router::with_path("register/finish")
                                        .post(passkeys::register_finish),
                                )
                                .push(Router::with_path("auth/start").post(passkeys::auth_start))
                                .push(Router::with_path("auth/finish").post(passkeys::auth_finish)),
                        ),
                ),
        )
        // Users
        .push(
            Router::with_path("users")
                .get(users::list_users)
                .post(users::add_user)
                .push(Router::with_path("by-username/{username}").get(users::get_by_username))
                .push(Router::with_path("batch-invite").post(users::batch_invite))
                .push(
                    Router::with_path("{id}")
                        .get(users::get_user)
                        .patch(users::update_user)
                        .push(Router::with_path("set-password").post(users::set_password))
                        .push(Router::with_path("risk-action").post(users::risk_action)),
                ),
        )
        // User emails
        .push(
            Router::with_path("user-emails")
                .get(user_emails::list_emails)
                .post(user_emails::add_email)
                .push(
                    Router::with_path("{id}")
                        .get(user_emails::get_email)
                        .patch(user_emails::update_email)
                        .delete(user_emails::delete_email),
                ),
        )
        // User sessions
        .push(
            Router::with_path("user-sessions")
                .get(user_sessions::list_sessions)
                .push(
                    Router::with_path("{id}")
                        .get(user_sessions::get_session)
                        .push(Router::with_path("finish").post(user_sessions::finish_session)),
                ),
        )
        // OAuth sessions
        .push(
            Router::with_path("oauth-sessions")
                .get(oauth_sessions::list_sessions)
                .push(
                    Router::with_path("{id}")
                        .get(oauth_sessions::get_session)
                        .push(Router::with_path("finish").post(oauth_sessions::finish_session)),
                ),
        )
        // OAuth client localised metadata
        .push(
            Router::with_path("oauth-clients").push(
                Router::with_path("{id}").push(
                    Router::with_path("localized-metadata")
                        .get(oauth_clients::get_localized_metadata)
                        .put(oauth_clients::replace_localized_metadata),
                ),
            ),
        )
        // RFC 7591 admin dynamic client registration
        .push(Router::with_path("oauth/clients/register").post(oauth_clients_register::register))
        // Admin-curated OAuth client display name + description per locale.
        .push(
            Router::with_path("oauth/clients/{id}/i18n")
                .get(oauth_clients_i18n::get_i18n)
                .post(oauth_clients_i18n::upsert_i18n),
        )
        // Personal sessions
        .push(
            Router::with_path("personal-sessions")
                .get(personal_sessions::list_sessions)
                .post(personal_sessions::add_session)
                .push(
                    Router::with_path("{id}")
                        .get(personal_sessions::get_session)
                        .push(
                            Router::with_path("regenerate")
                                .post(personal_sessions::regenerate_session),
                        )
                        .push(Router::with_path("revoke").post(personal_sessions::revoke_session)),
                ),
        )
        // Cokret devices
        .push(
            Router::with_path("devices")
                .get(devices::list_devices)
                .push(Router::with_path("{id}/revoke").post(devices::revoke_device)),
        )
        // User registration tokens
        .push(
            Router::with_path("user-registration-tokens")
                .get(user_registration_tokens::list_tokens)
                .post(user_registration_tokens::add_token)
                .push(
                    Router::with_path("{id}")
                        .get(user_registration_tokens::get_token)
                        .put(user_registration_tokens::update_token)
                        .push(
                            Router::with_path("revoke")
                                .post(user_registration_tokens::revoke_token),
                        )
                        .push(
                            Router::with_path("unrevoke")
                                .post(user_registration_tokens::unrevoke_token),
                        ),
                ),
        )
        // Upstream OAuth providers
        .push(
            Router::with_path("upstream-oauth-providers")
                .get(upstream_oauth_providers::list_providers)
                .post(upstream_oauth_providers::add_provider)
                .push(
                    Router::with_path("{id}")
                        .get(upstream_oauth_providers::get_provider)
                        .patch(upstream_oauth_providers::update_provider)
                        .delete(upstream_oauth_providers::delete_provider)
                        .push(
                            Router::with_path("disable")
                                .post(upstream_oauth_providers::disable_provider),
                        )
                        .push(
                            Router::with_path("enable")
                                .post(upstream_oauth_providers::enable_provider),
                        ),
                ),
        )
        // Upstream OAuth links
        .push(
            Router::with_path("upstream-oauth-links")
                .get(upstream_oauth_links::list_links)
                .post(upstream_oauth_links::add_link)
                .push(
                    Router::with_path("{id}")
                        .get(upstream_oauth_links::get_link)
                        .patch(upstream_oauth_links::update_link)
                        .delete(upstream_oauth_links::delete_link),
                ),
        )
        // Policy data
        .push(
            Router::with_path("policy-data")
                .push(Router::with_path("latest").get(policy_data::get_latest))
                .push(Router::with_path("{id}").get(policy_data::get_by_id))
                .put(policy_data::set_data),
        )
        // Cokret claims and policy checks
        .push(
            Router::with_path("claims")
                .post(claims::issue_claim)
                .push(Router::with_path("status").get(claims::list_claim_status))
                .push(Router::with_path("{id}/revoke").post(claims::revoke_claim)),
        )
        .push(
            Router::with_path("policy-checks")
                .push(Router::with_path("dry-run").post(policy_checks::dry_run)),
        )
        .push(
            Router::with_path("policy-decision-audits")
                .push(Router::with_path("{id}").get(policy_checks::get_signed_decision_audit)),
        );

    // Generate OpenAPI spec and Swagger UI for the admin API
    let admin_doc = build_admin_openapi_doc(&admin_router);
    let admin_doc_yaml = OpenApiYaml::from_doc(&admin_doc);

    router
        .push(admin_router)
        .push(admin_doc.clone().into_router("/api-doc/admin/openapi.json"))
        .push(Router::with_path("/_coauth/admin/openapi.yaml").get(admin_doc_yaml.clone()))
        .push(Router::with_path("/.well-known/cokret/openapi.yaml").get(admin_doc_yaml))
        .push(
            salvo::oapi::swagger_ui::SwaggerUi::new("/api-doc/admin/openapi.json")
                .into_router("admin-swagger-ui"),
        )
}

fn build_admin_openapi_doc(admin_router: &Router) -> salvo::oapi::OpenApi {
    salvo::oapi::OpenApi::new("coauth Admin API", env!("CARGO_PKG_VERSION"))
        .merge_router(admin_router)
}

#[handler]
async fn change_password_redirect_handler(depot: &Depot) -> impl Writer + use<> {
    use crate::app_state::DepotExt;

    let url_builder = depot.get_url_builder().cloned();
    Redirect::found(absolute_redirect_location(
        url_builder.as_ref(),
        "/password/change",
    ))
}

fn absolute_redirect_location(url_builder: Option<&UrlBuilder>, path: &str) -> String {
    url_builder.map_or_else(
        || path.to_owned(),
        |url_builder| url_builder.absolute_url(path).to_string(),
    )
}

#[handler]
async fn connection_info_handler(req: &Request) -> String {
    if let Some(conn_info) = req.extensions().get::<ConnectionInfo>() {
        format!("{conn_info:?}")
    } else {
        "No connection info available".to_owned()
    }
}

pub fn build_tls_server_config(config: &HttpTlsConfig) -> Result<ServerConfig, anyhow::Error> {
    let (key, chain) = config.load()?;

    // Pin the protocol-version floor to TLS 1.2 (TLS 1.3 preferred and
    // negotiated automatically). rustls 0.23 already refuses TLS 1.0/1.1
    // by default, but stating the policy explicitly makes it reviewable
    // and prevents a silent downgrade if a future rustls release widens
    // its default range.
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .context("failed to build TLS server config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

fn bind_description(bind: &HttpBindConfig) -> String {
    match bind {
        HttpBindConfig::Listen { host, port } => match host {
            Some(host) => format!("TCP listener {host}:{port}"),
            None => format!("TCP listener [::]:{port} or 0.0.0.0:{port}"),
        },
        HttpBindConfig::Address { address } => format!("TCP listener {address}"),
        HttpBindConfig::Unix { socket } => format!("UNIX socket {socket}"),
        HttpBindConfig::FileDescriptor {
            fd,
            kind: UnixOrTcp::Tcp,
        } => format!("TCP listener on file descriptor {fd}"),
        HttpBindConfig::FileDescriptor {
            fd,
            kind: UnixOrTcp::Unix,
        } => format!("UNIX listener on file descriptor {fd}"),
    }
}

pub fn build_listeners(
    fd_manager: &mut ListenFd,
    configs: &[HttpBindConfig],
) -> Result<Vec<UnixOrTcpListener>, anyhow::Error> {
    let mut listeners = Vec::with_capacity(configs.len());

    for bind in configs {
        let bind_description = bind_description(bind);
        let listener = match bind {
            HttpBindConfig::Listen { host, port } => {
                let addrs = match host.as_deref() {
                    Some(host) => (host, *port)
                        .to_socket_addrs()
                        .with_context(|| {
                            format!("could not parse listener host for {bind_description}")
                        })?
                        .collect(),

                    None => vec![
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), *port),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port),
                    ],
                };

                let listener = TcpListener::bind(&addrs[..])
                    .with_context(|| format!("could not bind {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            HttpBindConfig::Address { address } => {
                let addr: SocketAddr = address
                    .parse()
                    .with_context(|| format!("could not parse listener address {address}"))?;
                let listener = TcpListener::bind(addr)
                    .with_context(|| format!("could not bind {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            #[cfg(unix)]
            HttpBindConfig::Unix { socket } => {
                let listener = UnixListener::bind(&socket)
                    .with_context(|| format!("could not bind {bind_description}"))?;
                listener.set_nonblocking(true)?;
                UnixOrTcpListener::Unix {
                    listener: tokio::net::UnixListener::from_std(listener)?,
                    path: Some(socket.into()),
                }
            }

            #[cfg(not(unix))]
            HttpBindConfig::Unix { .. } => {
                anyhow::bail!("UNIX domain sockets are not supported on this platform");
            }

            HttpBindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Tcp,
            } => {
                let listener = fd_manager
                    .take_tcp_listener(*fd)?
                    .with_context(|| format!("no listener found for {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            #[cfg(unix)]
            HttpBindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Unix,
            } => {
                let listener = fd_manager
                    .take_unix_listener(*fd)?
                    .with_context(|| format!("no listener found for {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            #[cfg(not(unix))]
            HttpBindConfig::FileDescriptor {
                kind: UnixOrTcp::Unix,
                ..
            } => {
                anyhow::bail!(
                    "UNIX domain socket file descriptors are not supported on this platform"
                );
            }
        };

        listeners.push(listener);
    }

    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use coauth_config::HttpBindConfig;
    use coauth_data::UrlBuilder;
    use http::StatusCode;
    use http::header::{ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
    use salvo::prelude::Router;
    use salvo::test::{ResponseExt, TestClient};

    use super::{
        absolute_redirect_location, build_account_api_router, build_admin_router, build_listeners,
    };

    #[test]
    fn bind_error_mentions_requested_address() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = occupied.local_addr().unwrap().port();
        let mut fd_manager = listenfd::ListenFd::from_env();

        let error = match build_listeners(
            &mut fd_manager,
            &[HttpBindConfig::Address {
                address: format!("127.0.0.1:{port}"),
            }],
        ) {
            Ok(_) => panic!("expected listener bind to fail"),
            Err(error) => error,
        };

        let message = format!("{error:#}");
        assert!(message.contains(&format!("127.0.0.1:{port}")), "{message}");
    }

    #[test]
    fn change_password_discovery_uses_frontend_route() {
        let url_builder = UrlBuilder::new("https://example.com/mas/".parse().unwrap(), None, None);

        let location = absolute_redirect_location(Some(&url_builder), "/password/change");

        assert_eq!(location, "https://example.com/mas/password/change");
    }

    #[tokio::test]
    async fn admin_openapi_json_uses_coauth_title() {
        let service = salvo::Service::new(build_admin_router(Router::new()));
        let mut response = TestClient::get("http://127.0.0.1:8698/api-doc/admin/openapi.json")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::OK));
        let body = response.take_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(json["info"]["title"], "coauth Admin API");
        assert!(json["paths"]["/_coauth/admin/user-sessions"].is_object());
        assert!(json["paths"]["/_coauth/admin/user-sessions/{id}"].is_object());
        assert!(json["paths"]["/_coauth/admin/user-sessions/{id}/finish"].is_object());
        assert!(json["paths"]["/_coauth/admin/oauth-sessions"].is_object());
        assert!(json["paths"]["/_coauth/admin/oauth-sessions/{id}"].is_object());
        assert!(json["paths"]["/_coauth/admin/oauth-sessions/{id}/finish"].is_object());
        assert!(json["paths"]["/_coauth/admin/personal-sessions"].is_object());
        assert!(json["paths"]["/_coauth/admin/personal-sessions/{id}"].is_object());
        assert!(json["paths"]["/_coauth/admin/personal-sessions/{id}/revoke"].is_object());
        assert!(json["paths"]["/_coauth/admin/accounts"].is_object());
        assert!(json["paths"]["/_coauth/admin/accounts/{id}"].is_object());
        assert!(json["paths"]["/_coauth/admin/accounts/{id}/lock"].is_object());
        assert!(json["paths"]["/_coauth/admin/accounts/{id}/disable"].is_object());
        assert!(json["paths"]["/_coauth/admin/accounts/{id}/dids"].is_object());
        assert!(json["paths"]["/_coauth/admin/devices"].is_object());
        assert!(json["paths"]["/_coauth/admin/devices/{id}/revoke"].is_object());
        assert!(json["paths"]["/_coauth/admin/claims"].is_object());
        assert!(json["paths"]["/_coauth/admin/claims/status"].is_object());
        assert!(json["paths"]["/_coauth/admin/policy-checks/dry-run"].is_object());
        assert!(!body.contains("Pasion Admin API"));
    }

    #[tokio::test]
    async fn admin_openapi_yaml_is_served_from_admin_and_well_known_paths() {
        let service = salvo::Service::new(build_admin_router(Router::new()));

        for path in [
            "/_coauth/admin/openapi.yaml",
            "/.well-known/cokret/openapi.yaml",
        ] {
            let mut response = TestClient::get(format!("http://127.0.0.1:8698{path}"))
                .send(&service)
                .await;

            assert_eq!(response.status_code, Some(StatusCode::OK));
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/yaml; charset=utf-8")
            );

            let body = response.take_string().await.unwrap();
            assert!(body.contains("title: coauth Admin API"), "{body}");
            assert!(body.contains("/_coauth/admin/user-sessions:"), "{body}");
            assert!(!body.contains("Pasion Admin API"), "{body}");
        }
    }

    #[tokio::test]
    async fn oidc_exchange_preflight_allows_dpop_header() {
        let service = salvo::Service::new(build_account_api_router(Router::new()));
        let response =
            TestClient::options("http://127.0.0.1:8698/_coauth/gate/account/auth/oidc/exchange")
                .add_header("Origin", "http://127.0.0.1:8080", true)
                .add_header("Access-Control-Request-Method", "POST", true)
                .add_header("Access-Control-Request-Headers", "content-type,dpop", true)
                .send(&service)
                .await;

        assert_eq!(response.status_code, Some(StatusCode::NO_CONTENT));
        assert_eq!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        let allow_headers = response
            .headers()
            .get(ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            allow_headers
                .split(',')
                .any(|header| header.trim() == "dpop"),
            "OIDC browser exchange must allow the DPoP header; got {allow_headers}",
        );
    }

    #[tokio::test]
    async fn oidc_exchange_post_error_keeps_browser_cors_headers() {
        let service = salvo::Service::new(build_account_api_router(Router::new()));
        let response =
            TestClient::post("http://127.0.0.1:8698/_coauth/gate/account/auth/oidc/exchange")
                .add_header("Origin", "http://127.0.0.1:8080", true)
                .add_header("Content-Type", "application/json", true)
                .add_header("DPoP", "malformed-proof", true)
                .body(
                    serde_json::json!({
                        "authorization_code": "stale-code",
                        "code_verifier": "verifier",
                        "redirect_uri": "http://127.0.0.1:8080/auth/callback",
                        "issuer": "https://offline.invalid",
                        "token_endpoint": "https://offline.invalid/oauth/token",
                        "userinfo_endpoint": "https://offline.invalid/oauth/userinfo",
                        "client_id": "yougen",
                        "device_id": "ck:device:01964137-0000-7000-8000-000000000001"
                    })
                    .to_string(),
                )
                .send(&service)
                .await;

        assert_eq!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("*"),
            "OIDC browser exchange POST errors must remain visible to browser callers",
        );
    }
}
