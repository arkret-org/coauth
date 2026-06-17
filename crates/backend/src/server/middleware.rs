use std::time::Duration;

use headers::{CacheControl, HeaderMapExt as _, UserAgent};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, USER_AGENT};
use http::{HeaderValue, Method, StatusCode, Version};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_semantic_conventions::trace::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, HTTP_ROUTE, NETWORK_PROTOCOL_NAME,
    NETWORK_PROTOCOL_VERSION, URL_PATH, URL_QUERY, URL_SCHEME, USER_AGENT_ORIGINAL,
};
use salvo::cors::{Any, Cors};
use salvo::prelude::*;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::app_state::AppState;
use crate::listener::ConnectionInfo;

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
pub(super) struct RequestTimeout {
    pub(super) duration: Duration,
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
pub(super) struct InjectAppState(pub(super) AppState);

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
pub(super) struct OpenApiYaml {
    yaml: String,
}

impl OpenApiYaml {
    pub(super) fn from_doc(doc: &salvo::oapi::OpenApi) -> Self {
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

pub(super) fn public_oidc_browser_cors() -> impl Handler {
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
pub(super) async fn oidc_preflight_handler() -> StatusCode {
    StatusCode::NO_CONTENT
}

const INLINE_FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#1f7a4f"/><text x="32" y="41" text-anchor="middle" font-size="34" font-family="Arial,sans-serif" font-weight="700" fill="white">C</text></svg>"##;

#[handler]
pub(super) async fn favicon_handler(res: &mut Response) {
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml; charset=utf-8"),
    );
    res.render(Text::Plain(INLINE_FAVICON_SVG));
}
