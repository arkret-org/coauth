use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arkret_egress_policy::{AddressClass, OutboundPolicy};
use futures_util::FutureExt as _;
use headers::{ContentLength, HeaderMapExt as _, UserAgent};
use hyper_util::client::legacy::connect::HttpInfo;
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
use opentelemetry_http::HeaderInjector;
use opentelemetry_semantic_conventions::attribute::{
    HTTP_REQUEST_BODY_SIZE, HTTP_RESPONSE_BODY_SIZE,
};
use opentelemetry_semantic_conventions::metric::{
    HTTP_CLIENT_ACTIVE_REQUESTS, HTTP_CLIENT_REQUEST_DURATION,
};
use opentelemetry_semantic_conventions::trace::{
    ERROR_TYPE, HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, NETWORK_LOCAL_ADDRESS,
    NETWORK_LOCAL_PORT, NETWORK_PEER_ADDRESS, NETWORK_PEER_PORT, NETWORK_TRANSPORT, NETWORK_TYPE,
    SERVER_ADDRESS, SERVER_PORT, URL_FULL, URL_SCHEME, USER_AGENT_ORIGINAL,
};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::time::{Instant, sleep};
use tower_service::Service as _;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::telemetry::METER;

static USER_AGENT: &str = concat!("coauth/", env!("CARGO_PKG_VERSION"));

const ENABLE_TEST_ENDPOINTS_ENV: &str = "COAUTH_ENABLE_TEST_ENDPOINTS";
const ALLOW_INSECURE_LOOPBACK_HTTP_ENV: &str = "COAUTH_ALLOW_INSECURE_LOOPBACK_HTTP";

static HTTP_REQUESTS_DURATION_HISTOGRAM: std::sync::LazyLock<Histogram<u64>> =
    std::sync::LazyLock::new(|| {
        METER
            .u64_histogram(HTTP_CLIENT_REQUEST_DURATION)
            .with_unit("ms")
            .with_description("Duration of HTTP client requests")
            .build()
    });

static HTTP_REQUESTS_IN_FLIGHT: std::sync::LazyLock<UpDownCounter<i64>> =
    std::sync::LazyLock::new(|| {
        METER
            .i64_up_down_counter(HTTP_CLIENT_ACTIVE_REQUESTS)
            .with_unit("{requests}")
            .with_description("Number of HTTP client requests in flight")
            .build()
    });

static OUTBOUND_HTTP_RETRIES: std::sync::LazyLock<Counter<u64>> = std::sync::LazyLock::new(|| {
    METER
        .u64_counter("coauth.outbound_http.retries")
        .with_unit("{retry}")
        .with_description("Outbound HTTP retry attempts by upstream service and operation")
        .build()
});

static OUTBOUND_HTTP_ERRORS: std::sync::LazyLock<Counter<u64>> = std::sync::LazyLock::new(|| {
    METER
        .u64_counter("coauth.outbound_http.errors")
        .with_unit("{error}")
        .with_description("Outbound HTTP terminal errors by upstream service and operation")
        .build()
});

#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboundRequestPolicy {
    service: &'static str,
    operation: &'static str,
    timeout: Duration,
    max_attempts: usize,
    backoff: Duration,
}

impl OutboundRequestPolicy {
    #[must_use]
    pub(crate) const fn new(service: &'static str, operation: &'static str) -> Self {
        Self {
            service,
            operation,
            timeout: Duration::from_secs(10),
            max_attempts: 1,
            backoff: Duration::from_millis(100),
        }
    }

    #[must_use]
    pub(crate) const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub(crate) const fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    #[must_use]
    pub(crate) const fn with_backoff(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }

    fn max_attempts(self) -> usize {
        self.max_attempts.max(1)
    }
}

#[must_use]
pub(crate) const fn soland_policy(operation: &'static str) -> OutboundRequestPolicy {
    OutboundRequestPolicy::new("soland", operation)
        .with_timeout(Duration::from_secs(10))
        .with_max_attempts(2)
        .with_backoff(Duration::from_millis(100))
}

/// Policy for upstream OIDC / IdP authentication-path egress
/// (discovery / JWKS / userinfo / token exchange) — COA-SEC-02. Short per-call
/// timeout with a small bounded retry budget, replacing the previous reliance
/// on the shared client's 60 s global timeout, so a slow/hung upstream cannot
/// pile up coauth auth-processing tasks.
#[must_use]
pub(crate) const fn oidc_upstream_policy(operation: &'static str) -> OutboundRequestPolicy {
    OutboundRequestPolicy::new("oidc_upstream", operation)
        .with_timeout(Duration::from_secs(10))
        .with_max_attempts(2)
        .with_backoff(Duration::from_millis(100))
}

struct TracingResolver {
    inner: GaiResolver,
    allow_loopback: bool,
    trusted_loopback_https_hosts: Arc<HashSet<String>>,
}

impl TracingResolver {
    fn new(allow_loopback: bool, trusted_loopback_https_hosts: &[String]) -> Self {
        Self {
            inner: GaiResolver::new(),
            allow_loopback,
            trusted_loopback_https_hosts: Arc::new(
                trusted_loopback_https_hosts
                    .iter()
                    .map(|host| normalize_host(host))
                    .collect(),
            ),
        }
    }
}

impl reqwest::dns::Resolve for TracingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let requested_name = name.as_str().to_owned();
        let span = tracing::info_span!("dns.resolve", name = requested_name);
        // Parse the hostname into the inner resolver's `Name` exactly once,
        // mapping a parse failure to a resolver error instead of panicking
        // (COA-COR-01). `name` was constructed by reqwest/hyper so this round
        // trip normally succeeds; the explicit error path guards against any
        // hostname-validation drift between hyper and this `Name::from_str`.
        let parsed_name = match Name::from_str(name.as_str()) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Box::pin(
                    async move { Err(Box::new(error) as Box<dyn StdError + Send + Sync>) },
                );
            }
        };
        if self.allow_loopback && !is_explicit_loopback_host(&requested_name) {
            return Box::pin(async move {
                Err(Box::new(BlockedEgressTarget::new(
                    requested_name,
                    "debug loopback client only permits localhost or loopback IP literals",
                )) as Box<dyn StdError + Send + Sync>)
            });
        }
        if let Some(reason) = blocked_domain_reason(&requested_name, self.allow_loopback) {
            return Box::pin(async move {
                Err(Box::new(BlockedEgressTarget::new(requested_name, reason))
                    as Box<dyn StdError + Send + Sync>)
            });
        }
        if let Ok(ip) = requested_name.parse::<IpAddr>()
            && let Some(reason) = blocked_ip_reason(ip, self.allow_loopback)
        {
            return Box::pin(async move {
                Err(Box::new(BlockedEgressTarget::new(requested_name, reason))
                    as Box<dyn StdError + Send + Sync>)
            });
        }
        let mut inner = self.inner.clone();
        let allow_loopback = self.allow_loopback;
        let trusted_loopback_https_hosts = Arc::clone(&self.trusted_loopback_https_hosts);
        Box::pin(
            inner
                .call(parsed_name)
                .map(move |result| {
                    let addrs = result
                        .map_err(|err| -> Box<dyn StdError + Send + Sync> { Box::new(err) })?;
                    let addrs: Vec<SocketAddr> = addrs.collect();
                    enforce_resolved_egress_policy(
                        &requested_name,
                        &addrs,
                        allow_loopback,
                        &trusted_loopback_https_hosts,
                    )?;
                    Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
                })
                .instrument(span),
        )
    }
}

#[derive(Debug)]
struct BlockedEgressTarget {
    target: String,
    reason: String,
}

impl BlockedEgressTarget {
    fn new(target: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for BlockedEgressTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "outbound HTTP target {} blocked by egress policy: {}",
            self.target, self.reason
        )
    }
}

impl StdError for BlockedEgressTarget {}

fn enforce_resolved_egress_policy(
    host: &str,
    addrs: &[SocketAddr],
    allow_loopback: bool,
    trusted_loopback_https_hosts: &HashSet<String>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    if let Some(reason) = blocked_domain_reason(host, allow_loopback) {
        return Err(Box::new(BlockedEgressTarget::new(host, reason)));
    }
    if allow_loopback {
        for addr in addrs {
            if !addr.ip().is_loopback() {
                return Err(Box::new(BlockedEgressTarget::new(
                    host,
                    "debug loopback client resolved outside the loopback range",
                )));
            }
        }
        return Ok(());
    }
    // Arkret service endpoints are operator-controlled trust anchors. Permit an
    // exact configured hostname to resolve wholly to loopback so local HTTPS
    // deployments can use stable names such as `local.host`. This exception is
    // deliberately narrower than private-network egress: it never permits an
    // unconfigured host, a private/LAN address, or a mixed DNS answer.
    if trusted_loopback_https_hosts.contains(&normalize_host(host))
        && !addrs.is_empty()
        && addrs.iter().all(|addr| addr.ip().is_loopback())
    {
        return Ok(());
    }
    OutboundPolicy::public_https()
        .validate_resolved_addresses(addrs)
        .map_err(|error| Box::new(error) as Box<dyn StdError + Send + Sync>)
}

pub(crate) fn blocked_domain_reason(host: &str, allow_loopback: bool) -> Option<&'static str> {
    let reason = arkret_egress_policy::classify_host(host)?;
    if allow_loopback && reason == "localhost name" {
        return None;
    }
    Some(reason)
}

pub(crate) fn blocked_ip_reason(ip: IpAddr, allow_loopback: bool) -> Option<&'static str> {
    let class = arkret_egress_policy::classify_ip(ip)?;
    if allow_loopback && class == AddressClass::Loopback {
        return None;
    }
    Some(match class {
        AddressClass::Unspecified => "unspecified address",
        AddressClass::Loopback => "loopback address",
        AddressClass::Private => "private address",
        AddressClass::LinkLocal => "link-local address",
        AddressClass::CarrierGradeNat => "carrier-grade NAT address",
        AddressClass::Benchmark => "benchmark address",
        AddressClass::ProtocolAssignment => "protocol-assignment address",
        AddressClass::Documentation => "documentation address",
        AddressClass::Multicast => "multicast address",
        AddressClass::Reserved => "reserved address",
        AddressClass::Broadcast => "broadcast address",
        _ => "non-public address",
    })
}

fn is_explicit_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Create a new [`reqwest::Client`] with sane parameters.
///
/// # Panics
///
/// Panics if the client fails to build, which should never happen.
#[must_use]
pub fn reqwest_client() -> reqwest::Client {
    reqwest_client_builder(insecure_loopback_http_enabled(), &[])
        .build()
        .expect("failed to create HTTP client")
}

#[cfg(test)]
pub(crate) fn reqwest_client_for_tests() -> reqwest::Client {
    reqwest_client_builder(true, &[])
        .build()
        .expect("failed to create loopback HTTP test client")
}

/// Create the server-runtime HTTP client with narrowly scoped loopback HTTPS
/// exceptions for operator-configured Arkret service hosts.
///
/// The configured host name must match exactly and every resolved address must
/// be loopback. All other targets retain the normal public-HTTPS-only policy.
#[must_use]
pub fn reqwest_client_for_arkret(config: &coauth_config::ArkretConfig) -> reqwest::Client {
    let trusted_hosts = config.trusted_outbound_hosts();
    reqwest_client_builder(insecure_loopback_http_enabled(), &trusted_hosts)
        .build()
        .expect("failed to create Arkret HTTP client")
}

/// Create the HTTP client used by the server process.
///
/// In addition to configured Arkret service trust anchors, the server's own
/// public and issuer origins are exact trust anchors. Coauth performs live OIDC
/// discovery against its issuer during authorization-code exchange, so a local
/// Caddy-fronted issuer such as `auth.local.host` must be able to resolve to
/// loopback without weakening the policy for any other hostname.
#[must_use]
pub fn reqwest_client_for_server(
    config: &coauth_config::ArkretConfig,
    public_base: &url::Url,
    issuer: Option<&url::Url>,
) -> reqwest::Client {
    let trusted_hosts = server_trusted_loopback_https_hosts(config, public_base, issuer);
    reqwest_client_builder(insecure_loopback_http_enabled(), &trusted_hosts)
        .build()
        .expect("failed to create server HTTP client")
}

fn server_trusted_loopback_https_hosts(
    config: &coauth_config::ArkretConfig,
    public_base: &url::Url,
    issuer: Option<&url::Url>,
) -> Vec<String> {
    let mut hosts = config.trusted_outbound_hosts();
    for origin in std::iter::once(public_base).chain(issuer) {
        let Some(host) = origin.host_str() else {
            continue;
        };
        let host = normalize_host(host);
        if !hosts.iter().any(|trusted| normalize_host(trusted) == host) {
            hosts.push(host);
        }
    }
    hosts
}

/// Create a new [`reqwest::Client`] that pins `host` to already-resolved
/// socket addresses while retaining the standard outbound HTTP guardrails.
///
/// This is used by SSRF-sensitive callers that pre-resolve and validate DNS
/// answers before request dispatch and then need to prevent a second DNS lookup
/// from rebinding to a different address set.
///
/// # Panics
///
/// Panics if the client fails to build, which should never happen.
pub(crate) fn reqwest_client_with_static_resolution(
    host: &str,
    addrs: &[SocketAddr],
) -> reqwest::Client {
    reqwest_client_builder(false, &[])
        .resolve_to_addrs(host, addrs)
        .build()
        .expect("failed to create static-resolution HTTP client")
}

fn reqwest_client_builder(
    allow_insecure_loopback_http: bool,
    trusted_loopback_https_hosts: &[String],
) -> reqwest::ClientBuilder {
    let tls_config: rustls::ClientConfig =
        rustls::ClientConfig::with_platform_verifier().expect("failed to create TLS config");

    reqwest::Client::builder()
        .https_only(!allow_insecure_loopback_http)
        .dns_resolver(Arc::new(TracingResolver::new(
            allow_insecure_loopback_http,
            trusted_loopback_https_hosts,
        )))
        .use_preconfigured_tls(tls_config)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_mins(1))
        .connect_timeout(Duration::from_secs(30))
}

fn insecure_loopback_http_enabled() -> bool {
    cfg!(debug_assertions)
        && runtime_flag_enabled(ENABLE_TEST_ENDPOINTS_ENV)
        && runtime_flag_enabled(ALLOW_INSECURE_LOOPBACK_HTTP_ENV)
}

fn runtime_flag_enabled(name: &str) -> bool {
    coauth_config::runtime_var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn telemetry_url(url: &url::Url) -> url::Url {
    let mut sanitized = url.clone();
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    let _ = sanitized.set_username("");
    let _ = sanitized.set_password(None);
    sanitized
}

async fn send_traced(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    let start = Instant::now();
    let (client, request) = request.build_split();
    let mut request = request?;

    let headers = request.headers();
    let server_address = request.url().host_str().map(ToOwned::to_owned);
    let server_port = request.url().port_or_known_default();
    let scheme = request.url().scheme().to_owned();
    let user_agent = headers
        .typed_get::<UserAgent>()
        .map(tracing::field::display);
    let content_length = headers.typed_get().map(|ContentLength(len)| len);
    let method = request.method().to_string();
    let telemetry_url = telemetry_url(request.url());

    let span = tracing::info_span!(
        "http.client.request",
        "otel.kind" = "client",
        "otel.status_code" = tracing::field::Empty,
        { HTTP_REQUEST_METHOD } = method,
        { URL_FULL } = %telemetry_url,
        { HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { SERVER_ADDRESS } = server_address,
        { SERVER_PORT } = server_port,
        { HTTP_REQUEST_BODY_SIZE } = content_length,
        { HTTP_RESPONSE_BODY_SIZE } = tracing::field::Empty,
        { NETWORK_TRANSPORT } = "tcp",
        { NETWORK_TYPE } = tracing::field::Empty,
        { NETWORK_LOCAL_ADDRESS } = tracing::field::Empty,
        { NETWORK_LOCAL_PORT } = tracing::field::Empty,
        { NETWORK_PEER_ADDRESS } = tracing::field::Empty,
        { NETWORK_PEER_PORT } = tracing::field::Empty,
        { USER_AGENT_ORIGINAL } = user_agent,
        "rust.error" = tracing::field::Empty,
    );

    let context = span.context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        let mut injector = HeaderInjector(request.headers_mut());
        propagator.inject_context(&context, &mut injector);
    });

    let mut metrics_labels = vec![
        KeyValue::new(HTTP_REQUEST_METHOD, method.clone()),
        KeyValue::new(URL_SCHEME, scheme),
    ];

    if let Some(server_address) = server_address {
        metrics_labels.push(KeyValue::new(SERVER_ADDRESS, server_address));
    }

    if let Some(server_port) = server_port {
        metrics_labels.push(KeyValue::new(SERVER_PORT, i64::from(server_port)));
    }

    HTTP_REQUESTS_IN_FLIGHT.add(1, &metrics_labels);
    async move {
        let span = tracing::Span::current();
        let result = client.execute(request).await;

        HTTP_REQUESTS_IN_FLIGHT.add(-1, &metrics_labels);

        let duration = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let result = match result {
            Ok(response) => {
                span.record("otel.status_code", "OK");
                span.record(HTTP_RESPONSE_STATUS_CODE, response.status().as_u16());

                if let Some(ContentLength(content_length)) = response.headers().typed_get() {
                    span.record(HTTP_RESPONSE_BODY_SIZE, content_length);
                }

                if let Some(http_info) = response.extensions().get::<HttpInfo>() {
                    let local = http_info.local_addr();
                    let peer = http_info.remote_addr();
                    let family = if local.is_ipv4() { "ipv4" } else { "ipv6" };
                    span.record(NETWORK_TYPE, family);
                    span.record(NETWORK_LOCAL_ADDRESS, local.ip().to_string());
                    span.record(NETWORK_LOCAL_PORT, local.port());
                    span.record(NETWORK_PEER_ADDRESS, peer.ip().to_string());
                    span.record(NETWORK_PEER_PORT, peer.port());
                } else {
                    tracing::warn!("No HttpInfo injected in response extensions");
                }

                metrics_labels.push(KeyValue::new(
                    HTTP_RESPONSE_STATUS_CODE,
                    i64::from(response.status().as_u16()),
                ));

                Ok(response)
            }
            Err(err) => {
                span.record("otel.status_code", "ERROR");
                span.record("rust.error", &err as &dyn std::error::Error);

                metrics_labels.push(KeyValue::new(ERROR_TYPE, "NO_RESPONSE"));

                Err(err)
            }
        };

        HTTP_REQUESTS_DURATION_HISTOGRAM.record(duration, &metrics_labels);

        result
    }
    .instrument(span)
    .await
}

pub(crate) async fn send_with_policy<F>(
    policy: OutboundRequestPolicy,
    build_request: F,
) -> Result<reqwest::Response, reqwest::Error>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let max_attempts = policy.max_attempts();
    for attempt in 1..max_attempts {
        let result = build_request().timeout(policy.timeout).send_traced().await;
        match result {
            Ok(response) => {
                let status = response.status();
                if retryable_status(status) {
                    record_retry(
                        policy,
                        attempt,
                        "http_status",
                        Some(i64::from(status.as_u16())),
                    );
                    sleep(policy.backoff).await;
                    continue;
                }
                if !status.is_success() {
                    record_terminal_error(policy, "http_status", Some(i64::from(status.as_u16())));
                }
                return Ok(response);
            }
            Err(error) if retryable_error(&error) => {
                record_retry(policy, attempt, reqwest_error_type(&error), None);
                sleep(policy.backoff).await;
            }
            Err(error) => {
                record_terminal_error(policy, reqwest_error_type(&error), None);
                return Err(error);
            }
        }
    }

    let result = build_request().timeout(policy.timeout).send_traced().await;
    match result {
        Ok(response) => {
            if !response.status().is_success() {
                record_terminal_error(
                    policy,
                    "http_status",
                    Some(i64::from(response.status().as_u16())),
                );
            }
            Ok(response)
        }
        Err(error) => {
            record_terminal_error(policy, reqwest_error_type(&error), None);
            Err(error)
        }
    }
}

fn retryable_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

fn reqwest_error_type(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_decode() {
        "decode"
    } else if error.is_body() {
        "body"
    } else if error.is_builder() {
        "builder"
    } else {
        "request"
    }
}

fn policy_labels(
    policy: OutboundRequestPolicy,
    outcome: &'static str,
    status_code: Option<i64>,
) -> Vec<KeyValue> {
    let mut labels = vec![
        KeyValue::new("service", policy.service),
        KeyValue::new("operation", policy.operation),
        KeyValue::new("outcome", outcome),
    ];
    if let Some(status_code) = status_code {
        labels.push(KeyValue::new(HTTP_RESPONSE_STATUS_CODE, status_code));
    }
    labels
}

fn record_retry(
    policy: OutboundRequestPolicy,
    attempt: usize,
    outcome: &'static str,
    status_code: Option<i64>,
) {
    let labels = policy_labels(policy, outcome, status_code);
    OUTBOUND_HTTP_RETRIES.add(1, &labels);
    tracing::warn!(
        service = policy.service,
        operation = policy.operation,
        attempt,
        max_attempts = policy.max_attempts(),
        timeout_ms = policy.timeout.as_millis(),
        backoff_ms = policy.backoff.as_millis(),
        outcome,
        status_code,
        "outbound HTTP request failed; retrying within budget"
    );
}

fn record_terminal_error(
    policy: OutboundRequestPolicy,
    outcome: &'static str,
    status_code: Option<i64>,
) {
    let labels = policy_labels(policy, outcome, status_code);
    OUTBOUND_HTTP_ERRORS.add(1, &labels);
    tracing::warn!(
        service = policy.service,
        operation = policy.operation,
        max_attempts = policy.max_attempts(),
        timeout_ms = policy.timeout.as_millis(),
        outcome,
        status_code,
        "outbound HTTP request failed"
    );
}

/// Adds the standard outbound tracing instrumentation to a request builder.
pub trait RequestBuilderExt {
    fn send_traced(self) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> + Send;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn send_traced(self) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> + Send {
        send_traced(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Once};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        OutboundPolicy, OutboundRequestPolicy, blocked_domain_reason, blocked_ip_reason,
        enforce_resolved_egress_policy, reqwest_client_builder, send_with_policy,
        server_trusted_loopback_https_hosts, telemetry_url,
    };

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[test]
    fn egress_policy_blocks_internal_names() {
        assert!(blocked_domain_reason("localhost", false).is_some());
        assert!(blocked_domain_reason("api.internal", false).is_some());
        assert!(blocked_domain_reason("metadata.google.internal", false).is_some());
        assert!(blocked_domain_reason("example.com", false).is_none());
    }

    #[test]
    fn egress_policy_blocks_non_public_ip_ranges() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            let ip = ip.parse().unwrap();
            assert!(blocked_ip_reason(ip, false).is_some(), "{ip}");
        }

        assert!(blocked_ip_reason("8.8.8.8".parse().unwrap(), false).is_none());
        assert!(blocked_ip_reason("2001:4860:4860::8888".parse().unwrap(), false).is_none());
    }

    #[tokio::test]
    async fn explicit_test_client_allows_only_loopback_plain_http() {
        install_crypto_provider();
        let (url, attempts) = spawn_status_http_server(200).await;
        let client = reqwest_client_builder(true, &[]).build().unwrap();

        let response = client.get(url).send().await.unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let non_loopback = client
            .get("http://example.com/")
            .send()
            .await
            .expect_err("non-loopback HTTP must stay blocked");
        assert!(
            non_loopback.is_connect() || non_loopback.is_builder(),
            "{non_loopback}"
        );
    }

    #[test]
    fn configured_arkret_host_allows_only_exact_loopback_resolution() {
        let trusted = HashSet::from(["local.host".to_owned()]);
        let loopback = ["127.0.0.1:443".parse().unwrap()];
        assert!(enforce_resolved_egress_policy("LOCAL.HOST.", &loopback, false, &trusted).is_ok());

        assert!(enforce_resolved_egress_policy("other.host", &loopback, false, &trusted).is_err());
        let private = ["192.168.1.10:443".parse().unwrap()];
        assert!(enforce_resolved_egress_policy("local.host", &private, false, &trusted).is_err());
        let mixed = [
            "127.0.0.1:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ];
        assert!(enforce_resolved_egress_policy("local.host", &mixed, false, &trusted).is_err());
    }

    #[test]
    fn server_self_issuer_is_an_exact_loopback_https_trust_anchor() {
        let config = coauth_config::ArkretConfig::default();
        let public_base = url::Url::parse("https://auth.local.host/").unwrap();
        let trusted_hosts = server_trusted_loopback_https_hosts(&config, &public_base, None);
        let trusted = HashSet::from_iter(trusted_hosts);
        let loopback = ["127.0.0.1:443".parse().unwrap()];

        assert!(
            enforce_resolved_egress_policy("auth.local.host", &loopback, false, &trusted).is_ok()
        );
        assert!(
            enforce_resolved_egress_policy("attacker.local.host", &loopback, false, &trusted)
                .is_err()
        );
        let private = ["192.168.1.10:443".parse().unwrap()];
        assert!(
            enforce_resolved_egress_policy("auth.local.host", &private, false, &trusted).is_err()
        );
    }

    #[test]
    fn outbound_url_policy_blocks_ip_literals_that_bypass_dns_resolution() {
        for raw in [
            "http://8.8.8.8/jwks",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/jwks",
            "https://[::1]/jwks",
            "https://198.18.0.1/jwks",
            "https://192.0.2.1/jwks",
            "https://[64:ff9b::a9fe:a9fe]/jwks",
            "https://[2002:0a00:0001::]/jwks",
            "https://[2001:0000:7f00:0001:0000:0000:3f57:fefe]/jwks",
        ] {
            let url = url::Url::parse(raw).unwrap();
            assert!(
                OutboundPolicy::public_https().validate_url(&url).is_err(),
                "{raw} should be rejected before dispatch"
            );
        }
        assert!(
            OutboundPolicy::public_https()
                .validate_url(&url::Url::parse("https://8.8.8.8/jwks").unwrap())
                .is_ok()
        );
    }

    #[test]
    fn telemetry_url_drops_credentials_query_and_fragment() {
        let url = url::Url::parse(
            "https://client:password@example.com/token?secret=top-secret&access_token=value#frag",
        )
        .unwrap();
        assert_eq!(telemetry_url(&url).as_str(), "https://example.com/token");
    }

    #[tokio::test]
    async fn send_with_policy_applies_timeout() {
        install_crypto_provider();
        let (url, attempts) = spawn_sleeping_http_server(Duration::from_millis(200)).await;
        let client = reqwest::Client::new();
        let policy = OutboundRequestPolicy::new("test", "timeout")
            .with_timeout(Duration::from_millis(20))
            .with_max_attempts(1);

        let err = send_with_policy(policy, || client.get(url.clone()))
            .await
            .expect_err("request should time out");

        assert!(err.is_timeout(), "expected timeout, got {err}");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn send_with_policy_stops_at_retry_budget() {
        install_crypto_provider();
        let (url, attempts) = spawn_status_http_server(500).await;
        let client = reqwest::Client::new();
        let policy = OutboundRequestPolicy::new("test", "retry_budget")
            .with_timeout(Duration::from_secs(1))
            .with_max_attempts(2)
            .with_backoff(Duration::ZERO);

        let response = send_with_policy(policy, || client.get(url.clone()))
            .await
            .expect("final HTTP response is returned after retry budget is spent");

        assert_eq!(
            response.status(),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    async fn spawn_sleeping_http_server(delay: Duration) -> (String, Arc<AtomicUsize>) {
        spawn_http_server(move |_| {
            let delay = delay;
            async move {
                tokio::time::sleep(delay).await;
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
            }
        })
        .await
    }

    async fn spawn_status_http_server(status: u16) -> (String, Arc<AtomicUsize>) {
        spawn_http_server(move |_| async move {
            format!("HTTP/1.1 {status} test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        })
        .await
    }

    async fn spawn_http_server<F, Fut>(response: F) -> (String, Arc<AtomicUsize>)
    where
        F: Fn(usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = String> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test http server");
        let addr = listener.local_addr().expect("test server addr");
        let attempts = Arc::new(AtomicUsize::new(0));
        let response = Arc::new(response);
        let attempts_for_task = Arc::clone(&attempts);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let attempt = attempts_for_task.fetch_add(1, Ordering::SeqCst) + 1;
                let response = Arc::clone(&response);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    let _ = stream.read(&mut buffer).await;
                    let body = response(attempt).await;
                    let _ = stream.write_all(body.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}/"), attempts)
    }
}
