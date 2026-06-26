use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

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
const COAUTH_OUTBOUND_HTTP_PRIVATE_ALLOWLIST: &str = "COAUTH_OUTBOUND_HTTP_PRIVATE_ALLOWLIST";

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
pub(crate) const fn starid_mutation_policy(operation: &'static str) -> OutboundRequestPolicy {
    OutboundRequestPolicy::new("starid", operation)
        .with_timeout(Duration::from_secs(10))
        .with_max_attempts(1)
}

#[must_use]
pub(crate) const fn starid_verification_policy(operation: &'static str) -> OutboundRequestPolicy {
    OutboundRequestPolicy::new("starid", operation)
        .with_timeout(Duration::from_secs(10))
        .with_max_attempts(2)
        .with_backoff(Duration::from_millis(100))
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

#[must_use]
pub(crate) const fn policy_frontier_policy() -> OutboundRequestPolicy {
    OutboundRequestPolicy::new("policy_frontier", "fetch")
        .with_timeout(Duration::from_millis(1_500))
        .with_max_attempts(2)
        .with_backoff(Duration::from_millis(50))
}

struct TracingResolver {
    inner: GaiResolver,
}

impl TracingResolver {
    fn new() -> Self {
        Self {
            inner: GaiResolver::new(),
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
                return Box::pin(async move {
                    Err(Box::new(error) as Box<dyn StdError + Send + Sync>)
                });
            }
        };
        if !private_networks_allowed() {
            if private_egress_target_allowed(&requested_name) {
                let mut inner = self.inner.clone();
                return Box::pin(
                    inner
                        .call(parsed_name)
                        .map(move |result| {
                            let addrs =
                                result.map_err(|err| -> Box<dyn StdError + Send + Sync> {
                                    Box::new(err)
                                })?;
                            let addrs: Vec<SocketAddr> = addrs.collect();
                            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
                        })
                        .instrument(span),
                );
            }
            if let Some(reason) = blocked_domain_reason(&requested_name) {
                return Box::pin(async move {
                    Err(Box::new(BlockedEgressTarget::new(requested_name, reason))
                        as Box<dyn StdError + Send + Sync>)
                });
            }
            if let Ok(ip) = requested_name.parse::<IpAddr>()
                && let Some(reason) = blocked_ip_reason(ip)
            {
                return Box::pin(async move {
                    Err(Box::new(BlockedEgressTarget::new(requested_name, reason))
                        as Box<dyn StdError + Send + Sync>)
                });
            }
        }
        let mut inner = self.inner.clone();
        Box::pin(
            inner
                .call(parsed_name)
                .map(move |result| {
                    let addrs = result
                        .map_err(|err| -> Box<dyn StdError + Send + Sync> { Box::new(err) })?;
                    let addrs: Vec<SocketAddr> = addrs.collect();
                    enforce_resolved_egress_policy(&requested_name, &addrs)?;
                    Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
                })
                .instrument(span),
        )
    }
}

#[derive(Debug)]
struct BlockedEgressTarget {
    target: String,
    reason: &'static str,
}

impl BlockedEgressTarget {
    fn new(target: impl Into<String>, reason: &'static str) -> Self {
        Self {
            target: target.into(),
            reason,
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
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    if private_networks_allowed() {
        return Ok(());
    }

    if private_egress_target_allowed(host) {
        return Ok(());
    }

    if let Some(reason) = blocked_domain_reason(host) {
        return Err(Box::new(BlockedEgressTarget::new(host, reason)));
    }

    for addr in addrs {
        if let Some(reason) = blocked_ip_reason(addr.ip()) {
            return Err(Box::new(BlockedEgressTarget::new(
                format!("{} ({})", host, addr.ip()),
                reason,
            )));
        }
    }

    Ok(())
}

fn private_networks_allowed() -> bool {
    if env_flag_enabled("COAUTH_OUTBOUND_HTTP_DENY_PRIVATE") {
        return false;
    }
    // COA-SEC-01: private/cloud-metadata egress is allowed ONLY when explicitly
    // opted in via env flag. Previously `cfg!(debug_assertions)` defaulted debug
    // builds to allow, silently disabling SSRF protection for the whole
    // private/loopback/link-local/metadata range whenever a debug image was
    // (mis)deployed. debug and release now behave identically: deny by default.
    env_flag_enabled("COAUTH_OUTBOUND_HTTP_ALLOW_PRIVATE")
        || env_flag_enabled("COAUTH_ALLOW_PRIVATE_EGRESS")
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        let value = value.trim();
        !(value.is_empty()
            || value.eq_ignore_ascii_case("0")
            || value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("no"))
    })
}

fn private_egress_target_allowed(host: &str) -> bool {
    std::env::var(COAUTH_OUTBOUND_HTTP_PRIVATE_ALLOWLIST)
        .ok()
        .is_some_and(|raw| target_allowed_by_private_allowlist(host, &raw))
}

fn target_allowed_by_private_allowlist(host: &str, raw: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    raw.split([',', ';', '\n'])
        .map(|entry| entry.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            let entry = entry
                .strip_prefix("host:")
                .or_else(|| entry.strip_prefix("domain:"))
                .unwrap_or(entry.as_str());
            if let Some(domain) = entry.strip_prefix("*.") {
                host.ends_with(&format!(".{domain}"))
            } else {
                host == entry
            }
        })
}

fn blocked_domain_reason(host: &str) -> Option<&'static str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return Some("localhost names are not routable outbound targets");
    }
    if matches!(
        host.rsplit_once('.').map(|(_, suffix)| suffix),
        Some("local" | "internal")
    ) {
        return Some("internal-only DNS suffix");
    }
    if host == "metadata.google.internal" {
        return Some("cloud metadata hostname");
    }
    None
}

fn blocked_ip_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(addr) => blocked_ipv4_reason(addr),
        IpAddr::V6(addr) => blocked_ipv6_reason(addr),
    }
}

fn blocked_ipv4_reason(addr: Ipv4Addr) -> Option<&'static str> {
    let octets = addr.octets();
    if octets[0] == 0 {
        return Some("this-network IPv4 range");
    }
    if octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
    {
        return Some("private IPv4 range");
    }
    if octets[0] == 127 {
        return Some("loopback IPv4 range");
    }
    if octets[0] == 169 && octets[1] == 254 {
        return Some("link-local IPv4 range");
    }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return Some("carrier-grade NAT IPv4 range");
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return Some("IETF protocol-assignment IPv4 range");
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return Some("documentation IPv4 range");
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Some("benchmark IPv4 range");
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return Some("documentation IPv4 range");
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return Some("documentation IPv4 range");
    }
    if (224..=239).contains(&octets[0]) {
        return Some("multicast IPv4 range");
    }
    if octets[0] >= 240 {
        return Some("reserved IPv4 range");
    }
    if addr == Ipv4Addr::BROADCAST {
        return Some("broadcast IPv4 address");
    }
    None
}

fn blocked_ipv6_reason(addr: Ipv6Addr) -> Option<&'static str> {
    let segments = addr.segments();
    if addr.is_unspecified() {
        return Some("unspecified IPv6 address");
    }
    if addr.is_loopback() {
        return Some("loopback IPv6 address");
    }
    if segments[0] & 0xfe00 == 0xfc00 {
        return Some("unique-local IPv6 range");
    }
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some("link-local IPv6 range");
    }
    if segments[0] & 0xff00 == 0xff00 {
        return Some("multicast IPv6 range");
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some("documentation IPv6 range");
    }
    None
}

/// Create a new [`reqwest::Client`] with sane parameters.
///
/// # Panics
///
/// Panics if the client fails to build, which should never happen.
#[must_use]
pub fn reqwest_client() -> reqwest::Client {
    reqwest_client_builder()
        .build()
        .expect("failed to create HTTP client")
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
    reqwest_client_builder()
        .resolve_to_addrs(host, addrs)
        .build()
        .expect("failed to create static-resolution HTTP client")
}

fn reqwest_client_builder() -> reqwest::ClientBuilder {
    let tls_config: rustls::ClientConfig =
        rustls::ClientConfig::with_platform_verifier().expect("failed to create TLS config");

    reqwest::Client::builder()
        .dns_resolver(Arc::new(TracingResolver::new()))
        .use_preconfigured_tls(tls_config)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_mins(1))
        .connect_timeout(Duration::from_secs(30))
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

    let span = tracing::info_span!(
        "http.client.request",
        "otel.kind" = "client",
        "otel.status_code" = tracing::field::Empty,
        { HTTP_REQUEST_METHOD } = method,
        { URL_FULL } = %request.url(),
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

pub(crate) trait RequestBuilderExt {
    fn send_traced(self) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> + Send;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn send_traced(self) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> + Send {
        send_traced(self)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Once};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        OutboundRequestPolicy, blocked_domain_reason, blocked_ip_reason, send_with_policy,
        target_allowed_by_private_allowlist,
    };

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[test]
    fn egress_policy_blocks_internal_names() {
        assert!(blocked_domain_reason("localhost").is_some());
        assert!(blocked_domain_reason("api.internal").is_some());
        assert!(blocked_domain_reason("metadata.google.internal").is_some());
        assert!(blocked_domain_reason("example.com").is_none());
    }

    #[test]
    fn private_egress_allowlist_matches_exact_and_wildcard_hosts() {
        let raw = "host:soland.internal,*.svc.cluster.local,10.10.20.30";

        assert!(target_allowed_by_private_allowlist("soland.internal", raw));
        assert!(target_allowed_by_private_allowlist(
            "coauth.auth.svc.cluster.local",
            raw
        ));
        assert!(target_allowed_by_private_allowlist("10.10.20.30", raw));
        assert!(!target_allowed_by_private_allowlist(
            "metadata.google.internal",
            raw
        ));
        assert!(!target_allowed_by_private_allowlist(
            "evilsoland.internal",
            raw
        ));
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
            assert!(blocked_ip_reason(ip).is_some(), "{ip}");
        }

        assert!(blocked_ip_reason("8.8.8.8".parse().unwrap()).is_none());
        assert!(blocked_ip_reason("2001:4860:4860::8888".parse().unwrap()).is_none());
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
