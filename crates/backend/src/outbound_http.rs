use std::future::Future;
use std::time::Duration;

use arkret_egress_reqwest::{EgressGuard, LockedEgressUrl, normalize_host};
use arkret_retry::{RetryPolicy, RetrySchedule};
use headers::{ContentLength, HeaderMapExt as _, UserAgent};
use hyper_util::client::legacy::connect::HttpInfo;
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
    retry: RetryPolicy,
}

impl OutboundRequestPolicy {
    #[must_use]
    pub(crate) const fn new(service: &'static str, operation: &'static str) -> Self {
        Self {
            service,
            operation,
            timeout: Duration::from_secs(10),
            max_attempts: 1,
            retry: RetryPolicy::arkret_default(),
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
    #[cfg(test)]
    pub(crate) const fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    fn max_attempts(self) -> usize {
        self.max_attempts.max(1)
    }

    const fn operation(self) -> &'static str {
        self.operation
    }
}

/// Hard upper bound on a fetched `did:webvh` history log. Shared by every
/// caller that verifies method-native history so one deployment-wide cap
/// governs the evidence transport.
pub(crate) const WEBVH_LOG_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Failure of [`fetch_bounded`], split so callers can keep a transient
/// transport problem apart from evidence that must never be accepted.
#[derive(Debug)]
pub(crate) enum BoundedFetchError {
    /// The peer was unreachable or answered with a non-success status.
    Unreachable(String),
    /// The shared egress guard refused the request.
    EgressDenied(String),
    /// The peer answered, but the body exceeded the caller's hard bound.
    TooLarge(String),
}

/// `GET` `url` under `policy` and read at most `max_bytes` of the body.
///
/// The bound is enforced twice — once against an advertised `Content-Length`
/// and again while streaming — so a peer that lies about or omits the header
/// still cannot make this allocate without limit.
pub(crate) async fn fetch_bounded(
    http_client: &reqwest::Client,
    policy: OutboundRequestPolicy,
    url: url::Url,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedFetchError> {
    let operation = policy.operation();
    let response = send_with_policy(policy, || http_client.get(url.clone()))
        .await
        .map_err(|error| {
            if error.is_connect() || error.is_timeout() {
                BoundedFetchError::Unreachable(error.to_string())
            } else {
                BoundedFetchError::EgressDenied(error.to_string())
            }
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(BoundedFetchError::Unreachable(format!(
            "{operation} returned status {status}"
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(BoundedFetchError::TooLarge(format!(
            "{operation} response exceeds {max_bytes} bytes"
        )));
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| BoundedFetchError::Unreachable(error.to_string()))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(BoundedFetchError::TooLarge(format!(
                "{operation} response exceeds {max_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Policy for calls to the principal server.
///
/// The backoff curve is `sync/api-conventions.md` §9 and is normative, not a
/// coauth tuning knob: the previous flat 100 ms wait breached the 1,000 ms
/// first-wait floor that §9 requires for every `(actor, service DID, endpoint)`
/// retry. The attempt budget stays deliberately below the §9 ceiling of 5
/// retries per 5 minutes.
#[must_use]
pub(crate) const fn soland_policy(operation: &'static str) -> OutboundRequestPolicy {
    OutboundRequestPolicy::new("soland", operation)
        .with_timeout(Duration::from_secs(10))
        .with_max_attempts(2)
}

/// Policy for upstream OIDC / IdP authentication-path egress
/// (discovery / JWKS / userinfo / token exchange) — COA-SEC-02. Short per-call
/// timeout with a small bounded retry budget, replacing the previous reliance
/// on the shared client's 60 s global timeout, so a slow/hung upstream cannot
/// pile up coauth auth-processing tasks.
///
/// The spec does not cover upstream IdP retries, so this deliberately reuses
/// the §9 curve rather than inventing a second one.
#[must_use]
pub(crate) const fn oidc_upstream_policy(operation: &'static str) -> OutboundRequestPolicy {
    OutboundRequestPolicy::new("oidc_upstream", operation)
        .with_timeout(Duration::from_secs(10))
        .with_max_attempts(2)
}

/// The outbound posture of a coauth HTTP client.
///
/// Both loopback affordances are deployment configuration carried by the shared
/// guard, not coauth-private code paths:
///
/// * `trusted_loopback_https_hosts` names operator-controlled hosts that may resolve *wholly* to
///   loopback while HTTPS is still enforced, so a Caddy-fronted `auth.local.host` works without
///   weakening any other target. An unnamed host, a private address, or a mixed DNS answer falls
///   back to the public-HTTPS policy.
/// * the debug client (`allow_insecure_loopback_http`) is restricted to loopback destinations only,
///   so enabling plain HTTP in a debug build cannot also open a path off the machine.
fn egress_guard(
    allow_insecure_loopback_http: bool,
    trusted_loopback_https_hosts: &[String],
) -> EgressGuard {
    if allow_insecure_loopback_http {
        EgressGuard::local_development()
            .loopback_only_with_trusted_hosts(trusted_loopback_https_hosts)
    } else {
        EgressGuard::public_https().with_trusted_loopback_https_hosts(trusted_loopback_https_hosts)
    }
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

/// Create a new [`reqwest::Client`] from a shared guard's already-judged,
/// already-resolved target.
///
/// This is used by SSRF-sensitive callers that pre-resolve and validate DNS
/// answers before request dispatch and then need to prevent a second DNS lookup
/// from rebinding to a different address set.
///
/// # Panics
///
/// Panics if the client fails to build, which should never happen.
pub(crate) fn reqwest_client_for_locked_egress(target: &LockedEgressUrl) -> reqwest::Client {
    target
        .apply_to_client_builder(base_client_builder().https_only(true))
        .build()
        .expect("failed to create locked-egress HTTP client")
}

fn reqwest_client_builder(
    allow_insecure_loopback_http: bool,
    trusted_loopback_https_hosts: &[String],
) -> reqwest::ClientBuilder {
    let guard = egress_guard(allow_insecure_loopback_http, trusted_loopback_https_hosts);
    guard.apply_to_client_builder(base_client_builder())
}

fn base_client_builder() -> reqwest::ClientBuilder {
    let builder = if let Some(path) = coauth_config::runtime_var_os("SSL_CERT_FILE") {
        let pem = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read SSL_CERT_FILE {}: {error}",
                std::path::Path::new(&path).display()
            )
        });
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .expect("SSL_CERT_FILE must contain at least one valid PEM certificate");
        reqwest::Client::builder().tls_certs_merge(certificates)
    } else {
        let tls_config: rustls::ClientConfig =
            rustls::ClientConfig::with_platform_verifier().expect("failed to create TLS config");
        reqwest::Client::builder().use_preconfigured_tls(tls_config)
    };
    builder
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
    let mut schedule = RetrySchedule::from_policy(policy.retry)
        .with_jitter(policy.retry.jitter_ratio(), retry_jitter_seed());
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
                    // `api-conventions.md:545`/`:547` — the server hint wins
                    // over the local ladder and MUST NOT be clamped shorter.
                    sleep(schedule.next_delay_with_hint(retry_after_hint(&response))).await;
                    continue;
                }
                if !status.is_success() {
                    record_terminal_error(policy, "http_status", Some(i64::from(status.as_u16())));
                }
                return Ok(response);
            }
            Err(error) if retryable_error(&error) => {
                record_retry(policy, attempt, reqwest_error_type(&error), None);
                sleep(schedule.next_delay()).await;
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

/// The server's `Retry-After` hint, in either normative form.
///
/// `api-conventions.md:545` gives the header priority over a body
/// `retry_after_ms`, and permits both delta-seconds and an HTTP-date.
fn retry_after_hint(response: &reqwest::Response) -> Option<Duration> {
    let raw = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let deadline = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
    (deadline.with_timezone(&chrono::Utc) - chrono::Utc::now())
        .to_std()
        .ok()
}

/// A fresh per-call jitter seed, folding a monotonic counter into a wall-clock
/// sample so concurrent callers that share a timestamp do not line up.
fn retry_jitter_seed() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    nanos ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15)
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
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Once};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        EgressGuard, OutboundRequestPolicy, egress_guard, reqwest_client_builder, retry_after_hint,
        send_with_policy, server_trusted_loopback_https_hosts, telemetry_url,
    };

    fn addr(raw: &str) -> SocketAddr {
        raw.parse().expect("socket address")
    }

    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
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
        let guard = egress_guard(false, &["local.host".to_owned()]);
        let loopback = [addr("127.0.0.1:443")];
        assert!(
            guard
                .validate_addresses("LOCAL.HOST.", &loopback, "test")
                .is_ok()
        );

        assert!(
            guard
                .validate_addresses("other.host", &loopback, "test")
                .is_err()
        );
        let private = [addr("192.168.1.10:443")];
        assert!(
            guard
                .validate_addresses("local.host", &private, "test")
                .is_err()
        );
        let mixed = [addr("127.0.0.1:443"), addr("8.8.8.8:443")];
        assert!(
            guard
                .validate_addresses("local.host", &mixed, "test")
                .is_err()
        );
    }

    #[test]
    fn insecure_dev_client_allows_only_configured_named_loopback_hosts() {
        let guard = egress_guard(
            true,
            &["auth.local.host".to_owned(), "local.host".to_owned()],
        );
        let loopback = [addr("127.0.0.1:7080")];

        assert!(guard.validate_host("auth.local.host", "test").is_ok());
        assert!(
            guard
                .validate_addresses("auth.local.host", &loopback, "test")
                .is_ok()
        );
        assert!(guard.validate_host("attacker.local.host", "test").is_err());
        assert!(
            guard
                .validate_addresses("auth.local.host", &[addr("8.8.8.8:7080")], "test")
                .is_err()
        );
    }

    #[test]
    fn server_self_issuer_is_an_exact_loopback_https_trust_anchor() {
        let config = coauth_config::ArkretConfig::default();
        let public_base = url::Url::parse("https://auth.local.host/").unwrap();
        let trusted_hosts = server_trusted_loopback_https_hosts(&config, &public_base, None);
        let guard = egress_guard(false, &trusted_hosts);
        let loopback = [addr("127.0.0.1:443")];

        assert!(
            guard
                .validate_addresses("auth.local.host", &loopback, "test")
                .is_ok()
        );
        assert!(
            guard
                .validate_addresses("attacker.local.host", &loopback, "test")
                .is_err()
        );
        let private = [addr("192.168.1.10:443")];
        assert!(
            guard
                .validate_addresses("auth.local.host", &private, "test")
                .is_err()
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
                EgressGuard::public_https()
                    .validate_url(&url, "test")
                    .is_err(),
                "{raw} should be rejected before dispatch"
            );
        }
        assert!(
            EgressGuard::public_https()
                .validate_url(&url::Url::parse("https://8.8.8.8/jwks").unwrap(), "test")
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
            .with_retry(arkret_retry::RetryPolicy::none());

        let response = send_with_policy(policy, || client.get(url.clone()))
            .await
            .expect("final HTTP response is returned after retry budget is spent");

        assert_eq!(
            response.status(),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn send_with_policy_honours_retry_after_as_an_unclamped_floor() {
        install_crypto_provider();
        let (url, attempts) = spawn_http_server(|attempt| async move {
            if attempt == 1 {
                "HTTP/1.1 503 retry\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
            }
        })
        .await;
        let client = reqwest::Client::new();
        let policy = OutboundRequestPolicy::new("test", "retry_after")
            .with_timeout(Duration::from_secs(2))
            .with_max_attempts(2)
            .with_retry(arkret_retry::RetryPolicy::none());
        let started = std::time::Instant::now();

        let response = send_with_policy(policy, || client.get(url.clone()))
            .await
            .expect("retry should reach the second response");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "Retry-After must not be shortened to the local zero-delay schedule"
        );
    }

    #[tokio::test]
    async fn retry_after_parser_preserves_large_hints_and_rejects_invalid_values() {
        install_crypto_provider();
        let (large_url, _) = spawn_http_server(|_| async {
            "HTTP/1.1 503 retry\r\nRetry-After: 86400\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        })
        .await;
        let large = reqwest::Client::new().get(large_url).send().await.unwrap();
        assert_eq!(retry_after_hint(&large), Some(Duration::from_secs(86_400)));

        let (invalid_url, _) = spawn_http_server(|_| async {
            "HTTP/1.1 503 retry\r\nRetry-After: eventually\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        })
        .await;
        let invalid = reqwest::Client::new()
            .get(invalid_url)
            .send()
            .await
            .unwrap();
        assert_eq!(retry_after_hint(&invalid), None);
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
