use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use futures_util::FutureExt as _;
use headers::{ContentLength, HeaderMapExt as _, UserAgent};
use hyper_util::client::legacy::connect::{
    HttpInfo,
    dns::{GaiResolver, Name},
};
use opentelemetry::{
    KeyValue,
    metrics::{Histogram, UpDownCounter},
};
use opentelemetry_http::HeaderInjector;
use opentelemetry_semantic_conventions::{
    attribute::{HTTP_REQUEST_BODY_SIZE, HTTP_RESPONSE_BODY_SIZE},
    metric::{HTTP_CLIENT_ACTIVE_REQUESTS, HTTP_CLIENT_REQUEST_DURATION},
    trace::{
        ERROR_TYPE, HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, NETWORK_LOCAL_ADDRESS,
        NETWORK_LOCAL_PORT, NETWORK_PEER_ADDRESS, NETWORK_PEER_PORT, NETWORK_TRANSPORT,
        NETWORK_TYPE, SERVER_ADDRESS, SERVER_PORT, URL_FULL, URL_SCHEME, USER_AGENT_ORIGINAL,
    },
};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::time::Instant;
use tower_service::Service as _;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::telemetry::METER;

static USER_AGENT: &str = concat!("coauth/", env!("CARGO_PKG_VERSION"));

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
        if !private_networks_allowed() {
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
                .call(Name::from_str(name.as_str()).unwrap())
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
    cfg!(debug_assertions)
        || env_flag_enabled("COAUTH_OUTBOUND_HTTP_ALLOW_PRIVATE")
        || env_flag_enabled("COAUTH_ALLOW_PRIVATE_EGRESS")
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            let value = value.trim();
            !(value.is_empty()
                || value.eq_ignore_ascii_case("0")
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("no"))
        })
        .unwrap_or(false)
}

fn blocked_domain_reason(host: &str) -> Option<&'static str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return Some("localhost names are not routable outbound targets");
    }
    if host.ends_with(".local") || host.ends_with(".internal") {
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
        .build()
        .expect("failed to create HTTP client")
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
    use super::{blocked_domain_reason, blocked_ip_reason};

    #[test]
    fn egress_policy_blocks_internal_names() {
        assert!(blocked_domain_reason("localhost").is_some());
        assert!(blocked_domain_reason("api.internal").is_some());
        assert!(blocked_domain_reason("metadata.google.internal").is_some());
        assert!(blocked_domain_reason("example.com").is_none());
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
}
