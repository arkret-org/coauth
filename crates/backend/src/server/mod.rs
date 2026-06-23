use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use coauth_config::{HttpBindConfig, HttpResource, HttpTlsConfig, UnixOrTcp};
use listenfd::ListenFd;
use rustls::ServerConfig;
use salvo::prelude::*;
use salvo::serve_static::StaticDir;

use crate::app_state::{AppState, inject_app_state};
use crate::listener::unix_or_tcp::UnixOrTcpListener;

mod middleware;
mod routers;

use middleware::{InjectAppState, RequestTimeout, favicon_handler, public_oidc_browser_cors};
pub use middleware::{
    cache_control_middleware, log_response_middleware, override_response_csp,
    override_response_frame_options, security_headers_middleware, sentry_middleware,
    tracing_middleware,
};
use routers::{
    build_account_api_router, build_admin_router, build_human_router, build_oauth_router,
    connection_info_handler,
};

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

    use super::build_listeners;
    use super::routers::{
        absolute_redirect_location, build_account_api_router, build_admin_router,
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
        assert!(json["paths"]["/_coauth/admin/accounts/{id}/devices"].is_object());
        assert!(
            json["paths"]["/_coauth/admin/accounts/{id}/devices/{device_id}/revoke"].is_object()
        );
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
    async fn session_grants_preflight_allows_dpop_header() {
        let service = salvo::Service::new(build_account_api_router(Router::new()));
        for path in [
            "/_cokret/gate/account/session-grants",
            "/_cokret/gate/account/session-grants/refresh",
            "/_cokret/gate/account/session-grants/revoke",
        ] {
            let response = TestClient::options(format!("http://127.0.0.1:8698{path}"))
                .add_header("Origin", "http://127.0.0.1:8080", true)
                .add_header("Access-Control-Request-Method", "POST", true)
                .add_header("Access-Control-Request-Headers", "content-type,dpop", true)
                .send(&service)
                .await;

            assert_eq!(response.status_code, Some(StatusCode::NO_CONTENT), "{path}");
            assert_eq!(
                response
                    .headers()
                    .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|value| value.to_str().ok()),
                Some("*"),
                "{path}"
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
                "session-grant preflight for {path} must allow the DPoP header; got {allow_headers}",
            );
        }
    }

    #[tokio::test]
    async fn session_grants_post_error_keeps_browser_cors_headers() {
        let service = salvo::Service::new(build_account_api_router(Router::new()));
        let response =
            TestClient::post("http://127.0.0.1:8698/_cokret/gate/account/session-grants")
                .add_header("Origin", "http://127.0.0.1:8080", true)
                .add_header("Content-Type", "application/json", true)
                .add_header("DPoP", "malformed-proof", true)
                .body(
                    serde_json::json!({
                        "principal_id": "did:webvh:scid:offline.invalid:webvh:01k",
                        "device_id": "ck:device:01964137-0000-7000-8000-000000000001",
                        "proof": {
                            "proof_kind": "oidc_code_exchange",
                            "challenge": "0123456789abcdef0123",
                            "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                            "audience": "https://soland.example.com/api",
                            "signature": "unused-for-oidc",
                            "issuer": "https://offline.invalid",
                            "client_id": "yougen",
                            "redirect_uri": "http://127.0.0.1:8080/auth/callback",
                            "state": "ck-state-0123456789abcdef",
                            "nonce": "ck-nonce-0123456789abcdef",
                            "authorization_code": "stale-code",
                            "code_verifier": "0123456789012345678901234567890123456789012"
                        }
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
            "canonical session-grant issuance POST errors must remain visible to browser callers",
        );
    }
}
