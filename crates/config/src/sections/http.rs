use std::borrow::Cow;

use anyhow::bail;
use camino::Utf8PathBuf;
use coauth_keystore::PrivateKey;
use ipnetwork::IpNetwork;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn wellknown_public_base() -> Url {
    "http://[::]:7080".parse().unwrap()
}

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn http_listener_assets_path_default() -> Utf8PathBuf {
    "./dist/".into()
}

#[cfg(feature = "docker")]
fn http_listener_assets_path_default() -> Utf8PathBuf {
    "/usr/local/share/coauth/assets/".into()
}

#[cfg(feature = "dist")]
fn http_listener_assets_path_default() -> Utf8PathBuf {
    "./share/assets/".into()
}

fn is_default_http_listener_assets_path(value: &Utf8PathBuf) -> bool {
    *value == http_listener_assets_path_default()
}

/// RFC 1918 / RFC 4193 ranges commonly found behind reverse proxies
fn rfc_private_networks() -> Vec<IpNetwork> {
    vec![
        IpNetwork::new([192, 168, 0, 0].into(), 16).unwrap(),
        IpNetwork::new([172, 16, 0, 0].into(), 12).unwrap(),
        IpNetwork::new([10, 0, 0, 0].into(), 8).unwrap(),
        IpNetwork::new(std::net::Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        IpNetwork::new([0xfd00, 0, 0, 0, 0, 0, 0, 0].into(), 8).unwrap(),
        IpNetwork::new(std::net::Ipv6Addr::LOCALHOST.into(), 128).unwrap(),
    ]
}

// ---------------------------------------------------------------------------
// Socket kind
// ---------------------------------------------------------------------------

/// Protocol family for a listening socket
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum UnixOrTcp {
    /// UNIX domain socket
    Unix,
    /// TCP/IP socket
    Tcp,
}

impl UnixOrTcp {
    /// Construct the UNIX variant
    #[must_use]
    pub const fn unix() -> Self {
        Self::Unix
    }

    /// Construct the TCP variant
    #[must_use]
    pub const fn tcp() -> Self {
        Self::Tcp
    }
}

// ---------------------------------------------------------------------------
// Bind configuration
// ---------------------------------------------------------------------------

/// How a listener should bind to the network
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(untagged)]
pub enum BindConfig {
    /// Bind to host + port (host defaults to all interfaces)
    Listen {
        /// Optional hostname to restrict listening on
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// TCP port number
        port: u16,
    },

    /// Bind to a complete address string
    Address {
        /// Socket address, e.g. `[::]:7080` or `127.0.0.1:7080`
        #[schemars(
            example = &"[::1]:7080",
            example = &"[::]:7080",
            example = &"127.0.0.1:7080",
            example = &"0.0.0.0:7080",
        )]
        address: String,
    },

    /// Bind to a UNIX domain socket path
    Unix {
        /// Filesystem path for the socket
        #[schemars(with = "String")]
        socket: Utf8PathBuf,
    },

    /// Inherit a file descriptor from the parent process (e.g. systemd socket
    /// activation). The fd index is offset by 3 (stdin/stdout/stderr).
    FileDescriptor {
        /// Logical fd index (0 = actual fd 3)
        #[serde(default)]
        fd: usize,
        /// Whether the inherited socket is TCP or UNIX
        #[serde(default = "UnixOrTcp::tcp")]
        kind: UnixOrTcp,
    },
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// TLS termination settings for a listener
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TlsConfig {
    /// PEM certificate chain (inline). Mutually exclusive with
    /// `certificate_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,

    /// Path to a PEM certificate chain. Mutually exclusive with `certificate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub certificate_file: Option<Utf8PathBuf>,

    /// PEM private key (inline). Mutually exclusive with `key_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// Path to PEM/DER private key. Mutually exclusive with `key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub key_file: Option<Utf8PathBuf>,

    /// Passphrase for an encrypted private key (inline). Mutually exclusive
    /// with `password_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Path to key passphrase file. Mutually exclusive with `password`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub password_file: Option<Utf8PathBuf>,
}

impl TlsConfig {
    /// Read certificate chain and private key, returning material ready for
    /// `rustls`.
    ///
    /// # Errors
    ///
    /// Propagates I/O failures, PEM/DER parse errors, decryption mismatches,
    /// and empty certificate chains.
    pub fn load(
        &self,
    ) -> Result<(PrivateKeyDer<'static>, Vec<CertificateDer<'static>>), anyhow::Error> {
        // -- password --
        let pw = match (&self.password, &self.password_file) {
            (None, None) => None,
            (Some(_), Some(_)) => {
                bail!("Only one of `password` or `password_file` can be set at a time")
            }
            (Some(p), None) => Some(Cow::Borrowed(p)),
            (None, Some(path)) => Some(Cow::Owned(std::fs::read_to_string(path)?)),
        };

        // -- private key --
        let pk = match (&self.key, &self.key_file) {
            (None, None) => bail!("Either `key` or `key_file` must be set"),
            (Some(_), Some(_)) => bail!("Only one of `key` or `key_file` can be set at a time"),
            (Some(pem), None) => {
                if let Some(ref p) = pw {
                    PrivateKey::load_encrypted_pem(pem, p.as_bytes())?
                } else {
                    PrivateKey::load_pem(pem)?
                }
            }
            (None, Some(path)) => {
                let raw = std::fs::read(path)?;
                if let Some(ref p) = pw {
                    PrivateKey::load_encrypted(&raw, p.as_bytes())?
                } else {
                    PrivateKey::load(&raw)?
                }
            }
        };

        let der_bytes = pk.to_pkcs8_der()?;
        let key_der = PrivatePkcs8KeyDer::from(der_bytes.to_vec()).into();

        // -- certificate chain --
        let cert_pem = match (&self.certificate, &self.certificate_file) {
            (None, None) => bail!("Either `certificate` or `certificate_file` must be set"),
            (Some(_), Some(_)) => {
                bail!("Only one of `certificate` or `certificate_file` can be set at a time")
            }
            (Some(c), None) => Cow::Borrowed(c),
            (None, Some(path)) => Cow::Owned(std::fs::read_to_string(path)?),
        };

        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;

        if chain.is_empty() {
            bail!("TLS certificate chain is empty (or invalid)");
        }

        Ok((key_der, chain))
    }
}

// ---------------------------------------------------------------------------
// HTTP resources
// ---------------------------------------------------------------------------

/// A mountable HTTP resource (endpoint group)
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "name", rename_all = "lowercase")]
pub enum Resource {
    /// Liveness / readiness probe (`/health`)
    Health,
    /// Prometheus metrics scrape endpoint (`/metrics`)
    Prometheus,
    /// OpenID Connect discovery documents
    Discovery,
    /// Browser-facing HTML pages
    Human,
    /// REST API consumed by the frontend
    RestApi,
    /// OAuth / OIDC protocol endpoints
    OAuth,
    /// Static frontend assets
    Assets {
        /// Directory from which to serve files
        #[serde(
            default = "http_listener_assets_path_default",
            skip_serializing_if = "is_default_http_listener_assets_path"
        )]
        #[schemars(with = "String")]
        path: Utf8PathBuf,
    },
    /// Administrative REST API (`/_coauth/admin`)
    AdminApi,
    /// Debug handler exposing upstream connection metadata
    #[serde(rename = "connection-info")]
    ConnectionInfo,
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// A named HTTP listener with its resource set and bind points
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ListenerConfig {
    /// Human-readable label (appears in traces and metric tags)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Endpoint groups exposed on this listener
    pub resources: Vec<Resource>,

    /// Optional URL prefix for all resources on this listener
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,

    /// Network addresses / sockets this listener binds to
    pub binds: Vec<BindConfig>,

    /// Enable `HAProxy` PROXY protocol v1 on accepted connections
    #[serde(default)]
    pub proxy_protocol: bool,

    /// TLS termination settings (omit for plain HTTP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

// ---------------------------------------------------------------------------
// Top-level HTTP config
// ---------------------------------------------------------------------------

/// Web server and reverse-proxy integration
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpConfig {
    /// Ordered list of listeners to start
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// CIDR ranges of reverse proxies trusted to set `X-Forwarded-For`
    #[serde(default = "rfc_private_networks")]
    #[schemars(with = "Vec<String>", inner(ip))]
    pub trusted_proxies: Vec<IpNetwork>,

    /// Externally reachable base URL of the authentication service
    pub public_base: Url,

    /// OIDC issuer identifier. Falls back to `public_base` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Url>,

    /// Maximum accepted request-body size, in bytes. Requests exceeding this
    /// limit are rejected with `413 Payload Too Large` before they reach a
    /// handler. Defaults to 1 MiB to match the Arkret
    /// `ak.server.query.describe.limits.max_body_bytes` advertisement.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,

    /// Per-request handling deadline, in seconds. Long-running upstream calls
    /// have their own timeouts; this guards against accidentally unbounded
    /// handlers. Defaults to 30 seconds. Set to 0 to disable.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,

    /// Grace period (seconds) granted to in-flight requests when the process
    /// receives SIGTERM/SIGINT before the listener is forcibly closed.
    /// Defaults to 30 seconds.
    #[serde(default = "default_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,

    /// Browser HTTP Strict-Transport-Security policy. Disabled by default
    /// because TLS frequently terminates upstream and HSTS has cache
    /// semantics that can lock operators out of an HTTP-only host if
    /// emitted by mistake. Opt in only when this process or the trusted
    /// edge serves HTTPS to end users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hsts: Option<HstsConfig>,

    /// `Content-Security-Policy` value emitted on every HTML response.
    /// JSON / asset responses are unaffected. Set to an empty string to
    /// suppress the header entirely (for example, when a downstream CDN
    /// injects its own policy). When omitted, a conservative default
    /// scoped to `'self'` is applied — no third-party scripts, no
    /// inline scripts, no framing. Tighten or relax via this field.
    #[serde(default = "default_csp_html", skip_serializing_if = "Option::is_none")]
    pub csp_html: Option<String>,
}

fn default_csp_html() -> Option<String> {
    Some(
        concat!(
            "default-src 'self'; ",
            "script-src 'self' 'wasm-unsafe-eval'; ",
            "style-src 'self' 'unsafe-inline'; ",
            "img-src 'self' data:; ",
            "font-src 'self' data:; ",
            "connect-src 'self'; ",
            "frame-ancestors 'none'; ",
            "form-action 'self'; ",
            "base-uri 'self'; ",
            "object-src 'none'",
        )
        .to_owned(),
    )
}

/// HTTP Strict-Transport-Security policy.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct HstsConfig {
    /// `max-age` directive, in seconds. The IETF baseline is 6 months
    /// (`15_552_000`); production deployments often raise this to 1
    /// year (`31_536_000`) once they are confident TLS will stay on.
    #[serde(default = "default_hsts_max_age_seconds")]
    pub max_age_seconds: u64,

    /// Whether to include the `includeSubDomains` directive. Off by
    /// default — turning it on commits every subdomain of the public
    /// host to HTTPS.
    #[serde(default)]
    pub include_subdomains: bool,

    /// Whether to include the `preload` directive. Off by default —
    /// only set when you have read and intend to follow the
    /// hstspreload.org submission policy.
    #[serde(default)]
    pub preload: bool,
}

const fn default_hsts_max_age_seconds() -> u64 {
    15_552_000
}

const fn default_max_body_bytes() -> u64 {
    1_048_576
}

const fn default_request_timeout_seconds() -> u64 {
    30
}

const fn default_shutdown_grace_seconds() -> u64 {
    30
}

impl Default for HttpConfig {
    fn default() -> Self {
        let base = wellknown_public_base();
        Self {
            listeners: vec![
                ListenerConfig {
                    name: Some("web".to_owned()),
                    resources: vec![
                        Resource::Discovery,
                        Resource::Human,
                        Resource::OAuth,
                        Resource::RestApi,
                        Resource::Assets {
                            path: http_listener_assets_path_default(),
                        },
                    ],
                    prefix: None,
                    tls: None,
                    proxy_protocol: false,
                    binds: vec![BindConfig::Address {
                        address: "[::]:7080".into(),
                    }],
                },
                ListenerConfig {
                    name: Some("internal".to_owned()),
                    resources: vec![Resource::Health],
                    prefix: None,
                    tls: None,
                    proxy_protocol: false,
                    binds: vec![BindConfig::Listen {
                        host: Some("localhost".to_owned()),
                        port: 8091,
                    }],
                },
            ],
            trusted_proxies: rfc_private_networks(),
            issuer: Some(base.clone()),
            public_base: base,
            max_body_bytes: default_max_body_bytes(),
            request_timeout_seconds: default_request_timeout_seconds(),
            shutdown_grace_seconds: default_shutdown_grace_seconds(),
            hsts: None,
            csp_html: default_csp_html(),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl ConfigurationSection for HttpConfig {
    const PATH: &'static str = "http";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        for (idx, listener) in self.listeners.iter().enumerate() {
            let annotate_err = |mut e: figment::Error| {
                e.metadata = figment
                    .find_metadata(&format!("{root}.listeners", root = Self::PATH))
                    .cloned();
                e.profile = Some(figment::Profile::Default);
                e.path = vec![
                    Self::PATH.to_owned(),
                    "listeners".to_owned(),
                    idx.to_string(),
                ];
                e
            };

            if listener.resources.is_empty() {
                return Err(annotate_err(figment::Error::from(
                    "listener has no resources".to_owned(),
                ))
                .into());
            }

            if listener.binds.is_empty() {
                return Err(annotate_err(figment::Error::from(
                    "listener does not bind to any address".to_owned(),
                ))
                .into());
            }

            if let Some(tls) = &listener.tls {
                // certificate
                if tls.certificate.is_some() && tls.certificate_file.is_some() {
                    return Err(annotate_err(figment::Error::from(
                        "Only one of `certificate` or `certificate_file` can be set at a time"
                            .to_owned(),
                    ))
                    .into());
                }
                if tls.certificate.is_none() && tls.certificate_file.is_none() {
                    return Err(annotate_err(figment::Error::from(
                        "TLS configuration is missing a certificate".to_owned(),
                    ))
                    .into());
                }

                // private key
                if tls.key.is_some() && tls.key_file.is_some() {
                    return Err(annotate_err(figment::Error::from(
                        "Only one of `key` or `key_file` can be set at a time".to_owned(),
                    ))
                    .into());
                }
                if tls.key.is_none() && tls.key_file.is_none() {
                    return Err(annotate_err(figment::Error::from(
                        "TLS configuration is missing a private key".to_owned(),
                    ))
                    .into());
                }

                // password
                if tls.password.is_some() && tls.password_file.is_some() {
                    return Err(annotate_err(figment::Error::from(
                        "Only one of `password` or `password_file` can be set at a time".to_owned(),
                    ))
                    .into());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn default_trusted_proxies_cover_rfc1918_ten_eight() {
        let networks = rfc_private_networks();
        let in_first_quarter: IpAddr = "10.10.20.30".parse().unwrap();
        let outside_old_ten_ten: IpAddr = "10.128.20.30".parse().unwrap();

        assert!(
            networks
                .iter()
                .any(|network| network.contains(in_first_quarter)),
            "10.0.0.0/8 default must include common 10.x proxy ranges"
        );
        assert!(
            networks
                .iter()
                .any(|network| network.contains(outside_old_ten_ten)),
            "10.0.0.0/8 default must include addresses outside the former /10"
        );
    }
}
