#![allow(deprecated)]

use std::borrow::Cow;

use anyhow::bail;
use camino::Utf8PathBuf;
use coauth_keystore::PrivateKey;
use ipnetwork::IpNetwork;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
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
        IpNetwork::new([10, 0, 0, 0].into(), 10).unwrap(),
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
    #[serde(alias = "graphql")]
    RestApi {
        /// Deprecated -- no longer used
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        playground: bool,
        /// Deprecated -- no longer used
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        undocumented_oauth2_access: bool,
    },
    /// OAuth 2.0 / OIDC protocol endpoints
    OAuth,
    /// Matrix compatibility layer
    Compat,
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
    /// Administrative REST API (`/api/admin/v1`)
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

    /// Enable HAProxy PROXY protocol v1 on accepted connections
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
                        Resource::Compat,
                        Resource::RestApi {
                            playground: false,
                            undocumented_oauth2_access: false,
                        },
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
