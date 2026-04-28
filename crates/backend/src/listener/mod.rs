//! Network listener infrastructure for the Pasion authentication service.
//!
//! Provides TCP/Unix socket binding, optional TLS termination, and PROXY
//! protocol v1 support.  The [`server`] module drives the accept loop and
//! hands established connections to a hyper service.

use self::{maybe_tls::TlsStreamInfo, proxy_protocol::ProxyProtocolV1Info};

/// TLS acceptor and stream metadata.
pub mod maybe_tls;
/// PROXY protocol v1 parsing and optional acceptor.
pub mod proxy_protocol;
/// Connection accept loop with graceful shutdown.
pub mod server;
/// Buffered-prefix stream used during protocol negotiation.
pub mod stream;
/// TCP / Unix socket binding and accept.
pub mod unix_or_tcp;

// Keep `rewind` as a hidden alias for internal use within this module tree.
pub(in crate::listener) use stream as rewind;

/// Metadata collected during connection establishment.
///
/// Aggregates TLS session details, PROXY protocol information, and the
/// network-level peer address.  A value of this type is inserted into the
/// hyper request extensions for every accepted connection so that handlers
/// can inspect connection-level properties.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    tls: Option<TlsStreamInfo>,
    proxy: Option<ProxyProtocolV1Info>,
    net_peer_addr: Option<std::net::SocketAddr>,
}

impl ConnectionInfo {
    /// Build a new `ConnectionInfo` from its constituent parts.
    #[must_use]
    pub fn new(
        tls: Option<TlsStreamInfo>,
        proxy: Option<ProxyProtocolV1Info>,
        net_peer_addr: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            tls,
            proxy,
            net_peer_addr,
        }
    }

    /// TLS session metadata, if the connection was established over TLS.
    #[must_use]
    pub fn tls(&self) -> Option<&TlsStreamInfo> {
        self.tls.as_ref()
    }

    /// PROXY protocol v1 header, if one was present.
    #[must_use]
    pub fn proxy(&self) -> Option<&ProxyProtocolV1Info> {
        self.proxy.as_ref()
    }

    /// Network-level peer address.  `None` for UNIX-domain sockets.
    #[must_use]
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.net_peer_addr
    }

    /// Whether the connection was established over TLS.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// The source IP reported by the PROXY protocol, falling back to the
    /// network peer address.
    #[must_use]
    pub fn client_ip(&self) -> Option<std::net::IpAddr> {
        self.proxy
            .as_ref()
            .and_then(|p| match p {
                ProxyProtocolV1Info::Tcp { source, .. }
                | ProxyProtocolV1Info::Udp { source, .. } => Some(source.ip()),
                ProxyProtocolV1Info::Unknown => None,
            })
            .or_else(|| self.net_peer_addr.map(|a| a.ip()))
    }

    // Keep old method names as hidden aliases for backward compat.
    #[doc(hidden)]
    #[must_use]
    pub fn get_tls_ref(&self) -> Option<&TlsStreamInfo> {
        self.tls()
    }
    #[doc(hidden)]
    #[must_use]
    pub fn get_proxy_ref(&self) -> Option<&ProxyProtocolV1Info> {
        self.proxy()
    }
    #[doc(hidden)]
    #[must_use]
    pub fn get_peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr()
    }
}
