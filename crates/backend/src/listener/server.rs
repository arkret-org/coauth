use std::{pin::Pin, sync::Arc, task::Poll, time::Duration};

use futures_util::{StreamExt, stream::SelectAll};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use thiserror::Error;
use tokio_rustls::rustls::ServerConfig;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use super::{
    ConnectionInfo,
    maybe_tls::{MaybeTlsAcceptor, TlsStreamInfo},
    proxy_protocol::{MaybeProxyAcceptor, ProxyAcceptError},
    unix_or_tcp::{SocketAddr, UnixOrTcpConnection, UnixOrTcpListener},
};

/// The timeout for the handshake to complete
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Server<F> {
    tls: Option<Arc<ServerConfig>>,
    proxy: bool,
    listener: UnixOrTcpListener,
    handler: F,
}

impl<F> Server<F> {
    /// # Errors
    ///
    /// Returns an error if the listener couldn't be converted via [`TryInto`]
    pub fn try_new<L>(listener: L, handler: F) -> Result<Self, L::Error>
    where
        L: TryInto<UnixOrTcpListener>,
    {
        Ok(Self {
            tls: None,
            proxy: false,
            listener: listener.try_into()?,
            handler,
        })
    }

    #[must_use]
    pub fn new(listener: impl Into<UnixOrTcpListener>, handler: F) -> Self {
        Self {
            tls: None,
            proxy: false,
            listener: listener.into(),
            handler,
        }
    }

    #[must_use]
    pub const fn with_proxy(mut self) -> Self {
        self.proxy = true;
        self
    }

    #[must_use]
    pub fn with_tls(mut self, config: Arc<ServerConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// Run a single server
    pub async fn run<Fut, B, E>(
        self,
        soft_shutdown_token: CancellationToken,
        hard_shutdown_token: CancellationToken,
    ) where
        F: Fn(Request<hyper::body::Incoming>) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<B>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        run_servers(
            std::iter::once(self),
            soft_shutdown_token,
            hard_shutdown_token,
        )
        .await;
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
enum AcceptError {
    #[error("failed to complete the TLS handshake")]
    TlsHandshake {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to complete the proxy protocol handshake")]
    ProxyHandshake {
        #[source]
        source: ProxyAcceptError,
    },

    #[error("connection handshake timed out")]
    HandshakeTimeout {
        #[source]
        source: tokio::time::error::Elapsed,
    },
}

impl AcceptError {
    fn tls_handshake(source: std::io::Error) -> Self {
        Self::TlsHandshake { source }
    }

    fn proxy_handshake(source: ProxyAcceptError) -> Self {
        Self::ProxyHandshake { source }
    }

    fn handshake_timeout(source: tokio::time::error::Elapsed) -> Self {
        Self::HandshakeTimeout { source }
    }
}

/// Accept a connection and do the proxy protocol and TLS handshake.
///
/// Returns a boxed future that serves the connection with graceful shutdown
/// support. Returns an error if the proxy protocol or TLS handshake failed.
#[tracing::instrument(
    name = "accept",
    skip_all,
    fields(
        network.protocol.name = "http",
        network.peer.address,
        network.peer.port,
    ),
)]
async fn accept<F, Fut, B, E>(
    maybe_proxy_acceptor: &MaybeProxyAcceptor,
    maybe_tls_acceptor: &MaybeTlsAcceptor,
    peer_addr: SocketAddr,
    stream: UnixOrTcpConnection,
    handler: F,
    shutdown_token: CancellationToken,
) -> Result<Pin<Box<dyn Future<Output = ()> + Send>>, AcceptError>
where
    F: Fn(Request<hyper::body::Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<B>, E>> + Send + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let span = tracing::Span::current();

    match peer_addr {
        SocketAddr::Net(addr) => {
            span.record("network.peer.address", tracing::field::display(addr.ip()));
            span.record("network.peer.port", addr.port());
        }
        #[cfg(unix)]
        SocketAddr::Unix(ref addr) => {
            span.record("network.peer.address", tracing::field::debug(addr));
        }
    }

    // Wrap the connection acceptation logic in a timeout
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let (proxy, stream) = maybe_proxy_acceptor
            .accept(stream)
            .await
            .map_err(AcceptError::proxy_handshake)?;

        let stream = maybe_tls_acceptor
            .accept(stream)
            .await
            .map_err(AcceptError::tls_handshake)?;

        let tls = stream.tls_info();

        // Figure out if it's HTTP/2 based on the negociated ALPN info
        let is_h2 = tls.as_ref().is_some_and(TlsStreamInfo::is_alpn_h2);

        let info = ConnectionInfo::new(tls, proxy, peer_addr.into_net());

        let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        if is_h2 {
            builder = builder.http2_only();
        }
        builder.http1().keep_alive(true);

        // Create a hyper service that injects ConnectionInfo into the request
        // extensions and delegates to the handler
        let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
            req.extensions_mut().insert(info.clone());
            handler(req)
        });

        let conn = builder
            .serve_connection(TokioIo::new(stream), service)
            .into_owned();

        // Return a future that serves the connection with graceful shutdown
        let serve_future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
            let mut conn = std::pin::pin!(conn);
            let mut shutdown_started = false;

            loop {
                tokio::select! {
                    biased;

                    () = shutdown_token.cancelled(), if !shutdown_started => {
                        shutdown_started = true;
                        conn.as_mut().graceful_shutdown();
                    }

                    result = conn.as_mut() => {
                        if let Err(e) = result {
                            tracing::warn!(error = &*e as &dyn std::error::Error, "Failed to serve connection");
                        }
                        break;
                    }
                }
            }
        });

        Ok(serve_future)
    })
    .instrument(span)
    .await
    .map_err(AcceptError::handshake_timeout)?
}

pub async fn run_servers<F, Fut, B, E>(
    listeners: impl IntoIterator<Item = Server<F>>,
    soft_shutdown_token: CancellationToken,
    hard_shutdown_token: CancellationToken,
) where
    F: Fn(Request<hyper::body::Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Response<B>, E>> + Send + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // This guard on the shutdown token is to ensure that if this task crashes for
    // any reason, the server will shut down
    let _guard = soft_shutdown_token.clone().drop_guard();

    // Create a stream of accepted connections out of the listeners
    let mut accept_stream: SelectAll<_> = listeners
        .into_iter()
        .map(|server| {
            let maybe_proxy_acceptor = MaybeProxyAcceptor::new(server.proxy);
            let maybe_tls_acceptor = MaybeTlsAcceptor::new(server.tls);
            futures_util::stream::poll_fn(move |cx| {
                let res =
                    std::task::ready!(server.listener.poll_accept(cx)).map(|(addr, stream)| {
                        (
                            maybe_proxy_acceptor,
                            maybe_tls_acceptor.clone(),
                            server.handler.clone(),
                            addr,
                            stream,
                        )
                    });
                Poll::Ready(Some(res))
            })
        })
        .collect();

    // A JoinSet which collects connections that are being accepted
    let mut accept_tasks = tokio::task::JoinSet::new();
    // A JoinSet which collects connections that are being served
    let mut connection_tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;

            // First look for the shutdown signal
            () = soft_shutdown_token.cancelled() => {
                tracing::debug!("Shutting down listeners");
                break;
            },

            // Poll on the JoinSet to collect connections to serve
            res = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                match res {
                    Some(Ok(Some(serve_future))) => {
                        connection_tasks.spawn(async move {
                            tracing::debug!("Accepted connection");
                            serve_future.await;
                        });
                    },
                    Some(Ok(None)) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                    Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Poll on the JoinSet to collect finished connections
            res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                match res {
                    Some(Ok(())) => { /* Connection finished, any errors should be logged in in the spawned task */ },
                    Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Look for connections to accept
            res = accept_stream.next() => {
                let Some(res) = res else { continue };

                let shutdown_token = soft_shutdown_token.child_token();

                // Spawn the connection in the set, so we don't have to wait for the handshake to
                // accept the next connection. This allows us to keep track of active connections
                // and waiting on them for a graceful shutdown
                accept_tasks.spawn(async move {
                    let (maybe_proxy_acceptor, maybe_tls_acceptor, handler, peer_addr, stream) = match res {
                        Ok(res) => res,
                        Err(e) => {
                            tracing::warn!(error = &e as &dyn std::error::Error, "Failed to accept connection from the underlying socket");
                            return None;
                        }
                    };

                    match accept(&maybe_proxy_acceptor, &maybe_tls_acceptor, peer_addr, stream, handler, shutdown_token).await {
                        Ok(serve_future) => Some(serve_future),
                        Err(e) => {
                            tracing::warn!(error = &e as &dyn std::error::Error, "Failed to accept connection");
                            None
                        }
                    }
                });
            },
        };
    }

    // Wait for connections to cleanup
    if !accept_tasks.is_empty() || !connection_tasks.is_empty() {
        tracing::info!(
            "There are {active} active connections ({pending} pending), performing a graceful shutdown. Send the shutdown signal again to force.",
            active = connection_tasks.len(),
            pending = accept_tasks.len(),
        );

        while !accept_tasks.is_empty() || !connection_tasks.is_empty() {
            tokio::select! {
                biased;

                // Poll on the JoinSet to collect connections to serve
                res = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                    match res {
                        Some(Ok(Some(serve_future))) => {
                            connection_tasks.spawn(async move {
                                tracing::debug!("Accepted connection");
                                serve_future.await;
                            });
                        }
                        Some(Ok(None)) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                        Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Poll on the JoinSet to collect finished connections
                res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                    match res {
                        Some(Ok(())) => { /* Connection finished, any errors should be logged in in the spawned task */ },
                        Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Handle when we are asked to hard shutdown
                () = hard_shutdown_token.cancelled() => {
                    tracing::warn!(
                        "Forcing shutdown ({active} active connections, {pending} pending connections)",
                        active = connection_tasks.len(),
                        pending = accept_tasks.len(),
                    );
                    break;
                },
            }
        }
    }

    accept_tasks.shutdown().await;
    connection_tasks.shutdown().await;
}
