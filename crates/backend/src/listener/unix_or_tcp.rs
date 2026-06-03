//! A listener which can listen on either TCP sockets or on UNIX domain sockets

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};

pub enum SocketAddr {
    #[cfg(unix)]
    Unix(tokio::net::unix::SocketAddr),
    Net(std::net::SocketAddr),
}

#[cfg(unix)]
impl From<tokio::net::unix::SocketAddr> for SocketAddr {
    fn from(value: tokio::net::unix::SocketAddr) -> Self {
        Self::Unix(value)
    }
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(value: std::net::SocketAddr) -> Self {
        Self::Net(value)
    }
}

impl std::fmt::Debug for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(unix)]
            Self::Unix(l) => std::fmt::Debug::fmt(l, f),
            Self::Net(l) => std::fmt::Debug::fmt(l, f),
        }
    }
}

impl SocketAddr {
    #[must_use]
    pub fn into_net(self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Net(socket) => Some(socket),
            #[cfg(unix)]
            Self::Unix { .. } => None,
        }
    }

    #[cfg(unix)]
    #[must_use]
    pub fn into_unix(self) -> Option<tokio::net::unix::SocketAddr> {
        match self {
            Self::Net(_) => None,
            Self::Unix(socket) => Some(socket),
        }
    }

    #[must_use]
    pub const fn as_net(&self) -> Option<&std::net::SocketAddr> {
        match self {
            Self::Net(socket) => Some(socket),
            #[cfg(unix)]
            Self::Unix { .. } => None,
        }
    }

    #[cfg(unix)]
    #[must_use]
    pub const fn as_unix(&self) -> Option<&tokio::net::unix::SocketAddr> {
        match self {
            Self::Net(_) => None,
            Self::Unix(socket) => Some(socket),
        }
    }
}

pub enum UnixOrTcpListener {
    #[cfg(unix)]
    Unix {
        listener: UnixListener,
        /// Path to unlink on drop (if the socket was bound by us).
        path: Option<std::path::PathBuf>,
    },
    Tcp(TcpListener),
}

impl Drop for UnixOrTcpListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Self::Unix { path: Some(p), .. } = self {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(unix)]
impl From<UnixListener> for UnixOrTcpListener {
    fn from(listener: UnixListener) -> Self {
        Self::Unix {
            listener,
            path: None,
        }
    }
}

impl From<TcpListener> for UnixOrTcpListener {
    fn from(listener: TcpListener) -> Self {
        Self::Tcp(listener)
    }
}

#[cfg(unix)]
impl TryFrom<std::os::unix::net::UnixListener> for UnixOrTcpListener {
    type Error = std::io::Error;

    fn try_from(listener: std::os::unix::net::UnixListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        Ok(Self::Unix {
            listener: UnixListener::from_std(listener)?,
            path: None,
        })
    }
}

impl TryFrom<std::net::TcpListener> for UnixOrTcpListener {
    type Error = std::io::Error;

    fn try_from(listener: std::net::TcpListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        Ok(Self::Tcp(TcpListener::from_std(listener)?))
    }
}

impl UnixOrTcpListener {
    /// Get the local address of the listener
    ///
    /// # Errors
    ///
    /// Returns an error on rare cases where the underlying [`TcpListener`] or
    /// [`UnixListener`] couldn't provide the local address
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            #[cfg(unix)]
            Self::Unix { listener, .. } => listener.local_addr().map(SocketAddr::from),
            Self::Tcp(listener) => listener.local_addr().map(SocketAddr::from),
        }
    }

    #[cfg(unix)]
    pub const fn is_unix(&self) -> bool {
        matches!(self, Self::Unix { .. })
    }

    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// Accept an incoming connection
    ///
    /// # Cancel safety
    ///
    /// This function is safe to cancel, as both [`UnixListener::accept`] and
    /// [`TcpListener::accept`] are safe to cancel.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket couldn't accept the connection
    pub async fn accept(&self) -> Result<(SocketAddr, UnixOrTcpConnection), std::io::Error> {
        match self {
            #[cfg(unix)]
            Self::Unix { listener, .. } => {
                let (stream, remote_addr) = listener.accept().await?;

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;

                Ok((remote_addr.into(), UnixOrTcpConnection::unix(stream)))
            }
            Self::Tcp(listener) => {
                let (stream, remote_addr) = listener.accept().await?;

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;
                socket.set_tcp_nodelay(true)?;

                Ok((remote_addr.into(), UnixOrTcpConnection::tcp(stream)))
            }
        }
    }

    /// Poll for an incoming connection
    ///
    /// # Cancel safety
    ///
    /// This function is safe to cancel, as both [`UnixListener::poll_accept`]
    /// and [`TcpListener::poll_accept`] are safe to cancel.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket couldn't accept the connection
    pub fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(SocketAddr, UnixOrTcpConnection), std::io::Error>> {
        match self {
            #[cfg(unix)]
            Self::Unix { listener, .. } => {
                let (stream, remote_addr) = ready!(listener.poll_accept(cx)?);

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;

                Poll::Ready(Ok((remote_addr.into(), UnixOrTcpConnection::unix(stream))))
            }
            Self::Tcp(listener) => {
                let (stream, remote_addr) = ready!(listener.poll_accept(cx)?);

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;
                socket.set_tcp_nodelay(true)?;

                Poll::Ready(Ok((remote_addr.into(), UnixOrTcpConnection::tcp(stream))))
            }
        }
    }
}

/// A connection that can be either a Unix domain socket or a TCP stream.
///
/// On non-Unix platforms, only TCP is available.
pub struct UnixOrTcpConnection {
    inner: ConnectionInner,
}

enum ConnectionInner {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl UnixOrTcpConnection {
    #[cfg(unix)]
    fn unix(stream: UnixStream) -> Self {
        Self {
            inner: ConnectionInner::Unix(stream),
        }
    }

    fn tcp(stream: TcpStream) -> Self {
        Self {
            inner: ConnectionInner::Tcp(stream),
        }
    }
}

impl From<TcpStream> for UnixOrTcpConnection {
    fn from(stream: TcpStream) -> Self {
        Self::tcp(stream)
    }
}

impl UnixOrTcpConnection {
    /// Get the local address of the stream
    ///
    /// # Errors
    ///
    /// Returns an error on rare cases where the underlying [`TcpStream`] or
    /// [`UnixStream`] couldn't provide the local address
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match &self.inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => stream.local_addr().map(SocketAddr::from),
            ConnectionInner::Tcp(stream) => stream.local_addr().map(SocketAddr::from),
        }
    }

    /// Get the remote address of the stream
    ///
    /// # Errors
    ///
    /// Returns an error on rare cases where the underlying [`TcpStream`] or
    /// [`UnixStream`] couldn't provide the remote address
    pub fn peer_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match &self.inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => stream.peer_addr().map(SocketAddr::from),
            ConnectionInner::Tcp(stream) => stream.peer_addr().map(SocketAddr::from),
        }
    }
}

impl AsyncRead for UnixOrTcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // SAFETY: we only project to inner fields which are Unpin (TcpStream,
        // UnixStream)
        let inner = &mut self.get_mut().inner;
        match inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            ConnectionInner::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UnixOrTcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        match inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            ConnectionInner::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        match inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            ConnectionInner::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => stream.is_write_vectored(),
            ConnectionInner::Tcp(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        match inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => Pin::new(stream).poll_flush(cx),
            ConnectionInner::Tcp(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        match inner {
            #[cfg(unix)]
            ConnectionInner::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            ConnectionInner::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
