use tokio::io::AsyncRead;

use super::acceptor::ProxyAcceptError;
use super::{ProxyAcceptor, ProxyProtocolV1Info};
use crate::listener::stream::BufferedStream;

#[derive(Clone, Copy)]
pub struct MaybeProxyAcceptor {
    acceptor: Option<ProxyAcceptor>,
}

impl MaybeProxyAcceptor {
    #[must_use]
    pub const fn new(proxied: bool) -> Self {
        let acceptor = if proxied {
            Some(ProxyAcceptor::new())
        } else {
            None
        };

        Self { acceptor }
    }

    #[must_use]
    pub const fn new_proxied(acceptor: ProxyAcceptor) -> Self {
        Self {
            acceptor: Some(acceptor),
        }
    }

    #[must_use]
    pub const fn new_unproxied() -> Self {
        Self { acceptor: None }
    }

    #[must_use]
    pub const fn is_proxied(&self) -> bool {
        self.acceptor.is_some()
    }

    /// Accept a connection and do the proxy protocol handshake
    ///
    /// # Errors
    ///
    /// Returns an error if the proxy protocol handshake failed
    pub async fn accept<T>(
        &self,
        stream: T,
    ) -> Result<(Option<ProxyProtocolV1Info>, BufferedStream<T>), ProxyAcceptError>
    where
        T: AsyncRead + Unpin,
    {
        if let Some(acceptor) = self.acceptor {
            let (info, stream) = acceptor.accept(stream).await?;
            Ok((Some(info), stream))
        } else {
            let stream = BufferedStream::new(stream);
            Ok((None, stream))
        }
    }
}
