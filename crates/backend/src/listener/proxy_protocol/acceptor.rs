use bytes::BytesMut;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::ProxyProtocolV1Info;
use crate::listener::rewind::Rewind;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProxyAcceptor {
    _private: (),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub enum ProxyAcceptError {
    Parse(#[from] super::v1::ParseError),
    Read(#[from] std::io::Error),
}

impl ProxyAcceptor {
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Accept a proxy-protocol stream
    ///
    /// # Errors
    ///
    /// Returns an error on read error on the underlying stream, or when the
    /// proxy protocol preamble couldn't be parsed
    pub async fn accept<T>(
        &self,
        mut stream: T,
    ) -> Result<(ProxyProtocolV1Info, Rewind<T>), ProxyAcceptError>
    where
        T: AsyncRead + Unpin,
    {
        let mut buf = BytesMut::new();
        let info = loop {
            stream.read_buf(&mut buf).await?;

            match ProxyProtocolV1Info::parse(&mut buf) {
                Ok(info) => break info,
                Err(e) if e.not_enough_bytes() => {}
                Err(e) => return Err(e.into()),
            }
        };

        let stream = Rewind::new_buffered(stream, buf.into());

        Ok((info, stream))
    }
}
