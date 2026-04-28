//! Buffered stream wrapper that replays prefetched bytes before reading from
//! the underlying I/O.
//!
//! This is used by the proxy protocol acceptor which needs to peek at the first
//! bytes of a connection and then hand the full stream (including those bytes)
//! back to the caller.

use std::{
    cmp, io,
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream wrapper that can replay a prefix buffer before delegating to the
/// inner I/O.
#[derive(Debug)]
pub struct BufferedStream<T> {
    prefix: Option<Bytes>,
    inner: T,
}

/// Backward-compatible alias used by internal modules.
pub type Rewind<T> = BufferedStream<T>;

impl<T> BufferedStream<T> {
    /// Wrap a stream without any prefix data.
    pub(crate) fn new(io: T) -> Self {
        Self {
            prefix: None,
            inner: io,
        }
    }

    /// Wrap a stream with buffered prefix data that will be read first.
    pub(crate) fn new_buffered(io: T, buf: Bytes) -> Self {
        Self {
            prefix: Some(buf),
            inner: io,
        }
    }

    #[cfg(test)]
    pub(crate) fn rewind(&mut self, bs: Bytes) {
        debug_assert!(self.prefix.is_none());
        self.prefix = Some(bs);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for BufferedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut prefix) = self.prefix.take() {
            if !prefix.is_empty() {
                let n = cmp::min(prefix.len(), buf.remaining());
                buf.put_slice(&prefix[..n]);
                prefix.advance(n);
                if !prefix.is_empty() {
                    self.prefix = Some(prefix);
                }
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for BufferedStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::AsyncReadExt;

    use super::BufferedStream;

    #[tokio::test]
    async fn partial_rewind() {
        let underlying = [104, 101, 108, 108, 111];
        let mock = tokio_test::io::Builder::new().read(&underlying).build();
        let mut stream = BufferedStream::new(mock);

        let mut buf = [0; 2];
        stream.read_exact(&mut buf).await.expect("read1");
        stream.rewind(Bytes::copy_from_slice(&buf[..]));

        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.expect("read2");
        assert_eq!(&buf, &underlying);
    }

    #[tokio::test]
    async fn full_rewind() {
        let underlying = [104, 101, 108, 108, 111];
        let mock = tokio_test::io::Builder::new().read(&underlying).build();
        let mut stream = BufferedStream::new(mock);

        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.expect("read1");
        stream.rewind(Bytes::copy_from_slice(&buf[..]));

        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.expect("read2");
    }
}
