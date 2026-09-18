//! Transport layer abstraction
//!
//! Provides unified interface for different transport protocols:
//! - TCP (plain)
//! - TLS (TCP + TLS)
//! - WebSocket (over TCP or TLS)
//! - gRPC (HTTP/2 over TCP or TLS)

pub mod grpc;
mod tls;
pub mod ws;

pub use grpc::GrpcConnection;
pub use tls::TlsTransportListener;

use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Unified transport stream trait combining AsyncRead + AsyncWrite + Send + Unpin
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// Unified transport stream type
pub type TransportStream = Pin<Box<dyn AsyncStream>>;

/// Client transport wrapper for the relay: when the transport cannot
/// half-close (WebSocket, gRPC), `poll_shutdown` only flushes, so a remote
/// EOF does not cut the client's remaining upload with a Close frame or
/// trailers. The session owner closes the transport once both directions
/// are done. On TCP/TLS, shutdown is the usual FIN half-close.
pub struct NoHalfClose {
    inner: TransportStream,
    half_close: bool,
}

impl NoHalfClose {
    pub fn new(inner: TransportStream, half_close: bool) -> Self {
        Self { inner, half_close }
    }

    pub fn inner_mut(&mut self) -> &mut TransportStream {
        &mut self.inner
    }
}

impl AsyncRead for NoHalfClose {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NoHalfClose {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.half_close {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        } else {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
    }
}

/// Transport type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Tcp,
    WebSocket,
    Grpc,
}

impl TransportType {
    /// Whether shutting down the write side is a half-close (TCP/TLS FIN)
    /// that leaves the read side usable, as opposed to a full close (WebSocket
    /// Close frame, gRPC trailers).
    pub fn half_close(self) -> bool {
        match self {
            TransportType::Tcp => true,
            TransportType::WebSocket | TransportType::Grpc => false,
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Tcp => write!(f, "tcp"),
            TransportType::WebSocket => write!(f, "ws"),
            TransportType::Grpc => write!(f, "grpc"),
        }
    }
}

/// Connection metadata
#[derive(Debug, Clone)]
pub struct ConnectionMeta {
    pub peer_addr: SocketAddr,
    pub transport_type: TransportType,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without half-close support, shutdown flushes but keeps the transport
    /// open for the other direction; with it, shutdown is a real half-close.
    #[tokio::test]
    async fn no_half_close_keeps_transport_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for half_close in [false, true] {
            let (a, mut b) = tokio::io::duplex(1024);
            let mut w = NoHalfClose::new(Box::pin(a), half_close);
            w.write_all(b"resp").await.unwrap();
            w.shutdown().await.unwrap();
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf).await.unwrap();
            b.write_all(b"late").await.unwrap();
            w.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"late");
            let mut rest = Vec::new();
            if half_close {
                b.read_to_end(&mut rest).await.unwrap();
                assert!(rest.is_empty());
            } else {
                w.write_all(b"more").await.unwrap();
                b.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"more");
            }
        }
    }

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::Tcp), "tcp");
        assert_eq!(format!("{}", TransportType::WebSocket), "ws");
        assert_eq!(format!("{}", TransportType::Grpc), "grpc");
    }

    #[test]
    fn test_transport_type_eq() {
        assert_eq!(TransportType::Tcp, TransportType::Tcp);
        assert_ne!(TransportType::Tcp, TransportType::WebSocket);
    }

    #[test]
    fn test_connection_meta_clone() {
        let meta = ConnectionMeta {
            peer_addr: "127.0.0.1:1234".parse().unwrap(),
            transport_type: TransportType::Tcp,
        };
        let cloned = meta.clone();
        assert_eq!(cloned.peer_addr, meta.peer_addr);
        assert_eq!(cloned.transport_type, meta.transport_type);
    }
}
