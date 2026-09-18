//! WebSocket transport
//!
//! Provides WebSocket transport for VMess protocol.
//! Uses generic type parameter to work with any AsyncRead + AsyncWrite stream,
//! including both plain TCP and TLS streams.
//!
//! Key design decisions for high-throughput + high-connection-count scenarios:
//! - No intermediate write buffer — data goes directly from relay buffer to WS sink
//! - Backpressure returns Poll::Pending (not Error) so connections survive slow peers
//! - Data stays in copy_bidirectional's buffer when sink is not ready (zero extra copies)

use bytes::Bytes;
use futures_util::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream as TungsteniteStream};

/// WebSocket transport wrapper
///
/// Implements AsyncRead + AsyncWrite to provide a unified stream interface
/// for any underlying transport (TCP, TLS, etc.)
///
/// `TungsteniteStream<S>` is `Unpin` when `S: Unpin` (all fields are owned,
/// no `PhantomPinned`), so we store it directly instead of `Pin<Box<...>>`.
/// This saves one heap allocation per connection and one pointer indirection
/// on every poll_read/poll_write/poll_flush call (the hottest path).
pub struct WebSocketTransport<S> {
    ws_stream: TungsteniteStream<S>,
    read_buffer: Bytes,
    read_pos: usize,
    /// Peer closed (Close frame / EOF / fatal error): reads return EOF.
    read_closed: bool,
    /// We sent Close: further writes fail; reads continue until the peer closes
    /// (RFC 6455 §5.5.1 — data may still arrive before the peer's Close).
    write_closed: bool,
}

impl<S> WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new WebSocket transport from a WebSocket stream
    #[cfg(test)]
    pub fn new(ws_stream: TungsteniteStream<S>) -> Self {
        Self::with_early_data(ws_stream, Bytes::new())
    }

    /// Like `new`, but bytes the client sent in the handshake (WebSocket
    /// early data, `Sec-WebSocket-Protocol`) are served before any frame.
    pub fn with_early_data(ws_stream: TungsteniteStream<S>, early: Bytes) -> Self {
        Self {
            ws_stream,
            read_buffer: early,
            read_pos: 0,
            read_closed: false,
            write_closed: false,
        }
    }
}

/// Maximum accepted WebSocket early data. Xray caps `?ed=` at 2048; other
/// clients (sing-box `max_early_data`) go higher, so allow a generous
/// bound and *reject* the handshake beyond it rather than silently dropping
/// the bytes (which would only surface as an authentication failure).
pub const MAX_EARLY_DATA: usize = 16 * 1024;

/// Accept a WebSocket upgrade, enforcing `expected_path` and consuming Xray-style
/// early data (`Sec-WebSocket-Protocol: <base64url(first bytes)>`, sent when the
/// client path carries `?ed=N`). The header is echoed back as the accepted
/// subprotocol, as Xray's server does, and the decoded bytes become the first
/// bytes read from the transport.
pub async fn accept<S>(
    stream: S,
    expected_path: &str,
    config: tokio_tungstenite::tungstenite::protocol::WebSocketConfig,
) -> Result<WebSocketTransport<S>, tokio_tungstenite::tungstenite::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use base64::Engine;
    use std::sync::{Arc, Mutex};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    let early: Arc<Mutex<Bytes>> = Arc::new(Mutex::new(Bytes::new()));
    let early_slot = Arc::clone(&early);
    let expected = expected_path.to_string();
    let ws_stream = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        #[allow(clippy::result_large_err)] // Err type fixed by tungstenite Callback trait
        move |req: &Request, mut response: Response| {
            // Exact match on the percent-decoded path, as Xray
            // (`request.URL.Path != h.path` → 404); the default "/" is a path
            // like any other, not a wildcard.
            let raw = req.uri().path();
            let path = percent_encoding::percent_decode_str(raw).decode_utf8_lossy();
            if path != expected {
                tracing::debug!(path = %path, expected = %expected, "WebSocket path mismatch");
                let reject = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(None)
                    .unwrap();
                return Err(reject);
            }
            if let Some(proto) = req.headers().get("sec-websocket-protocol") {
                let decoded = proto
                    .to_str()
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(s)
                            .ok()
                    })
                    .filter(|b| !b.is_empty());
                // Not base64url (a genuine subprotocol name) → no early data, like Xray.
                if let Some(bytes) = decoded {
                    if bytes.len() > MAX_EARLY_DATA {
                        tracing::debug!(
                            len = bytes.len(),
                            max = MAX_EARLY_DATA,
                            "WebSocket early data too large"
                        );
                        let reject = http::Response::builder()
                            .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                            .body(None)
                            .unwrap();
                        return Err(reject);
                    }
                    *early_slot.lock().unwrap() = Bytes::from(bytes);
                    response
                        .headers_mut()
                        .insert("sec-websocket-protocol", proto.clone());
                }
            }
            Ok(response)
        },
        Some(config),
    )
    .await?;
    let early = std::mem::take(&mut *early.lock().unwrap());
    Ok(WebSocketTransport::with_early_data(ws_stream, early))
}

impl<S> AsyncRead for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_closed {
            return Poll::Ready(Ok(()));
        }

        // If buffer has data, consume it first
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Read from WebSocket stream, looping to skip non-binary messages (Ping/Pong/Text)
        // without returning Pending + wake_by_ref (which causes a spurious poll cycle).
        loop {
            return match Stream::poll_next(Pin::new(&mut self.ws_stream), cx) {
                // An empty binary frame carries no bytes; returning Ready with
                // nothing filled would read as EOF to every AsyncRead consumer.
                Poll::Ready(Some(Ok(Message::Binary(data)))) if data.is_empty() => continue,
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    let to_copy = data.len().min(buf.remaining());
                    buf.put_slice(&data[..to_copy]);

                    if to_copy < data.len() {
                        // Zero-copy slice
                        self.read_buffer = data.slice(to_copy..);
                        self.read_pos = 0;
                    }

                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) => {
                    self.read_closed = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Some(Err(e))) => {
                    self.read_closed = true;
                    match e {
                        // orderly close: EOF
                        tokio_tungstenite::tungstenite::Error::ConnectionClosed
                        | tokio_tungstenite::tungstenite::Error::AlreadyClosed => {
                            Poll::Ready(Ok(()))
                        }
                        // protocol or I/O failure: must surface as an error, not a clean EOF
                        // (the relay would otherwise forward a graceful FIN to the remote)
                        e => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("WebSocket read error: {e}"),
                        ))),
                    }
                }
                Poll::Ready(Some(Ok(_))) => {
                    // Skip non-binary messages, poll again immediately
                    continue;
                }
                Poll::Ready(None) => {
                    self.read_closed = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

impl<S> AsyncWrite for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed || self.read_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket closed",
            )));
        }

        let me = &mut *self;

        // Check if sink is ready to accept a message
        match Sink::poll_ready(Pin::new(&mut me.ws_stream), cx) {
            Poll::Ready(Ok(())) => {
                // Sink ready — send data directly as a single WS Binary message.
                // No intermediate buffer needed: data comes from copy_bidirectional's
                // 32KB relay buffer and goes straight to tungstenite.
                let data = Bytes::copy_from_slice(buf);
                Sink::start_send(Pin::new(&mut me.ws_stream), Message::Binary(data)).map_err(
                    |_| io::Error::new(io::ErrorKind::BrokenPipe, "WebSocket send error"),
                )?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket error",
            ))),
            Poll::Pending => {
                // Sink not ready — apply backpressure via Pending.
                // Data stays in copy_bidirectional's relay buffer (no copy needed).
                // Waker is already registered by poll_ready above.
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use tokio_tungstenite::tungstenite::Error as WsError;
        match Sink::poll_flush(Pin::new(&mut self.ws_stream), cx) {
            // After the peer's Close has been answered tungstenite reports
            // ConnectionClosed on flush; that is an orderly end, not a failure.
            Poll::Ready(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => {
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("WebSocket flush error: {e}"),
            ))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_closed {
            // Queue the Close frame once the sink has room (a backpressured
            // sink must not make us skip it); a peer that already closed
            // makes start_send fail, which is fine.
            let me = &mut *self;
            match Sink::poll_ready(Pin::new(&mut me.ws_stream), cx) {
                Poll::Ready(Ok(())) => {
                    let _ = Sink::start_send(Pin::new(&mut me.ws_stream), Message::Close(None));
                }
                Poll::Ready(Err(_)) => {}
                Poll::Pending => return Poll::Pending,
            }
            self.write_closed = true;
        }
        // Push the Close frame out: tungstenite only buffers it in start_send,
        // and the stream is dropped right after shutdown. Callers bound this
        // (handler `CLOSE_TIMEOUT`), so a slow peer costs at most that
        // budget, not a lost Close.
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof that `WebSocketTransport<S>` is `Unpin` when `S: Unpin`.
    /// This guarantees we can use `Pin::new(&mut ws_stream)` instead of `Box::pin`,
    /// saving one heap allocation per WS connection and one pointer indirection
    /// on every poll_read/poll_write/poll_flush call.
    #[test]
    fn test_websocket_transport_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        // tokio::io::DuplexStream is a common Unpin stream
        assert_unpin::<WebSocketTransport<tokio::io::DuplexStream>>();
    }

    /// Verify that `WebSocketTransport<S>` implements `Send` when `S: Send`.
    /// Required for `tokio::spawn` in the accept loop.
    #[test]
    fn test_websocket_transport_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<WebSocketTransport<tokio::io::DuplexStream>>();
    }

    /// Helper: create a connected (client_ws, server_transport) pair over DuplexStream.
    async fn ws_pair() -> (
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        WebSocketTransport<tokio::io::DuplexStream>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (client_ws, server_ws) = tokio::join!(
            async {
                tokio_tungstenite::client_async("ws://localhost/", client_io)
                    .await
                    .unwrap()
                    .0
            },
            async { tokio_tungstenite::accept_async(server_io).await.unwrap() },
        );
        (client_ws, WebSocketTransport::new(server_ws))
    }

    /// Verify that poll_read skips a Text message and returns the following
    /// Binary message data.
    ///
    /// Regression test for loop optimization: replaced wake_by_ref() + Pending
    /// with a loop that continues past non-binary messages. If the loop were
    /// broken (e.g. returning Pending without re-polling), this test would hang.
    #[tokio::test]
    async fn test_poll_read_skips_text_message() {
        use futures_util::SinkExt;
        use tokio::io::AsyncReadExt;

        let (mut client_ws, mut transport) = ws_pair().await;

        // Client sends: Text (should be skipped) → Binary (should be read)
        client_ws
            .send(Message::Text("skip me".into()))
            .await
            .unwrap();
        client_ws
            .send(Message::Binary(Bytes::from_static(b"real data")))
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"real data",
            "Should skip Text and return Binary"
        );
    }

    /// Verify that poll_read skips multiple consecutive non-binary messages
    /// before returning Binary data.
    ///
    /// Tests the loop handles repeated non-binary messages without spinning
    /// or dropping data.
    #[tokio::test]
    async fn test_poll_read_skips_consecutive_non_binary_messages() {
        use futures_util::SinkExt;
        use tokio::io::AsyncReadExt;

        let (mut client_ws, mut transport) = ws_pair().await;

        // Client sends: Text, Text, Ping → then Binary
        client_ws.send(Message::Text("msg1".into())).await.unwrap();
        client_ws.send(Message::Text("msg2".into())).await.unwrap();
        client_ws
            .send(Message::Ping(Bytes::from_static(b"ping")))
            .await
            .unwrap();
        client_ws
            .send(Message::Binary(Bytes::from_static(b"payload")))
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"payload",
            "Should skip all non-binary messages and return Binary"
        );
    }

    /// Verify that Close message after non-binary messages is handled correctly.
    ///
    /// Tests: Text → Close → read should return 0 bytes (EOF).
    #[tokio::test]
    async fn test_poll_read_close_after_non_binary() {
        use futures_util::SinkExt;
        use tokio::io::AsyncReadExt;

        let (mut client_ws, mut transport) = ws_pair().await;

        // Client sends: Text → Close
        client_ws.send(Message::Text("skip".into())).await.unwrap();
        client_ws.send(Message::Close(None)).await.unwrap();

        let mut buf = [0u8; 64];
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "Close after non-binary should return EOF (0 bytes)");
    }

    /// Xray `?ed=N` clients send the first request bytes base64url-encoded in
    /// `Sec-WebSocket-Protocol`; the server must echo the header and serve
    /// those bytes before any frame.
    #[tokio::test]
    async fn accept_consumes_early_data_and_echoes_subprotocol() {
        use base64::Engine;
        use tokio::io::AsyncReadExt;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let (client_io, server_io) = tokio::io::duplex(8192);
        let early = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"early-trojan-header");
        let mut req = "ws://localhost/trojan".into_client_request().unwrap();
        req.headers_mut()
            .insert("sec-websocket-protocol", early.parse().unwrap());
        let server = tokio::spawn(async move {
            accept(server_io, "/trojan", Default::default())
                .await
                .unwrap()
        });
        let (mut client_ws, resp) = tokio_tungstenite::client_async(req, client_io)
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("sec-websocket-protocol")
                .unwrap()
                .to_str()
                .unwrap(),
            early
        );
        let mut transport = server.await.unwrap();
        let mut buf = [0u8; 64];
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"early-trojan-header");
        // subsequent frames follow the early bytes
        use futures_util::SinkExt;
        client_ws
            .send(Message::Binary(Bytes::from_static(b"frame")))
            .await
            .unwrap();
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"frame");
    }

    /// Path enforcement still applies (wrong path → handshake rejected).
    #[tokio::test]
    async fn accept_rejects_wrong_path() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let server =
            tokio::spawn(async move { accept(server_io, "/trojan", Default::default()).await });
        let r = tokio_tungstenite::client_async("ws://localhost/other", client_io).await;
        assert!(r.is_err());
        assert!(server.await.unwrap().is_err());
    }

    /// The default "/" is an exact path like any other (Xray: 404 on mismatch).
    #[tokio::test]
    async fn accept_root_path_is_not_a_wildcard() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move { accept(server_io, "/", Default::default()).await });
        let r = tokio_tungstenite::client_async("ws://localhost/anything", client_io).await;
        assert!(r.is_err());
        assert!(server.await.unwrap().is_err());

        let (client_io, server_io) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move { accept(server_io, "/", Default::default()).await });
        let r = tokio_tungstenite::client_async("ws://localhost/", client_io).await;
        assert!(r.is_ok());
        assert!(server.await.unwrap().is_ok());
    }

    /// shutdown must deliver the Close frame, not just queue it: the stream
    /// is dropped right after, and a queued frame would be lost.
    #[tokio::test]
    async fn shutdown_flushes_close_frame() {
        use futures_util::StreamExt;
        use tokio::io::AsyncWriteExt;

        let (mut client_ws, mut transport) = ws_pair().await;
        transport.shutdown().await.unwrap();
        drop(transport);
        let msg = client_ws.next().await.expect("a frame").unwrap();
        assert!(matches!(msg, Message::Close(_)), "{msg:?}");
    }

    /// Xray compares the decoded `request.URL.Path`.
    #[tokio::test]
    async fn accept_matches_percent_decoded_path() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let server =
            tokio::spawn(async move { accept(server_io, "/ws path", Default::default()).await });
        let r = tokio_tungstenite::client_async("ws://localhost/ws%20path", client_io).await;
        assert!(r.is_ok());
        assert!(server.await.unwrap().is_ok());
    }

    /// Half-close: after we send Close (writer shutdown), bytes the client
    /// already sent must still be readable instead of being dropped as EOF.
    #[tokio::test]
    async fn reads_continue_after_our_shutdown() {
        use futures_util::SinkExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_ws, mut transport) = ws_pair().await;
        client_ws
            .send(Message::Binary(Bytes::from_static(b"in-flight upload")))
            .await
            .unwrap();
        transport.shutdown().await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"in-flight upload");
        // writing after shutdown fails
        assert!(transport.write(b"x").await.is_err());
    }
}
