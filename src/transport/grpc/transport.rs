//! gRPC transport layer (v2ray compatible)
//!
//! Implements AsyncRead + AsyncWrite for use as a TCP-like stream.

use bytes::{Bytes, BytesMut};
use h2::server::SendResponse;
use h2::{Reason, RecvStream, SendStream};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

use super::codec::{declared_frame_len, encode_grpc_message, parse_grpc_message_zerocopy};

/// Initial read buffer size (start small, grow as needed)
const INITIAL_READ_BUFFER_SIZE: usize = 8 * 1024;

/// Maximum read buffer size (128KB — bounded to limit per-connection memory at high scale)
const MAX_READ_BUFFER_SIZE: usize = 128 * 1024;

/// Largest gRPC frame (declared in its 5-byte header) accepted from a peer.
/// Xray's gRPC transport sends one Hunk per write (≤ 8 KiB, multiMode batches
/// stay far below this); anything larger is a malformed or hostile stream.
const MAX_INBOUND_FRAME_LEN: usize = 256 * 1024;

/// Maximum frame size for HTTP/2
pub(super) const MAX_FRAME_SIZE: u32 = 64 * 1024;

/// Default gRPC message size (used when no config is provided)
const DEFAULT_GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024;

/// Maximum send queue bytes (128KB — bounded to limit per-connection memory at high scale)
pub(super) const MAX_SEND_QUEUE_BYTES: usize = 128 * 1024;

/// Response side of the stream. Like grpc-go (and so Xray), the response
/// HEADERS are sent with the first data frame, not on stream accept: a probe
/// that never authenticates only ever sees a trailers-only response.
pub(crate) enum Responder {
    /// Headers not sent yet.
    Pending(SendResponse<Bytes>),
    /// Headers sent; data flows on the stream.
    Open(SendStream<Bytes>),
}

/// gRPC transport layer (v2ray compatible)
///
/// Implements AsyncRead + AsyncWrite for use like a normal TCP stream
pub struct GrpcTransport {
    pub(crate) recv_stream: RecvStream,
    pub(crate) responder: Responder,
    pub(crate) read_pending: BytesMut,
    pub(crate) read_buf: Bytes,
    pub(crate) read_pos: usize,
    pub(crate) pending_release_capacity: usize,
    pub(crate) send_queue: VecDeque<Bytes>,
    pub(crate) send_queue_bytes: usize,
    pub(crate) current_frame: Option<Bytes>,
    pub(crate) current_frame_offset: usize,
    pub(crate) max_message_size: usize,
    /// Set whenever data arrives on this stream; the connection heartbeat
    /// treats it as proof of life (middleboxes may drop PING frames).
    activity: Option<Arc<AtomicBool>>,
    /// Peer finished sending (END_STREAM or stream error): reads return EOF.
    pub(crate) read_closed: bool,
    /// We shut down our write side: writes fail, reads keep draining.
    pub(crate) write_closed: bool,
}

impl GrpcTransport {
    /// `max_message_size` of 0 selects the default; `activity`, when given, is
    /// raised whenever data arrives so the connection heartbeat can treat
    /// stream traffic as proof of life.
    pub(crate) fn with_activity(
        recv_stream: RecvStream,
        responder: Responder,
        max_message_size: usize,
        activity: Option<Arc<AtomicBool>>,
    ) -> Self {
        let max_message_size = if max_message_size == 0 {
            DEFAULT_GRPC_MAX_MESSAGE_SIZE
        } else {
            max_message_size
        };
        Self {
            recv_stream,
            responder,
            read_pending: BytesMut::with_capacity(INITIAL_READ_BUFFER_SIZE),
            read_buf: Bytes::new(),
            read_pos: 0,
            pending_release_capacity: 0,
            send_queue: VecDeque::new(),
            send_queue_bytes: 0,
            current_frame: None,
            current_frame_offset: 0,
            max_message_size,
            activity,
            read_closed: false,
            write_closed: false,
        }
    }

    /// Ensure read buffer has capacity for `additional` more bytes.
    ///
    /// Growth is geometric up to `MAX_READ_BUFFER_SIZE`, but never less than
    /// what is needed: the total buffered size is bounded separately by the
    /// declared-frame-length check in `poll_read`, so this can never be asked
    /// to shrink below the current length (which used to underflow).
    #[inline]
    fn ensure_read_capacity(&mut self, additional: usize) {
        let reserve = read_buffer_reserve(
            self.read_pending.len(),
            self.read_pending.capacity(),
            additional,
        );
        if reserve > 0 {
            self.read_pending.reserve(reserve);
        }
    }

    fn poll_send_queued(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref frame) = self.current_frame {
                let remaining = frame.len() - self.current_frame_offset;
                if remaining > 0 {
                    let frame_len = frame.len();
                    match self.poll_send_current_frame(cx)? {
                        Poll::Ready(()) => {
                            self.send_queue_bytes = self.send_queue_bytes.saturating_sub(frame_len);
                            self.current_frame = None;
                            self.current_frame_offset = 0;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                } else {
                    self.current_frame = None;
                    self.current_frame_offset = 0;
                }
            }

            match self.send_queue.pop_front() {
                Some(frame) => {
                    self.current_frame = Some(frame);
                    self.current_frame_offset = 0;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }

    /// gRPC response headers (`:status 200`, content-type). Sent lazily with
    /// the first data frame, see [`Responder`].
    pub(super) fn response_headers() -> http::Response<()> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-accept-encoding", "identity,deflate,gzip")
            .body(())
            .expect("static response")
    }

    /// The data stream, sending the response headers first if needed.
    fn open_stream(&mut self) -> io::Result<&mut SendStream<Bytes>> {
        if let Responder::Pending(respond) = &mut self.responder {
            let stream = respond
                .send_response(Self::response_headers(), false)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("gRPC send response error: {e}"),
                    )
                })?;
            self.responder = Responder::Open(stream);
        }
        match &mut self.responder {
            Responder::Open(s) => Ok(s),
            Responder::Pending(_) => unreachable!("opened above"),
        }
    }

    fn poll_send_current_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(frame) = self.current_frame.clone() else {
            return Poll::Ready(Ok(()));
        };
        let mut offset = self.current_frame_offset;
        let send_stream = self.open_stream()?;

        loop {
            let remaining = frame.len() - offset;
            if remaining == 0 {
                self.current_frame_offset = offset;
                return Poll::Ready(Ok(()));
            }

            let capacity = send_stream.capacity();
            if capacity == 0 {
                send_stream.reserve_capacity(remaining.min(MAX_FRAME_SIZE as usize));
                match send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(cap))) if cap > 0 => continue,
                    // Ok(0): the capacity-increase flag was stale. Poll again —
                    // the second call registers the waker (h2 < 0.4.19 could
                    // otherwise leave us Pending with no wakeup).
                    Poll::Ready(Some(Ok(_))) => continue,
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "gRPC capacity error: {}",
                            e
                        ))));
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "gRPC stream closed",
                        )));
                    }
                    Poll::Pending => {
                        self.current_frame_offset = offset;
                        return Poll::Pending;
                    }
                }
            }

            let send_size = remaining.min(capacity);
            let chunk = frame.slice(offset..offset + send_size);

            match send_stream.send_data(chunk, false) {
                Ok(()) => {
                    offset += send_size;
                    if offset >= frame.len() {
                        self.current_frame_offset = offset;
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("gRPC send error: {}", e),
                    )));
                }
            }
        }
    }
}

fn is_normal_stream_close(error: &h2::Error) -> bool {
    if let Some(reason) = error.reason() {
        matches!(reason, Reason::NO_ERROR | Reason::CANCEL)
    } else {
        false
    }
}

/// Bytes to `reserve` so that `len + additional` fits, growing geometrically
/// up to `MAX_READ_BUFFER_SIZE` but never below what is needed (so the
/// result can never underflow when `len` already exceeds the soft cap).
fn read_buffer_reserve(len: usize, capacity: usize, additional: usize) -> usize {
    let needed = len + additional;
    if capacity >= needed {
        return 0;
    }
    let target = needed.max((capacity * 2).min(MAX_READ_BUFFER_SIZE));
    target - len
}

impl AsyncRead for GrpcTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_closed {
            return Poll::Ready(Ok(()));
        }

        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            // flow-control capacity for this frame was released when it was parsed

            if self.read_pos >= self.read_buf.len() {
                self.read_buf = Bytes::new();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            // Bound the frame before buffering it: an attacker-declared 4 GiB
            // length must not pin memory (or overflow the growth arithmetic).
            if let Some(declared) = declared_frame_len(&self.read_pending) {
                if declared > MAX_INBOUND_FRAME_LEN {
                    self.read_closed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "gRPC frame length {declared} exceeds limit {MAX_INBOUND_FRAME_LEN}"
                        ),
                    )));
                }
            }
            match parse_grpc_message_zerocopy(&mut self.read_pending) {
                Ok(Some((payload, consumed))) => {
                    // Release flow control for the consumed frame up front so an
                    // empty Hunk (valid protobuf, zero-length data) does not leak
                    // window; then skip it — a 0-byte read would look like EOF.
                    let to_release = self.pending_release_capacity.min(consumed);
                    if to_release > 0 {
                        if let Err(e) = self.recv_stream.flow_control().release_capacity(to_release)
                        {
                            warn!(error = %e, to_release, "Failed to release HTTP/2 flow control capacity");
                        }
                        self.pending_release_capacity -= to_release;
                    }
                    if payload.is_empty() {
                        continue;
                    }

                    let to_copy = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);

                    if to_copy < payload.len() {
                        self.read_buf = payload.slice(to_copy..);
                        self.read_pos = 0;
                    }

                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            if self.read_pending.is_empty()
                && self.read_pending.capacity() < INITIAL_READ_BUFFER_SIZE
            {
                // A parsed frame was split off, leaving no usable capacity. By
                // now its payload has usually been copied out and dropped, so
                // `reserve` reclaims the (unique) allocation instead of
                // allocating per frame; otherwise it starts a fresh
                // INITIAL-sized one and the shared block is freed with the
                // payload, so the buffer never grows without bound.
                self.read_pending.reserve(INITIAL_READ_BUFFER_SIZE);
            }
            match self.recv_stream.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let chunk_len = chunk.len();
                    if let Some(a) = &self.activity {
                        a.store(true, Ordering::Relaxed);
                    }
                    self.ensure_read_capacity(chunk_len);
                    self.read_pending.extend_from_slice(&chunk);
                    self.pending_release_capacity += chunk_len;
                }
                Poll::Ready(Some(Err(e))) => {
                    self.read_closed = true;
                    if is_normal_stream_close(&e) && self.read_pending.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    if is_normal_stream_close(&e) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "gRPC stream closed mid-frame",
                        )));
                    }
                    return Poll::Ready(Err(io::Error::other(format!("gRPC recv error: {}", e))));
                }
                Poll::Ready(None) => {
                    self.read_closed = true;
                    if !self.read_pending.is_empty() {
                        // END_STREAM in the middle of a gRPC frame: the peer
                        // aborted, this must not read as a graceful EOF.
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "gRPC stream ended mid-frame",
                        )));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed",
            )));
        }

        let _ = self.poll_send_queued(cx)?;

        if self.send_queue_bytes >= MAX_SEND_QUEUE_BYTES {
            return Poll::Pending;
        }

        let to_write = buf.len().min(self.max_message_size);
        let frame = encode_grpc_message(&buf[..to_write]);
        let frame_bytes = frame.len();
        self.send_queue.push_back(frame.freeze());
        self.send_queue_bytes += frame_bytes;

        let _ = self.poll_send_queued(cx)?;

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_send_queued(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Half-close: only the write side ends here. Data the peer already
        // sent (or is still sending on the H2 stream) stays readable.
        if self.write_closed && self.send_queue.is_empty() && self.current_frame.is_none() {
            // Already shut down (trailers or trailers-only response sent).
            return Poll::Ready(Ok(()));
        }
        self.write_closed = true;

        match self.as_mut().poll_flush(cx) {
            // poll_flush only returns Ready(Ok) once the queue is fully drained
            Poll::Ready(Ok(())) => {
                let this = &mut *self;
                let result = match &mut this.responder {
                    Responder::Open(stream) => {
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        stream.send_trailers(trailers)
                    }
                    // Nothing was ever written: trailers-only response, as
                    // grpc-go does for a handler that returns without sending.
                    Responder::Pending(respond) => {
                        let mut response = Self::response_headers();
                        response
                            .headers_mut()
                            .insert("grpc-status", "0".parse().unwrap());
                        respond.send_response(response, true).map(|_| ())
                    }
                };
                match result {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(e) => {
                        if e.is_remote() || e.is_io() {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::Error::other(format!(
                                "gRPC send trailers error: {}",
                                e
                            ))))
                        }
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_buffer_size() {
        assert_eq!(INITIAL_READ_BUFFER_SIZE, 8 * 1024);
        // Compile-time assertion that initial < max
        const _: () = assert!(INITIAL_READ_BUFFER_SIZE < MAX_READ_BUFFER_SIZE);
    }

    #[test]
    fn test_max_buffer_size() {
        assert_eq!(MAX_READ_BUFFER_SIZE, 128 * 1024);
    }

    #[test]
    fn test_default_grpc_max_message_size() {
        assert_eq!(DEFAULT_GRPC_MAX_MESSAGE_SIZE, 32 * 1024);
    }

    /// Regression: with more than MAX_READ_BUFFER_SIZE already buffered, the
    /// old `min(MAX)` clamp produced `new_capacity < len` and the subtraction
    /// wrapped (abort in release builds).
    #[test]
    fn read_buffer_reserve_never_underflows_past_max() {
        let len = MAX_READ_BUFFER_SIZE + 4096;
        let r = read_buffer_reserve(len, len, 16 * 1024);
        assert_eq!(r, 16 * 1024);
        // no-op when it fits; geometric growth below the cap; exact fit above it
        assert_eq!(read_buffer_reserve(0, 8192, 1000), 0);
        assert_eq!(read_buffer_reserve(8000, 8192, 1000), 16384 - 8000);
        assert_eq!(
            read_buffer_reserve(MAX_READ_BUFFER_SIZE - 10, MAX_READ_BUFFER_SIZE, 100),
            100
        );
    }

    #[test]
    fn test_max_send_queue_bytes() {
        assert_eq!(MAX_SEND_QUEUE_BYTES, 128 * 1024);
    }

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 64 * 1024);
    }

    /// Verify that read_pending is reset to initial size after all data is consumed.
    ///
    /// Problem: BytesMut::advance() creates "dead space" at the front of the
    /// allocation. After consuming a large gRPC message, the buffer is empty
    /// but the allocation stays large. For idle connections, this wastes memory.
    #[test]
    fn test_read_pending_shrinks_after_grpc_message_consumed() {
        use crate::transport::grpc::codec::{encode_grpc_message, parse_grpc_message_zerocopy};

        let mut read_pending = BytesMut::with_capacity(INITIAL_READ_BUFFER_SIZE);
        assert_eq!(read_pending.capacity(), INITIAL_READ_BUFFER_SIZE);

        // Simulate receiving a large gRPC message (same as poll_read does)
        let payload = vec![0xAB; 32 * 1024];
        let encoded = encode_grpc_message(&payload);
        read_pending.extend_from_slice(&encoded);

        let grown_capacity = read_pending.capacity();
        assert!(
            grown_capacity > INITIAL_READ_BUFFER_SIZE,
            "buffer should have grown, capacity={}",
            grown_capacity
        );

        // Parse and consume (same as poll_read line 205-215)
        let (parsed, consumed) = parse_grpc_message_zerocopy(&mut read_pending)
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed.len(),
            32 * 1024,
            "parsed payload should match original size"
        );
        assert_eq!(consumed, encoded.len());
        assert!(read_pending.is_empty());

        // After advance: capacity is near 0 because the pointer is at the end.
        // The underlying ALLOCATION is still large (64KB+) but inaccessible.
        // This is the "only grows, never shrinks" problem.
        let wasted_capacity = read_pending.capacity();
        assert!(
            wasted_capacity < INITIAL_READ_BUFFER_SIZE,
            "after full advance, usable capacity should be small, got {}",
            wasted_capacity
        );

        // Production (poll_read, before the next poll_data) reserves only
        // when the buffer is empty with no usable capacity. While `parsed`
        // still shares the allocation this starts a fresh INITIAL-sized one.
        if read_pending.is_empty() && read_pending.capacity() < INITIAL_READ_BUFFER_SIZE {
            read_pending.reserve(INITIAL_READ_BUFFER_SIZE);
        }
        assert!(
            read_pending.capacity() >= INITIAL_READ_BUFFER_SIZE
                && read_pending.capacity() < grown_capacity,
            "after reserve, buffer should be reset near initial size, got {}",
            read_pending.capacity()
        );
        // Once the payload is released the large allocation is unique again
        // and a later reserve (after consuming a frame) reuses it.
        drop(parsed);
        let mut reused = BytesMut::with_capacity(INITIAL_READ_BUFFER_SIZE);
        reused.extend_from_slice(&encoded);
        let big = reused.capacity();
        let (parsed, _) = parse_grpc_message_zerocopy(&mut reused).unwrap().unwrap();
        drop(parsed);
        if reused.is_empty() && reused.capacity() < INITIAL_READ_BUFFER_SIZE {
            reused.reserve(INITIAL_READ_BUFFER_SIZE);
        }
        assert_eq!(
            reused.capacity(),
            big,
            "unique allocation must be reclaimed"
        );
    }
}
