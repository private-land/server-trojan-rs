//! Bidirectional relay with idle timeout, half-close timeout, and traffic statistics
//!
//! Custom poll-based bidirectional copy that replaces tokio's `copy_bidirectional`
//! with support for:
//! - Idle timeout: disconnect if no data flows in either direction
//! - Half-close timeout: after one direction finishes (EOF), give the other
//!   direction a short deadline before closing (like Xray's uplinkOnly/downlinkOnly)
//! - Per-direction traffic byte counting

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::hooks::{StatsCollector, UserId};
use std::sync::Arc;

/// How the relay terminated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTermination {
    /// Both directions completed normally (EOF + shutdown)
    Completed,
    /// Half-close timeout: one direction got EOF, other didn't finish in time
    HalfCloseTimeout,
    /// Idle timeout: no data transferred for idle_timeout_secs
    IdleTimeout,
    /// I/O error during relay
    Error,
}

impl std::fmt::Display for RelayTermination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => f.write_str("completed"),
            Self::HalfCloseTimeout => f.write_str("half_close_timeout"),
            Self::IdleTimeout => f.write_str("idle_timeout"),
            Self::Error => f.write_str("error"),
        }
    }
}

/// Result of bidirectional copy with traffic stats and diagnostic info
#[derive(Debug, Clone, Copy)]
pub struct CopyResult {
    /// Bytes transferred from A to B (upload)
    pub a_to_b: u64,
    /// Bytes transferred from B to A (download)
    pub b_to_a: u64,
    /// How the relay terminated
    pub termination: RelayTermination,
    /// Whether client (a) reader received EOF
    pub client_eof: bool,
    /// Whether remote (b) reader received EOF
    pub remote_eof: bool,
}

/// Buffer for one direction of a bidirectional copy.
///
/// State machine: Read → Write → Flush (non-blocking) → (loop) or EOF → Shutdown → Done
///
/// Two mechanisms ensure EOF detection is never blocked by slow peers (realm):
///
/// 1. Non-blocking flush (v0.2.6): poll_flush is best-effort — if Pending, we
///    continue to read instead of blocking. Handles the case where all data is
///    written but flush is slow.
///
/// 2. Probe read on write backpressure (v0.2.8): when poll_write returns Pending
///    (WS sink full due to slow realm), we read into unused buffer space past `cap`
///    to detect EOF. This mirrors Xray's two-goroutine design where read and write
///    are independent. Handles responses > buffer_size through slow realm connections.
struct DirectionalBuffer {
    buf: Vec<u8>,
    /// Start of unwritten data in buf
    pos: usize,
    /// End of valid data in buf
    cap: usize,
    /// Total bytes written to destination
    amt: u64,
    /// Reader returned EOF
    read_done: bool,
    /// Writer shutdown complete — this direction is fully done
    shutdown_done: bool,
    /// Whether flush succeeded during the last poll_copy call.
    /// Used to distinguish data actually sent to the peer (flushed) from data
    /// merely buffered in an intermediate layer (e.g., tungstenite's WS write buffer).
    /// The idle timer should only reset when data reaches the wire, not when it's buffered.
    flush_ok: bool,
}

impl DirectionalBuffer {
    fn new(buf_size: usize) -> Self {
        Self {
            buf: vec![0u8; buf_size],
            pos: 0,
            cap: 0,
            amt: 0,
            read_done: false,
            shutdown_done: false,
            flush_ok: false,
        }
    }

    #[inline]
    fn is_done(&self) -> bool {
        self.shutdown_done
    }

    /// Reader has received EOF (the peer closed their write side).
    /// This is true before shutdown completes — use for half-close timer.
    #[inline]
    fn has_read_eof(&self) -> bool {
        self.read_done
    }

    /// EOF seen and every buffered byte handed to the writer: only now is
    /// this direction "finished" in the Xray sense (request/response copy
    /// done), so the other direction's half-close window may start.
    #[inline]
    fn is_drained(&self) -> bool {
        self.read_done && self.pos >= self.cap
    }

    #[inline]
    fn bytes_transferred(&self) -> u64 {
        self.amt
    }

    /// Whether flush succeeded during the last poll_copy call.
    /// True means data was confirmed sent to the TCP layer (reached the peer).
    /// False means data may be buffered in an intermediate layer (e.g., WS codec).
    #[inline]
    fn has_flushed(&self) -> bool {
        self.flush_ok
    }

    /// Try to make maximum progress on this direction.
    ///
    /// Returns:
    /// - `Poll::Ready(Ok(()))` — direction fully complete (EOF + flush + shutdown)
    /// - `Poll::Ready(Err(e))` — I/O error
    /// - `Poll::Pending` — blocked on I/O, waker registered
    fn poll_copy<R: AsyncRead, W: AsyncWrite>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }

        // Reset flush flag each call; set sticky-true when flush succeeds.
        // This tracks whether ANY data was confirmed sent to the wire during
        // this poll_copy invocation.
        self.flush_ok = false;

        loop {
            // Step 1: Write buffered data
            while self.pos < self.cap {
                match writer
                    .as_mut()
                    .poll_write(cx, &self.buf[self.pos..self.cap])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero bytes",
                        )));
                    }
                    Poll::Ready(Ok(i)) => {
                        self.pos += i;
                        self.amt += i as u64;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // Write blocked (e.g., WS sink full due to slow realm).
                        // Probe for EOF in unused buffer space so the half-close
                        // timer can start even while write is stalled.
                        // This mirrors Xray's two-goroutine design where read and
                        // write are independent — EOF detection is never blocked
                        // by write backpressure.
                        if !self.read_done && self.cap < self.buf.len() {
                            let mut read_buf = ReadBuf::new(&mut self.buf[self.cap..]);
                            match reader.as_mut().poll_read(cx, &mut read_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = read_buf.filled().len();
                                    if n == 0 {
                                        self.read_done = true;
                                    } else {
                                        self.cap += n;
                                    }
                                }
                                Poll::Ready(Err(e)) => {
                                    // Reader broken (e.g. VMess chunk auth failure or
                                    // ECONNRESET): surface it now. Marking EOF here would
                                    // never reach the normal read path again and would
                                    // turn a corrupted session into a clean shutdown.
                                    return Poll::Ready(Err(e));
                                }
                                Poll::Pending => {}
                            }
                        }
                        return Poll::Pending;
                    }
                }
            }

            // Step 2: Best-effort flush — push written data to the wire.
            // Non-blocking: if peer is slow (Pending), continue to read for EOF detection.
            // For direct connections, flush succeeds immediately, delivering data promptly.
            // For realm connections, flush may Pending — data delivered when peer catches up.
            //
            // Track flush result: Ready(Ok(())) means data reached the TCP layer.
            // Pending means data is still in an intermediate buffer (e.g., tungstenite).
            // The idle timer only resets on confirmed flush — prevents zombie connections
            // where writes succeed into a buffer but never reach the peer (v0.2.10 fix).
            match writer.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.flush_ok = true; // sticky: stays true for this poll_copy call
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {} // data buffered but not sent; don't set flush_ok
            }

            // Step 3: If reader hit EOF, shutdown writer
            if self.read_done {
                // Ignore shutdown errors (peer may have already closed)
                let _ = ready!(writer.as_mut().poll_shutdown(cx));
                self.shutdown_done = true;
                return Poll::Ready(Ok(()));
            }

            // Step 4: Read more data
            let mut buf = ReadBuf::new(&mut self.buf);
            ready!(reader.as_mut().poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                self.read_done = true;
                // Loop back to step 3 for shutdown
            } else {
                self.pos = 0;
                self.cap = n;
                // Loop back to step 1 for writing
            }
        }
    }
}

/// Bidirectional copy with idle timeout, per-direction half-close timeouts, and optional traffic statistics
///
/// - `a`: Client stream
/// - `b`: Remote/outbound stream
/// - `idle_timeout_secs`: Disconnect if no data flows for this many seconds
/// - `uplink_only_secs`: After remote EOF (b→a done), wait this long for the client's upload (a→b) to finish (Xray: uplinkOnly=2s)
/// - `downlink_only_secs`: After client EOF (a→b done), wait this long for the remote's download (b→a) to finish (Xray: downlinkOnly=5s)
/// - `buffer_size`: Buffer size for each direction of the relay
/// - `stats`: Optional (user_id, stats_collector) for traffic tracking
pub async fn copy_bidirectional_with_stats<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout_secs: u64,
    uplink_only_secs: u64,
    downlink_only_secs: u64,
    buffer_size: usize,
    stats: Option<(UserId, Arc<dyn StatsCollector>)>,
) -> io::Result<CopyResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a_to_b = DirectionalBuffer::new(buffer_size);
    let mut b_to_a = DirectionalBuffer::new(buffer_size);

    // Pre-compute durations to avoid repeated conversion in the poll loop
    let idle_timeout = tokio::time::Duration::from_secs(idle_timeout_secs);
    let uplink_only_timeout = tokio::time::Duration::from_secs(uplink_only_secs);
    let downlink_only_timeout = tokio::time::Duration::from_secs(downlink_only_secs);

    // Half-close deadline: activated when one direction gets EOF, fires after timeout.
    // Created upfront (stack-pinned) to avoid a Box::pin heap allocation per connection.
    let half_close_sleep = tokio::time::sleep(tokio::time::Duration::ZERO);
    tokio::pin!(half_close_sleep);
    let mut half_close_active = false;
    let mut half_close_timeout = tokio::time::Duration::ZERO;

    // Idle timeout: single Sleep that resets on every data transfer.
    // Unlike interval(30s), this avoids waking active connections every 30s
    // and fires precisely at idle_timeout instead of ±30s granularity.
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    let mut termination = RelayTermination::Completed;
    let mut reported_up: u64 = 0;
    let mut reported_down: u64 = 0;

    let result: io::Result<()> = std::future::poll_fn(|cx| {
        let a_bytes_before = a_to_b.bytes_transferred();
        let b_bytes_before = b_to_a.bytes_transferred();

        // Poll a→b (upload: read from client, write to remote)
        if !a_to_b.is_done() {
            match a_to_b.poll_copy(cx, Pin::new(&mut *a), Pin::new(&mut *b)) {
                Poll::Ready(Ok(())) | Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    termination = RelayTermination::Error;
                    return Poll::Ready(Err(e));
                }
            }
        }

        // Poll b→a (download: read from remote, write to client)
        if !b_to_a.is_done() {
            match b_to_a.poll_copy(cx, Pin::new(&mut *b), Pin::new(&mut *a)) {
                Poll::Ready(Ok(())) | Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    termination = RelayTermination::Error;
                    return Poll::Ready(Err(e));
                }
            }
        }

        // Set half-close timer on EOF detection, NOT on shutdown completion.
        // Bug fix: poll_shutdown on WebSocket can return Pending indefinitely
        // (e.g., flush blocked because realm/peer is slow), which prevented
        // poll_copy from returning Ready(Ok(())), and the half-close timer
        // was never set. Meanwhile the other direction kept transferring data,
        // resetting the idle timer — causing the connection to live forever.
        // Xray semantics (proxy/trojan/inbound): when the request direction
        // (client→remote) finishes only the downlink remains → DownlinkOnly;
        // when the response direction finishes only the uplink remains →
        // UplinkOnly.
        if a_to_b.is_drained() && !b_to_a.is_done() && !half_close_active {
            // Client closed (upload EOF) → wait downlinkOnly for the remaining download
            half_close_active = true;
            half_close_timeout = downlink_only_timeout;
            half_close_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + half_close_timeout);
        }
        if b_to_a.is_drained() && !a_to_b.is_done() && !half_close_active {
            // Remote closed (download EOF) → wait uplinkOnly for the remaining upload
            half_close_active = true;
            half_close_timeout = uplink_only_timeout;
            half_close_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + half_close_timeout);
        }

        // Report traffic incrementally: this future is dropped on kick,
        // graceful shutdown and transport-level cancellation, and bytes
        // only reported after completion would then never be billed.
        if let Some((user_id, collector)) = &stats {
            let up = a_to_b.bytes_transferred();
            if up > reported_up {
                collector.record_upload(*user_id, up - reported_up);
                reported_up = up;
            }
            let down = b_to_a.bytes_transferred();
            if down > reported_down {
                collector.record_download(*user_id, down - reported_down);
                reported_down = down;
            }
        }

        // Reset idle deadline only when data is confirmed sent to the wire.
        //
        // Bug fix (v0.2.10): Previously, the idle timer reset on any bytes_transferred
        // increase — but poll_write on WS returns Ok(n) when data enters tungstenite's
        // internal buffer, NOT when it reaches the TCP layer. With realm in front:
        //   target sends data → WS poll_write Ok (buffered in tungstenite) → amt++ → timer reset!
        //   BUT flush Pending (realm not reading) → data never reaches peer
        // This caused zombie connections: tungstenite's 64KB buffer absorbed writes,
        // keeping the idle timer alive indefinitely. Realm occasionally draining small
        // amounts reopened the buffer, restarting the cycle.
        //
        // Fix: only reset idle timer when BOTH conditions are true:
        //   1. New bytes were written (bytes_transferred increased)
        //   2. Flush succeeded (data confirmed sent to TCP layer)
        // For direct connections, flush always succeeds → no behavior change.
        // For realm connections, flush Pending when peer is slow → timer not reset →
        // zombie connections correctly time out.
        let a_progress = a_to_b.bytes_transferred() > a_bytes_before && a_to_b.has_flushed();
        let b_progress = b_to_a.bytes_transferred() > b_bytes_before && b_to_a.has_flushed();
        if a_progress || b_progress {
            idle_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + idle_timeout);
            // Like Xray's ActivityTimer.SetTimeout, the half-close timeout is an
            // inactivity window, not a hard deadline: a long download after the
            // client half-closed keeps the session alive while bytes flow.
            if half_close_active {
                half_close_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + half_close_timeout);
            }
        }

        // Both directions done → completed normally
        if a_to_b.is_done() && b_to_a.is_done() {
            termination = RelayTermination::Completed;
            return Poll::Ready(Ok(()));
        }

        // Half-close timeout
        if half_close_active && half_close_sleep.as_mut().poll(cx).is_ready() {
            termination = RelayTermination::HalfCloseTimeout;
            return Poll::Ready(Ok(()));
        }

        // Idle timeout: fires precisely after idle_timeout_secs of inactivity
        if idle_sleep.as_mut().poll(cx).is_ready() {
            termination = RelayTermination::IdleTimeout;
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    })
    .await;

    // Collect stats before any cleanup
    let a_to_b_bytes = a_to_b.bytes_transferred();
    let b_to_a_bytes = b_to_a.bytes_transferred();

    // No graceful shutdown here on timeout/error — just drop streams immediately.
    // This matches Xray behavior: timeout → close, no flush wait.
    // The caller (handler.rs) handles shutdown for cancel_token scenarios.
    //
    // Previous code called shutdown() with a 5s timeout per stream, which
    // blocked on poll_flush (e.g. tungstenite flush to slow realm), causing
    // up to 10s extra delay per connection and connection accumulation at peak.

    // Report whatever the last poll did not (an error return skips the
    // per-poll accounting above).
    if let Some((user_id, collector)) = &stats {
        if a_to_b_bytes > reported_up {
            collector.record_upload(*user_id, a_to_b_bytes - reported_up);
        }
        if b_to_a_bytes > reported_down {
            collector.record_download(*user_id, b_to_a_bytes - reported_down);
        }
    }

    let client_eof = a_to_b.has_read_eof();
    let remote_eof = b_to_a.has_read_eof();

    match result {
        Ok(()) => Ok(CopyResult {
            a_to_b: a_to_b_bytes,
            b_to_a: b_to_a_bytes,
            termination,
            client_eof,
            remote_eof,
        }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn test_copy_result_clone() {
        let result = CopyResult {
            a_to_b: 100,
            b_to_a: 200,
            termination: RelayTermination::Completed,
            client_eof: true,
            remote_eof: true,
        };
        let cloned = result;
        assert_eq!(cloned.a_to_b, 100);
        assert_eq!(cloned.b_to_a, 200);
        assert_eq!(cloned.termination, RelayTermination::Completed);
    }

    #[tokio::test]
    async fn test_basic_bidirectional_copy() {
        let data = b"hello world";
        let mut client = Cursor::new(data.to_vec());
        let mut remote = Cursor::new(Vec::new());

        let result = copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None)
            .await
            .unwrap();

        assert_eq!(result.termination, RelayTermination::Completed);
        assert!(result.a_to_b > 0);
    }

    /// Stream wrapper that tracks whether shutdown was called
    struct ShutdownTracker<S> {
        inner: S,
        shutdown_called: Arc<AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ShutdownTracker<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ShutdownTracker<S> {
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
            self.shutdown_called.store(true, Ordering::Release);
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A stream that always returns error on read (simulates broken connection)
    struct AlwaysError;

    impl AsyncRead for AlwaysError {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test error",
            )))
        }
    }

    impl AsyncWrite for AlwaysError {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test error",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Verify that relay does NOT call shutdown on error — caller handles cleanup.
    /// (Changed from previous behavior where relay did graceful shutdown internally.)
    #[tokio::test]
    async fn test_no_shutdown_on_relay_error() {
        let client_shutdown = Arc::new(AtomicBool::new(false));
        let remote_shutdown = Arc::new(AtomicBool::new(false));

        let mut client = ShutdownTracker {
            inner: AlwaysError,
            shutdown_called: Arc::clone(&client_shutdown),
        };
        let mut remote = ShutdownTracker {
            inner: Cursor::new(Vec::new()),
            shutdown_called: Arc::clone(&remote_shutdown),
        };

        let result =
            copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None).await;

        assert!(result.is_err(), "Should return error from broken stream");
        // Relay no longer calls shutdown — caller drops streams to close immediately
        assert!(
            !client_shutdown.load(Ordering::Acquire),
            "Relay should NOT call shutdown (caller handles cleanup)"
        );
        assert!(
            !remote_shutdown.load(Ordering::Acquire),
            "Relay should NOT call shutdown (caller handles cleanup)"
        );
    }

    /// A stream that accepts writes but never returns data on read.
    /// Simulates a peer that keeps the connection open without sending EOF.
    struct NeverEofSink;

    impl AsyncRead for NeverEofSink {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Never return data or EOF — peer keeps connection open.
            // The half-close timer will wake the task, so no waker needed here.
            Poll::Pending
        }
    }

    impl AsyncWrite for NeverEofSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// When client sends EOF first (a→b done), downlink_only applies (Xray:
    /// request done → DownlinkOnly). Asymmetric timeouts verify which fires.
    #[tokio::test(start_paused = true)]
    async fn test_downlink_only_timeout_on_client_eof() {
        let mut client = Cursor::new(b"hello".to_vec()); // Will EOF after data
        let mut remote = NeverEofSink; // Never sends EOF back

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout (high, won't trigger)
            100, // uplink_only: applies after remote EOF (Xray uplinkOnly)
            1,   // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        assert_ne!(
            result.termination,
            RelayTermination::Completed,
            "Should timeout, not complete normally"
        );
        assert!(result.a_to_b > 0, "Client data should have been relayed");
        // With paused time, mocked clock should advance to uplink_only (1s)
        let elapsed = start.elapsed();
        assert!(
            elapsed >= tokio::time::Duration::from_secs(1),
            "Should wait at least downlink_only timeout"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Should NOT wait for uplink_only (100s), elapsed={:?}",
            elapsed
        );
    }

    /// When remote sends EOF first (b→a done), uplink_only applies (Xray:
    /// response done → UplinkOnly). Asymmetric timeouts verify which fires.
    #[tokio::test(start_paused = true)]
    async fn test_uplink_only_timeout_on_remote_eof() {
        let mut client = NeverEofSink; // Never sends EOF
        let mut remote = Cursor::new(b"world".to_vec()); // Will EOF after data

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout (high, won't trigger)
            1,   // uplink_only: applies after remote EOF (Xray uplinkOnly)
            100, // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        assert_ne!(
            result.termination,
            RelayTermination::Completed,
            "Should timeout, not complete normally"
        );
        assert!(result.b_to_a > 0, "Remote data should have been relayed");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= tokio::time::Duration::from_secs(1),
            "Should wait at least downlink_only timeout"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Should NOT wait for uplink_only (100s), elapsed={:?}",
            elapsed
        );
    }

    /// Verify stats are recorded even when relay ends via half-close timeout
    #[tokio::test(start_paused = true)]
    async fn test_stats_recorded_on_half_close_timeout() {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        struct RecordingCollector {
            upload: AtomicU64,
            download: AtomicU64,
        }
        impl StatsCollector for RecordingCollector {
            fn record_request(&self, _: UserId) {}
            fn record_upload(&self, _: UserId, bytes: u64) {
                self.upload.fetch_add(bytes, AtomicOrdering::Relaxed);
            }
            fn record_download(&self, _: UserId, bytes: u64) {
                self.download.fetch_add(bytes, AtomicOrdering::Relaxed);
            }
        }

        let collector = Arc::new(RecordingCollector {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        });

        let mut client = Cursor::new(b"upload-data".to_vec());
        let mut remote = NeverEofSink;

        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300,
            1, // uplink_only = 1s
            5, // downlink_only = 5s
            1024,
            Some((42, Arc::clone(&collector) as Arc<dyn StatsCollector>)),
        )
        .await
        .unwrap();

        assert_ne!(result.termination, RelayTermination::Completed);
        assert_eq!(
            collector.upload.load(AtomicOrdering::Relaxed),
            result.a_to_b,
            "Upload stats should match bytes transferred"
        );
    }

    /// Traffic must be billed even when the relay future is dropped before it
    /// resolves (kick, graceful shutdown, transport cancellation).
    #[tokio::test(start_paused = true)]
    async fn test_stats_recorded_when_relay_future_is_dropped() {
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        struct RecordingCollector(AtomicU64);
        impl StatsCollector for RecordingCollector {
            fn record_request(&self, _: UserId) {}
            fn record_upload(&self, _: UserId, bytes: u64) {
                self.0.fetch_add(bytes, AtomicOrdering::Relaxed);
            }
            fn record_download(&self, _: UserId, _: u64) {}
        }
        let collector = Arc::new(RecordingCollector(AtomicU64::new(0)));

        let mut client = Cursor::new(b"upload-data".to_vec());
        let mut remote = NeverEofSink;
        let relay = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300,
            100, // both half-close timers far away: the relay is still pending when dropped
            100,
            1024,
            Some((42, Arc::clone(&collector) as Arc<dyn StatsCollector>)),
        );
        tokio::select! {
            _ = relay => panic!("relay must still be waiting on the half-close timer"),
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {}
        }
        assert_eq!(collector.0.load(AtomicOrdering::Relaxed), 11);
    }

    /// Reader that yields one chunk per `gap`, `n` times, then EOF — models a
    /// remote still streaming a response after the client half-closed.
    struct DrippingReader {
        left: usize,
        gap: tokio::time::Duration,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }
    impl AsyncRead for DrippingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.left == 0 {
                return Poll::Ready(Ok(()));
            }
            if self.sleep.is_none() {
                let gap = self.gap;
                self.sleep = Some(Box::pin(tokio::time::sleep(gap)));
            }
            match self.sleep.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    self.sleep = None;
                    self.left -= 1;
                    buf.put_slice(b"chunk");
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
    impl AsyncWrite for DrippingReader {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// After the client half-closes, a response that keeps flowing must not be
    /// cut by downlink_only as a hard deadline (Xray: inactivity timeout).
    #[tokio::test(start_paused = true)]
    async fn half_close_timeout_is_reset_by_activity() {
        let mut client = Cursor::new(b"GET".to_vec()); // EOF right after the request
        let mut remote = DrippingReader {
            left: 10,
            gap: tokio::time::Duration::from_secs(1),
            sleep: None,
        };
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300,
            100, // uplink_only
            2,   // downlink_only = 2s of inactivity; data arrives every 1s for 10s
            1024,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            result.termination,
            RelayTermination::Completed,
            "download must finish: {:?}",
            result.termination
        );
        assert_eq!(result.b_to_a, 50);
    }

    /// A stream where poll_shutdown always returns Pending (simulates WS flush
    /// blocked because realm/peer is slow). The reader sends EOF after data,
    /// but the writer's shutdown never completes.
    ///
    /// This reproduces the realm connection leak: when the target server closes,
    /// the relay tries to shutdown the client WS writer. If poll_shutdown hangs
    /// (flush blocked by realm), the old code would never set the half-close
    /// timer, and if the other direction kept sending data, the connection
    /// would live forever.
    struct ShutdownHangsStream {
        /// Data to return on first read, then EOF
        data: Option<Vec<u8>>,
    }

    impl AsyncRead for ShutdownHangsStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(data) = self.data.take() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                Poll::Ready(Ok(()))
            } else {
                // EOF
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for ShutdownHangsStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // Simulate WS flush blocked by realm — never completes
            Poll::Pending
        }
    }

    /// Regression test for realm connection leak:
    /// When remote EOF is received but poll_shutdown on client hangs,
    /// the half-close timer must still fire based on EOF detection.
    ///
    /// Before fix: half-close timer only started when poll_copy returned
    /// Ready(Ok(())), which required shutdown to complete. With hanging
    /// shutdown, the timer never started → connection lived forever.
    #[tokio::test(start_paused = true)]
    async fn test_half_close_fires_when_shutdown_hangs() {
        // Remote sends "response" then EOF; its shutdown hangs (simulates WS via realm)
        let mut remote = ShutdownHangsStream {
            data: Some(b"response".to_vec()),
        };
        // Client never sends EOF (keeps connection open, like real client through realm)
        let mut client = NeverEofSink;

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout 300s (should NOT trigger)
            2,   // uplink_only: applies after remote EOF (Xray uplinkOnly)
            100, // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_ne!(
            result.termination,
            RelayTermination::Completed,
            "Should timeout, not complete normally"
        );
        assert!(
            elapsed >= tokio::time::Duration::from_secs(2),
            "Should wait at least downlink_only timeout"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Should fire promptly, not wait for idle timeout (300s), elapsed={:?}",
            elapsed
        );
    }

    /// A stream that accepts writes, never returns data on read (like NeverEofSink),
    /// but whose poll_shutdown hangs (simulates WS flush blocked by realm).
    struct NeverEofShutdownHangs;

    impl AsyncRead for NeverEofShutdownHangs {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for NeverEofShutdownHangs {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// Same test but for the other direction: client EOF, shutdown on remote hangs.
    /// Remote never sends EOF (keeps reading), so uplink_only timer should fire.
    #[tokio::test(start_paused = true)]
    async fn test_half_close_fires_when_client_shutdown_hangs() {
        // Client sends "request" then EOF
        let mut client = Cursor::new(b"request".to_vec());
        // Remote accepts writes but never sends data and shutdown hangs
        let mut remote = NeverEofShutdownHangs;

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout (should NOT trigger)
            100, // uplink_only: applies after remote EOF (Xray uplinkOnly)
            2,   // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_ne!(result.termination, RelayTermination::Completed);
        assert!(result.a_to_b > 0, "Client data should have been relayed");
        assert!(
            elapsed >= tokio::time::Duration::from_secs(2),
            "Should wait at least uplink_only timeout"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Should fire promptly, not wait for idle timeout (300s), elapsed={:?}",
            elapsed
        );
    }

    /// Regression test: after half-close timeout, relay should NOT attempt
    /// additional graceful shutdown (which calls flush then shutdown).
    /// Xray behavior: timeout → drop immediately.
    ///
    /// Old code called shutdown() with 5s timeout per stream AFTER the relay
    /// loop returned, blocking on poll_flush (e.g. tungstenite flush to slow
    /// realm), causing up to 10s extra delay per connection and connection
    /// accumulation during peak traffic.
    ///
    /// Uses ShutdownHangsStream (flush=Ready, shutdown=Pending) so that
    /// the half-close timer can fire normally via poll_shutdown's Pending.
    #[tokio::test(start_paused = true)]
    async fn test_no_extra_shutdown_after_half_close_timeout() {
        // Remote sends "response" then EOF; its shutdown hangs
        let mut remote = ShutdownHangsStream {
            data: Some(b"response".to_vec()),
        };
        // Client never sends EOF
        let mut client = NeverEofSink;

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout (won't trigger)
            2,   // uplink_only: applies after remote EOF (Xray uplinkOnly)
            100, // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_ne!(result.termination, RelayTermination::Completed);
        // Should complete in ~2s (half-close timeout only).
        // Old code: 2s + 5s (shutdown a) + 5s (shutdown b) = 12s
        assert!(
            elapsed >= tokio::time::Duration::from_secs(2),
            "Should wait at least half-close timeout"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(4),
            "Should NOT wait for extra shutdown timeouts, elapsed={:?}",
            elapsed
        );
    }

    /// Verify that &mut reference pattern allows callers to access and
    /// shutdown streams after relay completes (enables cancel_token pattern).
    #[tokio::test]
    async fn test_mut_ref_allows_post_relay_shutdown() {
        let data = b"hello";
        let mut client = Cursor::new(data.to_vec());
        let mut remote = Cursor::new(Vec::new());

        let result = copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None)
            .await
            .unwrap();

        assert_eq!(result.termination, RelayTermination::Completed);
        assert!(result.a_to_b > 0);

        // Key: streams are still accessible after relay (not moved into the future).
        tokio::io::AsyncWriteExt::shutdown(&mut client)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut remote)
            .await
            .unwrap();
    }

    /// A stream where poll_flush returns Pending (simulates WS transport where
    /// tungstenite's flush is blocked because realm's TCP buffer is full).
    /// Reads return data once then Pending (simulates client that sent a request
    /// and is waiting for the response — connection alive but no new upload data).
    struct FlushHangsStream {
        read_data: Option<Vec<u8>>,
    }

    impl AsyncRead for FlushHangsStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(data) = self.read_data.take() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for FlushHangsStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// Simulates a request-response client over a persistent tunnel.
    ///
    /// Models real behavior: client sends a request, waits for the response
    /// to be flushed (delivered via network), then closes. Without flush in
    /// the relay, the response stays in the WS codec buffer and the client
    /// never receives it — causing the relay to hang until idle timeout.
    struct RequestResponseClient {
        /// Request data to send on first read
        request: Option<Vec<u8>>,
        /// Set by poll_write — indicates unflushed data exists
        has_pending_write: bool,
        /// Set by poll_flush when pending data is flushed — unlocks client read
        response_delivered: Arc<AtomicBool>,
        /// Waker for the read side, woken when flush delivers the response
        read_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    }

    impl AsyncRead for RequestResponseClient {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // First read: send the request
            if let Some(data) = self.request.take() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                return Poll::Ready(Ok(()));
            }
            // Subsequent reads: wait until response has been flushed
            if self.response_delivered.load(Ordering::Acquire) {
                // Client received response → close tunnel (EOF)
                Poll::Ready(Ok(()))
            } else {
                *self.read_waker.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for RequestResponseClient {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.has_pending_write = true;
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.has_pending_write {
                self.has_pending_write = false;
                self.response_delivered.store(true, Ordering::Release);
                if let Some(waker) = self.read_waker.lock().unwrap().take() {
                    waker.wake();
                }
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // Shutdown also delivers (WS poll_shutdown calls poll_ready which flushes)
            if self.has_pending_write {
                self.has_pending_write = false;
                self.response_delivered.store(true, Ordering::Release);
                if let Some(waker) = self.read_waker.lock().unwrap().take() {
                    waker.wake();
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    /// Remote server that sends one response then keeps connection open.
    /// Models a persistent target (database, API) waiting for the next request.
    struct PersistentRemote {
        response: Option<Vec<u8>>,
    }

    impl AsyncRead for PersistentRemote {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(data) = self.response.take() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                Poll::Ready(Ok(()))
            } else {
                // Waiting for next request — connection alive, no EOF
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for PersistentRemote {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Regression test: without flush in relay, response data stays in WS codec
    /// buffer and never reaches the client in direct-connect mode (no realm).
    ///
    /// Scenario: client sends request through WS tunnel, server sends response.
    /// The relay writes the response to the WS transport (poll_write → start_send),
    /// but without poll_flush, the data stays in tungstenite's codec buffer.
    /// The client never receives the response, never sends more data or closes,
    /// and the connection hangs until idle timeout.
    ///
    /// With non-blocking flush: data is delivered promptly, client sees response,
    /// closes tunnel → half-close timer fires at 2s instead of idle timeout at 30s.
    #[tokio::test(start_paused = true)]
    async fn test_direct_connect_flush_delivers_response() {
        let response_delivered = Arc::new(AtomicBool::new(false));
        let read_waker = Arc::new(std::sync::Mutex::new(None));

        let mut client = RequestResponseClient {
            request: Some(b"GET /".to_vec()),
            has_pending_write: false,
            response_delivered: Arc::clone(&response_delivered),
            read_waker: Arc::clone(&read_waker),
        };
        let mut remote = PersistentRemote {
            response: Some(b"HTTP/1.1 200 OK".to_vec()),
        };

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            30,  // idle timeout = 30s (should NOT fire if flush works)
            100, // uplink_only: applies after remote EOF (Xray uplinkOnly)
            2,   // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert!(result.a_to_b > 0, "Client request should be relayed");
        assert!(result.b_to_a > 0, "Server response should be relayed");
        // With flush: client receives response → EOF → uplink_only fires at ~2s
        // Without flush: response stuck in buffer → idle timeout at 30s
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Response must be flushed promptly (direct connect), not wait for idle timeout (30s), elapsed={:?}",
            elapsed
        );
    }

    /// A stream where poll_write returns Pending after N successful writes.
    /// Simulates WS transport where the sink is full (realm's TCP buffer full).
    /// Read always returns Pending (client waiting for response, no more upload data).
    struct WriteBlocksAfterN {
        /// How many more writes to accept before blocking
        writes_remaining: usize,
    }

    impl AsyncRead for WriteBlocksAfterN {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Client never sends more data (idle, waiting for response)
            Poll::Pending
        }
    }

    impl AsyncWrite for WriteBlocksAfterN {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.writes_remaining > 0 {
                self.writes_remaining -= 1;
                Poll::Ready(Ok(buf.len()))
            } else {
                Poll::Pending
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A remote server that sends multiple chunks of data then EOF.
    struct MultiChunkThenEof {
        chunks: Vec<Vec<u8>>,
        index: usize,
    }

    impl AsyncRead for MultiChunkThenEof {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.index < self.chunks.len() {
                let data = &self.chunks[self.index];
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                self.index += 1;
                Poll::Ready(Ok(()))
            } else {
                // EOF
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for MultiChunkThenEof {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A blocked write with bytes still buffered is governed by the idle
    /// timeout, not by the half-close window (Xray semantics: UplinkOnly /
    /// DownlinkOnly only arm once the copy, including its writes, is done).
    /// Otherwise a brief stall of the receiving side after the sender's EOF
    /// would discard the tail of the transfer.
    ///
    /// Scenario: target sends two chunks then closes. The relay writes chunk1
    /// to the client, reads chunk2, but poll_write for chunk2 stays Pending
    /// (realm's TCP buffer full). The EOF probe still sees the remote close,
    /// yet the half-close timer must not start while chunk2 is unwritten;
    /// the connection ends via the idle timeout instead.
    #[tokio::test(start_paused = true)]
    async fn test_blocked_write_with_pending_bytes_waits_for_idle_not_half_close() {
        // Client: accepts first write (chunk1), then blocks (realm buffer full)
        let mut client = WriteBlocksAfterN {
            writes_remaining: 1,
        };
        // Remote: sends two chunks then EOF
        let mut remote = MultiChunkThenEof {
            chunks: vec![b"chunk1-response".to_vec(), b"chunk2-response".to_vec()],
            index: 0,
        };

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            30,  // idle timeout = 30s — governs this case
            2,   // uplink_only: would fire at 2s if (wrongly) armed with pending bytes
            100, // downlink_only
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_eq!(result.termination, RelayTermination::IdleTimeout);
        assert!(
            elapsed >= tokio::time::Duration::from_secs(30),
            "half-close must not fire while chunk2 is unwritten, elapsed={:?}",
            elapsed
        );
    }

    /// Regression test: poll_flush blocking in relay prevents EOF detection,
    /// causing connections to wait for idle timeout (300s) instead of half-close (2-5s).
    ///
    /// Scenario: target sends response then closes. Trojan writes response to client WS,
    /// but poll_flush on client WS hangs (realm's TCP buffer full). poll_copy is stuck
    /// at flush step, never reads the next chunk from remote which would return EOF.
    /// Without EOF, half-close timer never starts → connection waits for idle timeout.
    #[tokio::test(start_paused = true)]
    async fn test_half_close_fires_when_flush_hangs_before_eof() {
        // Remote: sends response data then EOF
        let mut remote = ShutdownHangsStream {
            data: Some(b"response".to_vec()),
        };
        // Client: sends request then waits. Flush hangs (slow realm).
        let mut client = FlushHangsStream {
            read_data: Some(b"request".to_vec()),
        };

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            30,  // idle timeout = 30s (fallback — should NOT be needed)
            2,   // uplink_only: applies after remote EOF (Xray uplinkOnly)
            100, // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_ne!(
            result.termination,
            RelayTermination::Completed,
            "Should timeout, not complete normally"
        );
        assert!(
            elapsed >= tokio::time::Duration::from_secs(2),
            "Should wait at least downlink_only timeout"
        );
        // Key: should close at ~2s (half-close), NOT at ~30s (idle timeout).
        // Bug: poll_flush blocks poll_copy from reading remote EOF, so half-close
        // timer never starts, and connection waits for idle timeout instead.
        assert!(
            elapsed < tokio::time::Duration::from_secs(10),
            "Should fire at half-close (~2s), not idle timeout (30s), elapsed={:?}",
            elapsed
        );
    }

    /// Regression test (v0.2.10): idle timer must NOT reset when data is written to
    /// an intermediate buffer but never flushed to the wire.
    ///
    /// Scenario (realm connection leak):
    ///   target sends response every 1s → relay writes to client WS (poll_write Ok,
    ///   data enters tungstenite's 64KB buffer) → amt increases → BUT flush Pending
    ///   (realm not reading) → data never reaches the peer.
    ///
    /// Before fix: idle timer reset on bytes_transferred increase alone, so the
    /// connection lived forever — tungstenite's buffer absorbed writes, keeping the
    /// timer alive even though no data was delivered. With realm occasionally draining
    /// small amounts, the cycle repeated indefinitely, causing 54k+ zombie connections.
    ///
    /// After fix: idle timer only resets when flush succeeds (data confirmed on wire).
    /// Buffered-only writes do NOT reset the timer → connection correctly times out.
    ///
    /// Red/green: without `has_flushed()` check, the 20 periodic writes (at 1s intervals)
    /// keep resetting the idle timer → relay terminates at ~25s instead of ~5s.
    #[tokio::test(start_paused = true)]
    async fn test_idle_timer_not_reset_by_buffered_writes() {
        use tokio::io::AsyncWriteExt;

        // Client (a): accepts writes into buffer, flush never completes (realm blocking).
        // Read returns Pending (client not sending any data).
        let mut client = FlushHangsStream {
            read_data: None, // no client data → poll_read always Pending
        };

        // Remote (b): sends data every 1s via a spawned task, simulating a target
        // server streaming response data through realm. Uses DuplexStream so the
        // relay sees real AsyncRead/AsyncWrite with proper waker behavior.
        let (mut test_writer, mut relay_remote) = tokio::io::duplex(4096);

        let sender = tokio::spawn(async move {
            // Send 20 chunks at 1s intervals — enough to keep resetting the idle timer
            // well past 5s if the bug exists (unflushed writes reset timer).
            for _ in 0..20 {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                if test_writer.write_all(b"response-data").await.is_err() {
                    break; // relay closed
                }
            }
            // Keep connection open (no EOF) — will be aborted when test ends
            std::future::pending::<()>().await;
        });

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut relay_remote,
            5,   // idle timeout = 5s (THIS should fire — flush never succeeds)
            100, // uplink_only (should NOT fire — no client EOF)
            100, // downlink_only (should NOT fire — no remote EOF)
            1024,
            None,
        )
        .await
        .unwrap();

        sender.abort();

        let elapsed = start.elapsed();
        assert_eq!(
            result.termination,
            RelayTermination::IdleTimeout,
            "Should terminate via idle timeout"
        );
        assert!(
            result.b_to_a > 0,
            "Data should have been written (buffered)"
        );
        assert!(!result.client_eof, "Client did not send EOF");
        assert!(!result.remote_eof, "Remote did not send EOF");
        assert!(
            elapsed >= tokio::time::Duration::from_secs(5),
            "Should wait at least idle timeout (5s)"
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(7),
            "Should fire at idle timeout (~5s), not be kept alive by buffered writes, elapsed={:?}",
            elapsed
        );
    }

    /// Companion test (v0.2.10): direct connection (flush succeeds) → idle timer
    /// SHOULD reset on data activity, keeping the connection alive.
    ///
    /// Ensures the has_flushed() guard doesn't break direct-connect behavior.
    /// Without realm, poll_flush returns Ready(Ok(())) → flush_ok=true → timer resets.
    ///
    /// Red/green: always green — passes both with and without has_flushed() check,
    /// since flush succeeds and both code paths reset the timer.
    #[tokio::test(start_paused = true)]
    async fn test_idle_timer_resets_on_flushed_writes() {
        use tokio::io::AsyncWriteExt;

        // Client (a): flush succeeds (direct connection, no realm).
        // Read returns Pending (no client data).
        let mut client = PersistentRemote {
            response: None, // read=Pending, write=Ok, flush=Ok
        };

        // Remote (b): sends data every 2s for 10 rounds (t=0,2,...18) via DuplexStream.
        // Flush succeeds → timer resets each send → connection alive until t=23s.
        let (mut test_writer, mut relay_remote) = tokio::io::duplex(4096);

        let sender = tokio::spawn(async move {
            for i in 0..10 {
                if i > 0 {
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
                if test_writer.write_all(b"flushed-data").await.is_err() {
                    break;
                }
            }
            // Keep connection open (no EOF)
            std::future::pending::<()>().await;
        });

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut relay_remote,
            5,   // idle timeout = 5s — but flushed writes keep resetting it
            100, // uplink_only
            100, // downlink_only
            1024,
            None,
        )
        .await
        .unwrap();

        sender.abort();

        let elapsed = start.elapsed();
        assert_eq!(
            result.termination,
            RelayTermination::IdleTimeout,
            "Should terminate via idle timeout after data stops"
        );
        // Data flows until t=18, then 5s idle → terminates at ~t=23s.
        assert!(
            elapsed >= tokio::time::Duration::from_secs(20),
            "Direct connection: flushed writes should keep idle timer alive, elapsed={:?}",
            elapsed
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(30),
            "Should eventually idle-timeout after data stops, elapsed={:?}",
            elapsed
        );
    }

    /// Verify that the pre-created half-close timer does not fire spuriously
    /// when neither direction has received EOF.
    ///
    /// Regression test for stack-pin optimization: half_close_sleep is created
    /// with Duration::ZERO (already expired) but gated by half_close_active flag.
    /// If the flag check were missing, the expired timer would fire immediately
    /// and the relay would terminate at ~0s instead of waiting for idle timeout.
    #[tokio::test(start_paused = true)]
    async fn test_half_close_timer_inactive_without_eof() {
        // Both sides: read returns Pending (no data, no EOF)
        let mut client = NeverEofSink;
        let mut remote = NeverEofSink;

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            3, // idle timeout = 3s (THIS should fire)
            1, // uplink_only = 1s (should NOT fire — no EOF)
            1, // downlink_only = 1s (should NOT fire — no EOF)
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_eq!(
            result.termination,
            RelayTermination::IdleTimeout,
            "Should terminate via idle timeout, not half-close"
        );
        // Key: should idle-timeout at 3s, NOT half-close at 0-1s.
        // Without half_close_active guard, the pre-created Duration::ZERO timer
        // would fire immediately → elapsed ≈ 0s.
        assert!(
            elapsed >= tokio::time::Duration::from_secs(3),
            "Should wait for idle timeout (3s), not fire early, elapsed={:?}",
            elapsed
        );
        assert!(
            elapsed < tokio::time::Duration::from_secs(5),
            "Should fire at idle timeout (~3s), elapsed={:?}",
            elapsed
        );
    }

    /// Verify half-close timer fires correctly with zero-second timeout.
    ///
    /// Edge case for stack-pin optimization: the pre-created timer starts with
    /// Duration::ZERO, then gets reset to (now + 0s) on EOF detection.
    /// Tests that reset with zero duration works correctly and doesn't confuse
    /// the "already expired" initial state with the "just activated" state.
    #[tokio::test(start_paused = true)]
    async fn test_half_close_zero_timeout_fires_immediately() {
        let mut client = Cursor::new(b"data".to_vec()); // Client sends data then EOF
        let mut remote = NeverEofSink; // Remote never sends EOF

        let start = tokio::time::Instant::now();
        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300, // idle timeout = high (should NOT fire)
            300, // uplink_only: applies after remote EOF (Xray uplinkOnly)
            0,   // downlink_only: applies after client EOF (Xray downlinkOnly)
            1024,
            None,
        )
        .await
        .unwrap();

        let elapsed = start.elapsed();
        assert_eq!(
            result.termination,
            RelayTermination::HalfCloseTimeout,
            "Should terminate via half-close timeout"
        );
        assert!(result.client_eof, "Client should have sent EOF");
        // With 0s timeout, should fire essentially immediately after client EOF
        assert!(
            elapsed < tokio::time::Duration::from_secs(1),
            "Zero-second half-close should fire immediately, elapsed={:?}",
            elapsed
        );
    }
}
