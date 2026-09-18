//! gRPC HTTP/2 connection manager
//!
//! Manages HTTP/2 connections and accepts multiple streams,
//! each stream corresponds to an independent VMess tunnel.

use anyhow::Result;
use bytes::Bytes;
use h2::server;
use http::{Response, StatusCode};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::heartbeat::H2Heartbeat;
use super::transport::{GrpcTransport, Responder, MAX_FRAME_SIZE, MAX_SEND_QUEUE_BYTES};

/// Maximum concurrent HTTP/2 streams
const MAX_CONCURRENT_STREAMS: usize = 100;

/// Maximum HTTP/2 header list size
const MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;

/// Initial HTTP/2 stream window size (per stream)
/// Go net/http2 default is 1MB. 8MB was excessive and caused high memory
/// usage under load (100 streams × 8MB = 800MB per H2 connection).
const INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;

/// Initial HTTP/2 connection window size (shared across all streams)
const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024;

/// Go's `url.PathEscape`: everything except unreserved characters and the
/// path-segment-safe sub-delims (`$&+:=@`) is percent-encoded.
fn path_escape(s: &str) -> String {
    const KEEP: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b':')
        .remove(b'=')
        .remove(b'@');
    percent_encoding::utf8_percent_encode(s, KEEP).to_string()
}

/// Request paths for the Tun and TunMulti streams, derived from the panel's
/// `serviceName` exactly like Xray's `Config.getServiceName` /
/// `getTunStreamName` / `getTunMultiStreamName`:
///
/// * `name` → `/{escape(name)}/Tun` and `/{escape(name)}/TunMulti`;
/// * `/a/b/tun|multi` (leading slash: custom paths) → service `a/b`
///   (segments escaped), streams `tun` and `multi` (or `tun` for both when
///   no `|` part is given).
pub(crate) fn grpc_paths(service_name: &str) -> (String, String) {
    match service_name.strip_prefix('/') {
        None => {
            let svc = path_escape(service_name);
            (format!("/{svc}/Tun"), format!("/{svc}/TunMulti"))
        }
        Some(rest) => {
            let last = service_name.rfind('/').unwrap_or(0).max(1);
            let raw_service = &service_name[1..last];
            let svc = raw_service
                .split('/')
                .map(path_escape)
                .collect::<Vec<_>>()
                .join("/");
            let ending = &rest[rest.rfind('/').map_or(0, |i| i + 1)..];
            let mut names = ending.split('|');
            let tun = names.next().unwrap_or("");
            let multi = names.next().unwrap_or(tun);
            (
                format!("/{svc}/{}", path_escape(tun)),
                format!("/{svc}/{}", path_escape(multi)),
            )
        }
    }
}

/// gRPC HTTP/2 connection manager
///
/// Manages an HTTP/2 connection, accepting multiple streams where each
/// stream corresponds to an independent VMess tunnel.
pub struct GrpcConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
    /// A connection carrying no stream for this long is closed.
    idle_timeout: std::time::Duration,
    /// Expected gRPC path (format: "/${service_name}/Tun")
    expected_path: String,
    /// multiMode path (format: "/${service_name}/TunMulti")
    expected_multi_path: String,
    /// Buffer size for gRPC message framing
    buffer_size: usize,
}

impl<S> GrpcConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new gRPC connection with a custom service name and buffer size
    ///
    /// `buffer_size` controls the gRPC message framing size.
    /// If 0, uses the default (32KB).
    pub async fn with_config(
        stream: S,
        service_name: &str,
        buffer_size: usize,
        idle_timeout: std::time::Duration,
    ) -> io::Result<Self> {
        let h2_conn = server::Builder::new()
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS as u32)
            .max_send_buffer_size(MAX_SEND_QUEUE_BYTES)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("h2 handshake: {}", e)))?;

        let (expected_path, expected_multi_path) = grpc_paths(service_name);

        Ok(Self {
            h2_conn,
            idle_timeout,
            expected_path,
            expected_multi_path,
            buffer_size,
        })
    }

    /// Run the connection, calling the handler for each accepted stream
    ///
    /// When the H2 connection closes (error, heartbeat timeout, or graceful),
    /// all spawned handler tasks are cancelled via a shared CancellationToken
    /// to prevent orphaned tasks from holding resources until their idle timeout.
    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(GrpcTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let mut h2_conn = self.h2_conn;
        let buffer_size = self.buffer_size;
        // Streams currently handled on this connection (h2 itself enforces
        // MAX_CONCURRENT_STREAMS; this only feeds the idle check).
        let active_streams = Arc::new(AtomicUsize::new(0));
        // Half-interval ticks: GOAWAY on the third consecutive tick with no
        // stream (≥ 1× idle_timeout since the last stream ended, ≤ 1.5×), hard
        // close one tick later if the peer does not finish the drain.
        let mut idle_tick = tokio::time::interval(self.idle_timeout / 2);
        idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        idle_tick.tick().await; // first tick is immediate
        let mut idle_ticks = 0u32;

        // Shared token: cancelled when this H2 connection closes,
        // causing all spawned handler tasks to abort promptly.
        let conn_cancel = CancellationToken::new();

        let activity = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut heartbeat = H2Heartbeat::new(h2_conn.ping_pong(), Arc::clone(&activity));

        let result = loop {
            tokio::select! {
                result = h2_conn.accept() => {
                    match result {
                        Some(Ok((request, mut respond))) => {
                            heartbeat.on_activity();

                            if request.method() != http::Method::POST {
                                let response = Response::builder()
                                    .status(StatusCode::METHOD_NOT_ALLOWED)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(response, true);
                                continue;
                            }

                            // "/{service}/Tun" (Hunk) and "/{service}/TunMulti"
                            // (MultiHunk, client multiMode) share the wire encoding;
                            // the codec accepts both.
                            let path = request.uri().path();
                            if path != self.expected_path && path != self.expected_multi_path {
                                debug!(path = %path, expected = %self.expected_path, "gRPC path mismatch");
                                // grpc-go answers an unknown service with a
                                // trailers-only UNIMPLEMENTED (12), not HTTP 404.
                                let mut response = GrpcTransport::response_headers();
                                let headers = response.headers_mut();
                                headers.insert("grpc-status", "12".parse().unwrap());
                                headers.insert("grpc-message", "unknown service".parse().unwrap());
                                let _ = respond.send_response(response, true);
                                continue;
                            }

                            // Only an accepted stream counts against idleness;
                            // rejected probes must not keep the connection alive.
                            idle_ticks = 0;
                            // Response headers go out with the first data frame
                            // (see `Responder`); until then the stream looks like
                            // a grpc-go handler that has not replied yet.
                            let transport = GrpcTransport::with_activity(
                                request.into_body(),
                                Responder::Pending(respond),
                                buffer_size,
                                Some(Arc::clone(&activity)),
                            );

                            let handler_clone = Arc::clone(&handler);
                            let task_cancel = conn_cancel.child_token();
                            let streams = Arc::clone(&active_streams);
                            streams.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _guard = scopeguard::guard(streams, |s| {
                                    s.fetch_sub(1, Ordering::Relaxed);
                                });
                                tokio::select! {
                                    result = handler_clone(transport) => { let _ = result; }
                                    _ = task_cancel.cancelled() => {
                                        debug!("gRPC stream handler cancelled (connection closed)");
                                    }
                                }
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "gRPC connection error");
                            break Err(anyhow::anyhow!("gRPC connection error: {}", e));
                        }
                        None => {
                            debug!("gRPC connection closed normally");
                            break Ok(());
                        }
                    }
                }

                result = heartbeat.poll() => {
                    if let Err(e) = result {
                        break Err(anyhow::anyhow!("gRPC {}", e));
                    }
                }

                // An H2 connection with no stream is only a permit holder;
                // every H2 stack answers PING, so the heartbeat cannot tell a
                // live idle peer from a probe that opened the connection and
                // walked away. TCP/WS peers in that state hit request_timeout.
                _ = idle_tick.tick() => {
                    if active_streams.load(Ordering::Relaxed) == 0 {
                        idle_ticks += 1;
                        if idle_ticks == 3 {
                            // GOAWAY: a client that races a new stream retries
                            // it on a fresh connection instead of failing.
                            debug!("gRPC connection idle with no streams, draining");
                            h2_conn.graceful_shutdown();
                        } else if idle_ticks > 3 {
                            debug!("gRPC connection idle drain elapsed, closing");
                            break Ok(());
                        }
                    } else {
                        idle_ticks = 0;
                    }
                }
            }
        };

        // Cancel all handler tasks spawned on this H2 connection.
        // Tasks will drop their GrpcTransport, relay buffers, and
        // ConnectionManager registrations via scopeguard.
        conn_cancel.cancel();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn test_h2_window_sizes() {
        // Match Go net/http2 defaults (1MB stream, 4MB connection)
        assert_eq!(INITIAL_WINDOW_SIZE, 1024 * 1024);
        assert_eq!(INITIAL_CONNECTION_WINDOW_SIZE, 4 * 1024 * 1024);
    }

    #[test]
    fn test_h2_max_concurrent_streams() {
        // Memory bound: MAX_CONCURRENT_STREAMS × INITIAL_WINDOW_SIZE should be reasonable
        let max_memory_per_conn = MAX_CONCURRENT_STREAMS as u64 * INITIAL_WINDOW_SIZE as u64;
        // With 100 streams × 1MB = 100MB per H2 connection (was 800MB with 8MB windows)
        assert!(
            max_memory_per_conn <= 256 * 1024 * 1024,
            "per-connection memory bound too high: {}MB",
            max_memory_per_conn / (1024 * 1024)
        );
    }

    /// Verify that conn_cancel token cancels spawned handler tasks when
    /// the H2 connection closes, preventing orphaned tasks.
    #[tokio::test]
    async fn test_conn_cancel_token_cancels_handlers() {
        let conn_cancel = CancellationToken::new();
        let task_started = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicUsize::new(0));

        // Simulate spawning a handler task with child_token (same pattern as run())
        let task_cancel = conn_cancel.child_token();
        let started = Arc::clone(&task_started);
        let cancelled = Arc::clone(&task_cancelled);
        let counter_clone = Arc::clone(&counter);
        counter_clone.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let _guard = scopeguard::guard((), |_| {
                counter_clone.fetch_sub(1, Ordering::Relaxed);
            });
            started.store(true, Ordering::Release);

            tokio::select! {
                // Simulate a long-running handler (e.g. relay with 5min idle timeout)
                _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                _ = task_cancel.cancelled() => {
                    cancelled.store(true, Ordering::Release);
                }
            }
        });

        // Wait for task to start
        tokio::task::yield_now().await;
        assert!(task_started.load(Ordering::Acquire));
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        // Simulate H2 connection closing → cancel all handlers
        conn_cancel.cancel();

        handle.await.unwrap();

        assert!(
            task_cancelled.load(Ordering::Acquire),
            "Handler task should have been cancelled"
        );
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "Scopeguard should have decremented counter"
        );
    }

    /// Verify that multiple handler tasks are all cancelled when conn_cancel fires.
    #[tokio::test]
    async fn test_conn_cancel_token_cancels_multiple_handlers() {
        let conn_cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let task_cancel = conn_cancel.child_token();
            let active_clone = Arc::clone(&active);
            active_clone.fetch_add(1, Ordering::Relaxed);

            handles.push(tokio::spawn(async move {
                let _guard = scopeguard::guard((), |_| {
                    active_clone.fetch_sub(1, Ordering::Relaxed);
                });
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                    _ = task_cancel.cancelled() => {}
                }
            }));
        }

        tokio::task::yield_now().await;
        assert_eq!(active.load(Ordering::Relaxed), 10);

        // Cancel all at once
        conn_cancel.cancel();

        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(
            active.load(Ordering::Relaxed),
            0,
            "All handler tasks should have been cleaned up"
        );
    }

    /// Verify that already-completed handlers are not affected by conn_cancel.
    #[tokio::test]
    async fn test_conn_cancel_ignores_completed_handlers() {
        let conn_cancel = CancellationToken::new();
        let counter = Arc::new(AtomicUsize::new(0));

        // Spawn a handler that completes immediately
        let task_cancel = conn_cancel.child_token();
        let counter_clone = Arc::clone(&counter);
        counter_clone.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let _guard = scopeguard::guard((), |_| {
                counter_clone.fetch_sub(1, Ordering::Relaxed);
            });
            tokio::select! {
                _ = async { /* completes immediately */ } => {}
                _ = task_cancel.cancelled() => {}
            }
        });

        handle.await.unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        // Cancel after handler already finished — should be a no-op
        conn_cancel.cancel();
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod path_tests {
    use super::grpc_paths;

    /// Cases from Xray's transport/internet/grpc/config_test.go.
    #[test]
    fn service_name_forms_match_xray() {
        assert_eq!(
            grpc_paths("hello"),
            ("/hello/Tun".into(), "/hello/TunMulti".into())
        );
        assert_eq!(
            grpc_paths("hello/world!"),
            (
                "/hello%2Fworld%21/Tun".into(),
                "/hello%2Fworld%21/TunMulti".into()
            )
        );
        assert_eq!(
            grpc_paths("/my/sample/path/tun_service|multi_service"),
            (
                "/my/sample/path/tun_service".into(),
                "/my/sample/path/multi_service".into()
            )
        );
        assert_eq!(
            grpc_paths("/my/sample/path/tun_service"),
            (
                "/my/sample/path/tun_service".into(),
                "/my/sample/path/tun_service".into()
            )
        );
        assert_eq!(
            grpc_paths("/hello /world!/a|b"),
            ("/hello%20/world%21/a".into(), "/hello%20/world%21/b".into())
        );
        assert_eq!(
            grpc_paths("/m y/sa !mple/pa\\th/tun\\_serv!ice").0,
            "/m%20y/sa%20%21mple/pa%5Cth/tun%5C_serv%21ice"
        );
        assert_eq!(grpc_paths("/foo"), ("//foo".into(), "//foo".into()));
    }
}
