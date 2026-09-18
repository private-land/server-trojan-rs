//! Connection handling logic
//!
//! This module contains the request processing and connection relay logic.

use crate::acl;
use crate::core::dns::ResolvedAddrs;
use crate::core::{
    copy_bidirectional_with_stats, hooks, Address, DecodeResult, Server, TrojanCmd, TrojanRequest,
    TrojanUdpPacket, UserId,
};
use crate::logger::log;
use crate::transport::{ConnectionMeta, NoHalfClose, TransportStream, TransportType};

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// Maximum entries in per-session UDP route cache
const UDP_MAX_ROUTE_CACHE_ENTRIES: usize = 256;

/// Shutdown timeout — prevents infinite hang when peer is unresponsive
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Budget for closing the client transport (Close frame / trailers / FIN),
/// both before a relay (reject, dial failure) and after it. Nothing useful
/// is left to deliver; a stalled peer must not keep the connection permit
/// and buffers for long just to receive an orderly close.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Give up on a UDP session whose client does not drain its socket for this long
const UDP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Consecutive outbound send or receive failures before the session is closed
const UDP_MAX_CONSECUTIVE_ERRORS: u32 = 8;

/// Orderly close of the client transport (WS Close frame / gRPC trailers /
/// TCP FIN) rather than dropping it: unread bytes the client already sent
/// would otherwise turn the close into a TCP RST.
async fn close_client(stream: &mut TransportStream) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, stream.shutdown()).await;
}

/// Read and decode a complete Trojan request from the stream
///
/// This function handles partial reads by continuing to read until
/// a complete request is received or an error occurs.
pub async fn read_trojan_request(
    stream: &mut TransportStream,
    buf: &mut BytesMut,
    buffer_size: usize,
) -> Result<TrojanRequest> {
    loop {
        // Try to decode with current buffer (check completeness first to avoid clone)
        if buf.len() >= TrojanRequest::MIN_SIZE {
            match TrojanRequest::check_complete(buf) {
                Ok(_header_len) => {
                    // Buffer contains complete request, now decode it
                    match TrojanRequest::decode_zerocopy(buf) {
                        DecodeResult::Ok(req, _) => {
                            return Ok(req);
                        }
                        DecodeResult::Invalid(e) => {
                            return Err(anyhow!("Invalid request: {}", e));
                        }
                        DecodeResult::NeedMoreData => {
                            // Should not happen after check_complete succeeds
                            unreachable!("check_complete succeeded but decode failed");
                        }
                    }
                }
                Err(None) => {
                    // Need more data, continue reading
                }
                Err(Some(e)) => {
                    return Err(anyhow!("Invalid request: {}", e));
                }
            }
        }

        // Read directly into BytesMut spare capacity (avoids separate heap allocation)
        buf.reserve(buffer_size);
        let n = stream.read_buf(buf).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(anyhow!("Connection closed before receiving request"));
            } else {
                return Err(anyhow!("Connection closed with incomplete request"));
            }
        }

        // Prevent buffer from growing too large (protection against malicious clients)
        if buf.len() > buffer_size * 2 {
            return Err(anyhow!("Request too large"));
        }
    }
}

/// Process a single connection
pub async fn process_connection(
    server: &Server,
    mut stream: TransportStream,
    meta: ConnectionMeta,
) -> Result<()> {
    // Read Trojan request with timeout and retry for incomplete data
    let buffer_size = server.conn_config.buffer_size;
    let mut buf = BytesMut::with_capacity(buffer_size);

    let request = match tokio::time::timeout(
        server.conn_config.request_timeout,
        read_trojan_request(&mut stream, &mut buf, buffer_size),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            close_client(&mut stream).await;
            return Err(e);
        }
        Err(_) => {
            log::debug!(peer = %meta.peer_addr, stage = "request_timeout", "Connection failed");
            close_client(&mut stream).await;
            return Err(anyhow!("Request read timeout"));
        }
    };

    // Free request parsing buffer immediately — payload is an independent Bytes.
    // Saves 32KB per connection during the relay phase.
    drop(buf);

    let peer_addr = meta.peer_addr;

    // Authenticate user
    let user_id = match server.authenticator.authenticate(&request.password) {
        Some(id) => id,
        None => {
            log::authentication(peer_addr, false);
            log::debug!(
                peer = %peer_addr,
                transport = %meta.transport_type,
                "Invalid user credentials"
            );
            close_client(&mut stream).await;
            return Err(anyhow!("Invalid user credentials"));
        }
    };

    log::authentication(peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, "User authenticated");

    // Register connection for tracking and kick-off capability
    let (conn_id, cancel_token) = server.conn_manager.register(user_id);
    log::debug!(peer = %peer_addr, user_id = user_id, conn_id = conn_id, "Connection registered");

    // Ensure connection is unregistered when done
    let _guard = scopeguard::guard((), |_| {
        server.conn_manager.unregister(conn_id);
        log::debug!(conn_id = conn_id, "Connection unregistered");
    });

    // Record proxy request
    server.stats.record_request(user_id);

    match request.cmd {
        TrojanCmd::Connect => {
            handle_connect(
                server,
                stream,
                request.addr,
                request.payload,
                meta,
                user_id,
                cancel_token,
            )
            .await
        }
        TrojanCmd::UdpAssociate => {
            handle_udp_associate(
                server,
                stream,
                request.payload,
                peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
    }
}

/// Handle TCP CONNECT command
async fn handle_connect(
    server: &Server,
    client_stream: TransportStream,
    target: Address,
    initial_payload: bytes::Bytes,
    meta: ConnectionMeta,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    let peer_addr = meta.peer_addr;
    // Route the connection (passing Address directly avoids string allocation)
    let outbound_type = server.router.route(&target).await;
    log::debug!(peer = %peer_addr, target = %target, outbound = ?outbound_type, "Routed");

    let ctx = ConnectContext {
        server,
        client_stream,
        target,
        initial_payload,
        peer_addr,
        user_id,
        cancel_token,
        transport_type: meta.transport_type,
    };

    match outbound_type {
        hooks::OutboundType::Direct { resolved, handler } => {
            handle_direct_connect(ctx, resolved, handler).await
        }
        hooks::OutboundType::Proxy { handler, hijack } => {
            handle_proxy_connect(ctx, handler, hijack).await
        }
        hooks::OutboundType::Reject => {
            log::debug!(peer = %peer_addr, target = %ctx.target, "Connection rejected by router");
            let mut client_stream = ctx.client_stream;
            close_client(&mut client_stream).await;
            Ok(())
        }
    }
}

/// Context for handling outbound connections
struct ConnectContext<'a> {
    server: &'a Server,
    client_stream: TransportStream,
    target: Address,
    initial_payload: bytes::Bytes,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
    transport_type: TransportType,
}

impl ConnectContext<'_> {
    /// Relay data between client and remote with stats tracking
    async fn relay<S>(self, mut remote_stream: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Only a plain/TLS TCP transport can half-close (FIN) when the remote
        // finishes; a WebSocket Close frame or gRPC trailers would cut the
        // client's remaining upload, so there the relay only flushes and the
        // transport is closed once the whole session is over (as Xray does).
        let mut client_stream =
            NoHalfClose::new(self.client_stream, self.transport_type.half_close());

        // Write initial payload if any
        if !self.initial_payload.is_empty() {
            self.server
                .stats
                .record_upload(self.user_id, self.initial_payload.len() as u64);
            if let Err(e) = remote_stream.write_all(&self.initial_payload).await {
                close_client(client_stream.inner_mut()).await;
                return Err(e.into());
            }
        }

        // Relay data with stats tracking and cancellation support.
        // Pass &mut so streams aren't moved into the future — this allows
        // graceful shutdown even when cancel_token drops the relay future.
        let stats = Arc::clone(&self.server.stats);
        let relay_fut = copy_bidirectional_with_stats(
            &mut client_stream,
            &mut remote_stream,
            self.server.conn_config.idle_timeout_secs(),
            self.server.conn_config.uplink_only_timeout_secs(),
            self.server.conn_config.downlink_only_timeout_secs(),
            self.server.conn_config.buffer_size,
            Some((self.user_id, stats)),
        );

        let relay_start = std::time::Instant::now();
        let target = &self.target;
        let cancelled = tokio::select! {
            result = relay_fut => {
                let duration = relay_start.elapsed().as_secs();
                match result {
                    Ok(r) => log::debug!(peer = %self.peer_addr, target = %target, up = r.a_to_b, down = r.b_to_a, duration_secs = duration, termination = %r.termination, client_eof = r.client_eof, remote_eof = r.remote_eof, "Relay done"),
                    Err(e) => log::debug!(peer = %self.peer_addr, target = %target, duration_secs = duration, error = %e, "Relay error"),
                }
                false
            }
            _ = self.cancel_token.cancelled() => {
                log::debug!(peer = %self.peer_addr, "Connection kicked");
                true
            }
        };

        // Close the client transport once the session is over (the relay may
        // only have half-closed, or not closed at all on WS/gRPC).
        close_client(client_stream.inner_mut()).await;
        if cancelled {
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, remote_stream.shutdown()).await;
        }

        Ok(())
    }
}

/// Build the ACL address for a target, attaching the addresses the router
/// already resolved (both families) so the outbound's address-family mode
/// (only6 / prefer6 / auto) is honoured without a second lookup.
fn acl_addr_for(target: &Address, resolved: Option<ResolvedAddrs>) -> acl::Addr {
    let addr = acl::Addr::new(target.host().into_owned(), target.port());
    match resolved {
        Some(r) => addr.with_resolve_info(acl::ResolveInfo {
            ipv4: r.v4,
            ipv6: r.v6,
            error: None,
        }),
        None => addr,
    }
}

/// Handle direct connection
async fn handle_direct_connect(
    mut ctx: ConnectContext<'_>,
    resolved: Option<ResolvedAddrs>,
    handler: Option<Arc<acl::OutboundHandler>>,
) -> Result<()> {
    // When handler is present (ACL configured), use it for bind/fastOpen support
    if let Some(handler) = handler {
        return dial_via_handler(ctx, handler, resolved, "direct").await;
    }

    // Fast path: no ACL handler, plain TcpStream::connect with keepalive/nodelay.
    // Candidates in resolver-preference order; the other family is the
    // fallback so a dual-stack target reachable over one family only still
    // connects (sequential, each attempt bounded by connect_timeout).
    let resolved = match resolved {
        Some(addr) => addr,
        None => match crate::core::dns::resolve_addrs(&ctx.server.dns_cache, &ctx.target).await {
            Ok(r) => r,
            Err(e) => {
                log::debug!(peer = %ctx.peer_addr, target = %ctx.target, error = %e, "DNS resolution failed");
                close_client(&mut ctx.client_stream).await;
                return Err(e.into());
            }
        },
    };
    let candidates: Vec<SocketAddr> = resolved.candidates().collect();
    let mut last_err: Option<anyhow::Error> = None;
    let mut connected: Option<(TcpStream, SocketAddr)> = None;
    for remote_addr in candidates {
        match tokio::time::timeout(
            ctx.server.conn_config.connect_timeout,
            TcpStream::connect(remote_addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                crate::net::tune_tcp_stream(&stream, ctx.server.conn_config.tcp_nodelay);
                connected = Some((stream, remote_addr));
                break;
            }
            Ok(Err(e)) => {
                log::debug!(peer = %ctx.peer_addr, remote = %remote_addr, error = %e, "TCP connect failed");
                last_err = Some(e.into());
            }
            Err(_) => {
                log::debug!(peer = %ctx.peer_addr, remote = %remote_addr, "TCP connect timeout");
                last_err = Some(anyhow!("TCP connect timeout"));
            }
        }
    }
    let Some((remote_stream, remote_addr)) = connected else {
        close_client(&mut ctx.client_stream).await;
        return Err(last_err.unwrap_or_else(|| anyhow!("no address to connect to")));
    };
    log::debug!(peer = %ctx.peer_addr, remote = %remote_addr, "Connected to remote (direct)");
    ctx.relay(remote_stream).await
}

/// Handle proxy connection via ACL engine outbound handler
async fn handle_proxy_connect(
    mut ctx: ConnectContext<'_>,
    handler: Arc<acl::OutboundHandler>,
    hijack: Option<std::net::IpAddr>,
) -> Result<()> {
    if let Some(ip) = hijack {
        // proxies dial by name: rewrite the destination the proxy is asked for
        ctx.target = Address::from_ip(ip, ctx.target.port());
    }
    dial_via_handler(ctx, handler, None, "proxy").await
}

/// Dial the target through an ACL outbound handler (direct-with-options or
/// proxy) under `connect_timeout`, then relay. `resolved` carries the
/// router's pre-resolved addresses for direct handlers (None for proxies,
/// which resolve remotely).
async fn dial_via_handler(
    mut ctx: ConnectContext<'_>,
    handler: Arc<acl::OutboundHandler>,
    resolved: Option<ResolvedAddrs>,
    kind: &'static str,
) -> Result<()> {
    use acl::AsyncOutbound;
    let mut acl_addr = acl_addr_for(&ctx.target, resolved);
    let remote_stream = match tokio::time::timeout(
        ctx.server.conn_config.connect_timeout,
        handler.dial_tcp(&mut acl_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            log::debug!(peer = %ctx.peer_addr, target = %ctx.target, kind, error = %e, "Outbound connect failed");
            close_client(&mut ctx.client_stream).await;
            return Err(anyhow!("{kind} connect failed: {e}"));
        }
        Err(_) => {
            log::debug!(peer = %ctx.peer_addr, target = %ctx.target, kind, "Outbound connect timeout");
            close_client(&mut ctx.client_stream).await;
            return Err(anyhow!("{kind} connect timeout"));
        }
    };
    log::debug!(peer = %ctx.peer_addr, target = %ctx.target, kind, handler = ?handler, "Connected to remote");
    ctx.relay(remote_stream).await
}

/// Maximum UDP read buffer size to prevent memory exhaustion
const UDP_MAX_READ_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Where a UDP packet goes: the outbound decision plus the address handed to
/// `write_to` (pre-resolved once per target, hijack applied).
struct UdpRoute {
    outbound: hooks::OutboundType,
    send_addr: acl::Addr,
}

/// Route one UDP target: protocol-aware ACL match, hijack address applied.
async fn route_udp_target(server: &Server, target: &Address) -> UdpRoute {
    let outbound = server.router.route_udp(target).await;
    let send_addr = match &outbound {
        hooks::OutboundType::Direct { resolved, .. } => acl_addr_for(target, *resolved),
        hooks::OutboundType::Proxy {
            hijack: Some(ip), ..
        } => acl_addr_for(&Address::from_ip(*ip, target.port()), None),
        _ => acl_addr_for(target, None),
    };
    UdpRoute {
        outbound,
        send_addr,
    }
}

/// Handle UDP ASSOCIATE command
async fn handle_udp_associate(
    server: &Server,
    mut client_stream: TransportStream,
    initial_payload: bytes::Bytes,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    use acl::{Addr as AclAddr, AsyncOutbound, AsyncUdpConn};
    use std::collections::HashMap;

    // Buffer for reading UDP packets from TCP stream (with size limit)
    let mut read_buf = BytesMut::with_capacity(8 * 1024); // Start with 8KB
    if !initial_payload.is_empty() {
        read_buf.extend_from_slice(&initial_payload);
    }

    // Per-session route cache: avoids repeated router.route() + DNS for the
    // same target and caches the AclAddr for write_to().
    let mut route_cache: HashMap<Address, Arc<UdpRoute>> = HashMap::new();

    // UDP relay loop
    let mut udp_recv_buf = vec![0u8; 65536];
    let mut udp_conn: Option<Box<dyn AsyncUdpConn>> = None;
    let mut current_handler: Option<Arc<acl::OutboundHandler>> = None;

    // Idle timeout tracking (same mechanism as TCP relay)
    let idle_timeout_secs = server.conn_config.idle_timeout_secs();
    let start_time = std::time::Instant::now();
    let mut last_activity_secs: u64 = 0;
    // Check at most every 30 s, but never coarser than the configured
    // timeout itself (validation guarantees >= 1 s).
    let mut idle_interval =
        tokio::time::interval(Duration::from_secs(idle_timeout_secs.clamp(1, 30)));
    let mut recv_errors: u32 = 0;
    let mut send_errors: u32 = 0;
    // The Trojan request header and the first UDP packet(s) often arrive in
    // one TLS record, so `initial_payload` can already hold a full packet. A
    // client then waits for the reply before sending more, so that buffered
    // packet must be processed before the first blocking read — otherwise the
    // session deadlocks.
    let mut pending_buffered = !read_buf.is_empty();

    loop {
        tokio::select! {
            // Read from client TCP stream directly into BytesMut (avoids temp buffer)
            result = async {
                if pending_buffered {
                    // Process what is already buffered before reading more.
                    return Ok(usize::MAX);
                }
                // Check buffer size limit before reading
                if read_buf.len() >= UDP_MAX_READ_BUFFER_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "UDP read buffer exceeded limit",
                    ));
                }
                read_buf.reserve(8 * 1024);
                client_stream.read_buf(&mut read_buf).await
            } => {
                pending_buffered = false;
                match result {
                    // Sentinel: buffered data to process, no read performed.
                    Ok(usize::MAX) => {}
                    Ok(0) => {
                        log::debug!(peer = %peer_addr, "UDP client disconnected");
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::OutOfMemory {
                            log::warn!(
                                peer = %peer_addr,
                                buffer_size = read_buf.len(),
                                "UDP read buffer exceeded limit, closing connection"
                            );
                        } else {
                            log::debug!(peer = %peer_addr, error = %e, "UDP read error");
                        }
                        break;
                    }
                };

                // Process all complete UDP packets in buffer (zero-copy)
                let mut give_up = false;
                while !read_buf.is_empty() {
                    match TrojanUdpPacket::decode_zerocopy(&mut read_buf) {
                        DecodeResult::Ok(packet, _consumed) => {
                            // Route the packet (cached per target: no repeated DNS or String allocs)
                            let route = match route_cache.get(&packet.addr) {
                                Some(cached) => Arc::clone(cached),
                                None => {
                                    let route = Arc::new(route_udp_target(server, &packet.addr).await);
                                    // Evict all entries when cache is full to bound memory
                                    if route_cache.len() >= UDP_MAX_ROUTE_CACHE_ENTRIES {
                                        route_cache.clear();
                                    }
                                    route_cache.insert(packet.addr.clone(), Arc::clone(&route));
                                    route
                                }
                            };
                            let send_addr = &route.send_addr;

                            match &route.outbound {
                                hooks::OutboundType::Reject => {
                                    log::debug!(peer = %peer_addr, target = %packet.addr, "UDP packet rejected by router");
                                    continue;
                                }
                                hooks::OutboundType::Direct { handler, .. } => {
                                    // One direct socket serves every direct target;
                                    // (re)create it after a proxy association.
                                    if udp_conn.is_none() || current_handler.is_some() {
                                        drop(udp_conn.take());
                                        current_handler = None;

                                        // Use ACL handler if available (respects bind options),
                                        // otherwise fall back to default Direct
                                        let dial_handler: Arc<acl::OutboundHandler> = handler
                                            .clone()
                                            .unwrap_or_else(default_direct_handler);
                                        let mut dial_addr = send_addr.clone();
                                        match dial_handler.dial_udp(&mut dial_addr).await {
                                            Ok(conn) => {
                                                udp_conn = Some(conn);
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "Failed to create direct UDP connection");
                                                continue;
                                            }
                                        }
                                    }
                                }
                                hooks::OutboundType::Proxy { handler, .. } => {
                                    // Check if handler supports UDP
                                    if !handler.allows_udp() {
                                        log::debug!(peer = %peer_addr, target = %packet.addr, "UDP not allowed by outbound handler");
                                        continue;
                                    }

                                    // Create new UDP connection if handler changed or not exists
                                    let need_new_conn = match &current_handler {
                                        None => true,
                                        Some(h) => !Arc::ptr_eq(h, handler),
                                    };

                                    if need_new_conn {
                                        drop(udp_conn.take());
                                        let mut dial_addr = send_addr.clone();
                                        match handler.dial_udp(&mut dial_addr).await {
                                            Ok(conn) => {
                                                udp_conn = Some(conn);
                                                current_handler = Some(handler.clone());
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "Failed to create proxy UDP connection");
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }

                            // Send UDP packet using the cached AclAddr
                            if let Some(ref conn) = udp_conn {
                                match conn.write_to(&packet.payload, send_addr).await {
                                    Ok(n) => {
                                        // Only a datagram actually forwarded counts as activity.
                                        last_activity_secs = start_time.elapsed().as_secs();
                                        send_errors = 0;
                                        server.stats.record_upload(user_id, n as u64);
                                        log::trace!(peer = %peer_addr, target = %packet.addr, bytes = n, "UDP packet sent");
                                    }
                                    Err(e) => {
                                        // A destination the outbound can never reach (no
                                        // address for its family, dead proxy) fails every
                                        // send; do not let the client keep such a session
                                        // alive by retrying.
                                        send_errors += 1;
                                        log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, consecutive = send_errors, "UDP send error");
                                        if send_errors >= UDP_MAX_CONSECUTIVE_ERRORS {
                                            give_up = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        DecodeResult::NeedMoreData => break,
                        DecodeResult::Invalid(msg) => {
                            log::debug!(peer = %peer_addr, error = %msg, "Invalid UDP packet");
                            // The stream is out of sync: nothing after this byte
                            // can be framed again (Xray closes the session too).
                            give_up = true;
                            break;
                        }
                    }
                }
                if give_up {
                    break;
                }
            }

            // Read from UDP connection (if exists), reusing pre-allocated buffer
            result = async {
                if let Some(ref conn) = udp_conn {
                    conn.read_from(&mut udp_recv_buf).await
                } else {
                    // No UDP connection, wait forever
                    std::future::pending::<acl_engine_rs::Result<(usize, AclAddr)>>().await
                }
            } => {
                match result {
                    Ok((n, from_addr)) => {
                        // Convert AclAddr back to Address
                        let addr = acl_addr_to_address(&from_addr);

                        // Encode and send back to client. Flush: on WebSocket the
                        // frame would otherwise sit in tungstenite's write buffer
                        // until 32 KiB accumulate, and a single reply never leaves.
                        // Bounded: awaiting inside the arm suspends the whole
                        // select! (idle timer, kick token), so a client that stops
                        // reading must not pin this session indefinitely.
                        let response = TrojanUdpPacket::encode(&addr, &udp_recv_buf[..n]);
                        let written = tokio::time::timeout(UDP_WRITE_TIMEOUT, async {
                            client_stream.write_all(&response).await?;
                            client_stream.flush().await
                        })
                        .await;
                        match written {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                log::debug!(peer = %peer_addr, error = %e, "Failed to write UDP response");
                                break;
                            }
                            Err(_) => {
                                log::debug!(peer = %peer_addr, "UDP client write stalled, closing session");
                                break;
                            }
                        }
                        // Only a datagram actually delivered counts as activity.
                        last_activity_secs = start_time.elapsed().as_secs();
                        recv_errors = 0;
                        server.stats.record_download(user_id, n as u64);
                        log::trace!(peer = %peer_addr, from = %from_addr, bytes = n, "UDP packet received");
                    }
                    Err(e) => {
                        // A dead outbound (proxy UDP association gone) fails every read
                        // instantly; give up after a few in a row instead of spinning.
                        recv_errors += 1;
                        log::debug!(peer = %peer_addr, error = %e, consecutive = recv_errors, "UDP recv error");
                        if recv_errors >= UDP_MAX_CONSECUTIVE_ERRORS {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }

            // Idle timeout check
            _ = idle_interval.tick() => {
                let idle_secs = start_time.elapsed().as_secs().saturating_sub(last_activity_secs);
                if idle_secs >= idle_timeout_secs {
                    log::debug!(peer = %peer_addr, idle_secs = idle_secs, "UDP connection idle timeout");
                    break;
                }
            }

            // Handle cancellation
            _ = cancel_token.cancelled() => {
                log::debug!(peer = %peer_addr, "UDP connection kicked by admin");
                break;
            }
        }
    }

    // Bounded like the TCP path: a stalled client with a full send buffer must
    // not pin the task, its connection permit and its ConnectionManager entry.
    close_client(&mut client_stream).await;

    Ok(())
}

/// Shared default `Direct` outbound for UDP sessions without an ACL handler.
fn default_direct_handler() -> Arc<acl::OutboundHandler> {
    static DEFAULT: std::sync::OnceLock<Arc<acl::OutboundHandler>> = std::sync::OnceLock::new();
    Arc::clone(
        DEFAULT
            .get_or_init(|| Arc::new(acl::OutboundHandler::Direct(Arc::new(acl::Direct::new())))),
    )
}

/// Convert AclAddr to Address
fn acl_addr_to_address(addr: &acl::Addr) -> Address {
    match addr.host().parse::<std::net::IpAddr>() {
        Ok(ip) => Address::from_ip(ip, addr.port()),
        Err(_) => Address::Domain(addr.host().to_string(), addr.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acl::Addr as AclAddr;

    #[test]
    fn test_acl_addr_to_address_ipv4() {
        let acl_addr = AclAddr::new("192.168.1.1", 8080);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::IPv4([192, 168, 1, 1], 8080)));
    }

    #[test]
    fn test_acl_addr_to_address_ipv6() {
        let acl_addr = AclAddr::new("::1", 443);
        let addr = acl_addr_to_address(&acl_addr);
        match addr {
            Address::IPv6(ip, port) => {
                assert_eq!(port, 443);
                assert_eq!(ip, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
            _ => panic!("Expected IPv6 address"),
        }
    }

    #[test]
    fn test_acl_addr_to_address_ipv6_full() {
        let acl_addr = AclAddr::new("2001:db8::1", 80);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::IPv6(_, 80)));
    }

    #[test]
    fn test_acl_addr_to_address_domain() {
        let acl_addr = AclAddr::new("example.com", 80);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::Domain(ref d, 80) if d == "example.com"));
    }

    #[test]
    fn test_keepalive_and_shutdown_constants() {
        assert_eq!(crate::net::TCP_KEEPALIVE_SECS, 15);
        assert_eq!(SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(5));
        assert!(CLOSE_TIMEOUT < SHUTDOWN_TIMEOUT);
    }

    #[test]
    fn test_acl_addr_to_address_domain_with_subdomain() {
        let acl_addr = AclAddr::new("sub.example.com", 443);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::Domain(ref d, 443) if d == "sub.example.com"));
    }

    /// Build a valid Trojan CONNECT request as raw bytes
    fn build_trojan_request(password: &[u8; 56], addr: &Address, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(password);
        buf.extend_from_slice(b"\r\n");
        buf.push(1); // CONNECT
        addr.encode(&mut buf);
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(payload);
        buf
    }

    #[tokio::test]
    async fn test_read_trojan_request_complete_in_one_read() {
        let password = [b'a'; 56];
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let raw = build_trojan_request(&password, &addr, b"hello");

        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(raw));
        let mut buf = BytesMut::with_capacity(1024);

        let req = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(req.password, password);
        assert_eq!(req.cmd, TrojanCmd::Connect);
        assert!(matches!(req.addr, Address::IPv4([127, 0, 0, 1], 8080)));
        assert_eq!(req.payload.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn test_read_trojan_request_empty_connection() {
        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(Vec::new()));
        let mut buf = BytesMut::with_capacity(1024);

        let err = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("closed before receiving"),
            "Expected 'closed before receiving' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_trojan_request_incomplete_connection() {
        // Send partial password then EOF
        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(vec![b'a'; 30]));
        let mut buf = BytesMut::with_capacity(1024);

        let err = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("incomplete request"),
            "Expected 'incomplete request' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_trojan_request_too_large() {
        // Craft a request that looks like it needs more data (valid password + CRLF
        // + valid command + domain ATYP with large length), so the parser keeps
        // reading until the buffer exceeds the size limit.
        let buffer_size = 128;
        let mut data = Vec::new();
        data.extend_from_slice(&[b'a'; 56]); // valid password
        data.extend_from_slice(b"\r\n"); // valid first CRLF
        data.push(1); // CONNECT
        data.push(3); // ATYP_DOMAIN
        data.push(255); // domain length = 255 (will need more data to complete)
                        // Feed enough to exceed buffer_size * 2 without ever completing the domain
        data.extend_from_slice(&vec![b'x'; buffer_size * 2]);

        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(data));
        let mut buf = BytesMut::with_capacity(buffer_size);

        let err = read_trojan_request(&mut stream, &mut buf, buffer_size)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "Expected 'too large' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_trojan_request_no_payload() {
        let password = [b'z'; 56];
        let addr = Address::Domain("example.com".to_string(), 443);
        let raw = build_trojan_request(&password, &addr, b"");

        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(raw));
        let mut buf = BytesMut::with_capacity(1024);

        let req = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(req.password, password);
        assert!(matches!(
            req.addr,
            Address::Domain(ref d, 443) if d == "example.com"
        ));
        assert!(req.payload.is_empty());
    }

    /// Verify that reusing a pre-allocated buffer for UDP recv produces correct
    /// TrojanUdpPacket encoding — stale data beyond `n` bytes must not leak
    /// into the encoded packet.
    #[test]
    fn test_udp_recv_buf_reuse_no_stale_data() {
        // Simulate a reused 64KB buffer (like udp_recv_buf in handle_udp_associate)
        let mut recv_buf = vec![0xFFu8; 65536]; // filled with 0xFF "stale" data

        // --- First "read": 5 bytes ---
        let data1 = b"hello";
        recv_buf[..data1.len()].copy_from_slice(data1);
        let n1 = data1.len();

        let addr1 = Address::IPv4([8, 8, 8, 8], 53);
        let encoded1 = TrojanUdpPacket::encode(&addr1, &recv_buf[..n1]);

        // Decode and verify only "hello" is in the payload, no stale 0xFF
        match TrojanUdpPacket::decode(&encoded1) {
            DecodeResult::Ok(pkt, _) => {
                assert_eq!(pkt.payload.as_ref(), b"hello");
                assert_eq!(pkt.payload.len(), 5);
            }
            _ => panic!("Failed to decode first packet"),
        }

        // --- Second "read": 3 bytes (shorter than first) ---
        // Bytes 3..5 still contain 'l','o' from the first read — stale data
        let data2 = b"bye";
        recv_buf[..data2.len()].copy_from_slice(data2);
        let n2 = data2.len();

        let addr2 = Address::Domain("dns.example.com".to_string(), 53);
        let encoded2 = TrojanUdpPacket::encode(&addr2, &recv_buf[..n2]);

        match TrojanUdpPacket::decode(&encoded2) {
            DecodeResult::Ok(pkt, _) => {
                // Must be "bye" only, NOT "byelo" or anything longer
                assert_eq!(pkt.payload.as_ref(), b"bye");
                assert_eq!(pkt.payload.len(), 3);
            }
            _ => panic!("Failed to decode second packet"),
        }

        // --- Third "read": large payload ---
        let data3 = vec![0xABu8; 1024];
        recv_buf[..data3.len()].copy_from_slice(&data3);
        let n3 = data3.len();

        let addr3 = Address::IPv4([1, 1, 1, 1], 443);
        let encoded3 = TrojanUdpPacket::encode(&addr3, &recv_buf[..n3]);

        match TrojanUdpPacket::decode(&encoded3) {
            DecodeResult::Ok(pkt, _) => {
                assert_eq!(pkt.payload.len(), 1024);
                assert!(pkt.payload.iter().all(|&b| b == 0xAB));
            }
            _ => panic!("Failed to decode third packet"),
        }
    }
}
