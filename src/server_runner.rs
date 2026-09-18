//! Server startup and accept loop
//!
//! This module handles server initialization, transport configuration,
//! and the main connection accept loop.

use crate::acl;
use crate::config;
use crate::core::{hooks, Server};
use crate::handler::process_connection;
use crate::logger::log;
use crate::transport::{ConnectionMeta, TransportStream, TransportType};
use dns_cache_rs::DnsCache;

use anyhow::{anyhow, Result};
use std::sync::Arc;

/// ALPN protocols to advertise for a transport when TLS is enabled.
pub fn alpn_for_transport(transport_type: TransportType) -> &'static [&'static [u8]] {
    match transport_type {
        TransportType::Grpc => &[b"h2"],
        TransportType::WebSocket => &[b"http/1.1"],
        TransportType::Tcp => &[],
    }
}

/// Load the TLS server config for `config`, or `None` when TLS is disabled.
/// Called from `main` before node registration so a bad PEM fails fast.
pub fn load_tls(config: &config::ServerConfig) -> Result<Option<Arc<rustls::ServerConfig>>> {
    use crate::transport::TlsTransportListener;
    let (transport_type, has_tls) = build_transport_config(config);
    if !has_tls {
        return Ok(None);
    }
    let tls_config = TlsTransportListener::load_tls_config(
        config.cert.as_ref().unwrap(),
        config.key.as_ref().unwrap(),
        alpn_for_transport(transport_type),
    )?;
    Ok(Some(tls_config))
}

/// Inbound WebSocket frames are sized by the client's Trojan writer (Xray:
/// ≤ 8 KiB + AEAD overhead per message), not by our relay buffer, so the
/// accept limits have a floor independent of `--buffer_size`.
const WS_MIN_MAX_FRAME: usize = 64 * 1024;
const WS_MIN_MAX_MESSAGE: usize = 256 * 1024;

/// tungstenite limits: write buffers follow the relay buffer size (bounded
/// per connection, default max is usize::MAX); read limits are bounded but
/// never below what a compliant client sends.
pub fn ws_config_for(buf_size: usize) -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    let max_frame = (buf_size * 2).max(WS_MIN_MAX_FRAME);
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .write_buffer_size(buf_size)
        // tungstenite requires write_buffer_size + one full message, else
        // start_send fails with WriteBufferFull once the relay is backed up.
        .max_write_buffer_size(buf_size + max_frame + 16)
        .max_message_size(Some((buf_size * 4).max(WS_MIN_MAX_MESSAGE)))
        .max_frame_size(Some(max_frame))
}

/// Build transport configuration from server config
pub fn build_transport_config(config: &config::ServerConfig) -> (TransportType, bool) {
    let transport_type = if config.enable_grpc {
        TransportType::Grpc
    } else if config.enable_ws {
        TransportType::WebSocket
    } else {
        TransportType::Tcp
    };

    let has_tls = config.cert.is_some() && config.key.is_some();

    (transport_type, has_tls)
}

/// Build outbound router from ACL configuration
pub async fn build_router(
    config: &config::ServerConfig,
    refresh_geodata: bool,
    dns_cache: DnsCache,
) -> Result<Arc<dyn hooks::OutboundRouter>> {
    use crate::acl::AclRouter;

    // Existence and .yaml/.yml extension were already checked by CliArgs::validate.
    if let Some(ref acl_path) = config.acl_conf_file {
        let acl_config = acl::load_acl_config(acl_path).await?;
        let engine =
            acl::AclEngine::new(acl_config, Some(config.data_dir.as_path()), refresh_geodata)
                .await?;

        log::info!(
            acl_file = %acl_path.display(),
            rules = engine.rule_count(),
            block_private_ip = config.block_private_ip,
            refresh_geodata = refresh_geodata,
            "ACL router loaded"
        );

        Ok(Arc::new(AclRouter::with_cache(
            engine,
            config.block_private_ip,
            dns_cache,
        )) as Arc<dyn hooks::OutboundRouter>)
    } else {
        log::info!(
            block_private_ip = config.block_private_ip,
            "No ACL config, using direct connection for all traffic"
        );
        Ok(Arc::new(hooks::DirectRouter::with_cache(
            config.block_private_ip,
            dns_cache,
        )) as Arc<dyn hooks::OutboundRouter>)
    }
}

/// Network settings for transport layer
#[derive(Clone)]
pub struct NetworkSettings {
    /// gRPC service name (path becomes "/${service_name}/Tun")
    pub grpc_service_name: String,
    /// WebSocket path
    pub ws_path: String,
}

/// Accept and handle a connection with proper transport wrapping
pub async fn accept_connection<S>(
    server: Arc<Server>,
    stream: S,
    peer_addr: std::net::SocketAddr,
    transport_type: TransportType,
    network_settings: Arc<NetworkSettings>,
    conn_limiter: Option<Arc<tokio::sync::Semaphore>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use crate::transport::GrpcConnection;

    match transport_type {
        TransportType::Grpc => {
            log::debug!(peer = %peer_addr, "gRPC connection established, waiting for streams");
            // Bound the HTTP/2 preface/SETTINGS exchange like the WS and TLS
            // handshakes: a silent peer must not hold a connection permit forever.
            let grpc_conn = tokio::time::timeout(
                server.conn_config.request_timeout,
                GrpcConnection::with_config(
                    stream,
                    &network_settings.grpc_service_name,
                    server.conn_config.buffer_size,
                    server.conn_config.idle_timeout,
                ),
            )
            .await
            .map_err(|_| {
                log::debug!(peer = %peer_addr, stage = "h2_timeout", "Connection failed");
                anyhow!("HTTP/2 handshake timeout")
            })??;
            let result = grpc_conn
                .run(move |grpc_transport| {
                    let server = Arc::clone(&server);
                    let limiter = conn_limiter.clone();
                    async move {
                        // One H2 connection multiplexes up to 100 Trojan sessions;
                        // each one is a relay with its own outbound socket and
                        // buffers, so each takes a max_connections permit (the
                        // connection itself already holds one). At capacity the
                        // stream is refused instead of stalling the whole H2 link.
                        let _stream_permit = match limiter {
                            Some(l) => match l.try_acquire_owned() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    log::debug!(peer = %peer_addr, "gRPC stream refused: max_connections reached");
                                    return Err(anyhow!("max_connections reached"));
                                }
                            },
                            None => None,
                        };
                        let stream: TransportStream = Box::pin(grpc_transport);
                        let meta = ConnectionMeta {
                            peer_addr,
                            transport_type: TransportType::Grpc,
                        };
                        process_connection(&server, stream, meta).await
                    }
                })
                .await;

            match &result {
                Ok(()) => {
                    log::debug!(peer = %peer_addr, "gRPC connection closed normally");
                }
                Err(e) => {
                    log::debug!(peer = %peer_addr, error = %e, "gRPC connection closed with error");
                }
            }
            result
        }
        TransportType::WebSocket => {
            // Limit tungstenite internal buffers to prevent unbounded memory growth.
            // At 50k connections, tungstenite's defaults (write_buffer_size=128KB,
            // max_write_buffer_size=usize::MAX) would allow tens of GB total.
            // Our WebSocketTransport layer handles backpressure via Poll::Pending,
            // but tungstenite's own buffers must also be bounded.
            let ws_config = ws_config_for(server.conn_config.buffer_size);

            // WebSocket handshake with path validation, early data and timeout.
            let ws_transport = tokio::time::timeout(
                server.conn_config.request_timeout,
                crate::transport::ws::accept(stream, &network_settings.ws_path, ws_config),
            )
            .await
            .map_err(|_| {
                log::debug!(peer = %peer_addr, stage = "ws_timeout", "Connection failed");
                anyhow!("WebSocket handshake timeout")
            })??;
            let stream: TransportStream = Box::pin(ws_transport);
            let meta = ConnectionMeta {
                peer_addr,
                transport_type: TransportType::WebSocket,
            };
            process_connection(&server, stream, meta).await
        }
        TransportType::Tcp => {
            let stream: TransportStream = Box::pin(stream);
            let meta = ConnectionMeta {
                peer_addr,
                transport_type: TransportType::Tcp,
            };
            process_connection(&server, stream, meta).await
        }
    }
}

/// Run the server accept loop
///
/// `tls` is the config produced by [`load_tls`] (validated in `main` before
/// the node registers); `None` when the panel disabled TLS.
pub async fn run_server(
    server: Arc<Server>,
    config: &config::ServerConfig,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    use tokio::sync::Semaphore;

    let (transport_type, _) = build_transport_config(config);
    let has_tls = tls.is_some();

    // Connection limiter: 0 = unlimited
    let conn_limiter = if server.conn_config.max_connections > 0 {
        Some(Arc::new(Semaphore::new(server.conn_config.max_connections)))
    } else {
        None
    };

    // Build TLS acceptor if needed
    let tls_acceptor = tls.map(tokio_rustls::TlsAcceptor::from);

    // Bind TCP listener with IPv4+IPv6 dual-stack support
    let listener = crate::net::bind_dual_stack(config.port, server.conn_config.tcp_backlog)?;
    let local_addr = listener.local_addr()?;

    // Build network settings from config (Arc-wrapped to avoid per-connection String clones)
    let network_settings = Arc::new(NetworkSettings {
        grpc_service_name: config.grpc_service_name.clone(),
        ws_path: config.ws_path.clone(),
    });

    log::info!(
        address = %local_addr,
        transport = %transport_type,
        tls = has_tls,
        max_connections = server.conn_config.max_connections,
        ws_path = %network_settings.ws_path,
        grpc_service = %network_settings.grpc_service_name,
        "Server started"
    );

    // Housekeeping every 60 s: report DNS cache effectiveness.
    {
        let dns_cache = server.dns_cache.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await; // first tick fires immediately; nothing to do yet
            loop {
                tick.tick().await;
                let dns = dns_cache.stats();
                log::debug!(
                    dns_hits = dns.hits,
                    dns_misses = dns.misses,
                    dns_negative_hits = dns.negative_hits,
                    "Housekeeping"
                );
            }
        });
    }

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let peer_addr = addr;
                log::connection(peer_addr, "new");

                // Acquire connection permit (backpressure when at limit)
                let _permit = if let Some(ref limiter) = conn_limiter {
                    match limiter.clone().acquire_owned().await {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            // Semaphore closed, shutting down
                            break;
                        }
                    }
                } else {
                    None
                };

                let server = Arc::clone(&server);
                let limiter = conn_limiter.clone();
                let tls_acceptor = tls_acceptor.clone();
                let network_settings = Arc::clone(&network_settings);

                tokio::spawn(async move {
                    // Hold permit for the lifetime of this connection
                    let _permit = _permit;
                    let result = async {
                        crate::net::tune_tcp_stream(&stream, server.conn_config.tcp_nodelay);

                        if let Some(tls_acceptor) = tls_acceptor {
                            // TLS handshake with timeout
                            match tokio::time::timeout(
                                server.conn_config.tls_handshake_timeout,
                                tls_acceptor.accept(stream),
                            )
                            .await
                            {
                                Ok(Ok(tls_stream)) => {
                                    accept_connection(server, tls_stream, peer_addr, transport_type, network_settings, limiter).await
                                }
                                Ok(Err(e)) => {
                                    log::debug!(peer = %peer_addr, error = %e, stage = "tls", "Connection failed");
                                    Err(anyhow!("TLS handshake failed: {}", e))
                                }
                                Err(_) => {
                                    log::debug!(peer = %peer_addr, stage = "tls_timeout", "Connection failed");
                                    Err(anyhow!("TLS handshake timeout"))
                                }
                            }
                        } else {
                            accept_connection(server, stream, peer_addr, transport_type, network_settings, limiter).await
                        }
                    }
                    .await;

                    if let Err(e) = result {
                        log::debug!(peer = %peer_addr, error = %e, "Connection error");
                    }
                    log::connection(peer_addr, "closed");
                });
            }
            Err(e) => {
                // EMFILE/ENFILE/ECONNABORTED are transient; back off so an
                // exhausted fd table does not turn the accept loop into a
                // busy loop (std never yields ErrorKind::Other for OS errors,
                // so there is no reliable "fatal" kind to break on).
                log::error!(error = %e, "Failed to accept connection");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn test_conn_limiter_backpressure() {
        // Simulate max_connections = 2
        let limiter = Arc::new(Semaphore::new(2));

        // Acquire 2 permits (simulates 2 active connections)
        let permit1 = limiter.clone().acquire_owned().await.unwrap();
        let permit2 = limiter.clone().acquire_owned().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);

        // 3rd acquire should block — verify with try_acquire
        assert!(limiter.try_acquire().is_err());

        // Drop one permit (connection closes) -> slot freed
        drop(permit1);
        assert_eq!(limiter.available_permits(), 1);

        // Now a new connection can acquire
        let _permit3 = limiter.clone().acquire_owned().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);

        drop(permit2);
        drop(_permit3);
        assert_eq!(limiter.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_conn_limiter_unlimited_when_none() {
        // max_connections = 0 -> conn_limiter is None -> no limit
        let max_connections: usize = 0;
        let conn_limiter: Option<Arc<Semaphore>> = if max_connections > 0 {
            Some(Arc::new(Semaphore::new(max_connections)))
        } else {
            None
        };

        assert!(conn_limiter.is_none());
    }

    #[tokio::test]
    async fn test_conn_limiter_permit_moved_into_task() {
        let limiter = Arc::new(Semaphore::new(1));
        let limiter_clone = limiter.clone();

        // Simulate: acquire in accept loop, move into spawned task
        let handle = tokio::spawn(async move {
            let _permit = limiter_clone.acquire_owned().await.unwrap();
            // Simulate connection work
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // _permit dropped here when task ends
        });

        // Give the task time to acquire
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(limiter.available_permits(), 0);

        // Wait for task to finish
        handle.await.unwrap();
        assert_eq!(limiter.available_permits(), 1);
    }

    #[test]
    fn test_ws_config_buffer_limits() {
        let buf_size: usize = 32 * 1024;
        let ws_config = super::ws_config_for(buf_size);

        // Write buffer matches configured buffer_size
        assert_eq!(ws_config.write_buffer_size, buf_size);
        // Max write buffer holds the write buffer plus one full frame and is bounded
        assert_eq!(
            ws_config.max_write_buffer_size,
            buf_size + buf_size * 2 + 16
        );
        assert!(ws_config.max_write_buffer_size < usize::MAX);

        // Message and frame sizes are bounded
        assert_eq!(ws_config.max_message_size, Some(super::WS_MIN_MAX_MESSAGE));
        assert_eq!(ws_config.max_frame_size, Some(buf_size * 2));

        // a small relay buffer must not shrink inbound limits below what
        // a Trojan client sends per WebSocket message
        let small = super::ws_config_for(4096);
        assert_eq!(small.max_frame_size, Some(super::WS_MIN_MAX_FRAME));
        assert_eq!(small.max_message_size, Some(super::WS_MIN_MAX_MESSAGE));
        assert!(small.max_write_buffer_size >= small.write_buffer_size + super::WS_MIN_MAX_FRAME);
    }

    #[test]
    fn test_tcp_keepalive_interval() {
        use crate::net::TCP_KEEPALIVE_SECS;
        // Match Go net.ListenConfig default: 15s keepalive
        assert_eq!(TCP_KEEPALIVE_SECS, 15);
        // 3 probes × 15s interval = ~45s detection time
        let detection_time = TCP_KEEPALIVE_SECS * 3;
        assert!(
            detection_time <= 60,
            "keepalive detection should be under 60s"
        );
    }

    #[test]
    fn test_ws_config_defaults_are_unbounded() {
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        // Verify that tungstenite defaults are indeed unbounded -
        // this is the root cause we're protecting against.
        let defaults = WebSocketConfig::default();
        assert_eq!(defaults.max_write_buffer_size, usize::MAX);
    }

    /// Arc<NetworkSettings> clone is an atomic refcount increment (no heap allocation),
    /// unlike NetworkSettings::clone() which clones two Strings per connection.
    #[test]
    fn test_network_settings_arc_clone_shares_data() {
        use super::NetworkSettings;

        let settings = Arc::new(NetworkSettings {
            grpc_service_name: "trojan-grpc".to_string(),
            ws_path: "/ws-secret-path".to_string(),
        });

        // Arc::clone only increments refcount — no String allocation
        let cloned = Arc::clone(&settings);
        assert!(Arc::ptr_eq(&settings, &cloned));
        assert_eq!(cloned.grpc_service_name, "trojan-grpc");
        assert_eq!(cloned.ws_path, "/ws-secret-path");

        // Strong count reflects sharing
        assert_eq!(Arc::strong_count(&settings), 2);
        drop(cloned);
        assert_eq!(Arc::strong_count(&settings), 1);
    }

    /// Default max_connections must be bounded to prevent accept loop death spiral.
    ///
    /// Bug: when max_connections=0 (old default), accept loop spawns tokio tasks
    /// without backpressure. At 45k+ tasks, new tasks queue in tokio's run queue
    /// and their timeouts never start (task not polled yet). Connections accumulate
    /// indefinitely → death spiral.
    ///
    /// Fix: the `auto` resolver always returns a positive value (`.max(1)`),
    /// and the `MaxConnections` parser rejects `0`, so a bounded semaphore is
    /// always created in practice.
    ///
    /// Hardware-independent guarantee: feed the pure `compute_auto` function
    /// a representative minimum production config (1 CPU, 1 GB RAM, the
    /// systemd default 65536 nofile) and assert the result is within a sane
    /// operational range — meaningfully bounded but not absurdly small.
    #[test]
    fn test_default_max_connections_prevents_death_spiral() {
        use crate::config_auto::{self, MaxConnections};

        // Real host smoke test: never zero, always usable.
        let resolved = config_auto::resolve(MaxConnections::Auto);
        assert!(
            resolved.value >= 1,
            "auto-resolved max_connections must be >= 1 to prevent death spiral"
        );

        // Hardware-independent floor for a minimum production node.
        // 1 CPU, 1 GB RAM, 65536 fd:
        //   cpu_cap = 1*1500*1000/200 = 7500
        //   mem_cap = 1024*1024*0.5/200 ≈ 2621  ← binds
        //   fd_cap  = (65536-1024)/2 = 32256
        let min_prod = config_auto::compute_auto(1, 1024 * 1024, 65_536);
        assert!(
            min_prod.value >= 2_000 && min_prod.value <= 10_000,
            "min production config must yield a sensible cap, got {}",
            min_prod.value
        );
    }

    /// When default (auto) max_connections is used, a semaphore must be created (not None).
    /// This is the key invariant that prevents the death spiral.
    #[tokio::test]
    async fn test_default_max_connections_creates_semaphore() {
        use crate::config_auto::{self, MaxConnections};

        let max_connections = config_auto::resolve(MaxConnections::Auto).value;
        let conn_limiter = if max_connections > 0 {
            Some(Arc::new(Semaphore::new(max_connections)))
        } else {
            None
        };

        assert!(
            conn_limiter.is_some(),
            "Default config must create a semaphore for backpressure"
        );
        assert_eq!(conn_limiter.unwrap().available_permits(), max_connections);
    }

    /// WS handshake must be wrapped in a timeout so that clients that complete
    /// TLS but never send the HTTP Upgrade request don't hang forever.
    #[tokio::test(start_paused = true)]
    async fn test_ws_handshake_timeout_fires() {
        // Simulate a peer that completes TLS but sends nothing (no WS upgrade).
        // We use a DuplexStream where the client side is immediately dropped,
        // but importantly the server side stays open — so read returns Pending,
        // not EOF. This mirrors a real slow-loris / scanner scenario.
        let (server_stream, _client_stream) = tokio::io::duplex(1024);

        let timeout_duration = std::time::Duration::from_secs(5);

        let start = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            timeout_duration,
            tokio_tungstenite::accept_async(server_stream),
        )
        .await;

        // Must be a timeout error, not a successful handshake
        assert!(result.is_err(), "Should timeout, not succeed");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= timeout_duration,
            "Should wait at least the timeout duration, elapsed={:?}",
            elapsed
        );
        // Should not wait much longer than the timeout
        assert!(
            elapsed < timeout_duration + std::time::Duration::from_secs(1),
            "Should not wait significantly longer than timeout, elapsed={:?}",
            elapsed
        );
    }
}
