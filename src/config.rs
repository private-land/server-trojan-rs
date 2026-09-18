//! Configuration module for Trojan server (Agent version)
//!
//! This module handles CLI argument parsing with environment variable support.
//! Configuration is fetched from panel API via connect-rpc (QUIC/H3).

use anyhow::{anyhow, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

use crate::business::{IpVersion, NodeConfigEnum};
use crate::config_auto::MaxConnections;

/// Parse IP version string (v4, v6, auto) into IpVersion enum
fn parse_ip_version(s: &str) -> Result<IpVersion, String> {
    match s.to_lowercase().as_str() {
        "v4" | "ipv4" | "4" => Ok(IpVersion::V4),
        "v6" | "ipv6" | "6" => Ok(IpVersion::V6),
        "auto" => Ok(IpVersion::Auto),
        _ => Err(format!(
            "Invalid IP version '{}'. Use 'v4', 'v6', or 'auto'",
            s
        )),
    }
}

/// Parse duration string (e.g., "60s", "2m", "1h") or plain seconds
fn parse_duration(s: &str) -> Result<Duration, String> {
    // Try parsing as humantime duration first (e.g., "60s", "2m", "1h30m")
    if let Ok(d) = humantime::parse_duration(s) {
        return Ok(d);
    }
    // Fall back to parsing as plain seconds for backwards compatibility
    s.parse::<u64>().map(Duration::from_secs).map_err(|_| {
        format!(
            "Invalid duration '{}'. Use formats like '60s', '2m', '1h' or plain seconds",
            s
        )
    })
}

/// Default data directory for state persistence
const DEFAULT_DATA_DIR: &str = "/var/lib/trojan-agent-node";

/// CLI arguments for the Trojan server (Agent version with gRPC)
///
/// Supports environment variables with X_PANDA_TROJAN_ prefix
#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "Trojan Server Agent with gRPC Panel Integration"
)]
#[command(rename_all = "snake_case")]
pub struct CliArgs {
    /// gRPC server host (e.g., "127.0.0.1")
    #[arg(
        long = "server_host",
        env = "X_PANDA_TROJAN_SERVER_HOST",
        default_value = "127.0.0.1"
    )]
    pub server_host: String,

    /// gRPC server port (e.g., 8082)
    #[arg(long = "port", env = "X_PANDA_TROJAN_PORT", default_value_t = 8082)]
    pub port: u16,

    /// Node ID from the panel (required)
    #[arg(long, env = "X_PANDA_TROJAN_NODE")]
    pub node: u32,

    /// TLS certificate file path (default: /root/.cert/server.crt)
    #[arg(
        long,
        env = "X_PANDA_TROJAN_CERT_FILE",
        default_value = "/root/.cert/server.crt"
    )]
    pub cert_file: String,

    /// TLS private key file path (default: /root/.cert/server.key)
    #[arg(
        long,
        env = "X_PANDA_TROJAN_KEY_FILE",
        default_value = "/root/.cert/server.key"
    )]
    pub key_file: String,

    /// Interval for fetching users (e.g., "60s", "2m", default: 60s)
    #[arg(long, env = "X_PANDA_TROJAN_FETCH_USERS_INTERVAL", default_value = "60s", value_parser = parse_duration)]
    pub fetch_users_interval: Duration,

    /// Interval for reporting traffic (e.g., "100s", "2m", default: 100s)
    #[arg(long, env = "X_PANDA_TROJAN_REPORT_TRAFFICS_INTERVAL", default_value = "100s", value_parser = parse_duration)]
    pub report_traffics_interval: Duration,

    /// Interval for sending heartbeat (e.g., "3m", "180s", default: 180s)
    #[arg(long, env = "X_PANDA_TROJAN_HEARTBEAT_INTERVAL", default_value = "180s", value_parser = parse_duration)]
    pub heartbeat_interval: Duration,

    /// gRPC API request timeout (e.g., "15s", default: 15s)
    #[arg(long = "api_timeout", env = "X_PANDA_TROJAN_API_TIMEOUT", default_value = "15s", value_parser = parse_duration)]
    pub api_timeout: Duration,

    /// TLS server name (SNI) for panel connection (defaults to --server_host)
    #[arg(
        long = "server_name",
        env = "X_PANDA_TROJAN_SERVER_NAME",
        value_name = "NAME"
    )]
    pub server_name: Option<String>,

    /// CA certificate path for panel TLS (omit for system trust store)
    #[arg(long = "ca_file", env = "X_PANDA_TROJAN_CA_FILE", value_name = "PATH")]
    pub ca_file: Option<String>,

    /// Log mode: debug, info, warn, error (default: info)
    #[arg(long, env = "X_PANDA_TROJAN_LOG_MODE", default_value = "info")]
    pub log_mode: String,

    /// Data directory for state persistence (default: /var/lib/trojan-agent-node)
    #[arg(long, env = "X_PANDA_TROJAN_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    pub data_dir: PathBuf,

    /// ACL config file for ACL and Outbounds (.yaml format)
    #[arg(long, env = "X_PANDA_TROJAN_ACL_CONF_FILE")]
    pub acl_conf_file: Option<PathBuf>,

    /// Block connections to private/loopback IP addresses (SSRF protection)
    #[arg(long, env = "X_PANDA_TROJAN_BLOCK_PRIVATE_IP", default_value_t = true)]
    pub block_private_ip: bool,

    /// Force refresh geoip and geosite databases on startup
    #[arg(
        long = "refresh_geodata",
        env = "X_PANDA_TROJAN_REFRESH_GEODATA",
        default_value_t = false
    )]
    pub refresh_geodata: bool,

    /// IP version for panel API connections: v4, v6, or auto (default: v4)
    #[arg(
        long = "panel_ip_version",
        env = "X_PANDA_TROJAN_PANEL_IP_VERSION",
        default_value = "v4",
        value_parser = parse_ip_version,
        help_heading = "Network"
    )]
    pub panel_ip_version: IpVersion,

    // ==================== Performance Tuning ====================
    /// Connection idle timeout - disconnect if no data transferred (default: 5m)
    #[arg(long, env = "X_PANDA_TROJAN_CONN_IDLE_TIMEOUT", default_value = "5m", value_parser = parse_duration, help_heading = "Performance")]
    pub conn_idle_timeout: Duration,

    /// TCP connect timeout to target server (default: 5s)
    #[arg(long, env = "X_PANDA_TROJAN_TCP_CONNECT_TIMEOUT", default_value = "5s", value_parser = parse_duration, help_heading = "Performance")]
    pub tcp_connect_timeout: Duration,

    /// Timeout for reading Trojan request header (default: 5s)
    #[arg(long, env = "X_PANDA_TROJAN_REQUEST_TIMEOUT", default_value = "5s", value_parser = parse_duration, help_heading = "Performance")]
    pub request_timeout: Duration,

    /// TLS handshake timeout (default: 10s)
    #[arg(long, env = "X_PANDA_TROJAN_TLS_HANDSHAKE_TIMEOUT", default_value = "10s", value_parser = parse_duration, help_heading = "Performance")]
    pub tls_handshake_timeout: Duration,

    /// Buffer size for data transfer in bytes (default: 32KB)
    #[arg(long, env = "X_PANDA_TROJAN_BUFFER_SIZE", default_value_t = 32 * 1024, help_heading = "Performance")]
    pub buffer_size: usize,

    /// TCP listen backlog for pending connections (default: 1024)
    #[arg(
        long,
        env = "X_PANDA_TROJAN_TCP_BACKLOG",
        default_value_t = 1024,
        help_heading = "Performance"
    )]
    pub tcp_backlog: i32,

    /// Enable TCP_NODELAY for lower latency (default: true)
    #[arg(
        long,
        env = "X_PANDA_TROJAN_TCP_NODELAY",
        default_value_t = true,
        help_heading = "Performance"
    )]
    pub tcp_nodelay: bool,

    /// After client closes (upload EOF), wait this long for remote to finish (like Xray uplinkOnly, default: 2s)
    #[arg(long, env = "X_PANDA_TROJAN_UPLINK_ONLY_TIMEOUT", default_value = "2s", value_parser = parse_duration, help_heading = "Performance")]
    pub uplink_only_timeout: Duration,

    /// After remote closes (download EOF), wait this long for client to finish (like Xray downlinkOnly, default: 5s)
    #[arg(long, env = "X_PANDA_TROJAN_DOWNLINK_ONLY_TIMEOUT", default_value = "5s", value_parser = parse_duration, help_heading = "Performance")]
    pub downlink_only_timeout: Duration,

    /// Maximum concurrent connections. Use 'auto' to derive a sensible cap
    /// from CPU cores, total RAM, and the file-descriptor limit.
    #[arg(
        long,
        env = "X_PANDA_TROJAN_MAX_CONNECTIONS",
        default_value = "auto",
        help_heading = "Performance"
    )]
    pub max_connections: MaxConnections,
}

impl CliArgs {
    /// Parse CLI arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Validate the CLI arguments
    pub fn validate(&self) -> Result<()> {
        if self.server_host.is_empty() {
            return Err(anyhow!("gRPC server host is required"));
        }
        if self.node == 0 {
            return Err(anyhow!("Node ID must be a positive integer"));
        }

        // Validate TLS cert/key - both are required for Trojan protocol
        if self.cert_file.is_empty() {
            return Err(anyhow!(
                "TLS certificate file path is required (--cert_file)"
            ));
        }
        if self.key_file.is_empty() {
            return Err(anyhow!(
                "TLS private key file path is required (--key_file)"
            ));
        }

        // Validate cert file exists
        let cert_path = std::path::Path::new(&self.cert_file);
        if !cert_path.exists() {
            return Err(anyhow!(
                "TLS certificate file not found: {}",
                self.cert_file
            ));
        }

        // Validate key file exists
        let key_path = std::path::Path::new(&self.key_file);
        if !key_path.exists() {
            return Err(anyhow!("TLS private key file not found: {}", self.key_file));
        }

        // Validate intervals
        if self.fetch_users_interval.is_zero() {
            return Err(anyhow!("fetch_users_interval must be greater than 0"));
        }
        if self.report_traffics_interval.is_zero() {
            return Err(anyhow!("report_traffics_interval must be greater than 0"));
        }
        if self.heartbeat_interval.is_zero() {
            return Err(anyhow!("heartbeat_interval must be greater than 0"));
        }
        // A zero relay buffer makes every read return 0 bytes ("EOF"), so
        // every session would "complete" instantly with no data.
        if self.buffer_size == 0 {
            return Err(anyhow!("buffer_size must be greater than 0"));
        }
        // Two relay buffers per session are allocated at this size, and it is
        // also the gRPC message size (grpc-go clients refuse above 4 MiB).
        if self.buffer_size > MAX_BUFFER_SIZE {
            return Err(anyhow!("buffer_size must be at most {MAX_BUFFER_SIZE}"));
        }
        if self.log_mode.parse::<crate::logger::LogLevel>().is_err() {
            return Err(anyhow!(
                "Invalid log_mode '{}'. Use trace, debug, info, warn or error",
                self.log_mode
            ));
        }
        for (name, d) in [
            ("tcp_connect_timeout", self.tcp_connect_timeout),
            ("request_timeout", self.request_timeout),
            ("tls_handshake_timeout", self.tls_handshake_timeout),
        ] {
            if d.is_zero() {
                return Err(anyhow!("{name} must be greater than 0"));
            }
        }
        if self.tcp_backlog <= 0 {
            return Err(anyhow!("tcp_backlog must be greater than 0"));
        }
        if let MaxConnections::Fixed(n) = self.max_connections {
            if n > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(anyhow!(
                    "max_connections must be at most {}",
                    tokio::sync::Semaphore::MAX_PERMITS
                ));
            }
        }
        // These are consumed with whole-second resolution (`as_secs`); a
        // sub-second value would silently become 0 and end every session.
        for (name, d) in [
            ("conn_idle_timeout", self.conn_idle_timeout),
            ("uplink_only_timeout", self.uplink_only_timeout),
            ("downlink_only_timeout", self.downlink_only_timeout),
            ("api_timeout", self.api_timeout),
        ] {
            if d < Duration::from_secs(1) {
                return Err(anyhow!("{name} must be at least 1s"));
            }
        }
        // Timer deadlines are `Instant::now() + timeout`; an absurd value
        // (humantime accepts "300y") would overflow and abort the process on
        // the first relayed byte.
        for (name, d) in [
            ("conn_idle_timeout", self.conn_idle_timeout),
            ("uplink_only_timeout", self.uplink_only_timeout),
            ("downlink_only_timeout", self.downlink_only_timeout),
            ("api_timeout", self.api_timeout),
            ("tcp_connect_timeout", self.tcp_connect_timeout),
            ("request_timeout", self.request_timeout),
            ("tls_handshake_timeout", self.tls_handshake_timeout),
            ("fetch_users_interval", self.fetch_users_interval),
            ("report_traffics_interval", self.report_traffics_interval),
            ("heartbeat_interval", self.heartbeat_interval),
        ] {
            if d > MAX_DURATION {
                return Err(anyhow!(
                    "{name} must be at most {}",
                    humantime::format_duration(MAX_DURATION)
                ));
            }
        }

        // Validate acl_conf_file if provided
        if let Some(ref path) = self.acl_conf_file {
            if !path.exists() {
                return Err(anyhow!("ACL config file not found: {}", path.display()));
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
                return Err(anyhow!(
                    "Invalid ACL config file format: expected .yaml or .yml extension"
                ));
            }
        }

        Ok(())
    }
}

/// Trojan node configuration deserialized from panel API JSON.
///
/// The panel returns `NodeConfigEnum::Trojan(json_string)` which we
/// deserialize into this struct to extract transport settings.
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanConfig {
    pub server_port: u16,
    #[serde(default)]
    pub network: Option<String>,
    /// v2board emits `{network}_settings` (`ws_settings`); the panel client
    /// normalises it, the alias keeps raw panel JSON working too.
    #[serde(default, alias = "ws_settings")]
    pub websocket_config: Option<WebSocketConfig>,
    #[serde(default, alias = "grpc_settings")]
    pub grpc_config: Option<GrpcConfig>,
}

/// Upper bound for `buffer_size` (4 MiB): two relay buffers per session are
/// allocated at this size, and it is also the gRPC message size, which
/// grpc-go clients (Xray) refuse above their 4 MiB default.
const MAX_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Upper bound for every configurable duration (30 days).
const MAX_DURATION: Duration = Duration::from_secs(30 * 24 * 3600);

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WebSocketConfig {
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GrpcConfig {
    #[serde(default, alias = "serviceName")]
    pub service_name: Option<String>,
}

/// Normalize a panel-supplied WebSocket path the way Xray does on both ends:
/// strip any query (`?ed=2048` early-data hint), ensure a leading `/`.
/// The admin UI passes the value through unchanged, so `"trojan"` and
/// `"/trojan?ed=2048"` must both match a client requesting `GET /trojan`.
pub fn normalize_ws_path(raw: &str) -> String {
    let path = raw.trim().split('?').next().unwrap_or("").trim();
    if path.is_empty() {
        return String::new();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Parse a `NodeConfigEnum` into a `TrojanConfig`.
pub fn parse_trojan_config(config_enum: NodeConfigEnum) -> Result<TrojanConfig> {
    match config_enum {
        NodeConfigEnum::Trojan(json) => {
            serde_json::from_str(&json).map_err(|e| anyhow!("Failed to parse TrojanConfig: {}", e))
        }
        other => Err(anyhow!(
            "Expected Trojan config, got {:?}",
            std::mem::discriminant(&other)
        )),
    }
}

/// Default gRPC service name (Xray compatible)
pub const DEFAULT_GRPC_SERVICE_NAME: &str = "GunService";

/// Default WebSocket path (Xray compatible)
pub const DEFAULT_WS_PATH: &str = "/";

/// Connection performance configuration
#[derive(Debug, Clone, Copy)]
pub struct ConnConfig {
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// After client closes (upload EOF), wait for remote to finish (Xray uplinkOnly)
    pub uplink_only_timeout: Duration,
    /// After remote closes (download EOF), wait for client to finish (Xray downlinkOnly)
    pub downlink_only_timeout: Duration,
    /// TCP connect timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// TLS handshake timeout
    pub tls_handshake_timeout: Duration,
    /// Buffer size for data transfer
    pub buffer_size: usize,
    /// TCP listen backlog
    pub tcp_backlog: i32,
    /// Enable TCP_NODELAY
    pub tcp_nodelay: bool,
    /// Maximum concurrent connections (0 = unlimited)
    pub max_connections: usize,
}

impl ConnConfig {
    /// Create from CLI args plus a pre-resolved `max_connections`.
    ///
    /// The caller owns `config_auto::resolve(cli.max_connections)` so that
    /// the resolved value used for enforcement and the value used for
    /// diagnostic logging are guaranteed to come from the same call —
    /// no implicit "trust me, resolve is idempotent" contract.
    pub fn from_cli(cli: &CliArgs, max_connections: usize) -> Self {
        Self {
            idle_timeout: cli.conn_idle_timeout,
            uplink_only_timeout: cli.uplink_only_timeout,
            downlink_only_timeout: cli.downlink_only_timeout,
            connect_timeout: cli.tcp_connect_timeout,
            request_timeout: cli.request_timeout,
            tls_handshake_timeout: cli.tls_handshake_timeout,
            buffer_size: cli.buffer_size,
            tcp_backlog: cli.tcp_backlog,
            tcp_nodelay: cli.tcp_nodelay,
            max_connections,
        }
    }

    /// Get connection idle timeout in seconds (for relay function)
    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout.as_secs()
    }

    /// Get uplink-only timeout in seconds (client EOF → wait for remote)
    pub fn uplink_only_timeout_secs(&self) -> u64 {
        self.uplink_only_timeout.as_secs()
    }

    /// Get downlink-only timeout in seconds (remote EOF → wait for client)
    pub fn downlink_only_timeout_secs(&self) -> u64 {
        self.downlink_only_timeout.as_secs()
    }
}

/// Runtime server configuration (built from remote panel config + CLI args)
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port number
    pub port: u16,
    /// Enable WebSocket mode
    pub enable_ws: bool,
    /// Enable gRPC mode
    pub enable_grpc: bool,
    /// WebSocket path (Xray default: "/")
    pub ws_path: String,
    /// gRPC service name (Xray default: "GunService", path becomes "/${service_name}/Tun")
    pub grpc_service_name: String,
    /// TLS certificate file path
    pub cert: Option<PathBuf>,
    /// TLS private key file path
    pub key: Option<PathBuf>,
    /// ACL config file path
    pub acl_conf_file: Option<PathBuf>,
    /// Data directory for geo data files (default: /var/lib/trojan-node)
    pub data_dir: PathBuf,
    /// Block connections to private/loopback IP addresses (SSRF protection)
    pub block_private_ip: bool,
}

impl ServerConfig {
    /// Build ServerConfig from panel's TrojanConfig and CLI args
    pub fn from_remote(remote: &TrojanConfig, cli: &CliArgs) -> Result<Self> {
        // Determine transport mode from remote config
        let network = remote.network.as_deref().unwrap_or("tcp");
        let (enable_ws, enable_grpc) = match network.to_lowercase().as_str() {
            "ws" | "websocket" => (true, false),
            "grpc" => (false, true),
            _ => (false, false),
        };

        // Extract WebSocket path from remote config (Xray default: "/")
        let ws_path = remote
            .websocket_config
            .as_ref()
            .and_then(|c| c.path.as_deref())
            .map(normalize_ws_path)
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| DEFAULT_WS_PATH.to_string());

        // Extract gRPC service name from remote config (Xray default: "GunService")
        let grpc_service_name = remote
            .grpc_config
            .as_ref()
            .and_then(|c| c.service_name.clone())
            .unwrap_or_else(|| DEFAULT_GRPC_SERVICE_NAME.to_string());

        // Use CLI cert/key (required)
        let cert = Some(PathBuf::from(&cli.cert_file));
        let key = Some(PathBuf::from(&cli.key_file));

        Ok(Self {
            port: remote.server_port,
            enable_ws,
            enable_grpc,
            ws_path,
            grpc_service_name,
            cert,
            key,
            acl_conf_file: cli.acl_conf_file.clone(),
            data_dir: cli.data_dir.clone(),
            block_private_ip: cli.block_private_ip,
        })
    }

    /// Get the expected gRPC path (format: "/${service_name}/Tun")
    #[allow(dead_code)]
    pub fn grpc_path(&self) -> String {
        format!("/{}/Tun", self.grpc_service_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_path_is_normalized_like_xray() {
        assert_eq!(normalize_ws_path("trojan"), "/trojan");
        assert_eq!(normalize_ws_path("/trojan?ed=2048"), "/trojan");
        assert_eq!(normalize_ws_path(" /a "), "/a");
        assert_eq!(normalize_ws_path(""), "");
        assert_eq!(normalize_ws_path("?ed=1"), "");
    }

    #[test]
    fn panel_aliases_are_accepted() {
        let json = r#"{"server_port":443,"network":"grpc","grpc_settings":{"serviceName":"svc"},"ws_settings":{"path":"p"}}"#;
        let c: TrojanConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.grpc_config.unwrap().service_name.as_deref(), Some("svc"));
        assert_eq!(c.websocket_config.unwrap().path.as_deref(), Some("p"));
    }

    fn create_test_cli_args() -> CliArgs {
        CliArgs {
            server_host: "127.0.0.1".to_string(),
            port: 8082,
            node: 1,
            cert_file: "/path/to/cert.pem".to_string(),
            key_file: "/path/to/key.pem".to_string(),
            fetch_users_interval: Duration::from_secs(60),
            report_traffics_interval: Duration::from_secs(100),
            heartbeat_interval: Duration::from_secs(180),
            api_timeout: Duration::from_secs(15),
            log_mode: "info".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            acl_conf_file: None,
            conn_idle_timeout: Duration::from_secs(300),
            tcp_connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            tls_handshake_timeout: Duration::from_secs(10),
            buffer_size: 32 * 1024,
            tcp_backlog: 1024,
            tcp_nodelay: true,
            uplink_only_timeout: Duration::from_secs(2),
            downlink_only_timeout: Duration::from_secs(5),
            max_connections: MaxConnections::Fixed(10_000),
            block_private_ip: true,
            refresh_geodata: false,
            server_name: None,
            ca_file: None,
            panel_ip_version: IpVersion::V4,
        }
    }

    fn create_test_cli_args_with_temp_certs() -> (CliArgs, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Create dummy cert and key files
        std::fs::write(&cert_path, "dummy cert").unwrap();
        std::fs::write(&key_path, "dummy key").unwrap();

        let cli = CliArgs {
            server_host: "127.0.0.1".to_string(),
            port: 8082,
            node: 1,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            fetch_users_interval: Duration::from_secs(60),
            report_traffics_interval: Duration::from_secs(100),
            heartbeat_interval: Duration::from_secs(180),
            api_timeout: Duration::from_secs(15),
            log_mode: "info".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            acl_conf_file: None,
            block_private_ip: true,
            refresh_geodata: false,
            conn_idle_timeout: Duration::from_secs(300),
            tcp_connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            tls_handshake_timeout: Duration::from_secs(10),
            buffer_size: 32 * 1024,
            tcp_backlog: 1024,
            tcp_nodelay: true,
            uplink_only_timeout: Duration::from_secs(2),
            downlink_only_timeout: Duration::from_secs(5),
            max_connections: MaxConnections::Fixed(10_000),
            server_name: None,
            ca_file: None,
            panel_ip_version: IpVersion::V4,
        };
        (cli, temp_dir)
    }

    #[test]
    fn test_cli_args_defaults() {
        // Test that test helper creates valid default values
        let cli = create_test_cli_args();
        assert_eq!(cli.fetch_users_interval, Duration::from_secs(60));
        assert_eq!(cli.report_traffics_interval, Duration::from_secs(100));
        assert_eq!(cli.heartbeat_interval, Duration::from_secs(180));
    }

    #[test]
    fn test_cli_args_validate_success() {
        let (cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_cli_args_validate_empty_server_host() {
        let mut cli = create_test_cli_args();
        cli.server_host = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_invalid_node_id() {
        let mut cli = create_test_cli_args();
        cli.node = 0;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_empty_cert() {
        let mut cli = create_test_cli_args();
        cli.cert_file = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_empty_key() {
        let mut cli = create_test_cli_args();
        cli.key_file = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_cert_file_not_found() {
        let mut cli = create_test_cli_args();
        cli.cert_file = "/nonexistent/path/cert.pem".to_string();
        cli.key_file = "/nonexistent/path/key.pem".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_with_valid_cert_files() {
        let (cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_cli_args_validate_zero_interval() {
        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.fetch_users_interval = Duration::ZERO;
        assert!(cli.validate().is_err());

        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.report_traffics_interval = Duration::ZERO;
        assert!(cli.validate().is_err());

        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.heartbeat_interval = Duration::ZERO;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_conn_config_from_cli_max_connections_passes_through() {
        // from_cli is now a thin transcription: whatever resolved usize the
        // caller hands in is the value enforcement uses.  Both fixed and
        // auto-resolved values flow through the same way.
        let cli = create_test_cli_args();
        let config = ConnConfig::from_cli(&cli, 10_000);
        assert_eq!(config.max_connections, 10_000);

        let config_custom = ConnConfig::from_cli(&cli, 100_000);
        assert_eq!(config_custom.max_connections, 100_000);
    }

    #[test]
    fn test_conn_config_from_cli_accepts_resolved_auto_value() {
        // Auto must always produce a positive value — never 0 — to prevent
        // the accept-loop death spiral that an unlimited semaphore caused
        // in the original 0-default era.
        use crate::config_auto;

        let cli = create_test_cli_args();
        let resolved = config_auto::resolve(MaxConnections::Auto).value;
        assert!(resolved >= 1, "auto must resolve to a positive value");
        let config = ConnConfig::from_cli(&cli, resolved);
        assert_eq!(config.max_connections, resolved);
    }

    #[test]
    fn test_parse_duration() {
        // Test humantime format
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));

        // Test plain seconds (backwards compatibility)
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("120").unwrap(), Duration::from_secs(120));

        // Test invalid input
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_default_data_dir_value() {
        assert_eq!(DEFAULT_DATA_DIR, "/var/lib/trojan-agent-node");
    }

    fn create_test_trojan_config(network: Option<&str>) -> TrojanConfig {
        TrojanConfig {
            server_port: 443,
            network: network.map(String::from),
            websocket_config: None,
            grpc_config: None,
        }
    }

    #[test]
    fn test_parse_trojan_config_success() {
        let json = r#"{"server_port":443,"network":"ws"}"#;
        let config_enum = NodeConfigEnum::Trojan(json.to_string());
        let config = parse_trojan_config(config_enum).unwrap();
        assert_eq!(config.server_port, 443);
        assert_eq!(config.network.as_deref(), Some("ws"));
    }

    #[test]
    fn test_parse_trojan_config_wrong_variant() {
        let config_enum = NodeConfigEnum::Tuic("{}".to_string());
        assert!(parse_trojan_config(config_enum).is_err());
    }

    #[test]
    fn test_server_config_from_remote_tcp() {
        let remote = create_test_trojan_config(None);
        let cli = create_test_cli_args();
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert_eq!(config.port, 443);
        assert!(!config.enable_ws);
        assert!(!config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_websocket() {
        let remote = create_test_trojan_config(Some("ws"));
        let cli = create_test_cli_args();
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert!(config.enable_ws);
        assert!(!config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_websocket_full() {
        let remote = create_test_trojan_config(Some("websocket"));
        let cli = create_test_cli_args();
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert!(config.enable_ws);
        assert!(!config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_grpc() {
        let remote = create_test_trojan_config(Some("grpc"));
        let cli = create_test_cli_args();
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert!(!config.enable_ws);
        assert!(config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_network_case_insensitive() {
        let remote = create_test_trojan_config(Some("GRPC"));
        let cli = create_test_cli_args();
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert!(config.enable_grpc);
    }

    #[test]
    fn test_server_config_from_remote_with_cert() {
        let remote = create_test_trojan_config(None);
        let cli = create_test_cli_args();
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert_eq!(config.cert, Some(PathBuf::from("/path/to/cert.pem")));
        assert_eq!(config.key, Some(PathBuf::from("/path/to/key.pem")));
    }

    #[test]
    fn test_server_config_from_remote_with_acl_config() {
        let remote = create_test_trojan_config(None);
        let mut cli = create_test_cli_args();
        cli.acl_conf_file = Some(PathBuf::from("/path/to/acl.yaml"));
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert_eq!(
            config.acl_conf_file,
            Some(PathBuf::from("/path/to/acl.yaml"))
        );
    }

    #[test]
    fn test_server_config_default_ws_path() {
        let remote = create_test_trojan_config(Some("ws"));
        let cli = create_test_cli_args();

        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert_eq!(config.ws_path, DEFAULT_WS_PATH);
        assert_eq!(config.ws_path, "/");
    }

    #[test]
    fn test_server_config_custom_ws_path() {
        let mut remote = create_test_trojan_config(Some("ws"));
        remote.websocket_config = Some(WebSocketConfig {
            path: Some("/custom/path".to_string()),
        });
        let cli = create_test_cli_args();

        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert_eq!(config.ws_path, "/custom/path");
    }

    #[test]
    fn test_server_config_default_grpc_service_name() {
        let remote = create_test_trojan_config(Some("grpc"));
        let cli = create_test_cli_args();

        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert_eq!(config.grpc_service_name, DEFAULT_GRPC_SERVICE_NAME);
        assert_eq!(config.grpc_service_name, "GunService");
        assert_eq!(config.grpc_path(), "/GunService/Tun");
    }

    #[test]
    fn test_server_config_custom_grpc_service_name() {
        let mut remote = create_test_trojan_config(Some("grpc"));
        remote.grpc_config = Some(GrpcConfig {
            service_name: Some("MyCustomService".to_string()),
        });
        let cli = create_test_cli_args();

        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        assert_eq!(config.grpc_service_name, "MyCustomService");
        assert_eq!(config.grpc_path(), "/MyCustomService/Tun");
    }

    #[test]
    fn test_server_config_ws_config_with_empty_path() {
        let mut remote = create_test_trojan_config(Some("ws"));
        remote.websocket_config = Some(WebSocketConfig { path: None });
        let cli = create_test_cli_args();

        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        // Should fall back to default
        assert_eq!(config.ws_path, DEFAULT_WS_PATH);
    }

    #[test]
    fn test_conn_config_uplink_downlink_defaults() {
        let cli = create_test_cli_args();
        let config = ConnConfig::from_cli(&cli, 10_000);
        assert_eq!(config.uplink_only_timeout, Duration::from_secs(2));
        assert_eq!(config.downlink_only_timeout, Duration::from_secs(5));
        assert_eq!(config.uplink_only_timeout_secs(), 2);
        assert_eq!(config.downlink_only_timeout_secs(), 5);
    }

    #[test]
    fn test_conn_config_uplink_downlink_custom() {
        let mut cli = create_test_cli_args();
        cli.uplink_only_timeout = Duration::from_secs(10);
        cli.downlink_only_timeout = Duration::from_secs(30);
        let config = ConnConfig::from_cli(&cli, 10_000);
        assert_eq!(config.uplink_only_timeout_secs(), 10);
        assert_eq!(config.downlink_only_timeout_secs(), 30);
    }

    #[test]
    fn test_conn_config_uplink_downlink_independent() {
        let mut cli = create_test_cli_args();
        cli.uplink_only_timeout = Duration::from_secs(1);
        cli.downlink_only_timeout = Duration::from_secs(60);
        let config = ConnConfig::from_cli(&cli, 10_000);
        assert_ne!(
            config.uplink_only_timeout_secs(),
            config.downlink_only_timeout_secs()
        );
        assert_eq!(config.uplink_only_timeout_secs(), 1);
        assert_eq!(config.downlink_only_timeout_secs(), 60);
    }

    #[test]
    fn test_conn_config_uplink_downlink_zero() {
        let mut cli = create_test_cli_args();
        cli.uplink_only_timeout = Duration::ZERO;
        cli.downlink_only_timeout = Duration::ZERO;
        let config = ConnConfig::from_cli(&cli, 10_000);
        assert_eq!(config.uplink_only_timeout_secs(), 0);
        assert_eq!(config.downlink_only_timeout_secs(), 0);
    }

    #[test]
    fn test_parse_ip_version_valid() {
        assert_eq!(parse_ip_version("v4").unwrap(), IpVersion::V4);
        assert_eq!(parse_ip_version("v6").unwrap(), IpVersion::V6);
        assert_eq!(parse_ip_version("auto").unwrap(), IpVersion::Auto);
        assert_eq!(parse_ip_version("ipv4").unwrap(), IpVersion::V4);
        assert_eq!(parse_ip_version("ipv6").unwrap(), IpVersion::V6);
        assert_eq!(parse_ip_version("4").unwrap(), IpVersion::V4);
        assert_eq!(parse_ip_version("6").unwrap(), IpVersion::V6);
        assert_eq!(parse_ip_version("V4").unwrap(), IpVersion::V4);
        assert_eq!(parse_ip_version("AUTO").unwrap(), IpVersion::Auto);
    }

    #[test]
    fn test_parse_ip_version_invalid() {
        assert!(parse_ip_version("invalid").is_err());
        assert!(parse_ip_version("").is_err());
        assert!(parse_ip_version("v5").is_err());
    }

    #[test]
    fn test_server_config_grpc_config_with_empty_service_name() {
        let mut remote = create_test_trojan_config(Some("grpc"));
        remote.grpc_config = Some(GrpcConfig {
            service_name: None, // Explicitly None
        });
        let cli = create_test_cli_args();

        let config = ServerConfig::from_remote(&remote, &cli).unwrap();

        // Should fall back to default
        assert_eq!(config.grpc_service_name, DEFAULT_GRPC_SERVICE_NAME);
    }
}
