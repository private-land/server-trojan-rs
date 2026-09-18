//! TLS configuration utilities
//!
//! Provides TLS certificate loading for the server.

use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// TLS transport listener helper (provides TLS config loading)
pub struct TlsTransportListener;

impl TlsTransportListener {
    /// Create TLS config from certificate and key files.
    ///
    /// `alpn` is advertised in order of preference: `["h2"]` for gRPC (RFC 7540
    /// §3.3 — grpc-go clients refuse a TLS session without it), `["http/1.1"]`
    /// for WebSocket, empty for raw TCP.
    pub fn load_tls_config(
        cert_path: &Path,
        key_path: &Path,
        alpn: &[&[u8]],
    ) -> std::io::Result<Arc<ServerConfig>> {
        // Load certificates
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No certificates found in cert file",
            ));
        }

        // Load private key
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "No private key found")
        })?;

        // Build TLS config
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Enable TLS session tickets for faster reconnection.
        // Clients that reconnect skip the full handshake, saving ~1 RTT.
        // Keys are automatically rotated by rustls's TicketSwitcher.
        if let Ok(ticketer) = rustls::crypto::aws_lc_rs::Ticketer::new() {
            config.ticketer = ticketer;
        }

        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed P-256 test certificate (CN=test.local, 10 years).
    const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBgDCCASWgAwIBAgIUAvwoDT7San0NJQNF/mvPNVuVDGgwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKdGVzdC5sb2NhbDAeFw0yNjA5MTgwNDE3NThaFw0zNjA5MTUw
NDE3NThaMBUxEzARBgNVBAMMCnRlc3QubG9jYWwwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQTChsH2s87UohmL2L2mdONFA+TeQeikrsDjRZAM/zWJ62S6WWcftJr
WkwQawTkkVzyA4ht6EEhV23ewh8ldRP7o1MwUTAdBgNVHQ4EFgQUo1p9jGXtfL1B
f7l7O3YfDB86pwgwHwYDVR0jBBgwFoAUo1p9jGXtfL1Bf7l7O3YfDB86pwgwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA51g8AQ9vt45VrwVSo0dU
s2Z2figUbXTtw2/fJx6VBr4CIQCU+3QnE3NEtXTxOJQ8uDnfkbwc6QEyz4pvnWAk
ahpqGQ==
-----END CERTIFICATE-----"#;
    const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQQ81kmtLui+huYuw
MUv+g5TA6TRT3d9U9zGxjyJqHe2hRANCAAQTChsH2s87UohmL2L2mdONFA+TeQei
krsDjRZAM/zWJ62S6WWcftJrWkwQawTkkVzyA4ht6EEhV23ewh8ldRP7
-----END PRIVATE KEY-----"#;

    #[test]
    fn alpn_protocols_are_advertised_in_order() {
        use std::io::Write;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        std::fs::File::create(&cert)
            .unwrap()
            .write_all(TEST_CERT.as_bytes())
            .unwrap();
        std::fs::File::create(&key)
            .unwrap()
            .write_all(TEST_KEY.as_bytes())
            .unwrap();
        let cfg =
            TlsTransportListener::load_tls_config(&cert, &key, &[b"h2", b"http/1.1"]).unwrap();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let cfg = TlsTransportListener::load_tls_config(&cert, &key, &[]).unwrap();
        assert!(cfg.alpn_protocols.is_empty());
    }

    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_tls_config_invalid_cert() {
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(b"invalid cert").unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"invalid key").unwrap();

        let result = TlsTransportListener::load_tls_config(cert_file.path(), key_file.path(), &[]);

        assert!(result.is_err());
    }
}
