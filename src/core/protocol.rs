//! Trojan protocol parsing
//!
//! Implements the Trojan protocol format:
//! - 56-byte password (SHA224 hex encoded)
//! - CRLF
//! - Command (1 byte: CONNECT=1, UDP_ASSOCIATE=3)
//! - Address (ATYP + address + port)
//! - CRLF
//! - Payload

use bytes::{Bytes, BytesMut};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::logger::log;

/// Address type constants
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Trojan command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCmd {
    /// TCP connect
    Connect = 1,
    /// UDP associate
    UdpAssociate = 3,
}

impl TryFrom<u8> for TrojanCmd {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TrojanCmd::Connect),
            3 => Ok(TrojanCmd::UdpAssociate),
            _ => Err("invalid trojan command"),
        }
    }
}

/// Address types supported by Trojan
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// IPv4 address
    IPv4([u8; 4], u16),
    /// IPv6 address
    IPv6([u8; 16], u16),
    /// Domain name
    Domain(String, u16),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::IPv4(ip, port) => write!(f, "{}:{}", Ipv4Addr::from(*ip), port),
            Address::IPv6(ip, port) => write!(f, "[{}]:{}", Ipv6Addr::from(*ip), port),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

/// Address decode result
#[derive(Debug)]
pub enum DecodeResult<T> {
    /// Successfully decoded
    Ok(T, usize),
    /// Need more data
    NeedMoreData,
    /// Invalid data
    Invalid(&'static str),
}

impl Address {
    /// Build an IP-literal address (no domain) for `ip:port`.
    pub fn from_ip(ip: IpAddr, port: u16) -> Self {
        match ip {
            IpAddr::V4(v4) => Address::IPv4(v4.octets(), port),
            IpAddr::V6(v6) => Address::IPv6(v6.octets(), port),
        }
    }

    /// The IP this address names without DNS: IP variants directly, a domain
    /// only if it parses as an IP literal.
    pub fn literal_ip(&self) -> Option<IpAddr> {
        match self {
            Address::IPv4(ip, _) => Some(IpAddr::V4(Ipv4Addr::from(*ip))),
            Address::IPv6(ip, _) => Some(IpAddr::V6(Ipv6Addr::from(*ip))),
            Address::Domain(d, _) => d.parse().ok(),
        }
    }

    /// Decode address from buffer
    pub fn decode(buf: &[u8]) -> DecodeResult<Self> {
        if buf.is_empty() {
            return DecodeResult::NeedMoreData;
        }

        let atyp = buf[0];
        match atyp {
            ATYP_IPV4 => {
                // 1 (type) + 4 (ip) + 2 (port) = 7 bytes
                if buf.len() < 7 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                DecodeResult::Ok(Address::IPv4(ip, port), 7)
            }
            ATYP_IPV6 => {
                // 1 (type) + 16 (ip) + 2 (port) = 19 bytes
                if buf.len() < 19 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                DecodeResult::Ok(Address::IPv6(ip, port), 19)
            }
            ATYP_DOMAIN => {
                // 1 (type) + 1 (len) + len (domain) + 2 (port)
                if buf.len() < 2 {
                    return DecodeResult::NeedMoreData;
                }
                let domain_len = buf[1] as usize;
                let total_len = 1 + 1 + domain_len + 2;
                if buf.len() < total_len {
                    return DecodeResult::NeedMoreData;
                }
                let domain = match std::str::from_utf8(&buf[2..2 + domain_len]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return DecodeResult::Invalid("invalid domain encoding"),
                };
                let port = u16::from_be_bytes([buf[2 + domain_len], buf[3 + domain_len]]);
                DecodeResult::Ok(Address::Domain(domain, port), total_len)
            }
            _ => DecodeResult::Invalid("invalid address type"),
        }
    }

    /// Encode address to buffer
    /// Returns the number of bytes written
    pub fn encode(&self, buf: &mut Vec<u8>) -> usize {
        let start_len = buf.len();
        match self {
            Address::IPv4(ip, port) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::IPv6(ip, port) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Domain(domain, port) => {
                debug_assert!(
                    domain.len() <= 255,
                    "domain too long for Trojan protocol: {} bytes",
                    domain.len()
                );
                buf.push(ATYP_DOMAIN);
                buf.push(domain.len().min(255) as u8);
                buf.extend_from_slice(&domain.as_bytes()[..domain.len().min(255)]);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf.len() - start_len
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) => *port,
            Address::IPv6(_, port) => *port,
            Address::Domain(_, port) => *port,
        }
    }

    /// Get the host as a borrowed or owned string.
    ///
    /// Returns `Cow::Borrowed` for domains (zero allocation) and
    /// `Cow::Owned` for IP addresses (requires formatting).
    pub fn host(&self) -> Cow<'_, str> {
        match self {
            Address::IPv4(ip, _) => Cow::Owned(Ipv4Addr::from(*ip).to_string()),
            Address::IPv6(ip, _) => Cow::Owned(Ipv6Addr::from(*ip).to_string()),
            Address::Domain(domain, _) => Cow::Borrowed(domain),
        }
    }
}

/// Trojan protocol request
#[derive(Debug)]
pub struct TrojanRequest {
    /// Password (56 bytes, SHA224 hex encoded)
    pub password: [u8; 56],
    /// Command type
    pub cmd: TrojanCmd,
    /// Target address
    pub addr: Address,
    /// Initial payload (zero-copy)
    pub payload: Bytes,
}

impl TrojanRequest {
    /// Minimum request size: 56 (password) + 2 (CRLF) + 1 (cmd) + 7 (min addr) + 2 (CRLF) = 68
    pub const MIN_SIZE: usize = 68;

    /// Check if buffer contains a complete request without consuming it
    /// Returns Ok(header_len) if complete, Err for need more data or invalid
    pub fn check_complete(buf: &[u8]) -> Result<usize, Option<&'static str>> {
        if buf.len() < Self::MIN_SIZE {
            return Err(None); // Need more data
        }

        // Check first CRLF
        if buf[56] != b'\r' || buf[57] != b'\n' {
            return Err(Some("missing CRLF after password"));
        }

        // Validate command
        if TrojanCmd::try_from(buf[58]).is_err() {
            return Err(Some("invalid trojan command"));
        }

        // Check address length
        let addr_result = Address::decode(&buf[59..]);
        let addr_consumed = match addr_result {
            DecodeResult::Ok(_, consumed) => consumed,
            DecodeResult::NeedMoreData => return Err(None),
            DecodeResult::Invalid(msg) => return Err(Some(msg)),
        };

        let crlf_pos = 59 + addr_consumed;

        // Check second CRLF
        if buf.len() < crlf_pos + 2 {
            return Err(None);
        }
        if buf[crlf_pos] != b'\r' || buf[crlf_pos + 1] != b'\n' {
            return Err(Some("missing CRLF after address"));
        }

        Ok(crlf_pos + 2)
    }

    /// Decode trojan request from buffer (zero-copy for payload)
    ///
    /// Format: password(56) + CRLF + cmd(1) + address + CRLF + payload
    pub fn decode_zerocopy(buf: &mut BytesMut) -> DecodeResult<Self> {
        // Need at least minimum size
        if buf.len() < Self::MIN_SIZE {
            return DecodeResult::NeedMoreData;
        }

        // Parse password (56 bytes)
        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[..56]);

        // Check first CRLF
        if buf[56] != b'\r' || buf[57] != b'\n' {
            log::debug!("Invalid CRLF after password");
            return DecodeResult::Invalid("missing CRLF after password");
        }

        // Parse command
        let cmd = match TrojanCmd::try_from(buf[58]) {
            Ok(cmd) => cmd,
            Err(msg) => return DecodeResult::Invalid(msg),
        };

        // Parse address
        let (addr, addr_consumed) = match Address::decode(&buf[59..]) {
            DecodeResult::Ok(addr, consumed) => (addr, consumed),
            DecodeResult::NeedMoreData => return DecodeResult::NeedMoreData,
            DecodeResult::Invalid(msg) => return DecodeResult::Invalid(msg),
        };

        let crlf_pos = 59 + addr_consumed;

        // Check second CRLF
        if buf.len() < crlf_pos + 2 {
            return DecodeResult::NeedMoreData;
        }
        if buf[crlf_pos] != b'\r' || buf[crlf_pos + 1] != b'\n' {
            return DecodeResult::Invalid("missing CRLF after address");
        }

        let header_len = crlf_pos + 2;

        // Split off the header, remaining is payload
        let _ = buf.split_to(header_len);
        let payload = buf.split().freeze();

        DecodeResult::Ok(
            TrojanRequest {
                password,
                cmd,
                addr,
                payload,
            },
            header_len,
        )
    }
}

/// Trojan UDP packet format (within TCP stream)
///
/// Format: ATYP(1) + DST.ADDR(variable) + DST.PORT(2) + Length(2) + CRLF(2) + Payload
#[derive(Debug)]
pub struct TrojanUdpPacket {
    /// Target address
    pub addr: Address,
    /// Payload data
    pub payload: Bytes,
}

impl TrojanUdpPacket {
    /// Minimum packet size: 1 (atyp) + 4 (min addr IPv4) + 2 (port) + 2 (length) + 2 (CRLF) = 11
    pub const MIN_SIZE: usize = 11;

    /// Decode a single UDP packet from byte slice (copies payload).
    /// Prefer `decode_zerocopy` for hot paths.
    #[allow(dead_code)]
    pub fn decode(buf: &[u8]) -> DecodeResult<Self> {
        if buf.len() < Self::MIN_SIZE {
            return DecodeResult::NeedMoreData;
        }

        // Parse address
        let (addr, addr_len) = match Address::decode(buf) {
            DecodeResult::Ok(addr, len) => (addr, len),
            DecodeResult::NeedMoreData => return DecodeResult::NeedMoreData,
            DecodeResult::Invalid(msg) => return DecodeResult::Invalid(msg),
        };

        // Check we have length + CRLF
        if buf.len() < addr_len + 4 {
            return DecodeResult::NeedMoreData;
        }

        // Parse payload length
        let payload_len = u16::from_be_bytes([buf[addr_len], buf[addr_len + 1]]) as usize;

        // Check CRLF
        if buf[addr_len + 2] != b'\r' || buf[addr_len + 3] != b'\n' {
            return DecodeResult::Invalid("missing CRLF in UDP packet");
        }

        // Check we have full payload
        let total_len = addr_len + 4 + payload_len;
        if buf.len() < total_len {
            return DecodeResult::NeedMoreData;
        }

        let payload = Bytes::copy_from_slice(&buf[addr_len + 4..total_len]);

        DecodeResult::Ok(TrojanUdpPacket { addr, payload }, total_len)
    }

    /// Decode a single UDP packet from BytesMut (zero-copy for payload)
    pub fn decode_zerocopy(buf: &mut BytesMut) -> DecodeResult<Self> {
        if buf.len() < Self::MIN_SIZE {
            return DecodeResult::NeedMoreData;
        }

        let (addr, addr_len) = match Address::decode(buf) {
            DecodeResult::Ok(addr, len) => (addr, len),
            DecodeResult::NeedMoreData => return DecodeResult::NeedMoreData,
            DecodeResult::Invalid(msg) => return DecodeResult::Invalid(msg),
        };

        if buf.len() < addr_len + 4 {
            return DecodeResult::NeedMoreData;
        }

        let payload_len = u16::from_be_bytes([buf[addr_len], buf[addr_len + 1]]) as usize;

        if buf[addr_len + 2] != b'\r' || buf[addr_len + 3] != b'\n' {
            return DecodeResult::Invalid("missing CRLF in UDP packet");
        }

        let total_len = addr_len + 4 + payload_len;
        if buf.len() < total_len {
            return DecodeResult::NeedMoreData;
        }

        // Split header, then split payload as zero-copy Bytes
        let header_len = addr_len + 4;
        let _ = buf.split_to(header_len);
        let payload = buf.split_to(payload_len).freeze();

        DecodeResult::Ok(TrojanUdpPacket { addr, payload }, total_len)
    }

    /// Encode UDP packet to buffer
    pub fn encode(addr: &Address, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + payload.len());
        addr.encode(&mut buf);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_trojan_cmd_try_from() {
        assert_eq!(TrojanCmd::try_from(1), Ok(TrojanCmd::Connect));
        assert_eq!(TrojanCmd::try_from(3), Ok(TrojanCmd::UdpAssociate));
        assert!(TrojanCmd::try_from(0).is_err());
        assert!(TrojanCmd::try_from(2).is_err());
        assert!(TrojanCmd::try_from(4).is_err());
    }

    #[test]
    fn test_address_decode_ipv4() {
        let buf = [1, 192, 168, 1, 1, 0x1F, 0x90]; // 192.168.1.1:8080
        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 7);
                assert!(matches!(addr, Address::IPv4([192, 168, 1, 1], 8080)));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_address_decode_ipv6() {
        let mut buf = vec![4]; // ATYP_IPV6
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        buf.extend_from_slice(&[0x01, 0xBB]); // port 443

        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 19);
                assert!(matches!(addr, Address::IPv6(_, 443)));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_address_decode_domain() {
        let mut buf = vec![3, 11]; // ATYP_DOMAIN, length
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&[0x00, 0x50]); // port 80

        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 15);
                assert!(matches!(addr, Address::Domain(ref d, 80) if d == "example.com"));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_address_decode_need_more_data() {
        let buf = [1, 192, 168]; // Incomplete IPv4
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));

        let buf = [4, 0, 0, 0]; // Incomplete IPv6
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));

        let buf = [3, 11, b'e', b'x']; // Incomplete domain
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));
    }

    #[test]
    fn test_address_decode_invalid() {
        let buf = [99, 0, 0, 0, 0, 0, 0]; // Invalid ATYP
        assert!(matches!(Address::decode(&buf), DecodeResult::Invalid(_)));
    }

    #[test]
    fn test_address_display() {
        let ipv4 = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(format!("{}", ipv4), "192.168.1.1:8080");

        let ipv6 = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(format!("{}", ipv6), "[::1]:443");

        let domain = Address::Domain("example.com".to_string(), 80);
        assert_eq!(format!("{}", domain), "example.com:80");
    }

    #[test]
    fn test_trojan_request_decode_connect() {
        let mut buf = BytesMut::new();

        // Password (56 bytes)
        buf.extend_from_slice(&[b'a'; 56]);
        // CRLF
        buf.extend_from_slice(b"\r\n");
        // Command (CONNECT)
        buf.put_u8(1);
        // Address (IPv4)
        buf.extend_from_slice(&[1, 127, 0, 0, 1, 0x1F, 0x90]); // 127.0.0.1:8080
                                                               // CRLF
        buf.extend_from_slice(b"\r\n");
        // Payload
        buf.extend_from_slice(b"hello");

        match TrojanRequest::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(req, _) => {
                assert_eq!(req.password, [b'a'; 56]);
                assert_eq!(req.cmd, TrojanCmd::Connect);
                assert!(matches!(req.addr, Address::IPv4([127, 0, 0, 1], 8080)));
                assert_eq!(req.payload.as_ref(), b"hello");
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_request_decode_udp_associate() {
        let mut buf = BytesMut::new();

        // Password
        buf.extend_from_slice(&[b'x'; 56]);
        // CRLF
        buf.extend_from_slice(b"\r\n");
        // Command (UDP_ASSOCIATE)
        buf.put_u8(3);
        // Address (domain)
        buf.extend_from_slice(&[3, 7]); // ATYP_DOMAIN, length
        buf.extend_from_slice(b"udp.com");
        buf.extend_from_slice(&[0x00, 0x35]); // port 53
                                              // CRLF
        buf.extend_from_slice(b"\r\n");

        match TrojanRequest::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(req, _) => {
                assert_eq!(req.cmd, TrojanCmd::UdpAssociate);
                assert!(matches!(req.addr, Address::Domain(ref d, 53) if d == "udp.com"));
                assert!(req.payload.is_empty());
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_request_decode_need_more_data() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[b'a'; 50]); // Incomplete password

        assert!(matches!(
            TrojanRequest::decode_zerocopy(&mut buf),
            DecodeResult::NeedMoreData
        ));
    }

    #[test]
    fn test_trojan_request_decode_invalid_crlf() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[b'a'; 56]);
        buf.extend_from_slice(b"\n\r"); // Wrong order
                                        // Add padding to meet MIN_SIZE
        buf.extend_from_slice(&[0u8; 20]);

        assert!(matches!(
            TrojanRequest::decode_zerocopy(&mut buf),
            DecodeResult::Invalid(_)
        ));
    }

    #[test]
    fn test_trojan_request_decode_invalid_command() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[b'a'; 56]);
        buf.extend_from_slice(b"\r\n");
        buf.put_u8(99); // Invalid command
                        // Add padding to meet MIN_SIZE (need at least 68 bytes total)
        buf.extend_from_slice(&[0u8; 20]);

        assert!(matches!(
            TrojanRequest::decode_zerocopy(&mut buf),
            DecodeResult::Invalid(_)
        ));
    }

    #[test]
    fn test_address_encode_ipv4() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        let mut buf = Vec::new();
        let len = addr.encode(&mut buf);
        assert_eq!(len, 7); // 1 (atyp) + 4 (ip) + 2 (port)
        assert_eq!(buf, vec![1, 192, 168, 1, 1, 0x1F, 0x90]);
    }

    #[test]
    fn test_address_encode_ipv6() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let mut buf = Vec::new();
        let len = addr.encode(&mut buf);
        assert_eq!(len, 19); // 1 (atyp) + 16 (ip) + 2 (port)
        assert_eq!(buf[0], 4); // ATYP_IPV6
        assert_eq!(buf[17..19], [0x01, 0xBB]); // port 443
    }

    #[test]
    fn test_address_encode_domain() {
        let addr = Address::Domain("example.com".to_string(), 80);
        let mut buf = Vec::new();
        let len = addr.encode(&mut buf);
        assert_eq!(len, 15); // 1 (atyp) + 1 (len) + 11 (domain) + 2 (port)
        assert_eq!(buf[0], 3); // ATYP_DOMAIN
        assert_eq!(buf[1], 11); // domain length
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(buf[13..15], [0x00, 0x50]); // port 80
    }

    #[test]
    fn test_address_port() {
        assert_eq!(Address::IPv4([127, 0, 0, 1], 8080).port(), 8080);
        assert_eq!(Address::IPv6([0; 16], 443).port(), 443);
        assert_eq!(Address::Domain("example.com".to_string(), 80).port(), 80);
    }

    #[test]
    fn test_address_host() {
        assert_eq!(
            Address::IPv4([192, 168, 1, 1], 8080).host().as_ref(),
            "192.168.1.1"
        );
        assert_eq!(
            Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443)
                .host()
                .as_ref(),
            "::1"
        );
        assert_eq!(
            Address::Domain("example.com".to_string(), 80)
                .host()
                .as_ref(),
            "example.com"
        );
    }

    /// Verify that host() returns Cow::Borrowed for domains (zero allocation)
    /// and Cow::Owned for IP addresses.
    #[test]
    fn test_address_host_cow_borrowing() {
        use std::borrow::Cow;

        // Domain: should be Cow::Borrowed (no heap allocation)
        let domain = Address::Domain("example.com".to_string(), 80);
        let host = domain.host();
        assert!(
            matches!(host, Cow::Borrowed(_)),
            "Domain host should be Cow::Borrowed"
        );

        // IPv4: must be Cow::Owned (requires formatting)
        let ipv4 = Address::IPv4([10, 0, 0, 1], 80);
        let host = ipv4.host();
        assert!(
            matches!(host, Cow::Owned(_)),
            "IPv4 host should be Cow::Owned"
        );

        // IPv6: must be Cow::Owned (requires formatting)
        let ipv6 = Address::IPv6([0; 16], 443);
        let host = ipv6.host();
        assert!(
            matches!(host, Cow::Owned(_)),
            "IPv6 host should be Cow::Owned"
        );
    }

    /// Verify that host().into_owned() works for AclAddr construction
    #[test]
    fn test_address_host_into_owned() {
        let domain = Address::Domain("test.com".to_string(), 443);
        let owned: String = domain.host().into_owned();
        assert_eq!(owned, "test.com");

        let ipv4 = Address::IPv4([8, 8, 8, 8], 53);
        let owned: String = ipv4.host().into_owned();
        assert_eq!(owned, "8.8.8.8");
    }

    #[test]
    fn test_address_encode_decode_roundtrip() {
        let addresses = vec![
            Address::IPv4([192, 168, 1, 1], 8080),
            Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443),
            Address::Domain("example.com".to_string(), 80),
        ];

        for original in addresses {
            let mut buf = Vec::new();
            original.encode(&mut buf);

            match Address::decode(&buf) {
                DecodeResult::Ok(decoded, _) => {
                    assert_eq!(original, decoded);
                }
                _ => panic!("Failed to decode address"),
            }
        }
    }

    #[test]
    fn test_trojan_udp_packet_decode_ipv4() {
        // Build a UDP packet: IPv4 addr + length + CRLF + payload
        let mut buf = Vec::new();
        buf.push(1); // ATYP_IPV4
        buf.extend_from_slice(&[8, 8, 8, 8]); // 8.8.8.8
        buf.extend_from_slice(&[0x00, 0x35]); // port 53
        buf.extend_from_slice(&[0x00, 0x05]); // length 5
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(b"hello");

        match TrojanUdpPacket::decode(&buf) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(packet.addr, Address::IPv4([8, 8, 8, 8], 53)));
                assert_eq!(packet.payload.as_ref(), b"hello");
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_decode_domain() {
        let mut buf = Vec::new();
        buf.push(3); // ATYP_DOMAIN
        buf.push(7); // domain length
        buf.extend_from_slice(b"dns.com");
        buf.extend_from_slice(&[0x00, 0x35]); // port 53
        buf.extend_from_slice(&[0x00, 0x03]); // length 3
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(b"abc");

        match TrojanUdpPacket::decode(&buf) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, buf.len());
                assert!(matches!(packet.addr, Address::Domain(ref d, 53) if d == "dns.com"));
                assert_eq!(packet.payload.as_ref(), b"abc");
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_decode_need_more_data() {
        // Incomplete header
        let buf = vec![1, 8, 8, 8]; // incomplete IPv4
        assert!(matches!(
            TrojanUdpPacket::decode(&buf),
            DecodeResult::NeedMoreData
        ));

        // Complete address but missing length
        let buf = vec![1, 8, 8, 8, 8, 0x00, 0x35]; // IPv4 + port, no length
        assert!(matches!(
            TrojanUdpPacket::decode(&buf),
            DecodeResult::NeedMoreData
        ));

        // Missing payload
        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(&[8, 8, 8, 8, 0x00, 0x35]); // addr
        buf.extend_from_slice(&[0x00, 0x10]); // length 16
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(b"short"); // only 5 bytes, need 16
        assert!(matches!(
            TrojanUdpPacket::decode(&buf),
            DecodeResult::NeedMoreData
        ));
    }

    #[test]
    fn test_trojan_udp_packet_decode_invalid_crlf() {
        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(&[8, 8, 8, 8, 0x00, 0x35]);
        buf.extend_from_slice(&[0x00, 0x05]);
        buf.extend_from_slice(b"\n\r"); // wrong order
        buf.extend_from_slice(b"hello");

        assert!(matches!(
            TrojanUdpPacket::decode(&buf),
            DecodeResult::Invalid(_)
        ));
    }

    #[test]
    fn test_trojan_udp_packet_encode() {
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        let payload = b"hello";
        let encoded = TrojanUdpPacket::encode(&addr, payload);

        // Verify structure
        assert_eq!(encoded[0], 1); // ATYP_IPV4
        assert_eq!(&encoded[1..5], &[8, 8, 8, 8]); // IP
        assert_eq!(&encoded[5..7], &[0x00, 0x35]); // port 53
        assert_eq!(&encoded[7..9], &[0x00, 0x05]); // length 5
        assert_eq!(&encoded[9..11], b"\r\n"); // CRLF
        assert_eq!(&encoded[11..], b"hello"); // payload
    }

    #[test]
    fn test_trojan_udp_packet_encode_decode_roundtrip() {
        let addr = Address::Domain("test.example.com".to_string(), 443);
        let payload = b"test data packet";

        let encoded = TrojanUdpPacket::encode(&addr, payload);

        match TrojanUdpPacket::decode(&encoded) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, encoded.len());
                assert_eq!(packet.addr, addr);
                assert_eq!(packet.payload.as_ref(), payload);
            }
            _ => panic!("Failed to decode encoded packet"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_decode_multiple_packets() {
        // Create two packets in one buffer
        let addr1 = Address::IPv4([1, 1, 1, 1], 53);
        let addr2 = Address::IPv4([8, 8, 8, 8], 53);
        let packet1 = TrojanUdpPacket::encode(&addr1, b"first");
        let packet2 = TrojanUdpPacket::encode(&addr2, b"second");

        let mut buf = Vec::new();
        buf.extend_from_slice(&packet1);
        buf.extend_from_slice(&packet2);

        // Decode first packet
        match TrojanUdpPacket::decode(&buf) {
            DecodeResult::Ok(p1, consumed1) => {
                assert!(matches!(p1.addr, Address::IPv4([1, 1, 1, 1], 53)));
                assert_eq!(p1.payload.as_ref(), b"first");

                // Decode second packet
                match TrojanUdpPacket::decode(&buf[consumed1..]) {
                    DecodeResult::Ok(p2, _) => {
                        assert!(matches!(p2.addr, Address::IPv4([8, 8, 8, 8], 53)));
                        assert_eq!(p2.payload.as_ref(), b"second");
                    }
                    _ => panic!("Failed to decode second packet"),
                }
            }
            _ => panic!("Failed to decode first packet"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_empty_payload() {
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let encoded = TrojanUdpPacket::encode(&addr, b"");

        match TrojanUdpPacket::decode(&encoded) {
            DecodeResult::Ok(packet, _) => {
                assert!(packet.payload.is_empty());
            }
            _ => panic!("Failed to decode empty payload packet"),
        }
    }

    // --- decode_zerocopy tests ---

    #[test]
    fn test_udp_decode_zerocopy_ipv4() {
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        let encoded = TrojanUdpPacket::encode(&addr, b"hello");
        let mut buf = BytesMut::from(&encoded[..]);

        match TrojanUdpPacket::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, encoded.len());
                assert!(matches!(packet.addr, Address::IPv4([8, 8, 8, 8], 53)));
                assert_eq!(packet.payload.as_ref(), b"hello");
            }
            _ => panic!("Expected successful zerocopy decode"),
        }
        // Buffer should be fully consumed
        assert!(buf.is_empty());
    }

    #[test]
    fn test_udp_decode_zerocopy_domain() {
        let addr = Address::Domain("dns.example.com".to_string(), 53);
        let encoded = TrojanUdpPacket::encode(&addr, b"query");
        let mut buf = BytesMut::from(&encoded[..]);

        match TrojanUdpPacket::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(packet, _) => {
                assert!(
                    matches!(packet.addr, Address::Domain(ref d, 53) if d == "dns.example.com")
                );
                assert_eq!(packet.payload.as_ref(), b"query");
            }
            _ => panic!("Expected successful zerocopy decode"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn test_udp_decode_zerocopy_empty_payload() {
        let addr = Address::IPv4([1, 2, 3, 4], 80);
        let encoded = TrojanUdpPacket::encode(&addr, b"");
        let mut buf = BytesMut::from(&encoded[..]);

        match TrojanUdpPacket::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(packet, _) => {
                assert!(packet.payload.is_empty());
            }
            _ => panic!("Expected successful zerocopy decode"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn test_udp_decode_zerocopy_need_more_data() {
        // Incomplete packet
        let mut buf = BytesMut::from(&[1u8, 8, 8, 8][..]);
        assert!(matches!(
            TrojanUdpPacket::decode_zerocopy(&mut buf),
            DecodeResult::NeedMoreData
        ));
        // Buffer should be unchanged on NeedMoreData
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_udp_decode_zerocopy_invalid_crlf() {
        let mut raw = Vec::new();
        raw.push(1); // ATYP_IPV4
        raw.extend_from_slice(&[8, 8, 8, 8, 0x00, 0x35]); // addr
        raw.extend_from_slice(&[0x00, 0x05]); // length
        raw.extend_from_slice(b"\n\r"); // wrong CRLF order
        raw.extend_from_slice(b"hello");

        let mut buf = BytesMut::from(&raw[..]);
        assert!(matches!(
            TrojanUdpPacket::decode_zerocopy(&mut buf),
            DecodeResult::Invalid(_)
        ));
    }

    /// Verify decode_zerocopy processes multiple packets from a single BytesMut,
    /// consuming data progressively — this is the pattern used in handle_udp_associate.
    #[test]
    fn test_udp_decode_zerocopy_multiple_packets() {
        let addr1 = Address::IPv4([1, 1, 1, 1], 53);
        let addr2 = Address::Domain("test.com".to_string(), 443);
        let pkt1 = TrojanUdpPacket::encode(&addr1, b"first");
        let pkt2 = TrojanUdpPacket::encode(&addr2, b"second");

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&pkt1);
        buf.extend_from_slice(&pkt2);

        let original_len = buf.len();

        // Decode first packet
        match TrojanUdpPacket::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(p, _) => {
                assert!(matches!(p.addr, Address::IPv4([1, 1, 1, 1], 53)));
                assert_eq!(p.payload.as_ref(), b"first");
            }
            _ => panic!("Failed to decode first packet"),
        }
        assert_eq!(buf.len(), original_len - pkt1.len());

        // Decode second packet
        match TrojanUdpPacket::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(p, _) => {
                assert!(matches!(p.addr, Address::Domain(ref d, 443) if d == "test.com"));
                assert_eq!(p.payload.as_ref(), b"second");
            }
            _ => panic!("Failed to decode second packet"),
        }
        assert!(buf.is_empty());
    }

    /// Verify zerocopy decode produces same result as copy-based decode
    #[test]
    fn test_udp_decode_zerocopy_matches_decode() {
        let test_cases = vec![
            (Address::IPv4([10, 0, 0, 1], 80), b"ipv4 payload".to_vec()),
            (
                Address::IPv6([0; 16], 443),
                b"ipv6 payload with more data".to_vec(),
            ),
            (
                Address::Domain("example.org".to_string(), 8080),
                b"domain".to_vec(),
            ),
            (Address::IPv4([255, 255, 255, 0], 1), vec![0xAB; 512]),
        ];

        for (addr, payload) in test_cases {
            let encoded = TrojanUdpPacket::encode(&addr, &payload);

            // Decode with copy-based method
            let copy_result = TrojanUdpPacket::decode(&encoded);

            // Decode with zerocopy method
            let mut buf = BytesMut::from(&encoded[..]);
            let zc_result = TrojanUdpPacket::decode_zerocopy(&mut buf);

            match (copy_result, zc_result) {
                (DecodeResult::Ok(p1, c1), DecodeResult::Ok(p2, c2)) => {
                    assert_eq!(p1.addr, p2.addr, "Addresses must match");
                    assert_eq!(p1.payload, p2.payload, "Payloads must match");
                    assert_eq!(c1, c2, "Consumed bytes must match");
                }
                _ => panic!("Both decode methods should succeed for addr={}", addr),
            }
        }
    }

    // --- Address::encode domain length protection tests ---

    #[test]
    fn test_address_encode_max_length_domain() {
        // 255 byte domain — maximum valid length
        let domain = "a".repeat(255);
        let addr = Address::Domain(domain.clone(), 80);
        let mut buf = Vec::new();
        let len = addr.encode(&mut buf);

        assert_eq!(len, 1 + 1 + 255 + 2); // atyp + len + domain + port
        assert_eq!(buf[1], 255); // length byte should be 255

        // Roundtrip: decode should recover the same domain
        match Address::decode(&buf) {
            DecodeResult::Ok(decoded, _) => {
                assert_eq!(decoded, addr);
            }
            _ => panic!("Failed to roundtrip 255-byte domain"),
        }
    }

    /// In debug builds, encoding a >255 byte domain panics via debug_assert.
    #[test]
    #[should_panic(expected = "domain too long for Trojan protocol")]
    fn test_address_encode_overlong_domain_panics_in_debug() {
        let domain = "b".repeat(300);
        let addr = Address::Domain(domain, 443);
        let mut buf = Vec::new();
        addr.encode(&mut buf);
    }
}
