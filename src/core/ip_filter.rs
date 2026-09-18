//! IP address filtering utilities for SSRF protection.
//!
//! Provides functions to detect private, loopback, and link-local addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if an IPv4 address is private/loopback/link-local/reserved
pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()                   // 127.0.0.0/8
        || ip.is_private()             // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()          // 169.254.0.0/16
        || octets[0] == 0             // 0.0.0.0/8 ("this network")
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)  // 100.64.0.0/10 (CGN, RFC 6598)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)  // 192.0.0.0/24 (IETF protocol)
        || ip.is_broadcast()           // 255.255.255.255
        || ip.is_multicast() // 224.0.0.0/4
}

/// Private/loopback/link-local check for either family.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// Check if an IPv6 address is private/loopback/link-local/ULA, or an IPv6
/// form that embeds a private IPv4 address (IPv4-mapped `::ffff:a.b.c.d`,
/// IPv4-compatible `::a.b.c.d`, NAT64 `64:ff9b::a.b.c.d`).
pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    if let Some(v4) = embedded_ipv4(ip) {
        return is_private_ipv4(&v4);
    }
    ip.is_unspecified()        // ::
        || ip.is_loopback()    // ::1
        || ip.is_multicast()   // ff00::/8
        || is_ipv6_ula(ip)     // fc00::/7 (Unique Local Address)
        || is_ipv6_link_local(ip) // fe80::/10
}

/// IPv4 address carried inside an IPv6 one, if any.
fn embedded_ipv4(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32));
    }
    // ::ffff:a.b.c.d
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    // the deprecated ::a.b.c.d, excluding :: and ::1 (handled as IPv6)
    if s[..6] == [0; 6] && (s[6] != 0 || s[7] > 1) {
        return Some(Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32));
    }
    None
}

/// Check if IPv6 is Unique Local Address (fc00::/7)
fn is_ipv6_ula(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if IPv6 is link-local (fe80::/10)
fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    #[test]
    fn ipv6_forms_embedding_private_ipv4_are_private() {
        use super::is_private_ipv6;
        use std::net::Ipv6Addr;
        for s in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.5",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "::",
            "ff02::1",
        ] {
            assert!(is_private_ipv6(&s.parse::<Ipv6Addr>().unwrap()), "{s}");
        }
        for s in ["::ffff:8.8.8.8", "64:ff9b::808:808", "2001:db8::1"] {
            assert!(!is_private_ipv6(&s.parse::<Ipv6Addr>().unwrap()), "{s}");
        }
    }

    use super::*;

    #[test]
    fn test_is_private_ipv4_loopback() {
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_class_a() {
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_class_b() {
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 1))); // Outside range
    }

    #[test]
    fn test_is_private_ipv4_class_c() {
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_link_local() {
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_public() {
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(142, 250, 80, 14)));
    }

    #[test]
    fn test_is_private_ipv6_loopback() {
        assert!(is_private_ipv6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_is_private_ipv6_ula() {
        assert!(is_private_ipv6(&"fc00::1".parse().unwrap()));
        assert!(is_private_ipv6(&"fd00::1".parse().unwrap()));
        assert!(is_private_ipv6(
            &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_link_local() {
        assert!(is_private_ipv6(&"fe80::1".parse().unwrap()));
        assert!(is_private_ipv6(
            &"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_public() {
        assert!(!is_private_ipv6(&"2001:4860:4860::8888".parse().unwrap())); // Google DNS
        assert!(!is_private_ipv6(&"2606:4700:4700::1111".parse().unwrap())); // Cloudflare
    }

    #[test]
    fn test_is_private_ipv4_this_network() {
        assert!(is_private_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(0, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_cgn() {
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(100, 128, 0, 1))); // Outside CGN range
    }

    #[test]
    fn test_is_private_ipv4_ietf_protocol() {
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 0, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(192, 0, 1, 1))); // Outside range
    }

    #[test]
    fn test_is_private_ipv4_broadcast() {
        assert!(is_private_ipv4(&Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_multicast() {
        assert!(is_private_ipv4(&Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(239, 255, 255, 255)));
    }
}
