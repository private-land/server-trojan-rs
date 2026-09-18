//! DNS resolution for vmess-rs.
//!
//! Single entry point for converting `Address` values into `SocketAddr`s,
//! and for the SSRF private-IP check that needs the resolved address.
//!
//! Backed by `dns_cache_rs::DnsCache`: per-entry TTL, singleflight,
//! negative caching, pluggable resolver. The cache is constructed in
//! `main.rs`, owned by `Server`, and cloned into the routers (cheap —
//! `DnsCache: Clone` over Arc).

use std::io;
use std::net::SocketAddr;

use dns_cache_rs::{DnsCache, DnsError};

use super::Address;

/// Map a `dns_cache_rs::DnsError` to an `io::Error`.
fn dns_error_to_io(err: DnsError) -> io::Error {
    match err {
        DnsError::NotFound(host) => io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses found for {host}"),
        ),
        DnsError::Timeout(d) => io::Error::new(
            io::ErrorKind::TimedOut,
            format!("DNS query timeout after {d:?}"),
        ),
        DnsError::InvalidHost(h) => {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid host: {h}"))
        }
        DnsError::Other(e) => io::Error::other(e.to_string()),
    }
}

/// Outcome of screening/resolving a direct target.
pub enum DirectTarget {
    /// Private/loopback (or unresolvable under block_private_ip): reject.
    Blocked,
    /// Connect with these pre-resolved addresses (None for IP literals when
    /// no screening was needed, or when resolution failed without screening).
    Allow(Option<ResolvedAddrs>),
}

/// Policy shared by every router for targets that go out directly:
/// screen against private ranges when `block_private_ip` (resolving
/// domains through the shared cache and failing closed), otherwise still
/// resolve domains through the cache so the outbound never has to.
pub(crate) async fn screen_direct_target(
    cache: &DnsCache,
    addr: &Address,
    block_private_ip: bool,
) -> DirectTarget {
    if block_private_ip {
        let (is_private, resolved) = check_private_and_resolve(cache, addr).await;
        if is_private {
            tracing::debug!(target = %addr, "Blocked private address");
            return DirectTarget::Blocked;
        }
        return DirectTarget::Allow(resolved);
    }
    match addr {
        // resolution failures are left to the outbound (it may retry)
        Address::Domain(..) => DirectTarget::Allow(resolve_addrs(cache, addr).await.ok()),
        _ => DirectTarget::Allow(None),
    }
}

/// Resolve an `Address` to connect candidates (first of each family, in
/// resolver order). IP literals bypass the cache.
pub async fn resolve_addrs(cache: &DnsCache, addr: &Address) -> io::Result<ResolvedAddrs> {
    let (host, port) = match addr {
        Address::IPv4(ip, port) => {
            return Ok(ResolvedAddrs {
                v4: Some((*ip).into()),
                v6: None,
                port: *port,
                v6_first: false,
            })
        }
        Address::IPv6(ip, port) => {
            return Ok(ResolvedAddrs {
                v4: None,
                v6: Some((*ip).into()),
                port: *port,
                v6_first: true,
            })
        }
        Address::Domain(host, port) => (host, *port),
    };
    let it = cache
        .resolve_with_port_iter(host, port)
        .await
        .map_err(dns_error_to_io)?;
    ResolvedAddrs::collect(port, it.map(|sa| sa.ip())).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses found for {host}"),
        )
    })
}

/// Public addresses a domain resolved to, one per family, so a direct
/// outbound can honour its address-family mode (only6 / prefer6 / auto)
/// without resolving again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAddrs {
    pub v4: Option<std::net::Ipv4Addr>,
    pub v6: Option<std::net::Ipv6Addr>,
    pub port: u16,
    /// The resolver listed an IPv6 address first (RFC 6724 preference on a
    /// v6-preferring host); `candidates` keeps that order.
    pub v6_first: bool,
}

impl ResolvedAddrs {
    /// Connect candidates in resolver-preference order, the other family as
    /// fallback (one or two entries).
    pub fn candidates(&self) -> impl Iterator<Item = SocketAddr> {
        use std::net::IpAddr;
        let v4 = self.v4.map(|ip| SocketAddr::new(IpAddr::V4(ip), self.port));
        let v6 = self.v6.map(|ip| SocketAddr::new(IpAddr::V6(ip), self.port));
        let (first, second) = if self.v6_first { (v6, v4) } else { (v4, v6) };
        first.into_iter().chain(second)
    }

    /// Fold resolver output: first address of each family, remembering
    /// which family the resolver listed first. `None` when empty.
    pub fn collect(port: u16, ips: impl IntoIterator<Item = std::net::IpAddr>) -> Option<Self> {
        use std::net::IpAddr;
        let mut out = ResolvedAddrs {
            v4: None,
            v6: None,
            port,
            v6_first: false,
        };
        for ip in ips {
            match ip {
                IpAddr::V4(v4) => {
                    out.v4.get_or_insert(v4);
                }
                IpAddr::V6(v6) => {
                    if out.v4.is_none() && out.v6.is_none() {
                        out.v6_first = true;
                    }
                    out.v6.get_or_insert(v6);
                }
            }
        }
        (out.v4.is_some() || out.v6.is_some()).then_some(out)
    }

    /// Preferred single address (first of `candidates`).
    pub fn socket_addr(&self) -> SocketAddr {
        self.candidates()
            .next()
            .expect("ResolvedAddrs always holds at least one address")
    }
}

/// Check whether an address is private/loopback/link-local. For domain
/// addresses, also returns the non-private resolved addresses (first of each
/// family) so callers can reuse them without a second DNS lookup.
///
/// **Error semantics**: a resolver error (NotFound, Timeout, InvalidHost,
/// Other) is reported as *private* (`(true, None)`). Callers only invoke this
/// under `block_private_ip`, and a domain whose addresses could not be
/// checked must not be handed to an outbound that re-resolves it unchecked
/// (fail closed).
pub(crate) async fn check_private_and_resolve(
    cache: &DnsCache,
    addr: &Address,
) -> (bool, Option<ResolvedAddrs>) {
    use super::ip_filter::is_private_ip;
    use std::net::IpAddr;

    match addr {
        Address::IPv4(ip, _) => (is_private_ip(&IpAddr::from(*ip)), None),
        Address::IPv6(ip, _) => (is_private_ip(&IpAddr::from(*ip)), None),
        Address::Domain(host, port) => {
            // A domain-typed literal needs no lookup either.
            if let Ok(ip) = host.parse::<IpAddr>() {
                return (is_private_ip(&ip), None);
            }
            let it = match cache.resolve_with_port_iter(host, *port).await {
                Ok(it) => it,
                Err(e) => {
                    tracing::debug!(host = %host, error = %e, "DNS resolution failed; rejecting under block_private_ip");
                    return (true, None);
                }
            };
            let ips: Vec<IpAddr> = it.map(|sa| sa.ip()).collect();
            let private = ips.iter().any(is_private_ip);
            if private {
                return (true, None);
            }
            (false, ResolvedAddrs::collect(*port, ips))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use dns_cache_rs::{DnsCache, MockResolver};

    fn mock_cache() -> (DnsCache, Arc<MockResolver>) {
        let mock = Arc::new(MockResolver::new());
        let cache = DnsCache::builder()
            .resolver_arc(mock.clone() as Arc<dyn dns_cache_rs::Resolver>)
            .build()
            .expect("DnsCache build with MockResolver");
        (cache, mock)
    }

    #[tokio::test]
    async fn resolve_addrs_ipv4_literal_bypasses_cache() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let got = resolve_addrs(&cache, &addr).await.unwrap().socket_addr();
        assert_eq!(got, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(mock.total_calls(), 0, "IP literal must not hit resolver");
    }

    #[tokio::test]
    async fn resolve_addrs_ipv6_literal_bypasses_cache() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let got = resolve_addrs(&cache, &addr).await.unwrap().socket_addr();
        assert_eq!(got.to_string(), "[::1]:443");
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn resolve_addrs_domain_returns_first_address_with_port() {
        let (cache, mock) = mock_cache();
        mock.set(
            "example.com",
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ]),
        );
        let addr = Address::Domain("example.com".into(), 8080);
        let got = resolve_addrs(&cache, &addr).await.unwrap().socket_addr();
        assert_eq!(got, "93.184.216.34:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(mock.call_count("example.com"), 1);
    }

    #[tokio::test]
    async fn resolve_addrs_domain_not_found_maps_to_io_not_found() {
        let (cache, mock) = mock_cache();
        // MockResolver returns NotFound for any unmapped host.
        let addr = Address::Domain("nx.invalid".into(), 80);
        let err = resolve_addrs(&cache, &addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(mock.call_count("nx.invalid") >= 1);
    }

    #[tokio::test]
    async fn resolve_addrs_domain_timeout_maps_to_io_timedout() {
        let (cache, mock) = mock_cache();
        mock.set(
            "slow.example",
            Err(dns_cache_rs::DnsError::Timeout(
                std::time::Duration::from_millis(50),
            )),
        );
        let addr = Address::Domain("slow.example".into(), 80);
        let err = resolve_addrs(&cache, &addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn check_private_and_resolve_ipv4_private_literal() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn check_private_and_resolve_ipv6_private_literal() {
        let (cache, mock) = mock_cache();
        // ::1 is loopback
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 80);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn check_private_and_resolve_public_ip_literal() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(!is_private);
        assert!(
            resolved.is_none(),
            "IP literals never carry a resolved addr"
        );
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn check_private_and_resolve_domain_resolves_to_private() {
        let (cache, mock) = mock_cache();
        mock.set(
            "internal.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]),
        );
        let addr = Address::Domain("internal.example".into(), 443);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
    }

    /// Both address families are kept so a direct outbound configured for
    /// only6/prefer6 still has an IPv6 candidate after the private-IP check.
    #[tokio::test]
    async fn check_private_and_resolve_keeps_first_public_of_each_family() {
        use std::net::Ipv6Addr;
        let (cache, mock) = mock_cache();
        mock.set(
            "dual.example",
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(
                    "2606:2800:220:1:248:1893:25c8:1946"
                        .parse::<Ipv6Addr>()
                        .unwrap(),
                ),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
            ]),
        );
        let addr = Address::Domain("dual.example".into(), 443);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(!is_private);
        let r = resolved.unwrap();
        assert_eq!(r.v4, Some(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(
            r.v6,
            Some("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap())
        );
        assert_eq!(r.port, 443);
        assert!(!r.v6_first);
        assert_eq!(
            r.socket_addr().ip(),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(r.candidates().count(), 2);

        // resolver order is preserved: AAAA first → connect IPv6 first, IPv4 fallback
        mock.set(
            "v6first.example",
            Ok(vec![
                IpAddr::V6(
                    "2606:2800:220:1:248:1893:25c8:1946"
                        .parse::<Ipv6Addr>()
                        .unwrap(),
                ),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            ]),
        );
        let (_, r) =
            check_private_and_resolve(&cache, &Address::Domain("v6first.example".into(), 80)).await;
        let r = r.unwrap();
        assert!(r.v6_first);
        let c: Vec<_> = r.candidates().collect();
        assert!(c[0].is_ipv6() && c[1].is_ipv4());
    }

    #[tokio::test]
    async fn check_private_and_resolve_domain_resolves_to_public() {
        let (cache, mock) = mock_cache();
        mock.set(
            "example.com",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        );
        let addr = Address::Domain("example.com".into(), 443);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(!is_private);
        let sa = resolved.expect("public domain must return a resolved addr");
        assert_eq!(
            sa.socket_addr(),
            "93.184.216.34:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn check_private_and_resolve_domain_resolution_failure_fails_closed() {
        // A domain we could not resolve cannot be checked for private
        // addresses; under block_private_ip it must be rejected rather than
        // handed to an outbound that resolves it again unchecked.
        let (cache, _mock) = mock_cache();
        let addr = Address::Domain("nx.invalid".into(), 80);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn resolve_addrs_hits_cache_on_second_call() {
        let (cache, mock) = mock_cache();
        mock.set(
            "hit.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
        );
        let addr = Address::Domain("hit.example".into(), 80);

        resolve_addrs(&cache, &addr).await.unwrap();
        resolve_addrs(&cache, &addr).await.unwrap();

        assert_eq!(
            mock.call_count("hit.example"),
            1,
            "cache must coalesce the second call"
        );
    }

    #[tokio::test]
    async fn resolve_addrs_singleflight_coalesces_concurrent_calls() {
        use futures_util::future::join_all;

        let (cache, mock) = mock_cache();
        mock.set(
            "race.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]),
        );
        // Force concurrent callers to overlap inside the resolver.
        mock.set_delay(Some(std::time::Duration::from_millis(50)));

        let futs: Vec<_> = (0..100)
            .map(|_| {
                let c = cache.clone();
                tokio::spawn(async move {
                    let addr = Address::Domain("race.example".into(), 80);
                    resolve_addrs(&c, &addr).await.unwrap();
                })
            })
            .collect();
        join_all(futs).await;

        assert_eq!(
            mock.call_count("race.example"),
            1,
            "singleflight must collapse 100 concurrent misses into one resolver call"
        );
    }

    #[tokio::test]
    async fn resolve_addrs_negative_caching_holds_not_found() {
        let (cache, mock) = mock_cache();
        // Unmapped host => NotFound on every direct resolver call.
        let addr = Address::Domain("nx.example".into(), 80);

        let _ = resolve_addrs(&cache, &addr).await;
        let _ = resolve_addrs(&cache, &addr).await;

        assert_eq!(
            mock.call_count("nx.example"),
            1,
            "negative caching must hold the NotFound result"
        );
    }

    #[tokio::test]
    async fn resolve_addrs_refetches_after_positive_ttl_expires() {
        // moka uses std::time::Instant (not tokio's mock clock), so we must use
        // a short real TTL + real sleep. This mirrors the approach used in
        // dns-cache-rs's own `positive_ttl_expires_then_re_resolves` test.
        let mock = std::sync::Arc::new(dns_cache_rs::MockResolver::new());
        mock.set(
            "ttl.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))]),
        );
        let cache = dns_cache_rs::DnsCache::builder()
            .resolver_arc(mock.clone() as std::sync::Arc<dyn dns_cache_rs::Resolver>)
            .ttl(std::time::Duration::from_millis(200))
            .build()
            .expect("DnsCache build with short TTL");
        let addr = Address::Domain("ttl.example".into(), 80);

        resolve_addrs(&cache, &addr).await.unwrap();
        assert_eq!(mock.call_count("ttl.example"), 1);

        // Advance past the 200ms TTL with a 400ms margin to absorb CI jitter.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        resolve_addrs(&cache, &addr).await.unwrap();
        assert_eq!(
            mock.call_count("ttl.example"),
            2,
            "after TTL expiry the resolver must be invoked again"
        );
    }

    // --- Regression: empty-domain edge case migrated from protocol.rs ---

    #[tokio::test]
    async fn migrated_to_socket_addr_empty_domain_fails() {
        // Pre-refactor: `Address::Domain("", 80).to_socket_addr()` returned Err.
        // dns-cache-rs's normalize step rejects empty hosts → InvalidHost.
        let (cache, _) = mock_cache();
        let addr = Address::Domain(String::new(), 80);
        let err = resolve_addrs(&cache, &addr).await.unwrap_err();
        // Either NotFound (no addrs) or InvalidInput (empty host) is acceptable;
        // we just need a hard error like the pre-refactor behavior.
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
            ),
            "expected NotFound or InvalidInput, got {:?}",
            err.kind()
        );
    }
}
