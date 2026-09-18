//! Hook traits for extensibility
//!
//! Defines the extension points that allow business logic to be injected into the core proxy.

use crate::core::Address;
use async_trait::async_trait;
use dns_cache_rs::DnsCache;

/// User ID type used throughout the system.
/// Using i64 for consistency with database and API layer.
pub type UserId = i64;

/// Authenticator trait for user authentication
///
/// Synchronous by design: authentication is a hash-table lookup (ArcSwap),
/// not an I/O operation. Eliminating `async_trait` avoids one `Box<dyn Future>`
/// heap allocation per connection on the hot path.
pub trait Authenticator: Send + Sync {
    /// Authenticate user by password hash, returns user_id if successful
    fn authenticate(&self, password: &[u8; 56]) -> Option<UserId>;
}

/// Statistics collector trait for traffic tracking
pub trait StatsCollector: Send + Sync {
    /// Record a proxy request
    fn record_request(&self, user_id: UserId);
    /// Record upload bytes (client -> remote)
    fn record_upload(&self, user_id: UserId, bytes: u64);
    /// Record download bytes (remote -> client)
    fn record_download(&self, user_id: UserId, bytes: u64);
}

/// Outbound router trait for routing decisions
#[async_trait]
pub trait OutboundRouter: Send + Sync {
    /// Route a TCP session by target address, returns the outbound handler
    async fn route(&self, addr: &Address) -> OutboundType;

    /// Route a UDP session by target address. Protocol-qualified ACL rules
    /// (`udp/443`) only apply here; routers without protocol awareness fall
    /// back to `route`.
    async fn route_udp(&self, addr: &Address) -> OutboundType {
        self.route(addr).await
    }
}

/// Outbound type for routing decisions
#[derive(Clone)]
pub enum OutboundType {
    /// Direct connection, optionally with a pre-resolved address to skip redundant DNS.
    /// When the router already resolved the domain (e.g. for SSRF checking), it passes
    /// the result here so the handler can reuse it instead of resolving again.
    /// The handler is passed when ACL is configured so bind/fastOpen options are respected.
    Direct {
        resolved: Option<crate::core::dns::ResolvedAddrs>,
        handler: Option<std::sync::Arc<crate::acl::OutboundHandler>>,
    },
    /// Reject connection
    Reject,
    /// Proxy connection via ACL engine outbound handler. `hijack` rewrites the
    /// destination (rule `outbound(match, proto/port, hijackAddress)`).
    Proxy {
        handler: std::sync::Arc<crate::acl::OutboundHandler>,
        hijack: Option<std::net::IpAddr>,
    },
}

impl std::fmt::Debug for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundType::Direct {
                resolved: None,
                handler: None,
            } => write!(f, "Direct"),
            OutboundType::Direct {
                resolved: Some(addr),
                ..
            } => write!(f, "Direct({})", addr.socket_addr()),
            OutboundType::Direct {
                handler: Some(h), ..
            } => write!(f, "Direct({:?})", h),
            OutboundType::Reject => write!(f, "Reject"),
            OutboundType::Proxy { handler, hijack } => match hijack {
                Some(ip) => write!(f, "Proxy({:?} → {})", handler, ip),
                None => write!(f, "Proxy({:?})", handler),
            },
        }
    }
}

/// Direct router - routes all traffic directly with optional private IP blocking
pub struct DirectRouter {
    /// Block connections to private/loopback IP addresses
    block_private_ip: bool,
    /// Shared DNS cache (clone of `Server.dns_cache`).
    dns_cache: DnsCache,
}

impl DirectRouter {
    /// Create a new DirectRouter sharing the given DNS cache.
    pub fn with_cache(block_private_ip: bool, dns_cache: DnsCache) -> Self {
        Self {
            block_private_ip,
            dns_cache,
        }
    }
}

#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, addr: &Address) -> OutboundType {
        use crate::core::dns::{screen_direct_target, DirectTarget};
        match screen_direct_target(&self.dns_cache, addr, self.block_private_ip).await {
            DirectTarget::Blocked => OutboundType::Reject,
            DirectTarget::Allow(resolved) => OutboundType::Direct {
                resolved,
                handler: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use dns_cache_rs::{DnsCache, MockResolver};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    /// Build a `DnsCache` backed by a `MockResolver` that returns the given
    /// result for the given host. Lets DirectRouter tests pin DNS behavior
    /// without depending on the network.
    fn mock_cache_with(
        host: &str,
        result: Result<Vec<IpAddr>, dns_cache_rs::DnsError>,
    ) -> DnsCache {
        let mock = Arc::new(MockResolver::new());
        mock.set(host, result);
        DnsCache::builder()
            .resolver_arc(mock as Arc<dyn dns_cache_rs::Resolver>)
            .build()
            .expect("DnsCache build with MockResolver")
    }

    #[tokio::test]
    async fn test_direct_router_public_domain() {
        let cache = mock_cache_with(
            "example.com",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        );
        let router = DirectRouter::with_cache(true, cache);
        let addr = Address::Domain("example.com".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            OutboundType::Direct {
                resolved: Some(_),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_loopback() {
        let router = DirectRouter::with_cache(true, dns_cache_rs::DnsCache::new());
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_private_ip() {
        let router = DirectRouter::with_cache(true, dns_cache_rs::DnsCache::new());

        // 10.0.0.0/8
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));

        // 192.168.0.0/16
        let addr = Address::IPv4([192, 168, 1, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_allows_public_ip() {
        let router = DirectRouter::with_cache(true, dns_cache_rs::DnsCache::new());
        let addr = Address::IPv4([8, 8, 8, 8], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            OutboundType::Direct {
                resolved: None,
                handler: None
            }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_allows_private_when_disabled() {
        let router = DirectRouter::with_cache(false, dns_cache_rs::DnsCache::new());
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            OutboundType::Direct {
                resolved: None,
                handler: None
            }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_domain_resolving_to_private() {
        // Replaces the previous network-based "localhost" test. Mocked
        // resolver returns a private IP, so the router must Reject the
        // domain target with block_private_ip=true.
        let cache = mock_cache_with(
            "internal.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]),
        );
        let router = DirectRouter::with_cache(true, cache);
        let addr = Address::Domain("internal.example".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }
}
