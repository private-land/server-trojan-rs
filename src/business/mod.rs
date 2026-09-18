//! Business logic implementations
//!
//! Thin wrappers bridging panel-core types to core::hooks traits.
//! All heavy lifting (API calls, user management, stats collection,
//! background tasks) lives in `panel-core` and `panel-connect-rpc`.

use std::sync::Arc;

use crate::core::hooks::{Authenticator, StatsCollector};
use crate::core::UserId;

pub use panel_connect_rpc::{
    ConnectRpcApiManager as ApiManager, ConnectRpcPanelConfig as PanelConfig, IpVersion,
};
pub use panel_core::{
    BackgroundTasks, NodeConfigEnum, NodeType, PanelApi, StatsCollector as PanelStatsCollector,
    TaskConfig, UserManager,
};

/// Trojan-specific UserManager using SHA-224 hex keys ([u8; 56])
pub type TrojanUserManager = UserManager<[u8; 56]>;

/// Trojan authenticator wrapping panel-core's UserManager.
///
/// Delegates SHA224 password lookup to UserManager's lock-free ArcSwap map.
pub struct TrojanAuthenticator(pub Arc<TrojanUserManager>);

impl Authenticator for TrojanAuthenticator {
    fn authenticate(&self, password: &[u8; 56]) -> Option<UserId> {
        self.0.authenticate(password)
    }
}

/// Submit everything the collector has accumulated right now.
///
/// Used once at shutdown *before* the node unregisters: after `unregister`
/// the HTTP client has no `register_id` and the background task's own final
/// report fails with "Not registered", silently dropping the drained traffic.
pub async fn flush_traffic(api: &dyn panel_core::PanelApi, stats: &PanelStatsCollector) {
    let snapshots = stats.reset_all();
    if snapshots.is_empty() {
        return;
    }
    let data: Vec<panel_core::UserTraffic> = snapshots
        .iter()
        .map(|s| panel_core::UserTraffic {
            user_id: s.user_id,
            upload: s.upload_bytes,
            download: s.download_bytes,
            request_count: s.request_count,
        })
        .collect();
    let (users, up, down) = (
        data.len(),
        data.iter().map(|t| t.upload).sum::<u64>(),
        data.iter().map(|t| t.download).sum::<u64>(),
    );
    match api.submit_traffic(data).await {
        Ok(()) => tracing::info!(
            users,
            upload = up,
            download = down,
            "Final traffic reported"
        ),
        Err(e) => {
            // keep it for the background task's own attempt (and the log)
            stats.restore(&snapshots);
            tracing::warn!(error = %e, "Failed to report final traffic before unregister");
        }
    }
}

/// Trojan stats collector wrapping panel-core's StatsCollector.
pub struct TrojanStatsCollector(pub Arc<PanelStatsCollector>);

impl StatsCollector for TrojanStatsCollector {
    fn record_request(&self, user_id: UserId) {
        self.0.record_request(user_id);
    }

    fn record_upload(&self, user_id: UserId, bytes: u64) {
        self.0.record_upload(user_id, bytes);
    }

    fn record_download(&self, user_id: UserId, bytes: u64) {
        self.0.record_download(user_id, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_authenticator_empty() {
        let user_manager = Arc::new(TrojanUserManager::new(panel_core::password_to_hex));
        let auth = TrojanAuthenticator(user_manager);
        let password = [b'x'; 56];
        assert_eq!(auth.authenticate(&password), None);
    }

    #[test]
    fn test_trojan_authenticator_with_users() {
        let user_manager = Arc::new(TrojanUserManager::new(panel_core::password_to_hex));
        let users = vec![panel_core::User {
            id: 42,
            uuid: "test-uuid-123".to_string(),
        }];
        user_manager.init(&users);

        let auth = TrojanAuthenticator(Arc::clone(&user_manager));
        let hex = panel_core::password_to_hex("test-uuid-123");
        assert_eq!(auth.authenticate(&hex), Some(42));
    }

    #[test]
    fn test_trojan_stats_collector() {
        let panel_stats = Arc::new(PanelStatsCollector::new());
        let stats = TrojanStatsCollector(Arc::clone(&panel_stats));

        stats.record_request(1);
        stats.record_upload(1, 100);
        stats.record_download(1, 200);

        let snapshot = panel_stats.get_stats(1).unwrap();
        assert_eq!(snapshot.request_count, 1);
        assert_eq!(snapshot.upload_bytes, 100);
        assert_eq!(snapshot.download_bytes, 200);
    }
}
