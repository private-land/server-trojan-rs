//! HTTP/2 heartbeat (PING/PONG)
//!
//! One PING is outstanding at a time (h2 rejects a second `send_ping` while
//! a PONG is pending). Every `PING_INTERVAL_SECS` tick either sends a PING
//! (idle) or counts the still-unanswered one as missed; after
//! `MAX_MISSED_PINGS` consecutive misses (≈90 s) the connection is declared
//! dead. A late PONG still clears the counter because the PONG is polled
//! for as long as one is outstanding.

use h2::Ping;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

/// Ping interval in seconds.
const PING_INTERVAL_SECS: u64 = 30;

/// Maximum missed pings before connection is considered dead
const MAX_MISSED_PINGS: u32 = 3;

pub(crate) struct H2Heartbeat {
    ping_pong: Option<h2::PingPong>,
    /// Set by stream transports when data arrives; checked at every tick.
    activity: Arc<AtomicBool>,
    /// A PING is in flight and its PONG has not been consumed yet.
    waiting_pong: bool,
    missed_pings: u32,
    timer: tokio::time::Interval,
}

impl H2Heartbeat {
    pub fn new(ping_pong: Option<h2::PingPong>, activity: Arc<AtomicBool>) -> Self {
        let mut timer = tokio::time::interval(tokio::time::Duration::from_secs(PING_INTERVAL_SECS));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            ping_pong,
            activity,
            waiting_pong: false,
            missed_pings: 0,
            timer,
        }
    }

    /// Any inbound frame (new stream, or data on an existing one via the
    /// shared flag) proves the peer is alive.
    pub fn on_activity(&mut self) {
        self.missed_pings = 0;
    }

    fn take_activity(&self) -> bool {
        self.activity.swap(false, Ordering::Relaxed)
    }

    /// Resolves after one heartbeat step (`Ok`, the caller loops) or when the
    /// peer must be considered dead (`Err`).
    pub async fn poll(&mut self) -> Result<(), &'static str> {
        let Some(pp) = self.ping_pong.as_mut() else {
            // No PING/PONG on this connection: never resolve, never spin.
            std::future::pending::<()>().await;
            unreachable!()
        };

        if self.waiting_pong {
            tokio::select! {
                result = futures_util::future::poll_fn(|cx| pp.poll_pong(cx)) => {
                    self.waiting_pong = false;
                    match result {
                        Ok(_) => {
                            self.missed_pings = 0;
                            debug!("Received HTTP/2 PONG response");
                            Ok(())
                        }
                        Err(e) => {
                            warn!(error = %e, "HTTP/2 PONG receive error");
                            Err("PONG error")
                        }
                    }
                }
                _ = self.timer.tick() => {
                    if self.take_activity() {
                        // Data flowed on some stream: the peer is alive even if a
                        // middlebox eats PING frames. Keep waiting for the PONG.
                        self.missed_pings = 0;
                        return Ok(());
                    }
                    // Still no PONG after a full interval: count it and keep
                    // waiting (h2 cannot send another PING until it is answered).
                    self.missed_pings += 1;
                    warn!(
                        missed_pings = self.missed_pings,
                        max_missed = MAX_MISSED_PINGS,
                        "HTTP/2 PING unanswered"
                    );
                    if self.missed_pings >= MAX_MISSED_PINGS {
                        return Err("heartbeat timeout");
                    }
                    Ok(())
                }
            }
        } else {
            self.timer.tick().await;
            // Activity before this PING says nothing about the peer after it:
            // discard the stale flag so only data that arrives while the PONG
            // is outstanding can excuse a missed one.
            self.activity.swap(false, Ordering::Relaxed);
            match pp.send_ping(Ping::opaque()) {
                Ok(()) => {
                    self.waiting_pong = true;
                    debug!("Sent HTTP/2 PING frame");
                }
                Err(e) => warn!(error = %e, "Failed to send HTTP/2 PING"),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_peer_detection_budget() {
        // A silent peer is dropped after MAX_MISSED_PINGS unanswered intervals.
        assert_eq!(PING_INTERVAL_SECS * MAX_MISSED_PINGS as u64, 90);
    }

    /// Activity recorded before a PING is sent must not excuse a PONG that
    /// never arrives afterwards: sending the PING consumes the flag.
    #[tokio::test]
    async fn sending_ping_discards_stale_activity() {
        let activity = Arc::new(AtomicBool::new(true));
        let mut hb = H2Heartbeat::new(None, activity.clone());
        // Simulate the send branch's bookkeeping without an h2 handle.
        hb.take_activity();
        assert!(!activity.load(Ordering::Relaxed));
        assert!(!hb.take_activity());
        hb.on_activity();
        assert_eq!(hb.missed_pings, 0);
    }

    /// Without PING/PONG support the heartbeat must stay pending (the
    /// connection loop relies on its other branches) rather than spin.
    #[tokio::test]
    async fn no_ping_pong_never_resolves() {
        let mut hb = H2Heartbeat::new(None, Arc::new(AtomicBool::new(false)));
        let r = tokio::time::timeout(tokio::time::Duration::from_millis(50), hb.poll()).await;
        assert!(r.is_err(), "poll must stay pending without PingPong");
    }
}
