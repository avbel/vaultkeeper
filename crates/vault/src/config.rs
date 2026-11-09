use std::{path::PathBuf, time::Duration};

use tokio::runtime::Handle;
use vk_api::{DeviceInfo, HttpTimeouts, notifications::ReconnectOptions};

/// Everything the vault needs from its host; nothing here is platform specific.
pub struct VaultConfig {
    /// Holds `accounts.json` and `accounts/<user_id>/`; created with mode 0700.
    pub data_dir: PathBuf,
    pub device: DeviceInfo,
    /// Runs the background tasks (sync timer, websocket, offline probe) and blocking work.
    pub runtime: Handle,
    pub timings: Timings,
}

impl VaultConfig {
    #[must_use]
    pub fn new(data_dir: PathBuf, device: DeviceInfo, runtime: Handle) -> Self {
        Self {
            data_dir,
            device,
            runtime,
            timings: Timings::default(),
        }
    }
}

/// Background cadence. The defaults are the documented production values; tests shrink them.
#[derive(Debug, Clone)]
pub struct Timings {
    /// Periodic full sync while unlocked.
    pub sync_interval: Duration,
    /// Quiet period that merges a burst of sync triggers into one sync.
    pub sync_debounce: Duration,
    /// First wait of the offline probe; doubles after each failure up to `probe_max`.
    pub probe_initial: Duration,
    pub probe_max: Duration,
    /// Per-request limit of one `GET /alive` probe.
    pub probe_timeout: Duration,
    /// Refresh the access token when it expires within this margin.
    pub token_refresh_margin: Duration,
    pub notifications: ReconnectOptions,
    pub http: HttpTimeouts,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_mins(30),
            sync_debounce: Duration::from_millis(300),
            probe_initial: Duration::from_secs(5),
            probe_max: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(10),
            token_refresh_margin: Duration::from_mins(5),
            notifications: ReconnectOptions::default(),
            http: HttpTimeouts::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_schedule() {
        let timings = Timings::default();
        assert_eq!(timings.sync_interval, Duration::from_mins(30));
        assert_eq!(timings.probe_initial, Duration::from_secs(5));
        assert_eq!(timings.probe_max, Duration::from_secs(60));
        assert_eq!(
            timings.notifications.listen.ping_interval,
            Duration::from_secs(15)
        );
        assert_eq!(
            timings.notifications.listen.stale_after,
            Duration::from_secs(35)
        );
    }
}
