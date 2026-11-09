//! When the UI process exits: 120 s after its last window closed (so the Quick Panel opens at
//! once on repeated use), and at once when the daemon goes away. A pending clipboard clear does
//! not hold it: the daemon owns the clipboard timer.

use std::time::Duration;

pub const LINGER: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linger {
    /// A window is open again: nothing to do until it closes.
    Stay,
    ExitNow,
}

/// Decides what the linger timer does when it fires.
#[must_use]
pub const fn decide(open_windows: usize) -> Linger {
    if open_windows > 0 {
        Linger::Stay
    } else {
        Linger::ExitNow
    }
}

/// `VAULTKEEPER_UI_LINGER_SECS` shortens the linger for manual checks.
#[must_use]
pub fn linger_from_env(value: Option<&str>) -> Duration {
    value
        .and_then(|seconds| seconds.trim().parse::<u64>().ok())
        .map_or(LINGER, Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_window_keeps_the_process() {
        assert_eq!(decide(1), Linger::Stay);
        assert_eq!(decide(2), Linger::Stay);
    }

    /// Replaces "a pending clipboard clear holds the exit": the clear now runs in the daemon, so
    /// a copy made just before the last window closed no longer keeps this process alive.
    #[test]
    fn no_windows_exits_whatever_was_copied() {
        assert_eq!(decide(0), Linger::ExitNow);
    }

    #[test]
    fn the_linger_can_be_shortened_for_testing() {
        assert_eq!(linger_from_env(None), Duration::from_secs(120));
        assert_eq!(linger_from_env(Some("5")), Duration::from_secs(5));
        assert_eq!(linger_from_env(Some("soon")), LINGER);
    }
}
