//! When the UI process exits: 120 s after its last window closed (so the Quick Panel opens at
//! once on repeated use), never while a clipboard clear is pending (the clearer lives here), and
//! at once when the daemon goes away.

use std::time::{Duration, Instant};

pub const LINGER: Duration = Duration::from_secs(120);
/// Lets the clearer run before the deadline check; it fires at the deadline itself.
const CLEAR_MARGIN: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linger {
    /// A window is open again: nothing to do until it closes.
    Stay,
    ExitNow,
    /// Look again at this time.
    RecheckAt(Instant),
}

/// Decides when the linger timer fires.
#[must_use]
pub fn decide(open_windows: usize, clear_pending_until: Option<Instant>, now: Instant) -> Linger {
    if open_windows > 0 {
        return Linger::Stay;
    }
    match clear_pending_until {
        Some(deadline) if deadline > now => Linger::RecheckAt(deadline + CLEAR_MARGIN),
        _ => Linger::ExitNow,
    }
}

/// `BW_LITE_UI_LINGER_SECS` shortens the linger for manual checks.
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
        let now = Instant::now();
        assert_eq!(decide(1, None, now), Linger::Stay);
        assert_eq!(decide(2, Some(now + LINGER), now), Linger::Stay);
    }

    #[test]
    fn no_windows_and_nothing_pending_exits() {
        let now = Instant::now();
        assert_eq!(decide(0, None, now), Linger::ExitNow);
        assert_eq!(
            decide(0, Some(now), now + Duration::from_secs(1)),
            Linger::ExitNow,
            "the clear already ran"
        );
    }

    #[test]
    fn a_pending_clipboard_clear_holds_the_exit_until_it_ran() {
        let now = Instant::now();
        let clears_at = now + Duration::from_secs(25);
        assert_eq!(
            decide(0, Some(clears_at), now),
            Linger::RecheckAt(clears_at + CLEAR_MARGIN)
        );
        assert_eq!(
            decide(0, Some(clears_at), clears_at + CLEAR_MARGIN),
            Linger::ExitNow
        );
    }

    #[test]
    fn the_linger_can_be_shortened_for_testing() {
        assert_eq!(linger_from_env(None), Duration::from_secs(120));
        assert_eq!(linger_from_env(Some("5")), Duration::from_secs(5));
        assert_eq!(linger_from_env(Some("soon")), LINGER);
    }
}
