//! When the daemon locks the vault: after `lock_timeout` without user activity (wall clock, so
//! time asleep counts), and on sleep or screen lock when the timeout is set to that.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bwl_platform::power::PowerEvent;

use crate::settings::LockTimeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockCheck {
    LockNow,
    /// Look again after this long (the activity may have moved on by then).
    After(Duration),
    /// No timer: only sleep or screen lock lock the vault.
    Never,
}

#[must_use]
pub fn check(timeout: LockTimeout, last_activity: SystemTime, now: SystemTime) -> LockCheck {
    let LockTimeout::Minutes(minutes) = timeout else {
        return LockCheck::Never;
    };
    let limit = Duration::from_secs(u64::from(minutes) * 60);
    // A clock set back reads as "just now", never as a lock.
    let idle = now.duration_since(last_activity).unwrap_or_default();
    match limit.checked_sub(idle) {
        Some(left) if !left.is_zero() => LockCheck::After(left),
        _ => LockCheck::LockNow,
    }
}

/// Whether `event` locks the vault right away.
#[must_use]
pub const fn locks_on(event: PowerEvent, timeout: LockTimeout) -> bool {
    matches!(
        (event, timeout),
        (
            PowerEvent::WillSleep | PowerEvent::ScreenLocked,
            LockTimeout::OnSleep
        )
    )
}

/// The last user action, as unix seconds; updated from any thread without waking the timer.
#[derive(Debug)]
pub struct Activity(AtomicU64);

impl Activity {
    #[must_use]
    pub fn new() -> Self {
        let activity = Self(AtomicU64::new(0));
        activity.touch();
        activity
    }

    pub fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        self.0.store(now, Ordering::Relaxed);
    }

    #[must_use]
    pub fn last(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::Relaxed))
    }
}

impl Default for Activity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_762_600_000 + seconds)
    }

    #[test]
    fn minutes_count_from_the_last_activity() {
        let fifteen = LockTimeout::Minutes(15);
        assert_eq!(
            check(fifteen, at(0), at(0)),
            LockCheck::After(Duration::from_mins(15))
        );
        assert_eq!(
            check(fifteen, at(0), at(600)),
            LockCheck::After(Duration::from_mins(5))
        );
        assert_eq!(check(fifteen, at(0), at(900)), LockCheck::LockNow);
        assert_eq!(
            check(fifteen, at(0), at(7200)),
            LockCheck::LockNow,
            "asleep for two hours"
        );
        assert_eq!(
            check(LockTimeout::Minutes(1), at(30), at(0)),
            LockCheck::After(Duration::from_mins(1)),
            "a clock set back never locks"
        );
    }

    #[test]
    fn on_sleep_has_no_timer_and_locks_on_sleep_and_screen_lock() {
        assert_eq!(
            check(LockTimeout::OnSleep, at(0), at(99_999)),
            LockCheck::Never
        );
        assert!(locks_on(PowerEvent::WillSleep, LockTimeout::OnSleep));
        assert!(locks_on(PowerEvent::ScreenLocked, LockTimeout::OnSleep));
        assert!(!locks_on(PowerEvent::DidWake, LockTimeout::OnSleep));
        assert!(!locks_on(PowerEvent::ScreenUnlocked, LockTimeout::OnSleep));
        assert!(!locks_on(PowerEvent::WillSleep, LockTimeout::Minutes(5)));
    }

    #[test]
    fn activity_moves_forward() {
        let activity = Activity::new();
        let first = activity.last();
        assert!(
            SystemTime::now().duration_since(first).unwrap_or_default() < Duration::from_secs(2)
        );
        activity.touch();
        assert!(activity.last() >= first);
    }
}
