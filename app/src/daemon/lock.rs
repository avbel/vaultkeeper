//! When the daemon locks the vault: after `lock_timeout` without user activity (wall clock, so
//! time asleep counts), and on sleep or screen lock when `lock_on_sleep` is set, independently.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use vk_platform::power::PowerEvent;

use crate::settings::LockTimeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockCheck {
    LockNow,
    /// Look again after this long (the activity may have moved on by then).
    After(Duration),
    /// No timer (locked, or the timeout is "never").
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

/// The lock timer's view of the session between two looks. An unlock it has not seen yet counts
/// as activity before the timeout is evaluated, so an unlock without keyboard or mouse input (an
/// SSH request answered with Touch ID after a long idle) never locks again at once, whichever of
/// the timer and the state loop runs first.
#[derive(Debug, Default)]
pub struct LockWatch {
    saw_unlocked: bool,
}

impl LockWatch {
    #[must_use]
    pub fn look(
        &mut self,
        unlocked: bool,
        timeout: LockTimeout,
        activity: &Activity,
        now: SystemTime,
    ) -> LockCheck {
        let newly_unlocked = unlocked && !self.saw_unlocked;
        self.saw_unlocked = unlocked;
        if !unlocked {
            return LockCheck::Never;
        }
        if newly_unlocked {
            activity.touch_at(now);
        }
        check(timeout, activity.last(), now)
    }

    /// The timer locked the vault itself.
    pub const fn locked(&mut self) {
        self.saw_unlocked = false;
    }
}

/// Whether `event` locks the vault right away.
#[must_use]
pub const fn locks_on(event: PowerEvent, lock_on_sleep: bool) -> bool {
    lock_on_sleep && matches!(event, PowerEvent::WillSleep | PowerEvent::ScreenLocked)
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
        self.touch_at(SystemTime::now());
    }

    /// Never moves the last activity back.
    pub fn touch_at(&self, now: SystemTime) {
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        self.0.fetch_max(seconds, Ordering::Relaxed);
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
    fn never_has_no_timer() {
        assert_eq!(
            check(LockTimeout::Never, at(0), at(99_999)),
            LockCheck::Never
        );
    }

    #[test]
    fn sleep_and_screen_lock_lock_when_the_setting_is_on() {
        assert!(locks_on(PowerEvent::WillSleep, true));
        assert!(locks_on(PowerEvent::ScreenLocked, true));
        assert!(!locks_on(PowerEvent::DidWake, true));
        assert!(!locks_on(PowerEvent::ScreenUnlocked, true));
        assert!(!locks_on(PowerEvent::WillSleep, false));
        assert!(!locks_on(PowerEvent::ScreenLocked, false));
    }

    fn idle_since(time: SystemTime) -> Activity {
        let activity = Activity(AtomicU64::new(0));
        activity.touch_at(time);
        activity
    }

    #[test]
    fn an_unlock_after_a_long_idle_restarts_the_timeout() {
        let fifteen = LockTimeout::Minutes(15);
        let activity = idle_since(at(0));
        let mut watch = LockWatch::default();
        assert_eq!(
            watch.look(false, fifteen, &activity, at(1200)),
            LockCheck::Never
        );
        // The state loop has not touched the activity yet: the timer must not lock on the
        // 20-minute-old value.
        assert_eq!(
            watch.look(true, fifteen, &activity, at(1200)),
            LockCheck::After(Duration::from_mins(15))
        );
        assert_eq!(activity.last(), at(1200));
        assert_eq!(
            watch.look(true, fifteen, &activity, at(1200 + 900)),
            LockCheck::LockNow,
            "idle for the timeout after the unlock"
        );
    }

    #[test]
    fn an_unlock_seen_before_is_not_activity_again() {
        let fifteen = LockTimeout::Minutes(15);
        let activity = idle_since(at(0));
        let mut watch = LockWatch::default();
        assert_eq!(
            watch.look(true, fifteen, &activity, at(60)),
            LockCheck::After(Duration::from_mins(15))
        );
        assert_eq!(
            watch.look(true, fifteen, &activity, at(960)),
            LockCheck::LockNow
        );
        watch.locked();
        assert_eq!(
            watch.look(true, fifteen, &activity, at(2000)),
            LockCheck::After(Duration::from_mins(15)),
            "the next unlock counts again"
        );
    }

    #[test]
    fn activity_never_moves_back() {
        let activity = idle_since(at(100));
        activity.touch_at(at(50));
        assert_eq!(activity.last(), at(100));
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
