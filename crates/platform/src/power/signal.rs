//! Portable half of the Linux power watcher: which bus signals mean what. Kept free of zbus types
//! so the mapping is unit-tested on every host.

use super::PowerEvent;

pub(super) const LOGIND_MANAGER: &str = "org.freedesktop.login1.Manager";
pub(super) const LOGIND_SESSION: &str = "org.freedesktop.login1.Session";
pub(super) const KDE_SCREENSAVER: &str = "org.freedesktop.ScreenSaver";
pub(super) const GNOME_SCREENSAVER: &str = "org.gnome.ScreenSaver";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BusSignal {
    PrepareForSleep(bool),
    PrepareForShutdown(bool),
    SessionLock,
    SessionUnlock,
    LockedHint(bool),
    ScreenSaverActive(bool),
}

/// `flag` is the signal's single boolean argument, when it carries one.
pub(super) fn classify(interface: &str, member: &str, flag: Option<bool>) -> Option<BusSignal> {
    match (interface, member) {
        (LOGIND_MANAGER, "PrepareForSleep") => flag.map(BusSignal::PrepareForSleep),
        (LOGIND_MANAGER, "PrepareForShutdown") => flag.map(BusSignal::PrepareForShutdown),
        (LOGIND_SESSION, "Lock") => Some(BusSignal::SessionLock),
        (LOGIND_SESSION, "Unlock") => Some(BusSignal::SessionUnlock),
        (KDE_SCREENSAVER | GNOME_SCREENSAVER, "ActiveChanged") => {
            flag.map(BusSignal::ScreenSaverActive)
        }
        _ => None,
    }
}

/// Collapses the several signals one lock produces (logind `Lock`, `LockedHint`, the screensaver's
/// `ActiveChanged`) into one event per transition.
#[derive(Debug, Default)]
pub(super) struct Tracker {
    locked: bool,
}

impl Tracker {
    pub(super) fn apply(&mut self, signal: BusSignal) -> Option<PowerEvent> {
        match signal {
            BusSignal::PrepareForSleep(true) => Some(PowerEvent::WillSleep),
            BusSignal::PrepareForSleep(false) => Some(PowerEvent::DidWake),
            BusSignal::PrepareForShutdown(true) => Some(PowerEvent::SessionEnding),
            BusSignal::PrepareForShutdown(false) => None,
            BusSignal::SessionLock => {
                // A request, not a state: swaylock and hyprlock never report an unlock, so a
                // later lock must not be swallowed as "already locked".
                self.locked = true;
                Some(PowerEvent::ScreenLocked)
            }
            BusSignal::SessionUnlock => self.set_locked(false),
            BusSignal::LockedHint(locked) | BusSignal::ScreenSaverActive(locked) => {
                self.set_locked(locked)
            }
        }
    }

    fn set_locked(&mut self, locked: bool) -> Option<PowerEvent> {
        if self.locked == locked {
            return None;
        }
        self.locked = locked;
        Some(if locked {
            PowerEvent::ScreenLocked
        } else {
            PowerEvent::ScreenUnlocked
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_logind_and_screensaver_signals() {
        assert_eq!(
            classify(LOGIND_MANAGER, "PrepareForSleep", Some(true)),
            Some(BusSignal::PrepareForSleep(true))
        );
        assert_eq!(
            classify(LOGIND_MANAGER, "PrepareForShutdown", Some(false)),
            Some(BusSignal::PrepareForShutdown(false))
        );
        assert_eq!(
            classify(LOGIND_SESSION, "Lock", None),
            Some(BusSignal::SessionLock)
        );
        assert_eq!(
            classify(LOGIND_SESSION, "Unlock", None),
            Some(BusSignal::SessionUnlock)
        );
        assert_eq!(
            classify(KDE_SCREENSAVER, "ActiveChanged", Some(true)),
            Some(BusSignal::ScreenSaverActive(true))
        );
        assert_eq!(
            classify(GNOME_SCREENSAVER, "ActiveChanged", Some(false)),
            Some(BusSignal::ScreenSaverActive(false))
        );
    }

    #[test]
    fn rejects_unknown_and_argumentless_signals() {
        assert_eq!(classify(LOGIND_MANAGER, "PrepareForSleep", None), None);
        assert_eq!(classify(KDE_SCREENSAVER, "ActiveChanged", None), None);
        assert_eq!(classify(LOGIND_MANAGER, "SessionNew", Some(true)), None);
        assert_eq!(classify("org.example.Other", "Lock", None), None);
    }

    #[test]
    fn sleep_shutdown_map_to_power_events() {
        let mut tracker = Tracker::default();
        assert_eq!(
            tracker.apply(BusSignal::PrepareForSleep(true)),
            Some(PowerEvent::WillSleep)
        );
        assert_eq!(
            tracker.apply(BusSignal::PrepareForSleep(false)),
            Some(PowerEvent::DidWake)
        );
        assert_eq!(
            tracker.apply(BusSignal::PrepareForShutdown(true)),
            Some(PowerEvent::SessionEnding)
        );
        assert_eq!(tracker.apply(BusSignal::PrepareForShutdown(false)), None);
    }

    #[test]
    fn one_lock_reports_once_however_many_sources_say_so() {
        let mut tracker = Tracker::default();
        assert_eq!(
            tracker.apply(BusSignal::SessionLock),
            Some(PowerEvent::ScreenLocked)
        );
        assert_eq!(tracker.apply(BusSignal::LockedHint(true)), None);
        assert_eq!(tracker.apply(BusSignal::ScreenSaverActive(true)), None);
        assert_eq!(
            tracker.apply(BusSignal::LockedHint(false)),
            Some(PowerEvent::ScreenUnlocked)
        );
        assert_eq!(tracker.apply(BusSignal::SessionUnlock), None);
        assert_eq!(
            tracker.apply(BusSignal::ScreenSaverActive(true)),
            Some(PowerEvent::ScreenLocked)
        );
    }

    #[test]
    fn repeated_lock_requests_each_report() {
        let mut tracker = Tracker::default();
        assert_eq!(
            tracker.apply(BusSignal::SessionLock),
            Some(PowerEvent::ScreenLocked)
        );
        assert_eq!(
            tracker.apply(BusSignal::SessionLock),
            Some(PowerEvent::ScreenLocked)
        );
    }

    #[test]
    fn unlock_without_a_lock_is_silent() {
        let mut tracker = Tracker::default();
        assert_eq!(tracker.apply(BusSignal::SessionUnlock), None);
        assert_eq!(tracker.apply(BusSignal::ScreenSaverActive(false)), None);
    }
}
