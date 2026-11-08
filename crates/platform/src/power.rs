//! System sleep/wake and screen lock/unlock events.
//!
//! [`subscribe`] works from any thread, but macOS delivers these notifications through the main
//! thread's run loop only (measured: observers on a thread running its own run loop get
//! nothing). They therefore arrive while the main thread runs an event loop, which the Slint
//! event loop does; a CLI has to run `CFRunLoopRun()` on its main thread.

use std::sync::mpsc::Sender;

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    WillSleep,
    DidWake,
    ScreenLocked,
    ScreenUnlocked,
}

impl PowerEvent {
    /// Codes sent by the Swift shim (`swift/Sources/BwlPlatform/Power.swift`).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    const fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::WillSleep),
            1 => Some(Self::DidWake),
            2 => Some(Self::ScreenLocked),
            3 => Some(Self::ScreenUnlocked),
            _ => None,
        }
    }
}

/// Dropping it unsubscribes; no event is sent after `drop` returns.
#[must_use = "dropping the watcher unsubscribes"]
pub struct PowerWatcher {
    #[cfg(target_os = "macos")]
    _subscription: macos::Subscription,
}

/// Sends every event to `tx` until the returned watcher is dropped. Sending never blocks the
/// main thread; events sent after the receiver is gone are dropped.
pub fn subscribe(tx: Sender<PowerEvent>) -> Result<PowerWatcher> {
    #[cfg(target_os = "macos")]
    {
        Ok(PowerWatcher {
            _subscription: macos::Subscription::new(tx),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        drop(tx);
        Err(crate::Error::Unsupported)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{ffi::c_void, ptr::NonNull, sync::mpsc::Sender};

    use super::PowerEvent;

    type Callback = extern "C" fn(*mut c_void, i32);

    unsafe extern "C" {
        fn bwl_power_subscribe(callback: Callback, context: *mut c_void) -> *mut c_void;
        fn bwl_power_unsubscribe(token: *mut c_void);
    }

    #[cfg(test)]
    unsafe extern "C" {
        pub(super) safe fn bwl_power_post_workspace_for_test(sleep: bool);
    }

    pub(super) struct Subscription {
        token: NonNull<c_void>,
        sender: NonNull<Sender<PowerEvent>>,
    }

    // SAFETY: the Swift observer is only touched through bwl_power_unsubscribe, which is
    // thread-safe (NSLock plus thread-safe NotificationCenter removal), and the boxed Sender is
    // Send. Nothing here is shared, so Sync is not claimed.
    unsafe impl Send for Subscription {}

    impl Subscription {
        pub(super) fn new(tx: Sender<PowerEvent>) -> Self {
            let sender = NonNull::from(Box::leak(Box::new(tx)));
            // SAFETY: `on_event` matches the C callback type; `sender` stays valid until
            // bwl_power_unsubscribe has returned in Drop, after which Swift never calls it.
            let token = unsafe { bwl_power_subscribe(on_event, sender.as_ptr().cast()) };
            let token = NonNull::new(token).expect("Swift returns a retained observer");
            Self { token, sender }
        }
    }

    impl Drop for Subscription {
        fn drop(&mut self) {
            // SAFETY: `token` came from bwl_power_subscribe and is released exactly once here.
            // Once it returns no callback is running or will run, so the Sender can be freed.
            unsafe {
                bwl_power_unsubscribe(self.token.as_ptr());
                drop(Box::from_raw(self.sender.as_ptr()));
            }
        }
    }

    extern "C" fn on_event(context: *mut c_void, code: i32) {
        let Some(event) = PowerEvent::from_code(code) else {
            return;
        };
        // SAFETY: `context` is the Sender leaked in `Subscription::new`, alive until Drop has
        // unsubscribed; Sender is Sync, so a shared reference from the main thread is fine.
        let sender = unsafe { &*context.cast::<Sender<PowerEvent>>() };
        let _ = sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_events() {
        assert_eq!(PowerEvent::from_code(0), Some(PowerEvent::WillSleep));
        assert_eq!(PowerEvent::from_code(1), Some(PowerEvent::DidWake));
        assert_eq!(PowerEvent::from_code(2), Some(PowerEvent::ScreenLocked));
        assert_eq!(PowerEvent::from_code(3), Some(PowerEvent::ScreenUnlocked));
        assert_eq!(PowerEvent::from_code(4), None);
        assert_eq!(PowerEvent::from_code(-1), None);
    }

    /// Posting on the workspace center delivers synchronously on the posting thread, so this
    /// exercises the real observer, the C callback and unsubscribe without sleeping the Mac.
    /// One test only: observers are process-wide, so parallel tests would see each other's posts.
    #[cfg(target_os = "macos")]
    #[test]
    fn workspace_notifications_reach_the_channel_until_dropped() {
        use std::sync::mpsc;

        let (orphan_tx, orphan_rx) = mpsc::channel();
        let _orphan = subscribe(orphan_tx).expect("subscribe orphan");
        drop(orphan_rx);

        let (tx, rx) = mpsc::channel();
        let watcher = subscribe(tx).expect("subscribe");
        macos::bwl_power_post_workspace_for_test(true);
        macos::bwl_power_post_workspace_for_test(false);
        assert_eq!(rx.try_recv(), Ok(PowerEvent::WillSleep));
        assert_eq!(rx.try_recv(), Ok(PowerEvent::DidWake));

        drop(watcher);
        macos::bwl_power_post_workspace_for_test(true);
        assert_eq!(rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }
}
