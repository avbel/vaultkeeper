//! Network path changes: the path became usable (or changed interface while usable), or it went
//! away.
//!
//! macOS observes `NWPathMonitor` on a system dispatch queue, from the first update the monitor
//! sends right after [`subscribe`] onwards; no run loop is needed. Windows uses the connectivity
//! hint callback registered with [`subscribe`], which reports the current hint immediately.

use std::sync::mpsc::Sender;

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// The path is satisfied: just connected, or another interface took over.
    Usable,
    Unusable,
}

impl NetworkEvent {
    /// Codes sent by the Swift shim (`swift/Sources/VkPlatform/Network.swift`).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    const fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Unusable),
            1 => Some(Self::Usable),
            _ => None,
        }
    }

    /// Windows `NL_NETWORK_CONNECTIVITY_HINT.ConnectivityLevel`. Unknown and hidden hints carry no
    /// usable signal; a hidden hint is not a disconnect, so it must not wake the probe either.
    /// Kept portable so the mapping is unit-tested on macOS too.
    #[cfg_attr(not(windows), allow(dead_code))]
    const fn from_connectivity_level(level: i32) -> Option<Self> {
        match level {
            1 => Some(Self::Unusable),
            2..=4 => Some(Self::Usable),
            _ => None,
        }
    }
}

/// Dropping it stops the monitor; no event is sent after `drop` returns.
#[must_use = "dropping the watcher unsubscribes"]
pub struct NetworkWatcher {
    #[cfg(target_os = "macos")]
    _subscription: macos::Subscription,
    #[cfg(windows)]
    _subscription: windows::Subscription,
}

/// Sends every path update to `tx` until the returned watcher is dropped. Events sent after the
/// receiver is gone are dropped.
pub fn subscribe(tx: Sender<NetworkEvent>) -> Result<NetworkWatcher> {
    #[cfg(target_os = "macos")]
    {
        Ok(NetworkWatcher {
            _subscription: macos::Subscription::new(tx),
        })
    }
    #[cfg(windows)]
    {
        Ok(NetworkWatcher {
            _subscription: windows::Subscription::new(tx)?,
        })
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        drop(tx);
        Err(crate::Error::Unsupported)
    }
}

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod macos {
    use std::{ffi::c_void, ptr::NonNull, sync::mpsc::Sender};

    use super::NetworkEvent;

    type Callback = extern "C" fn(*mut c_void, i32);

    unsafe extern "C" {
        fn vk_network_subscribe(callback: Callback, context: *mut c_void) -> *mut c_void;
        fn vk_network_unsubscribe(token: *mut c_void);
    }

    pub(super) struct Subscription {
        token: NonNull<c_void>,
        sender: NonNull<Sender<NetworkEvent>>,
    }

    // SAFETY: the Swift observer is only touched through vk_network_unsubscribe, which is
    // thread-safe (NSLock plus NWPathMonitor.cancel), and the boxed Sender is Send. Nothing here
    // is shared, so Sync is not claimed.
    unsafe impl Send for Subscription {}

    impl Subscription {
        pub(super) fn new(tx: Sender<NetworkEvent>) -> Self {
            let sender = NonNull::from(Box::leak(Box::new(tx)));
            // SAFETY: `on_event` matches the C callback type; `sender` stays valid until
            // vk_network_unsubscribe has returned in Drop, after which Swift never calls it.
            let token = unsafe { vk_network_subscribe(on_event, sender.as_ptr().cast()) };
            let token = NonNull::new(token).expect("Swift returns a retained observer");
            Self { token, sender }
        }
    }

    impl Drop for Subscription {
        fn drop(&mut self) {
            // SAFETY: `token` came from vk_network_subscribe and is released exactly once here.
            // Once it returns no callback is running or will run, so the Sender can be freed.
            unsafe {
                vk_network_unsubscribe(self.token.as_ptr());
                drop(Box::from_raw(self.sender.as_ptr()));
            }
        }
    }

    extern "C" fn on_event(context: *mut c_void, code: i32) {
        let Some(event) = NetworkEvent::from_code(code) else {
            return;
        };
        // SAFETY: `context` is the Sender leaked in `Subscription::new`, alive until Drop has
        // unsubscribed; Sender is Sync, so a shared reference from the monitor's queue is fine.
        let sender = unsafe { &*context.cast::<Sender<NetworkEvent>>() };
        let _ = sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_events() {
        assert_eq!(NetworkEvent::from_code(0), Some(NetworkEvent::Unusable));
        assert_eq!(NetworkEvent::from_code(1), Some(NetworkEvent::Usable));
        assert_eq!(NetworkEvent::from_code(2), None);
        assert_eq!(NetworkEvent::from_code(-1), None);
    }

    #[test]
    fn windows_connectivity_levels_map_to_events() {
        assert_eq!(
            NetworkEvent::from_connectivity_level(1),
            Some(NetworkEvent::Unusable)
        );
        for usable in 2..=4 {
            assert_eq!(
                NetworkEvent::from_connectivity_level(usable),
                Some(NetworkEvent::Usable)
            );
        }
        assert_eq!(NetworkEvent::from_connectivity_level(0), None);
        assert_eq!(NetworkEvent::from_connectivity_level(5), None);
    }

    /// NWPathMonitor reports the current path right after it starts, whatever the network is,
    /// so this exercises the real monitor, the C callback and unsubscribe without touching it.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_monitor_reports_the_current_path_until_dropped() {
        use std::{sync::mpsc, time::Duration};

        let (tx, rx) = mpsc::channel();
        let watcher = subscribe(tx).expect("subscribe");
        let first = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the initial path update");
        assert!(matches!(
            first,
            NetworkEvent::Usable | NetworkEvent::Unusable
        ));
        drop(watcher);
        while rx.try_recv().is_ok() {}
        assert_eq!(rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }
}
