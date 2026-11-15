//! Windows half of [`super::subscribe`]: the connectivity hint callback reports when the machine
//! gains, loses or changes its network path. The callback runs on a system thread, so nothing here
//! touches the main thread.
//!
//! Layout and rationale: docs/solutions/windows-support.md §7.3.

use std::{ffi::c_void, io, ptr, sync::mpsc::Sender};

use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, HANDLE, WIN32_ERROR},
    NetworkManagement::IpHelper::{CancelMibChangeNotify2, NotifyNetworkConnectivityHintChange},
    Networking::WinSock::NL_NETWORK_CONNECTIVITY_HINT,
};

use super::NetworkEvent;

/// Owns the notification handle; dropping cancels it, after which the Sender is freed.
pub(super) struct Subscription {
    handle: HANDLE,
    sender: ptr::NonNull<Sender<NetworkEvent>>,
}

// SAFETY: the handle is a cookie used only in `Drop` (CancelMibChangeNotify2), and the boxed
// Sender is Send. The callback shares a `&Sender`, which is Sync, so no state is shared mutably.
unsafe impl Send for Subscription {}

impl Subscription {
    pub(super) fn new(tx: Sender<NetworkEvent>) -> io::Result<Self> {
        let sender = ptr::NonNull::from(Box::leak(Box::new(tx)));
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: `on_change` matches the callback type, `sender` stays valid until
        // CancelMibChangeNotify2 returns in `Drop` (or is freed below), and `handle` is a valid
        // out-pointer. The callback may run synchronously for the initial notification, which only
        // reads the context, so `handle` being not-yet-written is fine.
        let status = unsafe {
            NotifyNetworkConnectivityHintChange(
                Some(on_change),
                sender.as_ptr().cast(),
                true,
                &raw mut handle,
            )
        };
        if status != ERROR_SUCCESS {
            // SAFETY: registration failed, so no callback can be running or will run; `sender`
            // was never shared.
            unsafe {
                drop(Box::from_raw(sender.as_ptr()));
            }
            return Err(os_error(status));
        }
        if handle.is_null() {
            // SAFETY: no handle means there is nothing to cancel; free the Sender as above.
            unsafe {
                drop(Box::from_raw(sender.as_ptr()));
            }
            return Err(io::Error::other(
                "the connectivity notification returned no handle",
            ));
        }
        Ok(Self { handle, sender })
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: `handle` came from NotifyNetworkConnectivityHintChange and is cancelled exactly
        // once. Once this returns no callback is running or will run, so the Sender can be freed.
        unsafe {
            let _ = CancelMibChangeNotify2(self.handle);
            drop(Box::from_raw(self.sender.as_ptr()));
        }
    }
}

unsafe extern "system" fn on_change(context: *const c_void, hint: NL_NETWORK_CONNECTIVITY_HINT) {
    let Some(event) = NetworkEvent::from_connectivity_level(hint.ConnectivityLevel) else {
        return;
    };
    // SAFETY: `context` is the Sender leaked in `Subscription::new`, alive until `Drop` has
    // cancelled the notification; Sender is Sync, so a shared reference from a system thread is
    // fine.
    let sender = unsafe { &*context.cast::<Sender<NetworkEvent>>() };
    let _ = sender.send(event);
}

fn os_error(status: WIN32_ERROR) -> io::Error {
    i32::try_from(status).map_or_else(
        |_| {
            io::Error::other(format!(
                "connectivity notification failed with status {status}"
            ))
        },
        io::Error::from_raw_os_error,
    )
}
