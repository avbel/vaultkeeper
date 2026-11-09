//! Copying, split across the two processes. The UI process ([`DaemonClipboard`]) hands each copy
//! to the daemon, which owns the concealed pasteboard, the "still ours" digest and the auto-clear
//! timer ([`Keeper`]). A UI that exits or is killed therefore leaves no secret behind, and the
//! daemon clears on lock, logout, account switch and quit, whichever UI process made the copy.

use std::{sync::Arc, time::Duration};

use vk_ipc::{ClipboardHost, RemoteVault};
use vk_platform::clipboard::{ClipboardBackend, SecretClipboard, SystemClipboard as Pasteboard};

use crate::hooks::{Clipboard, HookError, HookResult};

/// The UI process's clipboard hook: every call is one round-trip to the daemon.
pub struct DaemonClipboard {
    daemon: Arc<RemoteVault>,
}

impl DaemonClipboard {
    #[must_use]
    pub const fn new(daemon: Arc<RemoteVault>) -> Self {
        Self { daemon }
    }
}

impl Clipboard for DaemonClipboard {
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> HookResult<()> {
        self.daemon
            .copy_to_clipboard(text, clear_after)
            .map_err(|error| HookError::Failed(error.to_string()))
    }

    fn clear_if_ours(&self) {
        if let Err(error) = self.daemon.clear_clipboard() {
            tracing::warn!(%error, "could not clear the clipboard");
        }
    }
}

/// The daemon's clipboard: served to the UI over IPC and cleared by the daemon itself.
pub trait ClipboardKeeper: ClipboardHost {
    /// The system woke from sleep: a clear that fell due meanwhile runs now.
    fn recheck(&self);
}

pub struct Keeper<B: ClipboardBackend = Pasteboard> {
    inner: SecretClipboard<B>,
}

impl Keeper {
    /// The system pasteboard, or a keeper that refuses every copy when there is none.
    #[must_use]
    pub fn system() -> Arc<dyn ClipboardKeeper> {
        match SecretClipboard::new() {
            Ok(inner) => Arc::new(Self { inner }),
            Err(error) => {
                tracing::error!(%error, "no clipboard; copy buttons will report it");
                Arc::new(NoClipboard)
            }
        }
    }
}

impl<B: ClipboardBackend> Keeper<B> {
    #[must_use]
    pub const fn with(inner: SecretClipboard<B>) -> Self {
        Self { inner }
    }
}

impl<B: ClipboardBackend> ClipboardHost for Keeper<B> {
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<(), String> {
        self.inner
            .copy(text, clear_after)
            .map_err(|error| error.to_string())
    }

    fn clear_if_ours(&self) {
        if let Err(error) = self.inner.clear_if_ours() {
            tracing::warn!(%error, "could not clear the clipboard");
        }
    }
}

impl<B: ClipboardBackend> ClipboardKeeper for Keeper<B> {
    fn recheck(&self) {
        self.inner.recheck();
    }
}

pub struct NoClipboard;

impl ClipboardHost for NoClipboard {
    fn copy(&self, _text: &str, _clear_after: Option<Duration>) -> Result<(), String> {
        Err("the clipboard is not available".to_owned())
    }

    fn clear_if_ours(&self) {}
}

impl ClipboardKeeper for NoClipboard {
    fn recheck(&self) {}
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use zeroize::Zeroizing;

    use super::*;

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<Option<String>>>);

    impl Fake {
        fn content(&self) -> Option<String> {
            self.0.lock().expect("lock").clone()
        }
    }

    impl ClipboardBackend for Fake {
        fn set_secret(&mut self, text: &str) -> vk_platform::Result<()> {
            *self.0.lock().expect("lock") = Some(text.to_owned());
            Ok(())
        }

        fn text(&mut self) -> vk_platform::Result<Option<Zeroizing<String>>> {
            Ok(self.content().map(Zeroizing::new))
        }

        fn clear(&mut self) -> vk_platform::Result<()> {
            *self.0.lock().expect("lock") = None;
            Ok(())
        }
    }

    #[test]
    fn the_keeper_copies_and_clears_its_own_value() {
        let fake = Fake::default();
        let keeper = Keeper::with(SecretClipboard::with_backend(fake.clone()).expect("clipboard"));
        ClipboardHost::copy(&keeper, "hunter2", None).expect("copy");
        assert_eq!(fake.content().as_deref(), Some("hunter2"));
        ClipboardHost::clear_if_ours(&keeper);
        assert_eq!(fake.content(), None);
    }

    #[test]
    fn without_a_pasteboard_copies_fail_with_a_message() {
        let error = ClipboardHost::copy(&NoClipboard, "hunter2", None).expect_err("refused");
        assert_eq!(error, "the clipboard is not available");
    }
}
