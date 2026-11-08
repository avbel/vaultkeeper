//! The concealed clipboard with auto-clear (`bwl_platform::clipboard::SecretClipboard`), plus the
//! clear deadline the UI process needs: it must not exit while a clear is pending, because the
//! clearer runs in this process.

use std::{
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use bwl_platform::clipboard::{ClipboardBackend, SecretClipboard, SystemClipboard as Pasteboard};

use crate::hooks::{Clipboard, HookError, HookResult};

pub struct SystemClipboard<B: ClipboardBackend = Pasteboard> {
    inner: SecretClipboard<B>,
    clears_at: Mutex<Option<Instant>>,
}

impl SystemClipboard {
    pub fn new() -> bwl_platform::Result<Self> {
        Ok(Self::with(SecretClipboard::new()?))
    }
}

impl<B: ClipboardBackend> SystemClipboard<B> {
    #[must_use]
    pub fn with(inner: SecretClipboard<B>) -> Self {
        Self {
            inner,
            clears_at: Mutex::new(None),
        }
    }

    fn set_deadline(&self, deadline: Option<Instant>) {
        *self
            .clears_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = deadline;
    }
}

impl<B: ClipboardBackend> Clipboard for SystemClipboard<B> {
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> HookResult<()> {
        self.inner
            .copy(text, clear_after)
            .map_err(|error| HookError::Failed(error.to_string()))?;
        self.set_deadline(clear_after.and_then(|after| Instant::now().checked_add(after)));
        Ok(())
    }

    fn clear_if_ours(&self) {
        self.set_deadline(None);
        if let Err(error) = self.inner.clear_if_ours() {
            tracing::warn!(%error, "could not clear the clipboard");
        }
    }

    fn pending_clear(&self) -> Option<Instant> {
        let deadline = *self
            .clears_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        deadline.filter(|deadline| *deadline > Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    use super::*;

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<Option<String>>>);

    impl ClipboardBackend for Fake {
        fn set_secret(&mut self, text: &str) -> bwl_platform::Result<()> {
            *self.0.lock().expect("lock") = Some(text.to_owned());
            Ok(())
        }

        fn text(&mut self) -> bwl_platform::Result<Option<Zeroizing<String>>> {
            Ok(self.0.lock().expect("lock").clone().map(Zeroizing::new))
        }

        fn clear(&mut self) -> bwl_platform::Result<()> {
            *self.0.lock().expect("lock") = None;
            Ok(())
        }
    }

    #[test]
    fn a_timed_copy_is_pending_until_cleared() {
        let fake = Fake::default();
        let clipboard =
            SystemClipboard::with(SecretClipboard::with_backend(fake.clone()).expect("clipboard"));
        assert_eq!(clipboard.pending_clear(), None);
        clipboard
            .copy("hunter2", Some(Duration::from_secs(30)))
            .expect("copy");
        let pending = clipboard.pending_clear().expect("pending");
        assert!(pending > Instant::now() + Duration::from_secs(29));
        clipboard.clear_if_ours();
        assert_eq!(clipboard.pending_clear(), None);
        assert_eq!(*fake.0.lock().expect("lock"), None, "cleared now");
    }

    #[test]
    fn a_copy_without_timeout_has_nothing_pending() {
        let clipboard = SystemClipboard::with(
            SecretClipboard::with_backend(Fake::default()).expect("clipboard"),
        );
        clipboard.copy("kept", None).expect("copy");
        assert_eq!(clipboard.pending_clear(), None);
    }

    #[test]
    fn an_elapsed_deadline_is_not_pending() {
        let fake = Fake::default();
        let clipboard =
            SystemClipboard::with(SecretClipboard::with_backend(fake.clone()).expect("clipboard"));
        clipboard
            .copy("brief", Some(Duration::from_millis(20)))
            .expect("copy");
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(clipboard.pending_clear(), None);
    }
}
