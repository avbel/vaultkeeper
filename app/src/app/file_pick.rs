//! Native file pickers off the UI thread. A portal chooser stays open for as long as the user
//! likes, and a Slint event loop that stops answering the compositor's pings is reported as
//! "not responding" after about ten seconds.

use std::{cell::Cell, path::PathBuf, rc::Rc};

use vk_vault::VaultService;

use super::{App, handler};
use crate::hooks::FileDialogs;

/// Lets one picker run at a time; a second request while one is open is dropped.
#[derive(Default)]
pub(super) struct DialogGate(Cell<bool>);

impl DialogGate {
    pub(super) fn try_begin(&self) -> bool {
        !self.0.replace(true)
    }

    pub(super) fn finish(&self) {
        self.0.set(false);
    }
}

/// Reopens the gate when dropped. The continuation can be dropped without ever running (the
/// dialog thread panicked, or the UI loop refused the task); without this the gate would stay
/// shut and every later picker request would be ignored until restart.
struct Release(Rc<DialogGate>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.finish();
    }
}

impl<S: VaultService> App<S> {
    /// Runs `show` on a worker thread and `then` on the UI thread with the chosen path; a
    /// cancelled dialog or a request made while another dialog is open does nothing.
    pub(super) fn pick_file(
        &self,
        show: impl FnOnce(&dyn FileDialogs) -> Option<PathBuf> + Send + 'static,
        then: impl FnOnce(&Self, PathBuf) + 'static,
    ) {
        if !self.file_dialog.try_begin() {
            return;
        }
        let files = std::sync::Arc::clone(&self.hooks.files);
        let release = Release(Rc::clone(&self.file_dialog));
        self.exec.spawn_blocking(
            move || show(files.as_ref()),
            handler!(self, |app, picked| {
                drop(release);
                if let Some(path) = picked {
                    then(&app, path);
                }
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_dialog_is_open_at_a_time() {
        let gate = DialogGate::default();
        assert!(gate.try_begin());
        assert!(!gate.try_begin());
        gate.finish();
        assert!(gate.try_begin());
    }

    #[test]
    fn a_continuation_dropped_unrun_reopens_the_gate() {
        let gate = Rc::new(DialogGate::default());
        assert!(gate.try_begin());
        let release = Release(Rc::clone(&gate));
        drop(move || drop(release));
        assert!(gate.try_begin());
    }

    #[test]
    fn a_panic_while_the_continuation_is_alive_reopens_the_gate() {
        let gate = Rc::new(DialogGate::default());
        assert!(gate.try_begin());
        let release = Release(Rc::clone(&gate));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = release;
            panic!("dialog crashed");
        }));
        assert!(outcome.is_err());
        assert!(gate.try_begin());
    }
}
