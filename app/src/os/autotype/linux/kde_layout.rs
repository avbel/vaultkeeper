//! KWin resolves a keysym in any layout of the session, but typing one of another layout leaves
//! that layout active (a Cyrillic keysym with `us` active leaves `ru`). So the layout is read
//! before a run on KDE and put back afterwards by [`Restore`], on every way out of the run.
//! `org.kde.keyboard` switches in a millisecond or two; where the service is missing, typing goes
//! ahead without the restore.

use std::time::Duration;

use zbus::Connection;

use super::remote_desktop::runtime;

const SERVICE: &str = "org.kde.keyboard";
const PATH: &str = "/Layouts";
const INTERFACE: &str = "org.kde.KeyboardLayouts";
/// The calls take a millisecond or two; this only stops a hung service from holding up the end
/// of a typing job, which runs this on a drop.
const CALL_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) trait LayoutSwitcher {
    fn current(&self) -> Result<u32, String>;
    fn switch_to(&self, layout: u32) -> Result<(), String>;
}

/// Puts the layout that was active at [`Restore::capture`] back when dropped, if it changed.
pub(super) struct Restore<S: LayoutSwitcher> {
    switcher: S,
    saved: Option<u32>,
}

impl<S: LayoutSwitcher> Restore<S> {
    pub(super) fn capture(switcher: S) -> Self {
        let saved = switcher
            .current()
            .inspect_err(|error| tracing::debug!(%error, "cannot read the KDE keyboard layout"))
            .ok();
        Self { switcher, saved }
    }
}

impl<S: LayoutSwitcher> Drop for Restore<S> {
    fn drop(&mut self) {
        let Some(saved) = self.saved else {
            return;
        };
        match self.switcher.current() {
            Ok(now) if now == saved => {}
            Ok(_) => {
                if let Err(error) = self.switcher.switch_to(saved) {
                    tracing::debug!(%error, "cannot restore the KDE keyboard layout");
                }
            }
            Err(error) => tracing::debug!(%error, "cannot read the KDE keyboard layout"),
        }
    }
}

/// `org.kde.keyboard` on the session bus. Blocks on the portal runtime, so it must be used from
/// a plain thread, never from inside that runtime.
pub(super) struct Kwin {
    connection: Connection,
}

impl Kwin {
    pub(super) fn connect() -> Result<Self, String> {
        let runtime = runtime().map_err(|_| "no runtime".to_owned())?;
        let connection = runtime
            .block_on(async { tokio::time::timeout(CALL_TIMEOUT, Connection::session()).await })
            .map_err(|_| "the session bus did not answer in time".to_owned())?
            .map_err(|error| format!("no session bus ({error})"))?;
        Ok(Self { connection })
    }

    fn call<B>(&self, method: &'static str, body: &B) -> Result<zbus::Message, String>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        let runtime = runtime().map_err(|_| "no runtime".to_owned())?;
        let call = self
            .connection
            .call_method(Some(SERVICE), PATH, Some(INTERFACE), method, body);
        // A timer needs the runtime's context, so it is created inside the future.
        runtime
            .block_on(async { tokio::time::timeout(CALL_TIMEOUT, call).await })
            .map_err(|_| format!("{method} did not answer in time"))?
            .map_err(|error| format!("{method} failed ({error})"))
    }
}

impl LayoutSwitcher for Kwin {
    fn current(&self) -> Result<u32, String> {
        self.call("getLayout", &())?
            .body()
            .deserialize::<u32>()
            .map_err(|error| format!("getLayout answered oddly ({error})"))
    }

    fn switch_to(&self, layout: u32) -> Result<(), String> {
        let switched = self
            .call("setLayout", &(layout,))?
            .body()
            .deserialize::<bool>()
            .map_err(|error| format!("setLayout answered oddly ({error})"))?;
        if switched {
            Ok(())
        } else {
            Err("setLayout refused the layout".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;

    #[derive(Default)]
    struct Fake {
        layout: Cell<u32>,
        read_fails: Cell<bool>,
        set_fails: Cell<bool>,
        sets: RefCell<Vec<u32>>,
    }

    struct Shared(Rc<Fake>);

    impl LayoutSwitcher for Shared {
        fn current(&self) -> Result<u32, String> {
            if self.0.read_fails.get() {
                return Err("no service".to_owned());
            }
            Ok(self.0.layout.get())
        }

        fn switch_to(&self, layout: u32) -> Result<(), String> {
            self.0.sets.borrow_mut().push(layout);
            if self.0.set_fails.get() {
                return Err("refused".to_owned());
            }
            self.0.layout.set(layout);
            Ok(())
        }
    }

    fn fake(layout: u32) -> Rc<Fake> {
        let fake = Rc::new(Fake::default());
        fake.layout.set(layout);
        fake
    }

    #[test]
    fn the_saved_layout_comes_back_after_a_run_that_drifted() {
        let fake = fake(0);
        {
            let _restore = Restore::capture(Shared(Rc::clone(&fake)));
            fake.layout.set(1);
        }
        assert_eq!(fake.layout.get(), 0);
        assert_eq!(*fake.sets.borrow(), [0]);
    }

    #[test]
    fn the_layout_comes_back_when_the_run_fails_or_panics() {
        let failed = fake(0);
        let run = |fake: &Rc<Fake>| -> Result<(), &'static str> {
            let _restore = Restore::capture(Shared(Rc::clone(fake)));
            fake.layout.set(1);
            Err("stopped")
        };
        assert!(run(&failed).is_err());
        assert_eq!(failed.layout.get(), 0);

        let panicked = fake(1);
        let inner = Rc::clone(&panicked);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _restore = Restore::capture(Shared(Rc::clone(&inner)));
            inner.layout.set(0);
            panic!("typing blew up");
        }));
        assert!(outcome.is_err());
        assert_eq!(panicked.layout.get(), 1);
    }

    #[test]
    fn an_unchanged_layout_is_not_set_again() {
        let fake = fake(1);
        drop(Restore::capture(Shared(Rc::clone(&fake))));
        assert!(fake.sets.borrow().is_empty());
    }

    #[test]
    fn a_switcher_that_errors_never_fails_the_run() {
        let unreadable = fake(0);
        unreadable.read_fails.set(true);
        drop(Restore::capture(Shared(Rc::clone(&unreadable))));
        assert!(unreadable.sets.borrow().is_empty());

        let stuck = fake(0);
        {
            let _restore = Restore::capture(Shared(Rc::clone(&stuck)));
            stuck.layout.set(1);
            stuck.set_fails.set(true);
        }
        assert_eq!(*stuck.sets.borrow(), [0]);
        assert_eq!(stuck.layout.get(), 1);
    }
}
