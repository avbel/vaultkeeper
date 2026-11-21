//! The global shortcuts: the Quick Panel (default ⌘⇧Space, Ctrl+Shift+Space on Windows) and, if set, the Generator. The
//! manager must live on the main thread; presses arrive through its event handler on that thread,
//! no polling.

use std::{
    cell::RefCell,
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex, PoisonError},
};

use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState, hotkey::HotKey};

use crate::daemon::{
    Daemon,
    hotkey_pause::{HotkeyBinder, Unavailable},
    routing::{self, HotkeySlot},
};

pub struct Hotkey {
    manager: GlobalHotKeyManager,
    bound: RefCell<HashMap<HotkeySlot, (String, HotKey)>>,
    /// Hotkey id → slot, read by the event handler.
    slots: Arc<Mutex<HashMap<u32, HotkeySlot>>>,
}

impl Hotkey {
    pub fn new(daemon: &Arc<Daemon>) -> anyhow::Result<Self> {
        let manager = GlobalHotKeyManager::new()?;
        let daemon = Arc::clone(daemon);
        let slots: Arc<Mutex<HashMap<u32, HotkeySlot>>> = Arc::default();
        let lookup = Arc::clone(&slots);
        GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
            if event.state != HotKeyState::Pressed {
                return;
            }
            let slot = lookup
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&event.id)
                .copied();
            // Carbon calls hotkey handlers on the main thread (global-hotkey 0.9 installs them on
            // the application event target), where the frontmost app can be read.
            if let Some(slot) = slot {
                daemon.apply(routing::hotkey(slot, || daemon.typing_target()));
            }
        }));
        Ok(Self {
            manager,
            bound: RefCell::new(HashMap::new()),
            slots,
        })
    }

    /// Replaces the binding of `slot`; an empty `accelerator` removes it. On failure the previous
    /// binding stays registered.
    fn bind_slot(&self, slot: HotkeySlot, accelerator: &str) -> anyhow::Result<()> {
        let accelerator = accelerator.trim();
        let unchanged = self
            .bound
            .borrow()
            .get(&slot)
            .map_or_else(|| accelerator.is_empty(), |(text, _)| text == accelerator);
        if unchanged {
            return Ok(());
        }
        let hotkey = if accelerator.is_empty() {
            None
        } else {
            Some(
                HotKey::from_str(accelerator)
                    .map_err(|error| anyhow::anyhow!("not a shortcut: {accelerator}: {error}"))?,
            )
        };
        let previous = self.bound.borrow_mut().remove(&slot);
        if let Some((_, old)) = &previous {
            self.forget(*old);
        }
        let Some(hotkey) = hotkey else {
            tracing::info!(?slot, "global hotkey removed");
            return Ok(());
        };
        match self.manager.register(hotkey) {
            Ok(()) => {
                tracing::info!(?slot, accelerator, "global hotkey registered");
                self.remember(slot, accelerator.to_owned(), hotkey);
                Ok(())
            }
            Err(error) => {
                if let Some((text, old)) = previous
                    && self.manager.register(old).is_ok()
                {
                    self.remember(slot, text, old);
                }
                Err(classify(accelerator, error))
            }
        }
    }

    fn remember(&self, slot: HotkeySlot, text: String, hotkey: HotKey) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(hotkey.id(), slot);
        self.bound.borrow_mut().insert(slot, (text, hotkey));
    }

    fn forget(&self, hotkey: HotKey) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&hotkey.id());
        if let Err(error) = self.manager.unregister(hotkey) {
            tracing::debug!(%error, "previous hotkey was not registered");
        }
    }
}

/// The OS saying no (another app holds the shortcut, or Windows reserves it) becomes
/// [`Unavailable`]; anything else stays a plain error.
fn classify(accelerator: &str, error: global_hotkey::Error) -> anyhow::Error {
    use global_hotkey::Error;
    match error {
        Error::AlreadyRegistered(_) | Error::OsError(_) | Error::FailedToRegister(_) => {
            Unavailable {
                accelerator: accelerator.to_owned(),
                reason: error.to_string(),
            }
            .into()
        }
        other => anyhow::anyhow!("cannot register {accelerator}: {other}"),
    }
}

impl HotkeyBinder for Hotkey {
    fn bind(&self, slot: HotkeySlot, accelerator: &str) -> anyhow::Result<()> {
        self.bind_slot(slot, accelerator)
    }
}

impl Drop for Hotkey {
    fn drop(&mut self) {
        GlobalHotKeyEvent::set_event_handler(None::<fn(GlobalHotKeyEvent)>);
        for (_, (_, hotkey)) in self.bound.borrow_mut().drain() {
            let _ = self.manager.unregister(hotkey);
        }
    }
}

#[cfg(test)]
mod tests {
    use global_hotkey::Error;

    use super::*;

    fn is_unavailable(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Unavailable>().is_some()
    }

    #[test]
    fn a_taken_or_refused_shortcut_is_unavailable() {
        let hotkey = HotKey::from_str("Ctrl+Shift+Space").expect("parses");
        assert!(is_unavailable(&classify(
            "Ctrl+Shift+Space",
            Error::AlreadyRegistered(hotkey)
        )));
        assert!(is_unavailable(&classify(
            "Win+L",
            Error::OsError(std::io::Error::from_raw_os_error(1409))
        )));
        assert!(is_unavailable(&classify(
            "Cmd+Q",
            Error::FailedToRegister("denied".to_owned())
        )));
    }

    #[test]
    fn a_parse_failure_is_not_unavailable() {
        assert!(!is_unavailable(&classify(
            "Hyper+X",
            Error::HotKeyParseError("bad".to_owned())
        )));
    }
}
