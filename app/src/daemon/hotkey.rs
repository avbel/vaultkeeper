//! The global shortcuts: the Quick Panel (default ⌘⇧Space) and, if set, the Generator. The
//! manager must live on the main thread; presses arrive through its event handler on that thread,
//! no polling.

use std::{
    cell::RefCell,
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex, PoisonError},
};

use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState, hotkey::HotKey};

use super::{
    Daemon,
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
            if let Some(slot) = slot {
                daemon.apply(routing::hotkey(slot));
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
    pub fn bind(&self, slot: HotkeySlot, accelerator: &str) -> anyhow::Result<()> {
        let accelerator = accelerator.trim();
        if self
            .bound
            .borrow()
            .get(&slot)
            .is_some_and(|(text, _)| text == accelerator)
        {
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
                Err(anyhow::anyhow!("cannot register {accelerator}: {error}"))
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

impl Drop for Hotkey {
    fn drop(&mut self) {
        GlobalHotKeyEvent::set_event_handler(None::<fn(GlobalHotKeyEvent)>);
        for (_, (_, hotkey)) in self.bound.borrow_mut().drain() {
            let _ = self.manager.unregister(hotkey);
        }
    }
}
