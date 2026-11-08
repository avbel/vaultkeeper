//! The global Quick Panel shortcut (default ⌘⇧Space). The manager must live on the main thread;
//! presses arrive through its event handler on that thread, no polling.

use std::{cell::RefCell, str::FromStr, sync::Arc};

use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState, hotkey::HotKey};

use super::{Daemon, routing};

pub struct Hotkey {
    manager: GlobalHotKeyManager,
    bound: RefCell<Option<(String, HotKey)>>,
}

impl Hotkey {
    pub fn new(daemon: &Arc<Daemon>) -> anyhow::Result<Self> {
        let manager = GlobalHotKeyManager::new()?;
        let daemon = Arc::clone(daemon);
        GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
            if event.state == HotKeyState::Pressed {
                daemon.apply(routing::hotkey());
            }
        }));
        Ok(Self {
            manager,
            bound: RefCell::new(None),
        })
    }

    /// Replaces the binding; on failure the previous one stays registered.
    pub fn bind(&self, accelerator: &str) -> anyhow::Result<()> {
        if self
            .bound
            .borrow()
            .as_ref()
            .is_some_and(|(text, _)| text == accelerator)
        {
            return Ok(());
        }
        let hotkey = HotKey::from_str(accelerator)
            .map_err(|error| anyhow::anyhow!("not a shortcut: {accelerator}: {error}"))?;
        let previous = self.bound.borrow_mut().take();
        if let Some((_, old)) = &previous
            && let Err(error) = self.manager.unregister(*old)
        {
            tracing::debug!(%error, "previous hotkey was not registered");
        }
        match self.manager.register(hotkey) {
            Ok(()) => {
                tracing::info!(accelerator, "global hotkey registered");
                *self.bound.borrow_mut() = Some((accelerator.to_owned(), hotkey));
                Ok(())
            }
            Err(error) => {
                if let Some((text, old)) = previous
                    && self.manager.register(old).is_ok()
                {
                    *self.bound.borrow_mut() = Some((text, old));
                }
                Err(anyhow::anyhow!("cannot register {accelerator}: {error}"))
            }
        }
    }
}

impl Drop for Hotkey {
    fn drop(&mut self) {
        GlobalHotKeyEvent::set_event_handler(None::<fn(GlobalHotKeyEvent)>);
        if let Some((_, hotkey)) = self.bound.borrow_mut().take() {
            let _ = self.manager.unregister(hotkey);
        }
    }
}
