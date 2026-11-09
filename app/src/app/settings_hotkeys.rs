//! Settings → Shortcuts: the two shortcut recorders. Every path (a recorded key, an accessibility
//! set-value, Delete) ends in `accept_hotkey`, which validates, saves and re-shows both values.

use slint::{
    ComponentHandle,
    winit_030::{
        EventResult, WinitWindowAccessor,
        winit::{
            event::{ElementState, WindowEvent},
            keyboard::{ModifiersState, PhysicalKey},
        },
    },
};
use vk_vault::VaultService;

use super::{App, handler};
use crate::{
    hooks::{HookError, HookResult},
    hotkey_recorder::{Mods, accelerator, is_modifier_text, key_from_text, physical_accelerator},
    settings::{Settings, hotkey_symbols},
    ui::SettingsWindow,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    QuickPanel,
    Generator,
}

impl Slot {
    /// `recording-slot` of the Settings window.
    fn recording(window: &SettingsWindow) -> Option<Self> {
        match window.get_recording_slot() {
            1 => Some(Self::QuickPanel),
            2 => Some(Self::Generator),
            _ => None,
        }
    }
}

pub(super) fn show_hotkeys(window: &SettingsWindow, settings: &Settings) {
    window.set_hotkey(settings.hotkey.as_str().into());
    window.set_hotkey_shown(hotkey_symbols(&settings.hotkey).into());
    window.set_generator_hotkey(settings.generator_hotkey.as_str().into());
    window.set_generator_hotkey_shown(hotkey_symbols(&settings.generator_hotkey).into());
}

impl<S: VaultService> App<S> {
    /// Slint reports ⌘ as `control` and ⌃ as `meta` on macOS.
    pub(super) fn bind_hotkeys(&self, window: &SettingsWindow) {
        window.on_hotkey_accepted(handler!(self, |app, accelerator| {
            app.accept_hotkey(Slot::QuickPanel, &accelerator);
        }));
        window.on_generator_hotkey_accepted(handler!(self, |app, accelerator| {
            app.accept_hotkey(Slot::Generator, &accelerator);
        }));
        window.on_hotkey_pressed(handler!(
            self,
            false,
            |app, text, control, meta, alt, shift| {
                app.record_text(
                    Slot::QuickPanel,
                    &text,
                    Mods {
                        cmd: control,
                        ctrl: meta,
                        alt,
                        shift,
                    },
                )
            }
        ));
        window.on_generator_hotkey_pressed(handler!(
            self,
            false,
            |app, text, control, meta, alt, shift| {
                app.record_text(
                    Slot::Generator,
                    &text,
                    Mods {
                        cmd: control,
                        ctrl: meta,
                        alt,
                        shift,
                    },
                )
            }
        ));
        window.on_recording_changed(handler!(self, |app, recording| {
            app.hooks.hotkey.pause(recording);
        }));
        self.filter_recorder_keys(window);
    }

    /// A window closed mid-recording may never report the stop.
    pub(super) fn end_recording(&self, window: &SettingsWindow) {
        if window.get_recording_slot() != 0 {
            window.invoke_stop_recording();
            self.hooks.hotkey.pause(false);
        }
    }

    /// Records by physical key before Slint sees the press: Slint's key text is what the layout
    /// typed (⌥G gives "©", ⌥E is a dead key Slint drops, a Cyrillic layout gives "п"), while
    /// the daemon registers the physical key. Presses this cannot record (Esc, Delete, a key
    /// without ⌘/⌥/⌃) go on to the recorder's own handling. A no-op off the winit backend.
    fn filter_recorder_keys(&self, window: &SettingsWindow) {
        let app = std::rc::Weak::clone(&self.me);
        let weak = window.as_weak();
        let mut held = ModifiersState::empty();
        window
            .window()
            .on_winit_window_event(move |_, event| match event {
                WindowEvent::ModifiersChanged(modifiers) => {
                    held = modifiers.state();
                    EventResult::Propagate
                }
                WindowEvent::KeyboardInput {
                    event,
                    is_synthetic: false,
                    ..
                } if event.state == ElementState::Pressed => {
                    match (app.upgrade(), weak.upgrade()) {
                        (Some(app), Some(window)) => {
                            app.record_physical(&window, event.physical_key, held)
                        }
                        _ => EventResult::Propagate,
                    }
                }
                _ => EventResult::Propagate,
            });
    }

    fn record_physical(
        &self,
        window: &SettingsWindow,
        key: PhysicalKey,
        held: ModifiersState,
    ) -> EventResult {
        let Some(slot) = Slot::recording(window) else {
            return EventResult::Propagate;
        };
        let PhysicalKey::Code(code) = key else {
            return EventResult::Propagate;
        };
        let Ok(text) = physical_accelerator(code, held) else {
            return EventResult::Propagate;
        };
        if self.accept_hotkey(slot, &text) {
            window.invoke_stop_recording();
        }
        EventResult::PreventDefault
    }

    fn record_text(&self, slot: Slot, text: &str, mods: Mods) -> bool {
        if is_modifier_text(text) {
            return false;
        }
        match accelerator(mods, key_from_text(text)) {
            Ok(text) => self.accept_hotkey(slot, &text),
            Err(reject) => {
                self.report(Err(HookError::Failed(reject.to_string())));
                false
            }
        }
    }

    /// `true` when saved. Either way both recorders show the saved values again, so a refused
    /// shortcut does not stay on screen.
    fn accept_hotkey(&self, slot: Slot, accelerator: &str) -> bool {
        let accelerator = accelerator.trim();
        let saved = match self.check_hotkey(slot, accelerator) {
            Ok(()) => {
                self.update_settings(|settings| {
                    let field = match slot {
                        Slot::QuickPanel => &mut settings.hotkey,
                        Slot::Generator => &mut settings.generator_hotkey,
                    };
                    accelerator.clone_into(field);
                });
                true
            }
            Err(error) => {
                self.report(Err(error));
                false
            }
        };
        let window = self
            .settings_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = window {
            show_hotkeys(&window, &self.settings.borrow());
        }
        saved
    }

    fn check_hotkey(&self, slot: Slot, accelerator: &str) -> HookResult<()> {
        if accelerator.is_empty() {
            return match slot {
                Slot::Generator => Ok(()),
                Slot::QuickPanel => Err(HookError::Failed(
                    "The Quick Panel needs a hotkey".to_owned(),
                )),
            };
        }
        let taken = {
            let settings = self.settings.borrow();
            match slot {
                Slot::QuickPanel => same_shortcut(accelerator, &settings.generator_hotkey)
                    .then_some("Already the Generator hotkey"),
                Slot::Generator => same_shortcut(accelerator, &settings.hotkey)
                    .then_some("Already the Quick Panel hotkey"),
            }
        };
        if let Some(message) = taken {
            return Err(HookError::Failed(message.to_owned()));
        }
        // Checked before saving: the daemon registers whatever the file says.
        self.hooks.hotkey.register(accelerator)
    }
}

/// The same keys however they are spelled ("cmd+alt+g" and "Alt+Cmd+G"); empty matches nothing.
fn same_shortcut(a: &str, b: &str) -> bool {
    !a.is_empty() && hotkey_symbols(a).to_lowercase() == hotkey_symbols(b).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcuts_match_whatever_the_spelling() {
        assert!(same_shortcut("cmd+alt+g", "Alt+Cmd+G"));
        assert!(same_shortcut("Shift+Cmd+Space", "Cmd+Shift+Space"));
        assert!(!same_shortcut("Cmd+Alt+G", "Cmd+G"));
        assert!(!same_shortcut("", ""), "no hotkey is never a duplicate");
    }
}
