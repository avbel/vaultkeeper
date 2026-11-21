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
use vk_ipc::HotkeyMode;
use vk_vault::VaultService;

use super::{App, handler};
use crate::{
    hooks::{HookError, HookResult},
    hotkey_recorder::{
        ALTGR_WARNING, Mods, UNAVAILABLE_NOTICE, accelerator, is_modifier_text, key_from_text,
        physical_accelerator,
    },
    settings::{Settings, ctrl_alt_only, hotkey_display, hotkey_symbols},
    shortcut_syntax::{Compositor, compositor_lines},
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

/// Shortcuts the OS refused to register, as the daemon reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Issues {
    pub quick_panel: bool,
    pub generator: bool,
}

/// Who owns the shortcuts and what the desktop calls them, as the daemon reported (Linux only;
/// elsewhere the recorders are the whole story).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Bindings {
    pub mode: HotkeyMode,
    pub quick_panel: String,
    pub generator: String,
}

/// What Settings adds to the recorders when the desktop owns the shortcuts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SystemView {
    quick_panel_note: String,
    generator_note: String,
    /// The desktop has a shortcut dialog the "Change in system settings…" button opens.
    configurable: bool,
    lines_hint: String,
    lines: String,
}

fn system_view(bindings: &Bindings, settings: &Settings, compositor: Compositor) -> SystemView {
    match bindings.mode {
        HotkeyMode::Recorder => SystemView::default(),
        HotkeyMode::Portal => SystemView {
            quick_panel_note: assigned_note(&bindings.quick_panel),
            generator_note: if settings.generator_hotkey.trim().is_empty() {
                String::new()
            } else {
                assigned_note(&bindings.generator)
            },
            configurable: true,
            ..SystemView::default()
        },
        HotkeyMode::Manual => {
            let lines = compositor_lines(compositor, &settings.hotkey, &settings.generator_hotkey);
            SystemView {
                lines_hint: manual_hint(compositor, lines.is_some()).to_owned(),
                lines: lines.unwrap_or_default(),
                ..SystemView::default()
            }
        }
    }
}

fn assigned_note(trigger: &str) -> String {
    if trigger.is_empty() {
        "Not assigned by your desktop yet. Use \"Change in system settings…\".".to_owned()
    } else {
        format!("Your desktop uses: {trigger}")
    }
}

const fn manual_hint(compositor: Compositor, has_lines: bool) -> &'static str {
    match (compositor, has_lines) {
        (Compositor::Sway, true) => {
            "This desktop cannot register global shortcuts for apps. Add to your Sway config:"
        }
        (Compositor::Hyprland, true) => {
            "This desktop cannot register global shortcuts for apps. Add to your Hyprland config:"
        }
        (Compositor::Omarchy, true) => {
            "This desktop cannot register global shortcuts for apps. Add to ~/.config/hypr/bindings.lua:"
        }
        _ => {
            "This desktop cannot register global shortcuts for apps. Bind `vaultkeeper --search` (and `vaultkeeper --generator`) to keys in your desktop's keyboard settings."
        }
    }
}

#[cfg(target_os = "linux")]
fn current_compositor() -> Compositor {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let omarchy = vk_linux::distro::detect() == vk_linux::distro::Distro::Omarchy;
    Compositor::detect(&desktop, omarchy)
}

#[cfg(not(target_os = "linux"))]
const fn current_compositor() -> Compositor {
    Compositor::Other
}

/// The binding lines the Copy button puts on the clipboard.
pub(super) fn manual_lines(bindings: &Bindings, settings: &Settings) -> String {
    system_view(bindings, settings, current_compositor()).lines
}

/// What to show under a shortcut: the refusal wins over the AltGr hint, which macOS never needs.
pub(super) fn hotkey_note(accelerator: &str, refused: bool) -> (&'static str, bool) {
    if refused {
        (UNAVAILABLE_NOTICE, true)
    } else if cfg!(not(target_os = "macos")) && ctrl_alt_only(accelerator) {
        (ALTGR_WARNING, false)
    } else {
        ("", false)
    }
}

pub(super) fn show_hotkeys(
    window: &SettingsWindow,
    settings: &Settings,
    issues: Issues,
    bindings: &Bindings,
) {
    let system = system_view(bindings, settings, current_compositor());
    window.set_hotkey(settings.hotkey.as_str().into());
    window.set_hotkey_shown(hotkey_display(&settings.hotkey).into());
    window.set_generator_hotkey(settings.generator_hotkey.as_str().into());
    window.set_generator_hotkey_shown(hotkey_display(&settings.generator_hotkey).into());
    let (text, refused) = hotkey_note(&settings.hotkey, issues.quick_panel);
    let text = if system.quick_panel_note.is_empty() {
        text
    } else {
        system.quick_panel_note.as_str()
    };
    window.set_hotkey_note(text.into());
    window.set_hotkey_note_is_error(refused);
    let (text, refused) = hotkey_note(&settings.generator_hotkey, issues.generator);
    let text = if system.generator_note.is_empty() {
        text
    } else {
        system.generator_note.as_str()
    };
    window.set_generator_hotkey_note(text.into());
    window.set_generator_hotkey_note_is_error(refused);
    window.set_shortcuts_configurable(system.configurable);
    window.set_shortcut_lines_hint(system.lines_hint.into());
    window.set_shortcut_lines(system.lines.into());
}

/// Slint reports ⌘ as `control` and ⌃ as `meta` on macOS; elsewhere `control` is Ctrl and
/// `meta` is the Win or Super key.
#[allow(
    clippy::fn_params_excessive_bools,
    reason = "mirrors the Slint callback"
)]
fn slint_mods(control: bool, meta: bool, alt: bool, shift: bool) -> Mods {
    let (cmd, ctrl) = if cfg!(not(target_os = "macos")) {
        (meta, control)
    } else {
        (control, meta)
    };
    Mods {
        cmd,
        ctrl,
        alt,
        shift,
    }
}

impl<S: VaultService> App<S> {
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
                    slint_mods(control, meta, alt, shift),
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
                    slint_mods(control, meta, alt, shift),
                )
            }
        ));
        window.on_configure_shortcuts(handler!(self, |app| {
            app.hooks.hotkey.configure_system();
        }));
        window.on_copy_shortcut_lines(handler!(self, false, |app| {
            let lines = zeroize::Zeroizing::new(manual_lines(
                &app.hotkey_bindings.borrow(),
                &app.settings.borrow(),
            ));
            app.copy_text("shortcut lines", &lines)
        }));
        window.on_recording_changed(handler!(self, |app, recording| {
            app.hooks.hotkey.pause(recording);
        }));
        self.filter_recorder_keys(window);
    }

    pub(super) fn hotkey_issues_changed(&self, quick_panel: bool, generator: bool) {
        self.hotkey_issues.set(Issues {
            quick_panel,
            generator,
        });
        let window = self
            .settings_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = window {
            show_hotkeys(
                &window,
                &self.settings.borrow(),
                self.hotkey_issues.get(),
                &self.hotkey_bindings.borrow(),
            );
        }
    }

    pub(super) fn hotkey_bindings_changed(&self, bindings: Bindings) {
        self.hotkey_bindings.replace(bindings);
        let window = self
            .settings_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = window {
            show_hotkeys(
                &window,
                &self.settings.borrow(),
                self.hotkey_issues.get(),
                &self.hotkey_bindings.borrow(),
            );
        }
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
    /// without a modifier the recorder accepts) go on to the recorder's own handling. A no-op off the winit backend.
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
                let mut issues = self.hotkey_issues.get();
                match slot {
                    Slot::QuickPanel => issues.quick_panel = false,
                    Slot::Generator => issues.generator = false,
                }
                self.hotkey_issues.set(issues);
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
            show_hotkeys(
                &window,
                &self.settings.borrow(),
                self.hotkey_issues.get(),
                &self.hotkey_bindings.borrow(),
            );
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
    fn a_refused_shortcut_shows_the_platform_notice_as_an_error() {
        let (text, is_error) = hotkey_note("Ctrl+Shift+Space", true);
        assert_eq!(text, UNAVAILABLE_NOTICE);
        assert!(is_error);
        assert_eq!(hotkey_note("Ctrl+Shift+Space", false), ("", false));
    }

    #[test]
    fn the_altgr_hint_is_a_non_error_note_off_macos() {
        let expected = if cfg!(not(target_os = "macos")) {
            (ALTGR_WARNING, false)
        } else {
            ("", false)
        };
        assert_eq!(hotkey_note("Ctrl+Alt+G", false), expected);
    }

    fn bindings(mode: HotkeyMode, quick_panel: &str) -> Bindings {
        Bindings {
            mode,
            quick_panel: quick_panel.to_owned(),
            generator: String::new(),
        }
    }

    #[test]
    fn the_recorders_stand_alone_where_the_daemon_registers_the_shortcuts() {
        let view = system_view(&Bindings::default(), &Settings::default(), Compositor::Sway);
        assert_eq!(view, SystemView::default());
    }

    #[test]
    fn a_portal_shows_the_desktops_trigger_and_offers_its_dialog() {
        let settings = Settings {
            generator_hotkey: String::new(),
            ..Settings::default()
        };
        let view = system_view(
            &bindings(HotkeyMode::Portal, "Ctrl+Shift+Space"),
            &settings,
            Compositor::Other,
        );
        assert_eq!(view.quick_panel_note, "Your desktop uses: Ctrl+Shift+Space");
        assert_eq!(
            view.generator_note, "",
            "no Generator shortcut, nothing to say"
        );
        assert!(view.configurable);
        let unassigned = system_view(
            &bindings(HotkeyMode::Portal, ""),
            &settings,
            Compositor::Other,
        );
        assert!(unassigned.quick_panel_note.starts_with("Not assigned"));
    }

    #[test]
    fn without_a_portal_the_compositor_lines_follow_the_saved_shortcuts() {
        let settings = Settings {
            hotkey: "Ctrl+Shift+Space".to_owned(),
            generator_hotkey: String::new(),
            ..Settings::default()
        };
        let view = system_view(
            &bindings(HotkeyMode::Manual, ""),
            &settings,
            Compositor::Omarchy,
        );
        assert_eq!(
            view.lines,
            "o.bind(\"CTRL + SHIFT + SPACE\", \"Vaultkeeper\", \"vaultkeeper --search\")"
        );
        assert!(view.lines_hint.contains("bindings.lua"));
        assert!(!view.configurable);
        let other = system_view(
            &bindings(HotkeyMode::Manual, ""),
            &settings,
            Compositor::Other,
        );
        assert_eq!(other.lines, "");
        assert!(other.lines_hint.contains("vaultkeeper --search"));
    }

    #[test]
    fn shortcuts_match_whatever_the_spelling() {
        assert!(same_shortcut("cmd+alt+g", "Alt+Cmd+G"));
        assert!(same_shortcut("Shift+Cmd+Space", "Cmd+Shift+Space"));
        assert!(!same_shortcut("Cmd+Alt+G", "Cmd+G"));
        assert!(!same_shortcut("", ""), "no hotkey is never a duplicate");
    }
}
