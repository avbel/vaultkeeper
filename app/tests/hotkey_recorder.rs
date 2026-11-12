//! Settings → Shortcuts recorders, driven by key presses as the testing backend delivers them
//! (Slint key text; the winit physical-key path needs a real window).

mod common;

use common::{Harness, Setup, click, harness, pump, special};
use i_slint_backend_testing::{AccessibleRole, ElementHandle};
use slint::{
    ComponentHandle, SharedString,
    platform::{Key, WindowEvent},
};
use vaultkeeper::{hooks::SettingsStore, settings::Settings};

const QUICK: &str = "Quick Panel hotkey";
const GENERATOR: &str = "Generator hotkey";

fn open(setup: Setup) -> (Harness, vaultkeeper::ui::SettingsWindow) {
    let h = harness(setup);
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings");
    window
        .window()
        .set_size(slint::LogicalSize::new(520.0, 2400.0));
    pump();
    (h, window)
}

fn send(window: &vaultkeeper::ui::SettingsWindow, text: &str, pressed: bool) {
    let text = SharedString::from(text);
    window.window().dispatch_event(if pressed {
        WindowEvent::KeyPressed { text }
    } else {
        WindowEvent::KeyReleased { text }
    });
}

/// Holds `modifiers` (Slint keys: `Control` is ⌘, `Meta` is ⌃ on macOS) and taps `key`.
fn press(window: &vaultkeeper::ui::SettingsWindow, modifiers: &[Key], key: &str) {
    let held: Vec<String> = modifiers.iter().map(|m| special(*m)).collect();
    for modifier in &held {
        send(window, modifier, true);
    }
    send(window, key, true);
    send(window, key, false);
    for modifier in held.iter().rev() {
        send(window, modifier, false);
    }
    pump();
}

/// The recorder itself, not the row's caption of the same text.
fn recorder(window: &vaultkeeper::ui::SettingsWindow, label: &str) -> ElementHandle {
    ElementHandle::find_by_accessible_label(window, label)
        .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
        .unwrap_or_else(|| panic!("no recorder {label:?}"))
}

fn value_of(window: &vaultkeeper::ui::SettingsWindow, label: &str) -> String {
    recorder(window, label)
        .accessible_value()
        .map(|value| value.to_string())
        .unwrap_or_default()
}

fn saved(h: &Harness) -> Settings {
    h.settings.load()
}

#[test]
fn recording_the_quick_panel_hotkey_saves_it_at_once() {
    let (h, window) = open(Setup::default());
    assert_eq!(
        value_of(&window, QUICK),
        "⇧⌘Space",
        "the default in symbols"
    );
    click(&window, QUICK);
    assert_eq!(value_of(&window, QUICK), "Press a shortcut…");
    press(&window, &[Key::Control, Key::Alt], "k");
    assert_eq!(saved(&h).hotkey, "Cmd+Alt+K");
    assert_eq!(value_of(&window, QUICK), "⌥⌘K", "recording ended");
    assert_eq!(window.get_recording_slot(), 0);
    assert_eq!(window.get_error_text(), "");
}

#[test]
fn recording_the_generator_hotkey_saves_it_and_delete_clears_it() {
    let (h, window) = open(Setup::default());
    assert_eq!(value_of(&window, GENERATOR), "None");
    click(&window, GENERATOR);
    assert_eq!(window.get_recording_slot(), 2);
    press(&window, &[Key::Meta, Key::Shift], &special(Key::F5));
    assert_eq!(saved(&h).generator_hotkey, "Ctrl+Shift+F5");
    assert_eq!(value_of(&window, GENERATOR), "⌃⇧F5");
    click(&window, GENERATOR);
    press(&window, &[], &special(Key::Backspace));
    assert_eq!(saved(&h).generator_hotkey, "");
    assert_eq!(value_of(&window, GENERATOR), "None");
    assert_eq!(window.get_recording_slot(), 0);
}

#[test]
fn delete_does_not_clear_the_quick_panel_hotkey() {
    let (h, window) = open(Setup::default());
    click(&window, QUICK);
    press(&window, &[], &special(Key::Delete));
    assert_eq!(saved(&h).hotkey, "Cmd+Shift+Space");
    assert!(
        window.get_error_text().contains('⌘'),
        "{}",
        window.get_error_text()
    );
}

#[test]
fn escape_cancels_the_recording() {
    let (h, window) = open(Setup::default());
    click(&window, GENERATOR);
    press(&window, &[], &special(Key::Escape));
    assert_eq!(window.get_recording_slot(), 0);
    assert_eq!(value_of(&window, GENERATOR), "None");
    press(&window, &[Key::Control], "g");
    assert_eq!(
        saved(&h).generator_hotkey,
        "",
        "keys after Esc are not recorded"
    );
}

#[test]
fn shift_alone_or_no_modifier_is_refused_and_keeps_recording() {
    let (h, window) = open(Setup::default());
    click(&window, GENERATOR);
    press(&window, &[Key::Shift], "G");
    assert_eq!(saved(&h).generator_hotkey, "");
    assert!(window.get_error_text().contains("⌘, ⌥ or ⌃"));
    press(&window, &[], "g");
    assert_eq!(saved(&h).generator_hotkey, "");
    assert_eq!(
        window.get_recording_slot(),
        2,
        "still waiting for a shortcut"
    );
    press(&window, &[Key::Control, Key::Alt], "g");
    assert_eq!(saved(&h).generator_hotkey, "Cmd+Alt+G");
    assert_eq!(window.get_error_text(), "", "the error goes once saved");
}

#[test]
fn a_modifier_press_alone_keeps_waiting_without_an_error() {
    let (_h, window) = open(Setup::default());
    click(&window, QUICK);
    send(&window, &special(Key::Control), true);
    pump();
    assert_eq!(window.get_recording_slot(), 1);
    assert_eq!(window.get_error_text(), "");
}

#[test]
fn the_other_slots_shortcut_is_refused_both_ways() {
    let (h, window) = open(Setup {
        settings: Settings {
            generator_hotkey: "Cmd+Alt+G".to_owned(),
            ..Settings::default()
        },
        ..Setup::default()
    });
    click(&window, GENERATOR);
    press(&window, &[Key::Control, Key::Shift], " ");
    assert_eq!(saved(&h).generator_hotkey, "Cmd+Alt+G");
    assert!(window.get_error_text().contains("Quick Panel"));
    assert_eq!(value_of(&window, GENERATOR), "Press a shortcut…");
    press(&window, &[], &special(Key::Escape));
    assert_eq!(
        value_of(&window, GENERATOR),
        "⌥⌘G",
        "the refused one is not shown"
    );
    click(&window, QUICK);
    press(&window, &[Key::Alt, Key::Control], "g");
    assert_eq!(saved(&h).hotkey, "Cmd+Shift+Space");
    assert!(window.get_error_text().contains("Generator"));
}

#[test]
fn the_accessibility_set_value_saves_an_accelerator() {
    let (h, window) = open(Setup::default());
    recorder(&window, GENERATOR).set_accessible_value("Cmd+Alt+G");
    pump();
    assert_eq!(saved(&h).generator_hotkey, "Cmd+Alt+G");
    assert_eq!(value_of(&window, GENERATOR), "⌥⌘G");
    recorder(&window, QUICK).set_accessible_value("");
    pump();
    assert_eq!(
        saved(&h).hotkey,
        "Cmd+Shift+Space",
        "the Quick Panel keeps a hotkey"
    );
    assert!(window.get_error_text().contains("needs a hotkey"));
}

#[test]
fn recording_pauses_the_daemon_hotkeys_until_it_ends() {
    let (h, window) = open(Setup::default());
    assert_eq!(
        h.hotkey.pauses(),
        Vec::<bool>::new(),
        "nothing before a click"
    );
    click(&window, QUICK);
    assert_eq!(h.hotkey.pauses(), [true]);
    press(&window, &[Key::Control, Key::Alt], "k");
    assert_eq!(h.hotkey.pauses(), [true, false], "saving ends the pause");
    click(&window, GENERATOR);
    press(&window, &[], &special(Key::Escape));
    assert_eq!(
        h.hotkey.pauses(),
        [true, false, true, false],
        "Esc ends it too"
    );
}

#[test]
fn closing_settings_mid_recording_ends_the_pause() {
    let (h, window) = open(Setup::default());
    click(&window, GENERATOR);
    assert_eq!(h.hotkey.pauses(), [true]);
    window.window().dispatch_event(WindowEvent::CloseRequested);
    pump();
    assert_eq!(h.hotkey.pauses().last(), Some(&false));
    assert!(h.app.settings_window().is_none());
}
