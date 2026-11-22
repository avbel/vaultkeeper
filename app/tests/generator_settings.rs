//! Generator options, settings persistence and theme handling.

mod common;

use std::time::Duration;

use common::{CMD, Harness, Mods, Setup, click, elapse, harness, key, pump, special, type_into};
use slint::{ComponentHandle, platform::Key};
use vaultkeeper::hooks::SettingsStore;
use vaultkeeper::{
    settings::{Settings, TextScale, ThemeChoice},
    ui::{GeneratorState, Theme, ThemeMode},
};

fn open_generator() -> (Harness, vaultkeeper::ui::GeneratorWindow) {
    let h = harness(Setup::default());
    h.app.open_generator_window();
    let window = h.app.generator_window().expect("generator");
    window
        .window()
        .set_size(slint::LogicalSize::new(420.0, 1200.0));
    pump();
    (h, window)
}

#[test]
fn opening_generates_and_option_changes_regenerate() {
    let (_h, window) = open_generator();
    let state = window.global::<GeneratorState>();
    let first = state.get_result().to_string();
    assert_eq!(first.chars().count(), 14, "default length");
    click(&window, "0-9");
    let second = state.get_result().to_string();
    assert_ne!(second, first);
    assert!(
        !second.chars().any(|c| c.is_ascii_digit()),
        "numbers were turned off: {second}"
    );
    find_slider(&window).set_accessible_value("32");
    pump();
    assert_eq!(state.get_result().chars().count(), 32);
}

#[test]
fn every_opening_shows_a_new_value() {
    let (h, window) = open_generator();
    let first = window.global::<GeneratorState>().get_result().to_string();
    window.invoke_close_generator();
    pump();
    h.app.open_generator_window();
    let reopened = h.app.generator_window().expect("generator");
    let second = reopened.global::<GeneratorState>().get_result().to_string();
    assert_ne!(second, first);
    h.app.open_generator_window();
    let third = reopened.global::<GeneratorState>().get_result().to_string();
    assert_ne!(
        third, second,
        "showing the open window again regenerates too"
    );
}

fn find_slider(
    window: &vaultkeeper::ui::GeneratorWindow,
) -> i_slint_backend_testing::ElementHandle {
    i_slint_backend_testing::ElementHandle::find_by_accessible_label(window, "Length")
        .find(|element| {
            element.accessible_role() == Some(i_slint_backend_testing::AccessibleRole::Slider)
        })
        .expect("length slider")
}

#[test]
fn passphrase_mode_uses_words_and_separator() {
    let (_h, window) = open_generator();
    let state = window.global::<GeneratorState>();
    click(&window, "Passphrase");
    assert_eq!(state.get_mode(), 1);
    assert_eq!(state.get_result().split('-').count(), 6);
    type_into(&window, "Separator", "_");
    assert_eq!(state.get_result().split('_').count(), 6);
}

#[test]
fn copying_the_generated_value_uses_the_clipboard() {
    let (h, window) = open_generator();
    let value = window.global::<GeneratorState>().get_result().to_string();
    click(&window, "Copy generated value");
    assert_eq!(h.clipboard.last(), Some(value));
}

#[test]
fn generator_shortcuts_copy_and_close_the_window() {
    let (h, window) = open_generator();
    let value = window.global::<GeneratorState>().get_result().to_string();
    key(&window, "c", CMD);
    assert_eq!(h.clipboard.last(), Some(value));
    key(&window, &special(Key::Escape), Mods::default());
    assert!(h.app.generator_window().is_none());
}

fn open_settings(h: &Harness) -> vaultkeeper::ui::SettingsWindow {
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings");
    window
        .window()
        .set_size(slint::LogicalSize::new(520.0, 1600.0));
    pump();
    window
}

#[test]
fn settings_theme_switch_applies_to_open_windows_and_persists() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    let settings = open_settings(&h);
    let theme = manager.global::<Theme>();
    theme.set_system_dark(false);
    assert_eq!(theme.get_mode(), ThemeMode::System);
    assert_eq!(theme.get_bg(), slint::Color::from_rgb_u8(0xF6, 0xF7, 0xF9));
    click(&settings, "Dark");
    assert_eq!(theme.get_mode(), ThemeMode::Dark);
    assert_eq!(
        theme.get_bg(),
        slint::Color::from_rgb_u8(0x14, 0x15, 0x18),
        "manual Dark ignores the light system"
    );
    assert_eq!(
        settings.global::<Theme>().get_bg(),
        slint::Color::from_rgb_u8(0x14, 0x15, 0x18)
    );
    assert_eq!(h.settings.load().theme, ThemeChoice::Dark);
    click(&settings, "System");
    assert_eq!(
        theme.get_bg(),
        slint::Color::from_rgb_u8(0xF6, 0xF7, 0xF9),
        "System follows the OS again"
    );
    theme.set_system_dark(true);
    assert_eq!(
        theme.get_bg(),
        slint::Color::from_rgb_u8(0x14, 0x15, 0x18),
        "a system scheme change re-themes"
    );
    assert_eq!(h.settings.load().theme, ThemeChoice::System);
}

#[test]
fn saved_theme_and_text_size_apply_to_new_windows() {
    let h = harness(Setup {
        settings: Settings {
            theme: ThemeChoice::Light,
            text_scale: TextScale::Larger,
            ..Settings::default()
        },
        ..Setup::default()
    });
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    let theme = manager.global::<Theme>();
    theme.set_system_dark(true);
    assert_eq!(theme.get_mode(), ThemeMode::Light);
    assert_eq!(theme.get_bg(), slint::Color::from_rgb_u8(0xF6, 0xF7, 0xF9));
    assert!((theme.get_scale() - 1.3).abs() < f32::EPSILON);
    assert!(
        (theme.get_row_height() - 52.0).abs() < 0.01,
        "40 px rows scale to 52"
    );
    let settings = open_settings(&h);
    click(&settings, "Default");
    assert!((theme.get_scale() - 1.0).abs() < f32::EPSILON);
    assert_eq!(h.settings.load().text_scale, TextScale::Default);
}

#[test]
fn settings_toggles_persist_through_the_store() {
    let h = harness(Setup::default());
    let settings = open_settings(&h);
    click(&settings, "Start at login");
    click(&settings, "SSH requires Touch ID");
    let saved = h.settings.load();
    assert!(saved.start_at_login);
    assert!(saved.ssh_touch_id);
    settings.invoke_clipboard_selected(0);
    assert_eq!(
        h.settings.load().clipboard_clear,
        vaultkeeper::settings::ClipboardClear::Seconds(10)
    );
    settings.invoke_lock_selected(5);
    assert_eq!(
        h.settings.load().lock_timeout,
        vaultkeeper::settings::LockTimeout::Never
    );
    assert!(settings.get_lock_on_sleep(), "on by default");
    click(&settings, "Lock on sleep or screen lock");
    assert!(!h.settings.load().lock_on_sleep);
    assert_eq!(
        h.settings.load().lock_timeout,
        vaultkeeper::settings::LockTimeout::Never,
        "independent of the timeout"
    );
}

#[test]
fn tray_theme_choice_uses_the_same_path() {
    let h = harness(Setup::default());
    h.app.start(false);
    h.app.set_theme(ThemeChoice::Dark);
    let manager = h.app.manager_window().expect("manager");
    assert_eq!(manager.global::<Theme>().get_mode(), ThemeMode::Dark);
    assert_eq!(h.settings.load().theme, ThemeChoice::Dark);
}

#[test]
fn manager_geometry_is_saved_on_close_and_restored() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    manager
        .window()
        .set_size(slint::LogicalSize::new(900.0, 600.0));
    manager.set_sidebar_collapsed(true);
    drop(manager);
    h.app
        .manager_window()
        .expect("manager")
        .window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    let geometry = h.settings.load().manager_geometry.expect("saved geometry");
    assert_eq!(
        (geometry.width, geometry.height, geometry.sidebar_collapsed),
        (900, 600, true)
    );
    h.app.open_vault();
    let manager = h.app.manager_window().expect("reopened");
    assert!(manager.get_sidebar_collapsed());
    let size = manager
        .window()
        .size()
        .to_logical(manager.window().scale_factor());
    assert_eq!((size.width.round(), size.height.round()), (900.0, 600.0));
}

#[test]
fn a_ui_write_keeps_what_another_writer_stored_meanwhile() {
    let h = harness(Setup::default());
    h.app.start(false);
    let accepted = vaultkeeper::os::security_gate::Accepted {
        fingerprint: "0011223344556677".to_owned(),
        issues: vec!["wayland".to_owned()],
    };
    // `vaultkeeper security accept` writes the file while the Manager is open.
    h.settings
        .save(&Settings {
            security_accepted: Some(accepted.clone()),
            ..h.settings.load()
        })
        .expect("save");
    h.app
        .manager_window()
        .expect("manager")
        .window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    let saved = h.settings.load();
    assert!(
        saved.manager_geometry.is_some(),
        "the UI's own write landed"
    );
    assert_eq!(saved.security_accepted, Some(accepted));
}

#[test]
fn a_reset_of_unreadable_settings_is_shown_once_when_a_window_opens() {
    let h = harness(Setup::default());
    h.settings
        .reset_notice
        .store(true, std::sync::atomic::Ordering::SeqCst);
    h.app.show_pending_notices();
    assert!(
        h.settings
            .reset_notice
            .load(std::sync::atomic::Ordering::SeqCst),
        "kept until a window can show it"
    );
    h.app.handle(vaultkeeper::UiCommand::ShowManager);
    h.app.show_pending_notices();
    let manager = h.app.manager_window().expect("manager");
    assert!(manager.get_toast_shown());
    assert_eq!(
        manager.get_toast_text(),
        vaultkeeper::app::SETTINGS_RESET_NOTICE
    );
    assert!(
        !h.settings
            .reset_notice
            .load(std::sync::atomic::Ordering::SeqCst)
    );
}

fn settings_window(h: &Harness) -> vaultkeeper::ui::SettingsWindow {
    h.app.open_settings();
    pump();
    h.app.settings_window().expect("settings window")
}

fn saved_generator_hotkey(h: &Harness) -> String {
    h.settings.load().generator_hotkey
}

#[test]
fn a_generator_hotkey_is_saved_and_clearing_it_removes_it() {
    let h = harness(Setup::default());
    let window = settings_window(&h);
    assert_eq!(window.get_generator_hotkey(), "", "none by default");
    window.invoke_generator_hotkey_accepted("Cmd+Alt+G".into());
    pump();
    assert_eq!(saved_generator_hotkey(&h), "Cmd+Alt+G");
    window.invoke_generator_hotkey_accepted("  ".into());
    pump();
    assert_eq!(saved_generator_hotkey(&h), "");
}

#[test]
fn the_quick_panel_shortcut_is_refused_as_the_generator_hotkey() {
    let h = harness(Setup::default());
    let window = settings_window(&h);
    window.invoke_generator_hotkey_accepted(
        if cfg!(not(target_os = "macos")) {
            "shift+ctrl+space"
        } else {
            "shift+cmd+space"
        }
        .into(),
    );
    pump();
    assert_eq!(saved_generator_hotkey(&h), "");
    assert!(window.get_error_text().contains("Quick Panel"));
}

#[test]
fn the_ssh_config_lines_are_shown_and_copied() {
    let h = harness(Setup::default());
    let window = settings_window(&h);
    let lines = window.get_ssh_config().to_string();
    assert!(lines.starts_with("Host *\n    IdentityAgent \""), "{lines}");
    assert!(lines.contains(window.get_ssh_socket().as_str()));
    // Below the fold of the test window, so the copy action is invoked directly.
    assert!(window.invoke_copy_ssh_config());
    assert_eq!(h.clipboard.last().as_deref(), Some(lines.as_str()));
}

#[test]
fn generator_options_are_saved_and_the_next_generator_opens_with_them() {
    let (h, window) = open_generator();
    find_slider(&window).set_accessible_value("32");
    pump();
    click(&window, "0-9");
    elapse(Duration::from_millis(600));
    let saved = h.settings.load().generator;
    assert_eq!(saved.length, 32);
    assert!(!saved.numbers);

    let next = harness(Setup {
        settings: h.settings.load(),
        ..Setup::default()
    });
    next.app.open_generator_window();
    pump();
    let next_window = next.app.generator_window().expect("generator");
    let state = next_window.global::<GeneratorState>();
    assert_eq!(state.get_length(), 32);
    assert!(!state.get_numbers());
    let value = state.get_result().to_string();
    assert_eq!(value.chars().count(), 32);
    assert!(!value.chars().any(|c| c.is_ascii_digit()), "{value}");
}

#[test]
fn a_slider_drag_saves_the_options_once_it_settles_or_the_generator_closes() {
    let (h, window) = open_generator();
    let slider = find_slider(&window);
    for length in 15..=40 {
        slider.set_accessible_value(length.to_string());
        pump();
    }
    assert_eq!(
        window
            .global::<GeneratorState>()
            .get_result()
            .chars()
            .count(),
        40,
        "every step regenerates"
    );
    assert_eq!(h.settings.load().generator.length, 14, "not saved mid-drag");
    elapse(Duration::from_millis(600));
    assert_eq!(h.settings.load().generator.length, 40);

    slider.set_accessible_value("60");
    pump();
    window.invoke_close_generator();
    pump();
    assert_eq!(
        h.settings.load().generator.length,
        60,
        "closing saves the pending change"
    );
}

#[test]
fn unsaved_website_passwords_can_be_copied_and_removed() {
    use std::sync::{Arc, Mutex};
    use vaultkeeper::hooks::{GeneratedDto, MemoryGenerated};

    let memory = MemoryGenerated {
        entries: Arc::new(Mutex::new(vec![(
            GeneratedDto {
                id: 7,
                host: "signup.example".into(),
                created_unix: common::NOW - 5 * 60,
            },
            "Gen3rated!".into(),
        )])),
    };
    let entries = Arc::clone(&memory.entries);
    let h = harness(Setup {
        generated: Some(Arc::new(memory)),
        ..Setup::default()
    });
    h.app.open_generator_window();
    let window = h.app.generator_window().expect("generator");
    window
        .window()
        .set_size(slint::LogicalSize::new(420.0, 1200.0));
    pump();
    let state = window.global::<GeneratorState>();
    let rows: Vec<_> = slint::Model::iter(&state.get_unsaved()).collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].host, "signup.example");
    assert_eq!(rows[0].age, "5 min ago");

    click(&window, "Copy the password for signup.example");
    assert_eq!(h.clipboard.last().as_deref(), Some("Gen3rated!"));
    assert_eq!(state.get_unsaved_status(), "Password copied");

    click(&window, "Remove the password for signup.example");
    assert_eq!(slint::Model::row_count(&state.get_unsaved()), 0);
    assert_eq!(entries.lock().expect("entries").len(), 0);
}
