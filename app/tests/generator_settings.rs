//! Generator options, settings persistence and theme handling.

mod common;

use bw_lite::hooks::SettingsStore;
use bw_lite::{
    settings::{Settings, TextScale, ThemeChoice},
    ui::{GeneratorState, Theme, ThemeMode},
};
use common::{Harness, Setup, click, harness, pump, type_into};
use slint::{ComponentHandle, Model};

fn open_generator() -> (Harness, bw_lite::ui::GeneratorWindow) {
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
    assert_eq!(state.get_history().row_count(), 1);
    assert_eq!(
        state.get_history().row_data(0).expect("history").as_str(),
        first
    );
    find_slider(&window).set_accessible_value("32");
    pump();
    assert_eq!(state.get_result().chars().count(), 32);
}

fn find_slider(window: &bw_lite::ui::GeneratorWindow) -> i_slint_backend_testing::ElementHandle {
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

fn open_settings(h: &Harness) -> bw_lite::ui::SettingsWindow {
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
        bw_lite::settings::ClipboardClear::Seconds(10)
    );
    settings.invoke_lock_selected(5);
    assert_eq!(
        h.settings.load().lock_timeout,
        bw_lite::settings::LockTimeout::Never
    );
    assert!(settings.get_lock_on_sleep(), "on by default");
    click(&settings, "Lock on sleep or screen lock");
    assert!(!h.settings.load().lock_on_sleep);
    assert_eq!(
        h.settings.load().lock_timeout,
        bw_lite::settings::LockTimeout::Never,
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
    h.app.handle(bw_lite::UiCommand::ShowManager);
    h.app.show_pending_notices();
    let manager = h.app.manager_window().expect("manager");
    assert!(manager.get_toast_shown());
    assert_eq!(
        manager.get_toast_text(),
        bw_lite::app::SETTINGS_RESET_NOTICE
    );
    assert!(
        !h.settings
            .reset_notice
            .load(std::sync::atomic::Ordering::SeqCst)
    );
}
