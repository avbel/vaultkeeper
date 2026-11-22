//! "Show keyboard shortcuts": inline hints follow the setting live in every open window; the
//! shortcuts and the Quick Panel's key legend stay.

mod common;

use common::{Mods, Setup, click, exists, harness, key, pump, set_size};
use slint::ComponentHandle;
use vaultkeeper::{settings::Settings, ui::Theme};

const SEARCH_CAP: &str = if cfg!(target_os = "macos") {
    "⌘F"
} else {
    "Ctrl+F"
};

#[test]
fn hints_disappear_and_return_when_the_option_flips() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    assert!(exists(&manager, SEARCH_CAP), "the search field's key cap");
    h.app.open_settings();
    let settings = h.app.settings_window().expect("settings");
    // Tall enough that the whole scroll view is laid out.
    set_size(&settings, 520.0, 1800.0);
    assert!(settings.get_show_shortcuts(), "on by default");
    click(&settings, "Show keyboard shortcuts");
    assert!(
        !h.settings
            .saved
            .lock()
            .expect("settings")
            .as_ref()
            .expect("saved")
            .show_shortcuts,
        "saved"
    );
    assert!(!exists(&manager, SEARCH_CAP), "key cap hidden");
    assert!(exists(&manager, "Lock"), "the button itself stays");
    assert!(!manager.global::<Theme>().get_show_shortcuts());
    assert!(!settings.global::<Theme>().get_show_shortcuts());
    click(&settings, "Show keyboard shortcuts");
    assert!(exists(&manager, SEARCH_CAP), "key cap back");
}

#[test]
fn windows_opened_later_follow_the_setting_and_the_legend_stays() {
    let h = harness(Setup {
        settings: Settings {
            show_shortcuts: false,
            ..Settings::default()
        },
        ..Setup::default()
    });
    h.app.toggle_quick_panel();
    let quick = h.app.quick_panel().expect("Quick Panel");
    pump();
    assert!(
        !exists(&quick, "Esc"),
        "the search field's key cap is hidden"
    );
    assert!(exists(&quick, "TOTP"), "the footer legend stays");
}

#[test]
fn shortcuts_keep_working_with_hints_hidden() {
    let h = harness(Setup {
        settings: Settings {
            show_shortcuts: false,
            ..Settings::default()
        },
        ..Setup::default()
    });
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    key(
        &manager,
        "l",
        Mods {
            cmd: true,
            shift: true,
        },
    );
    assert!(h.app.lock_window().is_some(), "⌘⇧L still locks");
}
