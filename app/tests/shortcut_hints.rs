//! "Show keyboard shortcuts": inline hints follow the setting live in every open window; the
//! shortcuts and the Quick Panel's key legend stay.

mod common;

use bw_lite::{hooks::SettingsStore, settings::Settings, ui::Theme};
use common::{Mods, Setup, click, exists, harness, key, pump};
use slint::ComponentHandle;

#[test]
fn hints_disappear_and_return_when_the_option_flips() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    assert!(exists(&manager, "⌘⇧L"), "the Lock button's hint");
    assert!(exists(&manager, "⌘N"), "the New button's hint");
    assert!(exists(&manager, "⌘F"), "the search field's key cap");
    h.app.open_settings();
    let settings = h.app.settings_window().expect("settings");
    // Tall enough that the whole scroll view is laid out.
    settings
        .window()
        .set_size(slint::LogicalSize::new(520.0, 1800.0));
    pump();
    assert!(settings.get_show_shortcuts(), "on by default");
    click(&settings, "Show keyboard shortcuts");
    assert!(!h.settings.load().show_shortcuts, "saved");
    for hint in ["⌘⇧L", "⌘N", "⌘F"] {
        assert!(!exists(&manager, hint), "{hint} hidden");
    }
    assert!(exists(&manager, "Lock"), "the button itself stays");
    assert!(!manager.global::<Theme>().get_show_shortcuts());
    assert!(!settings.global::<Theme>().get_show_shortcuts());
    click(&settings, "Show keyboard shortcuts");
    for hint in ["⌘⇧L", "⌘N", "⌘F"] {
        assert!(exists(&manager, hint), "{hint} back");
    }
}

#[test]
fn windows_opened_later_and_after_a_reload_follow_the_setting() {
    let h = harness(Setup {
        settings: Settings {
            show_shortcuts: false,
            ..Settings::default()
        },
        ..Setup::default()
    });
    h.app.toggle_quick_panel();
    let quick = h.app.quick_panel().expect("Quick Panel");
    assert!(
        !exists(&quick, "Esc"),
        "the search field's key cap is hidden"
    );
    assert!(exists(&quick, "TOTP"), "the footer legend stays");
    h.app.lock();
    let lock = h.app.lock_window().expect("lock");
    assert!(exists(&lock, "Settings"));
    assert!(!exists(&lock, "Settings  ⌘,"));

    h.settings
        .save(&Settings::default())
        .expect("the daemon rewrites the file");
    h.app.handle(bw_lite::UiCommand::ReloadSettings);
    pump();
    assert!(exists(&lock, "Settings  ⌘,"), "follows a reload live");
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
