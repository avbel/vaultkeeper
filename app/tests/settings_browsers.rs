mod common;

use common::{Setup, click, exists, harness, set_size};
use slint::Model as _;
use vaultkeeper::{
    browser_status::{start_blocker, state_line},
    hooks::SettingsStore as _,
    settings::BrowserMatch,
};

fn saved(h: &common::Harness) -> vaultkeeper::settings::Settings {
    h.settings.load()
}

#[test]
fn the_browsers_section_writes_every_setting() {
    let h = harness(Setup::default());
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings window");
    set_size(&window, 520.0, 2400.0);
    assert_eq!(window.get_browser_state(), "Off");
    assert!(window.get_chrome_installed());
    assert!(window.get_firefox_installed());
    assert!(
        exists(&window, "Require Touch ID to fill"),
        "Touch ID is available in the mock"
    );

    click(&window, "Browser integration");
    assert!(saved(&h).browser_integration);
    assert_eq!(
        window.get_browser_state(),
        state_line(true, start_blocker())
    );

    click(&window, "Install for Firefox");
    click(&window, "Install for Google Chrome");
    click(&window, "Require Touch ID to fill");
    click(&window, "Offer to save logins");
    click(&window, "Copy TOTP code after filling");
    window.invoke_browser_match_selected(1);
    let settings = saved(&h);
    assert!(!settings.browser_firefox);
    assert!(!settings.browser_chrome);
    assert!(settings.browser_touch_id);
    assert!(!settings.browser_save_prompts);
    assert!(!settings.browser_copy_totp);
    assert_eq!(settings.browser_default_match, BrowserMatch::Host);
}

#[test]
fn removing_a_paired_browser_updates_the_list() {
    let h = harness(Setup::default());
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings window");
    set_size(&window, 520.0, 2400.0);
    let rows = window.get_paired_browsers();
    assert_eq!(rows.row_count(), 2);
    let first = rows.row_data(0).expect("first row");
    assert_eq!(first.name, "Firefox");
    assert_eq!(first.fingerprint, "A1B2-C3D4-E5F6-0718");
    click(&window, "Remove Firefox");
    let rows = window.get_paired_browsers();
    assert_eq!(rows.row_count(), 1);
    assert_eq!(rows.row_data(0).expect("remaining").name, "Google Chrome");
}
