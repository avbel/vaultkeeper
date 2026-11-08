//! Lock screen, login (2FA, new device, server URL), accounts and logout scenarios.

mod common;

use bw_lite::mock::{MOCK_2FA_CODE, MOCK_DEVICE_CODE, MOCK_MASTER_PASSWORD, MockCall};
use bwl_vault::{VaultService, model::SessionState};
use common::{Setup, click, exists, harness, pump, type_into, value_of};
use slint::Model;

fn locked() -> common::Harness {
    harness(Setup {
        unlocked: false,
        ..Setup::default()
    })
}

#[test]
fn unlock_success_closes_the_lock_screen_and_opens_the_manager() {
    let h = locked();
    h.app.start(false);
    let lock = h.app.lock_window().expect("lock window");
    assert_eq!(lock.get_email(), "alice@example.com");
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    pump();
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    assert!(h.app.lock_window().is_none());
    assert!(h.app.manager_window().is_some());
}

#[test]
fn wrong_password_shows_the_attempt_count_and_shakes_without_unlocking() {
    let h = locked();
    h.app.start(false);
    let lock = h.app.lock_window().expect("lock window");
    type_into(&lock, "Master password", "nope");
    click(&lock, "Unlock");
    assert_eq!(lock.get_failed_attempts(), 1);
    assert!(value_of(&lock, "Unlock error").contains("attempt 1"));
    assert_eq!(
        lock.get_password(),
        "",
        "the field is cleared after a failure"
    );
    type_into(&lock, "Master password", "still wrong");
    click(&lock, "Unlock");
    assert_eq!(lock.get_failed_attempts(), 2);
    assert!(value_of(&lock, "Unlock error").contains("attempt 2"));
    assert!(matches!(h.vault.state(), SessionState::Locked { .. }));
    assert!(h.app.manager_window().is_none());
}

#[test]
fn touch_id_unlock_after_enrolment() {
    let h = harness(Setup::default());
    h.app.start(false);
    h.app.open_settings();
    let settings = h.app.settings_window().expect("settings");
    click(&settings, "Enrol Touch ID");
    assert!(settings.get_touch_id_enrolled());
    h.app.lock();
    let lock = h.app.lock_window().expect("lock window");
    assert!(lock.get_touch_id_available());
    click(&lock, "Unlock with Touch ID");
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
}

fn open_login_for_new_account(h: &common::Harness) -> bw_lite::ui::LoginWindow {
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    manager.invoke_add_account();
    pump();
    h.app.login_window().expect("login window")
}

#[test]
fn add_account_prefills_the_server_and_cancel_returns_to_the_lock_screen() {
    let h = harness(Setup::default());
    let login = open_login_for_new_account(&h);
    assert_eq!(login.get_server(), "https://vault.example.com");
    assert!(login.get_can_cancel());
    assert!(
        h.app.manager_window().is_none(),
        "the unlocked account's views are dropped"
    );
    let suggestions: Vec<String> = login
        .get_server_suggestions()
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(suggestions.contains(&"https://vault.work.example.org".to_owned()));
    click(&login, "Cancel");
    assert!(h.app.login_window().is_none());
    let lock = h
        .app
        .lock_window()
        .expect("lock window for the previous account");
    assert_eq!(lock.get_email(), "alice@example.com");
}

#[test]
fn login_with_two_factor_step() {
    let h = harness(Setup::default());
    let login = open_login_for_new_account(&h);
    type_into(&login, "Email", "dave+2fa@example.com");
    type_into(&login, "Master password", MOCK_MASTER_PASSWORD);
    click(&login, "Log in");
    assert_eq!(login.get_step(), 1);
    let providers: Vec<String> = login
        .get_providers()
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(providers, ["Authenticator", "Email", "Recovery code"]);
    type_into(&login, "Verification code", "000000");
    click(&login, "Continue");
    assert_eq!(login.get_step(), 1, "a wrong code stays on the 2FA step");
    assert!(value_of(&login, "Login error").contains("Two-step token is invalid"));
    type_into(&login, "Verification code", MOCK_2FA_CODE);
    click(&login, "Continue");
    assert!(
        matches!(h.vault.state(), SessionState::Unlocked { ref email, .. } if email == "dave+2fa@example.com")
    );
    assert!(h.app.login_window().is_none());
    assert!(h.app.manager_window().is_some());
}

#[test]
fn login_with_new_device_step() {
    let h = harness(Setup::default());
    let login = open_login_for_new_account(&h);
    type_into(&login, "Email", "erin+newdevice@example.com");
    type_into(&login, "Master password", MOCK_MASTER_PASSWORD);
    click(&login, "Log in");
    assert_eq!(login.get_step(), 2);
    type_into(&login, "Device verification code", MOCK_DEVICE_CODE);
    click(&login, "Continue");
    assert!(
        matches!(h.vault.state(), SessionState::Unlocked { ref email, .. } if email == "erin+newdevice@example.com")
    );
}

#[test]
fn server_url_is_validated_inline_and_normalized() {
    let h = harness(Setup::default());
    let login = open_login_for_new_account(&h);
    type_into(&login, "Server URL", "http://vault.example.org");
    assert!(value_of(&login, "Server error").contains("https"));
    type_into(&login, "Server URL", "http://localhost:8080");
    assert!(!exists(&login, "Server error"));
    assert!(value_of(&login, "Server warning").contains("Unencrypted"));
    type_into(&login, "Server URL", "not a url at all");
    assert_eq!(value_of(&login, "Server error"), "Not a valid URL");
    type_into(&login, "Server URL", "https://vault.example.com/#/login");
    type_into(&login, "Email", "frank@example.com");
    type_into(&login, "Master password", MOCK_MASTER_PASSWORD);
    click(&login, "Log in");
    let login_call = h
        .vault
        .calls()
        .into_iter()
        .find_map(|call| match call {
            MockCall::Login { server, email } if email == "frank@example.com" => Some(server),
            _ => None,
        })
        .expect("login call");
    assert_eq!(login_call, "https://vault.example.com/");
}

#[test]
fn unreachable_server_is_reported_under_the_server_field() {
    let h = harness(Setup::default());
    let login = open_login_for_new_account(&h);
    type_into(&login, "Server URL", "https://unreachable.example");
    type_into(&login, "Email", "gina@example.com");
    type_into(&login, "Master password", MOCK_MASTER_PASSWORD);
    click(&login, "Log in");
    assert_eq!(value_of(&login, "Server error"), "Can't reach server");
    assert!(!exists(&login, "Login error"));
    type_into(&login, "Server URL", "https://notbitwarden.example");
    type_into(&login, "Master password", MOCK_MASTER_PASSWORD);
    click(&login, "Log in");
    assert_eq!(
        value_of(&login, "Server error"),
        "Not a Bitwarden-compatible server"
    );
}

fn assert_no_alice_strings(h: &common::Harness, alice_names: &[String]) {
    let strings = h.app.view_strings();
    for name in alice_names {
        assert!(!strings.contains(name), "{name} is still in a UI model");
    }
    if let Some(lock) = h.app.lock_window() {
        for account in lock.get_accounts().iter() {
            assert!(!alice_names.contains(&account.email.to_string()));
        }
    }
}

#[test]
fn switching_account_locks_and_shows_the_target_lock_screen_with_no_previous_data() {
    let h = harness(Setup::default());
    let alice_names = h.vault.item_names("alice@example.com");
    h.app.start(false);
    h.app.open_generator_window();
    assert_ne!(h.app.view_strings(), Vec::<String>::new());
    let manager = h.app.manager_window().expect("manager");
    let accounts: Vec<_> = manager.get_accounts().iter().collect();
    let badges: Vec<(String, String)> = accounts
        .iter()
        .map(|a| (a.email.to_string(), a.badge.to_string()))
        .collect();
    assert_eq!(
        badges,
        [
            ("alice@example.com".to_owned(), String::new()),
            ("bob@work.example.org".to_owned(), "locked".to_owned()),
            ("carol@home.example.net".to_owned(), "logged out".to_owned()),
        ]
    );
    assert!(accounts[0].active);
    manager.invoke_switch_account(1);
    pump();
    assert!(
        matches!(h.vault.state(), SessionState::Locked { ref email, .. } if email == "bob@work.example.org")
    );
    assert!(h.app.manager_window().is_none());
    let lock = h.app.lock_window().expect("bob's lock screen");
    assert_eq!(lock.get_email(), "bob@work.example.org");
    assert_no_alice_strings(&h, &alice_names);
    assert!(
        h.clipboard.clears() >= 1,
        "the clipboard is cleared if it still holds our value"
    );
}

#[test]
fn logout_with_confirm_activates_the_next_account_then_shows_login_when_none_is_left() {
    let h = harness(Setup::default());
    let alice_names = h.vault.item_names("alice@example.com");
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    let first = manager.get_rows().row_data(0).expect("row");
    assert!(manager.invoke_copy_row(0, 1), "copy a password first");
    assert!(alice_names.contains(&first.name.to_string()));
    manager.set_confirm_logout(true);
    manager.invoke_logout_confirmed();
    pump();
    assert!(
        matches!(h.vault.state(), SessionState::Locked { ref email, .. } if email == "bob@work.example.org")
    );
    let lock = h.app.lock_window().expect("next account's lock screen");
    assert_eq!(lock.get_email(), "bob@work.example.org");
    assert_no_alice_strings(&h, &alice_names);
    assert!(
        h.app.view_strings().is_empty(),
        "every model is empty after logout"
    );
    assert!(h.clipboard.clears() >= 1);
    lock.set_confirm_logout(true);
    click(&lock, "Confirm log out");
    assert!(matches!(h.vault.state(), SessionState::LoggedOut));
    assert!(h.app.lock_window().is_none());
    let login = h.app.login_window().expect("login when no account is left");
    assert!(!login.get_can_cancel());
}

#[test]
fn lock_screen_switcher_picks_another_account_before_unlocking() {
    let h = locked();
    h.app.start(false);
    let lock = h.app.lock_window().expect("lock");
    lock.invoke_switch_account(1);
    pump();
    let lock = h.app.lock_window().expect("lock");
    assert_eq!(lock.get_email(), "bob@work.example.org");
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    assert!(
        matches!(h.vault.state(), SessionState::Unlocked { ref email, .. } if email == "bob@work.example.org")
    );
    let manager = h.app.manager_window().expect("manager");
    assert_eq!(manager.get_account_email(), "bob@work.example.org");
}

#[test]
fn enter_on_an_empty_field_uses_touch_id_when_enrolled() {
    let h = harness(Setup::default());
    h.app.start(false);
    h.app.open_settings();
    click(
        &h.app.settings_window().expect("settings"),
        "Enrol Touch ID",
    );
    h.app.lock();
    let lock = h.app.lock_window().expect("lock window");
    assert!(lock.get_touch_id_available());
    assert!(common::control_exists(&lock, "Unlock with Touch ID"));
    common::key(
        &lock,
        &common::special(slint::platform::Key::Return),
        common::Mods::default(),
    );
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
}

#[test]
fn ask_to_unlock_on_start_offers_touch_id_once_and_stays_in_the_tray() {
    let h = harness(Setup {
        unlocked: true,
        settings: bw_lite::settings::Settings {
            ask_unlock_on_start: true,
            ..bw_lite::settings::Settings::default()
        },
        ..Setup::default()
    });
    h.app.open_settings();
    click(
        &h.app.settings_window().expect("settings"),
        "Enrol Touch ID",
    );
    h.app.lock();
    h.app.start(true);
    assert!(
        matches!(h.vault.state(), SessionState::Unlocked { .. }),
        "Touch ID ran right away"
    );
    assert!(h.app.lock_window().is_none());
    assert!(
        h.app.manager_window().is_none(),
        "an unlock at login opens no window"
    );
}

#[test]
fn ask_to_unlock_on_start_waits_for_the_password_when_it_is_required() {
    let h = harness(Setup {
        unlocked: true,
        settings: bw_lite::settings::Settings {
            ask_unlock_on_start: true,
            require_master_password_on_start: true,
            ..bw_lite::settings::Settings::default()
        },
        ..Setup::default()
    });
    h.app.open_settings();
    click(
        &h.app.settings_window().expect("settings"),
        "Enrol Touch ID",
    );
    h.app.lock();
    h.app.start(true);
    assert!(matches!(h.vault.state(), SessionState::Locked { .. }));
    let lock = h.app.lock_window().expect("lock window shown at start");
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
}
