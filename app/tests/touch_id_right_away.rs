//! "Unlock with Touch ID right away": the prompt starts before any lock window, and the window
//! the request would have shown opens only when Touch ID does not unlock.

mod common;

use std::{cell::Cell, rc::Rc};

use bw_lite::{SshApprovalRequest, UiCommand, mock::MOCK_MASTER_PASSWORD, settings::Settings};
use bwl_vault::{VaultService, model::SessionState};
use common::{
    CMD_SHIFT, Harness, Setup, TouchIdOutcome, click, during_next_prompt, enabled, harness, key,
    pump, safari, special, type_into, value_of,
};
use slint::ComponentHandle;
use slint::platform::Key;
use tokio::sync::oneshot;

fn locked_with(settings: Settings) -> Harness {
    harness(Setup {
        unlocked: false,
        settings,
        scripted_touch_id: true,
        ..Setup::default()
    })
}

fn right_away() -> Settings {
    Settings {
        touch_id_right_away: true,
        ..Settings::default()
    }
}

fn prompts(h: &Harness) -> usize {
    h.touch_id.as_ref().expect("scripted Touch ID").prompts()
}

fn answer_next(h: &Harness, outcome: TouchIdOutcome) {
    h.touch_id
        .as_ref()
        .expect("scripted Touch ID")
        .answer_next(outcome);
}

/// Records, from inside the prompt, whether any lock view was on screen.
fn watch_for_lock_views(h: &Harness) -> Rc<Cell<Option<bool>>> {
    let seen = Rc::new(Cell::new(None));
    let app = Rc::clone(&h.app);
    let record = Rc::clone(&seen);
    during_next_prompt(move || {
        record.set(Some(
            app.lock_window().is_some() || app.quick_panel().is_some(),
        ));
    });
    seen
}

#[test]
fn opening_the_vault_unlocks_with_touch_id_and_never_shows_the_lock_window() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Unlock);
    let seen = watch_for_lock_views(&h);
    h.app.handle(UiCommand::ShowManager);
    pump();
    assert_eq!(seen.get(), Some(false), "no lock view while Touch ID asked");
    assert_eq!(prompts(&h), 1);
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    assert!(h.app.manager_window().is_some(), "continues to the Manager");
    assert!(h.app.lock_window().is_none());
}

#[test]
fn the_tray_unlock_goes_straight_to_the_manager() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Unlock);
    let seen = watch_for_lock_views(&h);
    h.app.handle(UiCommand::ShowUnlock);
    pump();
    assert_eq!(seen.get(), Some(false));
    assert!(h.app.manager_window().is_some());
    assert!(h.app.lock_window().is_none());
}

#[test]
fn the_hotkey_opens_an_unlocked_quick_panel_after_touch_id() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Unlock);
    let seen = watch_for_lock_views(&h);
    h.app.handle(UiCommand::ToggleQuickPanel { target: None });
    pump();
    assert_eq!(seen.get(), Some(false), "no locked Quick Panel first");
    let quick = h.app.quick_panel().expect("Quick Panel");
    assert!(!quick.get_locked(), "the panel opens on its search");
    assert!(h.app.lock_window().is_none());
    assert!(h.app.manager_window().is_none());
}

#[test]
fn the_hotkey_target_survives_the_touch_id_unlock_and_gets_typed_into() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Unlock);
    // The system prompt and the UI process have the focus by now.
    *h.autotype.frontmost.lock().expect("frontmost") = None;
    h.app.handle(UiCommand::ToggleQuickPanel {
        target: Some(safari()),
    });
    pump();
    let quick = h.app.quick_panel().expect("Quick Panel");
    type_into(&quick, "Quick search", "tailscale");
    key(&quick, &special(Key::Return), CMD_SHIFT);
    let typed = h.autotype.typed();
    assert_eq!(typed.len(), 1, "{:?}", quick.get_toast_text());
    assert_eq!(typed[0].0, safari());
}

#[test]
fn a_cancel_shows_the_lock_window_without_an_error_and_does_not_ask_again() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Cancel);
    h.app.open_vault();
    pump();
    let lock = h.app.lock_window().expect("lock window after the cancel");
    assert_eq!(lock.get_error_text(), "", "a cancel is not an error");
    assert!(matches!(h.vault.state(), SessionState::Locked { .. }));
    h.app.open_vault();
    h.app.handle(UiCommand::ToggleQuickPanel { target: None });
    pump();
    assert_eq!(
        prompts(&h),
        1,
        "no new prompt while the lock window is open"
    );
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    pump();
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    assert!(
        h.app.quick_panel().is_some_and(|quick| !quick.get_locked()),
        "the password still works and the last request (the hotkey) opens"
    );
}

#[test]
fn a_lock_window_left_by_a_lock_does_not_stop_the_prompt() {
    let h = harness(Setup {
        settings: right_away(),
        scripted_touch_id: true,
        ..Setup::default()
    });
    h.app.start(false);
    h.app.lock();
    assert!(
        h.app.lock_window().is_some(),
        "locking with the Manager open"
    );
    assert_eq!(prompts(&h), 0, "a lock never prompts by itself");
    answer_next(&h, TouchIdOutcome::Unlock);
    h.app.toggle_quick_panel();
    pump();
    assert_eq!(prompts(&h), 1);
    assert!(h.app.quick_panel().is_some_and(|quick| !quick.get_locked()));
    assert!(h.app.lock_window().is_none());
}

#[test]
fn closing_the_lock_window_after_a_cancel_lets_the_next_request_prompt() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Cancel);
    h.app.open_vault();
    pump();
    let lock = h.app.lock_window().expect("lock window after the cancel");
    lock.window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    assert!(h.app.lock_window().is_none());
    answer_next(&h, TouchIdOutcome::Unlock);
    h.app.open_vault();
    pump();
    assert_eq!(prompts(&h), 2, "a new request after the window closed");
    assert!(h.app.manager_window().is_some());
}

#[test]
fn a_cancelled_hotkey_unlock_shows_the_locked_quick_panel() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Cancel);
    h.app.toggle_quick_panel();
    pump();
    let quick = h.app.quick_panel().expect("Quick Panel");
    assert!(quick.get_locked(), "with its master password field");
    assert!(h.app.lock_window().is_none());
    assert_eq!(prompts(&h), 1);
}

#[test]
fn a_failure_shows_the_lock_window_with_the_reason() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Fail("sensor unavailable"));
    h.app.open_vault();
    pump();
    let lock = h.app.lock_window().expect("lock window after the failure");
    assert_eq!(
        value_of(&lock, "Unlock error"),
        "Touch ID failed: sensor unavailable · use your master password"
    );
}

#[test]
fn the_master_password_is_still_required_for_the_first_unlock_after_start() {
    let settings = Settings {
        require_master_password_on_start: true,
        ..right_away()
    };
    let h = locked_with(settings.clone());
    h.app.open_vault();
    pump();
    assert_eq!(
        prompts(&h),
        0,
        "Touch ID is not offered before the first unlock"
    );
    assert!(h.app.lock_window().is_some(), "the password is asked for");

    // A UI process started after the first unlock (the daemon passes no `--first-unlock`).
    let later = locked_with(settings);
    later.app.set_first_unlock(false);
    answer_next(&later, TouchIdOutcome::Unlock);
    later.app.open_vault();
    pump();
    assert_eq!(prompts(&later), 1);
    assert!(later.app.lock_window().is_none());
    assert!(later.app.manager_window().is_some());
}

#[test]
fn it_is_off_by_default() {
    let h = locked_with(Settings::default());
    h.app.open_vault();
    pump();
    assert_eq!(prompts(&h), 0);
    assert!(h.app.lock_window().is_some());
}

#[test]
fn requests_while_the_prompt_is_up_start_no_second_prompt() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Unlock);
    let app = Rc::clone(&h.app);
    let windows = Rc::new(Cell::new(usize::MAX));
    let counted = Rc::clone(&windows);
    during_next_prompt(move || {
        app.handle(UiCommand::ToggleQuickPanel { target: None });
        app.handle(UiCommand::ShowManager);
        assert!(app.lock_window().is_none() && app.quick_panel().is_none());
        counted.set(app.open_window_count());
    });
    h.app.handle(UiCommand::ShowUnlock);
    pump();
    assert_eq!(prompts(&h), 1, "one Touch ID prompt for all three requests");
    assert_eq!(
        windows.get(),
        1,
        "the prompt counts as a window, so the UI process does not exit under it"
    );
    assert!(h.app.manager_window().is_some());
}

#[test]
fn ask_to_unlock_on_start_unlocks_in_the_tray_without_a_window() {
    let h = locked_with(Settings {
        ask_unlock_on_start: true,
        ..right_away()
    });
    answer_next(&h, TouchIdOutcome::Unlock);
    let seen = watch_for_lock_views(&h);
    h.app.start(true);
    pump();
    assert_eq!(seen.get(), Some(false));
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    assert_eq!(
        h.app.open_window_count(),
        0,
        "an unlock at login opens nothing"
    );
}

#[test]
fn an_ssh_request_while_locked_goes_straight_to_its_approval() {
    let h = locked_with(right_away());
    answer_next(&h, TouchIdOutcome::Unlock);
    let seen = watch_for_lock_views(&h);
    let (reply, _answer) = oneshot::channel();
    h.app.request_ssh_approval(SshApprovalRequest {
        process: "git".to_owned(),
        pid: Some(4242),
        key_name: "github-signing".to_owned(),
        fingerprint: "SHA256:abc".to_owned(),
        purpose: None,
        return_to: None,
        reply,
    });
    pump();
    assert_eq!(seen.get(), Some(false));
    assert!(
        h.app.ssh_prompt().is_some(),
        "the approval shows after the unlock"
    );
    assert!(h.app.lock_window().is_none());
    assert!(h.app.manager_window().is_none());
}

#[test]
fn the_setting_is_offered_only_with_touch_id_enrolled() {
    let h = harness(Setup {
        settings: Settings::default(),
        ..Setup::default()
    });
    h.app.open_settings();
    let settings = h.app.settings_window().expect("settings");
    // Tall enough that the whole scroll view is laid out.
    settings
        .window()
        .set_size(slint::LogicalSize::new(520.0, 1800.0));
    pump();
    assert!(!enabled(&settings, "Unlock with Touch ID right away"));
    click(&settings, "Enrol Touch ID");
    assert!(enabled(&settings, "Unlock with Touch ID right away"));
    click(&settings, "Unlock with Touch ID right away");
    let saved = bw_lite::hooks::SettingsStore::load(&*h.settings);
    assert!(saved.touch_id_right_away);
}
