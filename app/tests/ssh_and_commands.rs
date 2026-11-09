//! SSH approval prompt and the daemon command interface.

mod common;

use std::{cell::Cell, rc::Rc, time::Duration};

use common::{Mods, Setup, click, control_exists, elapse, harness, key, pump, special, type_into};
use slint::{ComponentHandle, platform::Key};
use tokio::sync::oneshot;
use vaultkeeper::{
    SshApprovalRequest, UiCommand,
    hooks::TypingTarget,
    mock::MOCK_MASTER_PASSWORD,
    settings::{Settings, SshApproval},
};
use vk_ipc::SshDecision;
use vk_vault::{VaultService, model::SessionState};

fn request(fingerprint: &str) -> (SshApprovalRequest, oneshot::Receiver<SshDecision>) {
    let (reply, answer) = oneshot::channel();
    (
        SshApprovalRequest {
            process: "git".to_owned(),
            pid: Some(4242),
            key_name: "github-signing".to_owned(),
            fingerprint: fingerprint.to_owned(),
            purpose: Some("git commit signing".to_owned()),
            return_to: None,
            reply,
        },
        answer,
    )
}

fn answer(mut receiver: oneshot::Receiver<SshDecision>) -> Option<bool> {
    receiver.try_recv().ok().map(|decision| decision.approved)
}

fn remember_mode() -> Setup {
    Setup {
        settings: Settings {
            ssh_approval: SshApproval::RememberUntilLock,
            ..Settings::default()
        },
        ..Setup::default()
    }
}

#[test]
fn approve_replies_true_and_closes_the_prompt() {
    let h = harness(Setup::default());
    let (req, rx) = request("SHA256:aaa");
    h.app.handle(UiCommand::ShowSshApproval(req));
    let prompt = h.app.ssh_prompt().expect("prompt");
    assert_eq!(prompt.get_process(), "git (pid 4242)");
    assert_eq!(prompt.get_fingerprint(), "SHA256:aaa");
    click(&prompt, "Approve");
    assert_eq!(answer(rx), Some(true));
    assert!(h.app.ssh_prompt().is_none());
}

#[test]
fn deny_and_escape_reply_false() {
    let h = harness(Setup::default());
    let (req, rx) = request("SHA256:bbb");
    h.app.request_ssh_approval(req);
    click(&h.app.ssh_prompt().expect("prompt"), "Deny");
    assert_eq!(answer(rx), Some(false));
    let (req, rx) = request("SHA256:ccc");
    h.app.request_ssh_approval(req);
    let prompt = h.app.ssh_prompt().expect("prompt");
    key(&prompt, &special(Key::Escape), Mods::default());
    assert_eq!(answer(rx), Some(false));
}

#[test]
fn unanswered_requests_are_denied_after_30_seconds() {
    let h = harness(Setup::default());
    let (req, mut rx) = request("SHA256:ddd");
    h.app.request_ssh_approval(req);
    let prompt = h.app.ssh_prompt().expect("prompt");
    // A repeated Slint timer fires once per mock-time step, as it would once per real second.
    for _ in 0..10 {
        elapse(Duration::from_secs(1));
    }
    assert_eq!(prompt.get_seconds_left(), 20, "the bar counts down");
    assert!(rx.try_recv().is_err(), "still waiting at 10 s");
    for _ in 0..21 {
        elapse(Duration::from_secs(1));
    }
    assert_eq!(answer(rx), Some(false));
    assert!(h.app.ssh_prompt().is_none());
}

#[test]
fn remember_is_left_to_the_daemon_so_the_ui_asks_again_for_the_same_fingerprint() {
    let h = harness(remember_mode());
    let (req, mut rx) = request("");
    h.app.request_ssh_approval(req);
    let prompt = h.app.ssh_prompt().expect("prompt");
    click(&prompt, "Remember for this key until lock");
    click(&prompt, "Approve");
    assert_eq!(
        rx.try_recv().ok(),
        Some(SshDecision::approve(true)),
        "the daemon learns to remember it"
    );
    let (req, rx) = request("");
    h.app.request_ssh_approval(req);
    let prompt = h
        .app
        .ssh_prompt()
        .expect("another item with the same empty fingerprint is not covered by that consent");
    click(&prompt, "Deny");
    assert_eq!(answer(rx), Some(false));
}

#[test]
fn queued_requests_are_shown_one_at_a_time_and_lock_denies_them() {
    let h = harness(Setup::default());
    let (first, rx1) = request("SHA256:f1");
    let (second, rx2) = request("SHA256:f2");
    h.app.request_ssh_approval(first);
    h.app.request_ssh_approval(second);
    assert_eq!(h.app.pending_ssh_requests(), 2);
    click(&h.app.ssh_prompt().expect("first"), "Approve");
    assert_eq!(answer(rx1), Some(true));
    assert_eq!(
        h.app.ssh_prompt().expect("second").get_fingerprint(),
        "SHA256:f2"
    );
    h.app.lock();
    assert_eq!(answer(rx2), Some(false));
    assert_eq!(h.app.pending_ssh_requests(), 0);
}

#[test]
fn touch_id_setting_gates_the_approval() {
    let h = harness(Setup {
        settings: Settings {
            ssh_touch_id: true,
            ..Settings::default()
        },
        ..Setup::default()
    });
    let (req, rx) = request("SHA256:ggg");
    h.app.request_ssh_approval(req);
    let prompt = h.app.ssh_prompt().expect("prompt");
    assert!(prompt.get_touch_id_required());
    click(&prompt, "Approve");
    assert_eq!(
        answer(rx),
        Some(true),
        "the UI answers at once; the daemon asks for Touch ID itself"
    );
    assert!(h.app.ssh_prompt().is_none());
}

#[test]
fn a_late_event_from_a_closed_prompt_never_decides_the_next_request() {
    let h = harness(remember_mode());
    let (first, rx1) = request("SHA256:old");
    let (second, mut rx2) = request("SHA256:new");
    h.app.request_ssh_approval(first);
    h.app.request_ssh_approval(second);
    let old_prompt = h.app.ssh_prompt().expect("first prompt");
    elapse(Duration::from_secs(31));
    pump();
    assert_eq!(answer(rx1), Some(false), "the first timed out");
    let current = h.app.ssh_prompt().expect("second prompt");
    assert_eq!(current.get_fingerprint(), "SHA256:new");

    // The first prompt's window handle still fires its callbacks (a late click, Esc, or a
    // result that was in flight), but they belong to the first request.
    old_prompt.invoke_approve(true);
    old_prompt.invoke_deny();
    pump();
    assert!(
        rx2.try_recv().is_err(),
        "the second request is still waiting for its own answer"
    );
    assert_eq!(h.app.pending_ssh_requests(), 1);
    let (repeat, repeat_rx) = request("SHA256:new");
    current.invoke_approve(false);
    pump();
    assert_eq!(answer(rx2), Some(true));
    h.app.request_ssh_approval(repeat);
    assert!(
        h.app
            .ssh_prompt()
            .is_some_and(|prompt| prompt.get_fingerprint() == "SHA256:new"),
        "the late approve with remember did not remember the second key"
    );
    drop(repeat_rx);
}

#[test]
fn commands_open_windows_and_the_last_close_is_reported() {
    let h = harness(Setup {
        unlocked: false,
        ..Setup::default()
    });
    let closed = Rc::new(Cell::new(0));
    let counter = Rc::clone(&closed);
    h.app
        .set_on_last_window_closed(move || counter.set(counter.get() + 1));
    h.app.handle(UiCommand::ShowUnlock);
    assert!(h.app.lock_window().is_some());
    assert_eq!(h.app.open_window_count(), 1);
    h.app.handle(UiCommand::ShowQuickPanel { target: None });
    let panel = h.app.quick_panel().expect("panel");
    assert!(panel.get_locked());
    panel.invoke_unlock(vaultkeeper::mock::MOCK_MASTER_PASSWORD.into());
    h.app.handle(UiCommand::VaultChanged);
    pump();
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    assert!(h.app.lock_window().is_none());
    assert_eq!(closed.get(), 0, "the Quick Panel is still open");
    h.app.handle(UiCommand::ShowManager);
    assert!(h.app.manager_window().is_some());
    h.app.lock();
    pump();
    assert!(h.app.manager_window().is_none());
    let lock = h.app.lock_window().expect("lock after lock");
    lock.window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    assert_eq!(h.app.open_window_count(), 0);
    assert_eq!(closed.get(), 1, "fires once when the last window closes");
    h.app.handle(UiCommand::ShowLogin);
    assert!(h.app.login_window().is_some());
}

#[test]
fn with_always_approve_nothing_is_remembered() {
    let h = harness(Setup::default());
    let (req, mut rx) = request("SHA256:always");
    h.app.request_ssh_approval(req);
    let prompt = h.app.ssh_prompt().expect("prompt");
    assert!(
        !control_exists(&prompt, "Remember for this key until lock"),
        "no remember option when every request needs approval"
    );
    prompt.invoke_approve(true);
    pump();
    assert_eq!(rx.try_recv().ok(), Some(SshDecision::approve(false)));
    let (req, _rx) = request("SHA256:always");
    h.app.request_ssh_approval(req);
    assert!(h.app.ssh_prompt().is_some(), "asked again");
}

#[test]
fn a_request_while_locked_shows_the_lock_screen_first() {
    let h = harness(Setup {
        unlocked: false,
        ..Setup::default()
    });
    let (req, rx) = request("SHA256:locked");
    h.app.request_ssh_approval(req);
    assert!(h.app.ssh_prompt().is_none(), "no prompt before the unlock");
    assert_eq!(h.app.pending_ssh_requests(), 1);
    let lock = h.app.lock_window().expect("lock screen");
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    pump();
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    let prompt = h.app.ssh_prompt().expect("prompt after the unlock");
    assert_eq!(prompt.get_fingerprint(), "SHA256:locked");
    assert!(
        h.app.manager_window().is_none(),
        "the unlock opened nothing else"
    );
    click(&prompt, "Approve");
    assert_eq!(answer(rx), Some(true));
}

#[test]
fn closing_the_lock_screen_denies_requests_waiting_on_it() {
    let h = harness(Setup {
        unlocked: false,
        ..Setup::default()
    });
    let (req, rx) = request("SHA256:closed");
    h.app.request_ssh_approval(req);
    let lock = h.app.lock_window().expect("lock screen");
    lock.window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    assert_eq!(answer(rx), Some(false));
    assert_eq!(h.app.pending_ssh_requests(), 0);
}

#[test]
fn a_request_while_logged_out_is_denied_at_once() {
    let h = harness(Setup {
        unlocked: false,
        ..Setup::default()
    });
    // The mock has two accounts; log out of both.
    while h.vault.state() != SessionState::LoggedOut {
        let logout = std::sync::Arc::clone(&h.vault);
        common::block_on(async move { logout.logout().await }).expect("logout");
    }
    h.app.handle(UiCommand::VaultChanged);
    let (req, rx) = request("SHA256:none");
    h.app.request_ssh_approval(req);
    assert_eq!(answer(rx), Some(false));
    assert!(h.app.ssh_prompt().is_none());
}

#[test]
fn daemon_commands_open_settings_generator_and_toggle_the_quick_panel() {
    let h = harness(Setup::default());
    h.app.handle(UiCommand::ShowSettings);
    assert!(h.app.settings_window().is_some());
    h.app.handle(UiCommand::ShowGenerator);
    assert!(h.app.generator_window().is_some());
    h.app.handle(UiCommand::ToggleQuickPanel { target: None });
    assert!(h.app.quick_panel().is_some());
    h.app.handle(UiCommand::ToggleQuickPanel { target: None });
    pump();
    assert!(
        h.app.quick_panel().is_none(),
        "the hotkey closes an open panel"
    );
}

#[test]
fn reload_settings_applies_what_the_daemon_saved() {
    let h = harness(Setup::default());
    h.app.handle(UiCommand::ShowManager);
    let manager = h.app.manager_window().expect("manager");
    h.settings
        .saved
        .lock()
        .expect("settings")
        .replace(Settings {
            theme: vaultkeeper::settings::ThemeChoice::Dark,
            ..Settings::default()
        });
    h.app.handle(UiCommand::ReloadSettings);
    assert_eq!(
        manager.global::<vaultkeeper::ui::Theme>().get_mode(),
        vaultkeeper::ui::ThemeMode::Dark
    );
}

fn terminal() -> TypingTarget {
    TypingTarget {
        pid: 377,
        name: "Terminal".to_owned(),
    }
}

/// A request the daemon saw arrive while Terminal was in front.
fn request_from_terminal(
    fingerprint: &str,
) -> (SshApprovalRequest, oneshot::Receiver<SshDecision>) {
    let (request, answer) = request(fingerprint);
    (
        SshApprovalRequest {
            return_to: Some(terminal()),
            ..request
        },
        answer,
    )
}

fn given_back(h: &common::Harness) -> Vec<TypingTarget> {
    h.autotype.given_back.lock().expect("given back").clone()
}

type AnswerWith = fn(&vaultkeeper::ui::SshPrompt);

#[test]
fn every_answer_hands_the_front_back_and_opens_no_manager() {
    let answers: [(&str, AnswerWith); 3] = [
        ("approve", |prompt| click(prompt, "Approve")),
        ("deny", |prompt| click(prompt, "Deny")),
        ("Esc", |prompt| {
            key(prompt, &special(Key::Escape), Mods::default());
        }),
    ];
    for (name, answer_with) in answers {
        let h = harness(Setup::default());
        let (req, _rx) = request_from_terminal("SHA256:term");
        h.app.handle(UiCommand::ShowSshApproval(req));
        answer_with(&h.app.ssh_prompt().expect("prompt"));
        pump();
        assert!(h.app.ssh_prompt().is_none(), "{name}");
        assert!(h.app.manager_window().is_none(), "{name}: no Manager");
        assert_eq!(given_back(&h), [terminal()], "{name}");
        assert_eq!(
            h.dock.hides(),
            1,
            "{name}: no windowless vaultkeeper in front"
        );
    }
}

#[test]
fn a_timed_out_prompt_hands_the_front_back_too() {
    let h = harness(Setup::default());
    let (req, rx) = request_from_terminal("SHA256:late");
    h.app.handle(UiCommand::ShowSshApproval(req));
    elapse(Duration::from_secs(31));
    pump();
    assert_eq!(answer(rx), Some(false));
    assert_eq!(given_back(&h), [terminal()]);
}

#[test]
fn the_front_goes_back_once_the_last_queued_prompt_is_answered() {
    let h = harness(Setup::default());
    let (first, _rx1) = request_from_terminal("SHA256:one");
    let (second, _rx2) = request_from_terminal("SHA256:two");
    h.app.request_ssh_approval(first);
    h.app.request_ssh_approval(second);
    click(&h.app.ssh_prompt().expect("first"), "Approve");
    assert!(given_back(&h).is_empty(), "the next prompt needs the keys");
    click(&h.app.ssh_prompt().expect("second"), "Approve");
    assert_eq!(given_back(&h), [terminal()]);
}

#[test]
fn a_manager_left_open_behind_the_terminal_stays_behind_it() {
    let h = harness(Setup::default());
    h.app.handle(UiCommand::ShowManager);
    let (req, _rx) = request_from_terminal("SHA256:behind");
    h.app.handle(UiCommand::ShowSshApproval(req));
    click(&h.app.ssh_prompt().expect("prompt"), "Approve");
    pump();
    assert_eq!(given_back(&h), [terminal()], "Terminal comes back on top");
    assert!(
        h.app.manager_window().is_some(),
        "the user's Manager is not closed"
    );
    assert_eq!(h.dock.hides(), 0, "a window is still open");
}

#[test]
fn an_unlock_for_ssh_after_a_lock_with_the_manager_open_shows_only_the_prompt() {
    let h = harness(Setup::default());
    h.app.handle(UiCommand::ShowManager);
    h.app.lock();
    pump();
    assert!(h.app.manager_window().is_none(), "the lock closed it");
    let (req, rx) = request_from_terminal("SHA256:after-lock");
    h.app.handle(UiCommand::ShowSshApproval(req));
    let lock = h.app.lock_window().expect("lock screen");
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    pump();
    assert!(
        h.app.manager_window().is_none(),
        "only the prompt after the unlock"
    );
    let prompt = h.app.ssh_prompt().expect("prompt");
    click(&prompt, "Approve");
    pump();
    assert_eq!(answer(rx), Some(true));
    assert!(
        h.app.manager_window().is_none(),
        "no Manager after the answer"
    );
    assert_eq!(given_back(&h), [terminal()]);
}

#[test]
fn a_lock_screen_closed_unanswered_forgets_the_manager_it_stood_for() {
    let h = harness(Setup::default());
    h.app.handle(UiCommand::ShowManager);
    h.app.lock();
    pump();
    let lock = h.app.lock_window().expect("lock screen for the Manager");
    lock.window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    // Unlocked later outside this window, e.g. by another request's Touch ID in the daemon.
    common::block_on(
        h.vault
            .unlock_with_password(zeroize::Zeroizing::new(MOCK_MASTER_PASSWORD.to_owned())),
    )
    .expect("unlock");
    h.app.handle(UiCommand::VaultChanged);
    pump();
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    assert!(h.app.manager_window().is_none());
}
