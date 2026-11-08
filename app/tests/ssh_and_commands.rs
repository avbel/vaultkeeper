//! SSH approval prompt and the daemon command interface.

mod common;

use std::{cell::Cell, rc::Rc, time::Duration};

use bw_lite::{
    SshApprovalRequest, UiCommand,
    mock::MOCK_MASTER_PASSWORD,
    settings::{Settings, SshApproval},
};
use bwl_ipc::SshDecision;
use bwl_vault::{VaultService, model::SessionState};
use common::{Mods, Setup, click, control_exists, elapse, harness, key, pump, special, type_into};
use slint::{ComponentHandle, platform::Key};
use tokio::sync::oneshot;

fn request(fingerprint: &str) -> (SshApprovalRequest, oneshot::Receiver<SshDecision>) {
    let (reply, answer) = oneshot::channel();
    (
        SshApprovalRequest {
            process: "git".to_owned(),
            pid: Some(4242),
            key_name: "github-signing".to_owned(),
            fingerprint: fingerprint.to_owned(),
            purpose: Some("git commit signing".to_owned()),
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
fn remember_until_lock_skips_the_prompt_for_that_key() {
    let h = harness(remember_mode());
    let (req, mut rx) = request("SHA256:eee");
    h.app.request_ssh_approval(req);
    let prompt = h.app.ssh_prompt().expect("prompt");
    click(&prompt, "Remember for this key until lock");
    click(&prompt, "Approve");
    assert_eq!(
        rx.try_recv().ok(),
        Some(SshDecision::approve(true)),
        "the daemon learns to remember it too"
    );
    let (req, rx) = request("SHA256:eee");
    h.app.request_ssh_approval(req);
    assert!(h.app.ssh_prompt().is_none());
    assert_eq!(answer(rx), Some(true));
    h.app.lock();
    let (req, _rx) = request("SHA256:eee");
    h.app.request_ssh_approval(req);
    let lock = h.app.lock_window().expect("unlock comes first");
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    pump();
    assert!(h.app.ssh_prompt().is_some(), "lock forgets remembered keys");
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
    assert_eq!(answer(rx), Some(true), "the stub's Touch ID check succeeds");
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
    h.app.handle(UiCommand::ShowQuickPanel);
    let panel = h.app.quick_panel().expect("panel");
    assert!(panel.get_locked());
    panel.invoke_unlock(bw_lite::mock::MOCK_MASTER_PASSWORD.into());
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
    h.app.handle(UiCommand::ToggleQuickPanel);
    assert!(h.app.quick_panel().is_some());
    h.app.handle(UiCommand::ToggleQuickPanel);
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
            theme: bw_lite::settings::ThemeChoice::Dark,
            ..Settings::default()
        });
    h.app.handle(UiCommand::ReloadSettings);
    assert_eq!(
        manager.global::<bw_lite::ui::Theme>().get_mode(),
        bw_lite::ui::ThemeMode::Dark
    );
}
