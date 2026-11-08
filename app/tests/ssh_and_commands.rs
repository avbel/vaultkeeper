//! SSH approval prompt and the daemon command interface.

mod common;

use std::{cell::Cell, rc::Rc, time::Duration};

use bw_lite::{SshApprovalRequest, UiCommand, settings::Settings};
use bwl_vault::{VaultService, model::SessionState};
use common::{Mods, Setup, click, elapse, harness, key, pump, special};
use slint::{ComponentHandle, platform::Key};
use tokio::sync::oneshot;

fn request(fingerprint: &str) -> (SshApprovalRequest, oneshot::Receiver<bool>) {
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

fn answer(mut receiver: oneshot::Receiver<bool>) -> Option<bool> {
    receiver.try_recv().ok()
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
    let h = harness(Setup::default());
    let (req, rx) = request("SHA256:eee");
    h.app.request_ssh_approval(req);
    let prompt = h.app.ssh_prompt().expect("prompt");
    click(&prompt, "Remember for this key until lock");
    click(&prompt, "Approve");
    assert_eq!(answer(rx), Some(true));
    let (req, rx) = request("SHA256:eee");
    h.app.request_ssh_approval(req);
    assert!(h.app.ssh_prompt().is_none());
    assert_eq!(answer(rx), Some(true));
    h.app.lock();
    let (req, _rx) = request("SHA256:eee");
    h.app.request_ssh_approval(req);
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
