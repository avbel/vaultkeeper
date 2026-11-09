//! SSH sign approvals: one prompt at a time, auto-deny after 30 s. A request that arrives while
//! the vault is locked shows the lock screen first and its prompt after the unlock.
//!
//! "Remember for this key until lock" is kept by the daemon, keyed by cipher id: displayed
//! fingerprints can be empty or shared between items, so the UI must not decide on them.
//!
//! "SSH requires Touch ID" is enforced by the daemon after it gets the approval, so a decision
//! here is final the moment it is made. Every queued request gets its own id, and each prompt's
//! buttons and timer answer only that id: an event from an old prompt can never decide a newer
//! request.

use std::{collections::VecDeque, time::Duration};

use bwl_ipc::SshDecision;
use bwl_vault::{VaultService, model::SessionState};
use slint::Timer;
use tokio::sync::oneshot;

use super::{App, handler, hide, retire, show};
use crate::{settings::SshApproval, ui::SshPrompt};

pub const SSH_TIMEOUT: Duration = Duration::from_secs(30);

/// What the integration step builds from a `bwl_ssh::ApprovalRequest` plus the vault's key data.
#[derive(Debug)]
pub struct SshApprovalRequest {
    pub process: String,
    pub pid: Option<u32>,
    pub key_name: String,
    pub fingerprint: String,
    /// e.g. "git commit signing" or "agent forwarding".
    pub purpose: Option<String>,
    /// Dropping it counts as deny.
    pub reply: oneshot::Sender<SshDecision>,
}

struct Queued {
    id: u64,
    request: SshApprovalRequest,
}

#[derive(Default)]
pub(super) struct SshQueue {
    next_id: u64,
    pending: VecDeque<Queued>,
    current: Option<Queued>,
    timeout: Option<Timer>,
}

/// The timer may be the one whose callback is running, so it is dropped later.
fn stop_timer(timer: Option<Timer>) {
    if let Some(timer) = timer {
        timer.stop();
        retire(timer);
    }
}

fn reply(request: SshApprovalRequest, decision: SshDecision) {
    if request.reply.send(decision).is_err() {
        tracing::debug!(
            key = request.key_name,
            "SSH requester went away before the answer"
        );
    }
}

impl SshQueue {
    fn enqueue(&mut self, request: SshApprovalRequest) {
        self.next_id += 1;
        self.pending.push_back(Queued {
            id: self.next_id,
            request,
        });
    }
}

impl<S: VaultService> App<S> {
    /// Entry point for the agent's approval channel.
    pub fn request_ssh_approval(&self, request: SshApprovalRequest) {
        match self.vault.state() {
            SessionState::LoggedOut => {
                reply(request, SshDecision::DENY);
                return;
            }
            SessionState::Locked { .. } => {
                self.ssh.borrow_mut().enqueue(request);
                self.request_unlock(super::unlock::UnlockView::LockWindow);
                return;
            }
            SessionState::Unlocked { .. } => {}
        }
        self.ssh.borrow_mut().enqueue(request);
        self.show_next_ssh_prompt();
    }

    /// Runs after every unlock too, for requests that waited on the lock screen.
    pub(super) fn show_next_ssh_prompt(&self) {
        if self.ssh.borrow().current.is_some()
            || !matches!(self.vault.state(), SessionState::Unlocked { .. })
        {
            return;
        }
        let Some(Queued { id, request }) = self.ssh.borrow_mut().pending.pop_front() else {
            return;
        };
        let window = match SshPrompt::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create the SSH prompt; denying");
                reply(request, SshDecision::DENY);
                return;
            }
        };
        self.apply_theme(&window);
        let process = request.pid.map_or_else(
            || request.process.clone(),
            |pid| format!("{} (pid {pid})", request.process),
        );
        window.set_process(process.into());
        window.set_key_name(request.key_name.as_str().into());
        window.set_fingerprint(request.fingerprint.as_str().into());
        window.set_purpose(request.purpose.clone().unwrap_or_default().into());
        window.set_touch_id_required(self.settings.borrow().ssh_touch_id);
        window.set_allow_remember(
            self.settings.borrow().ssh_approval == SshApproval::RememberUntilLock,
        );
        let seconds = i32::try_from(SSH_TIMEOUT.as_secs()).unwrap_or(30);
        window.set_timeout(seconds);
        window.set_seconds_left(seconds);
        window.on_approve(handler!(self, |app, remember| app.finish_ssh(id, true, remember)));
        window.on_deny(handler!(self, |app| app.finish_ssh(id, false, false)));
        let timeout = Timer::default();
        timeout.start(
            slint::TimerMode::SingleShot,
            SSH_TIMEOUT,
            handler!(self, |app| {
                tracing::info!("SSH approval timed out");
                app.finish_ssh(id, false, false);
            }),
        );
        {
            let mut queue = self.ssh.borrow_mut();
            queue.current = Some(Queued { id, request });
            queue.timeout = Some(timeout);
        }
        show(&window, "SSH prompt");
        *self.ssh_prompt.borrow_mut() = Some(window);
    }

    /// Answers request `id` if it is still the one on screen; anything else is a late event from
    /// a prompt that is already gone and is dropped.
    fn finish_ssh(&self, id: u64, approved: bool, remember: bool) {
        let remember = approved
            && remember
            && self.settings.borrow().ssh_approval == SshApproval::RememberUntilLock;
        let request = {
            let mut queue = self.ssh.borrow_mut();
            if queue
                .current
                .as_ref()
                .is_none_or(|current| current.id != id)
            {
                tracing::debug!(id, "SSH decision for a prompt that is gone; ignored");
                return;
            }
            stop_timer(queue.timeout.take());
            queue.current.take().map(|current| current.request)
        };
        if let Some(request) = request {
            reply(request, SshDecision { approved, remember });
        }
        if let Some(window) = self.ssh_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
        self.show_next_ssh_prompt();
    }

    /// Lock, logout and account switch: deny everything pending.
    pub(super) fn deny_all_ssh(&self) {
        let requests: Vec<SshApprovalRequest> = {
            let mut queue = self.ssh.borrow_mut();
            stop_timer(queue.timeout.take());
            queue
                .current
                .take()
                .into_iter()
                .chain(queue.pending.drain(..))
                .map(|queued| queued.request)
                .collect()
        };
        for request in requests {
            reply(request, SshDecision::DENY);
        }
        if let Some(window) = self.ssh_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
    }

    /// The lock screen was closed without unlocking: requests waiting behind it are denied.
    pub(super) fn deny_ssh_waiting_for_unlock(&self) {
        if matches!(self.vault.state(), SessionState::Unlocked { .. }) {
            return;
        }
        let waiting: Vec<SshApprovalRequest> = self
            .ssh
            .borrow_mut()
            .pending
            .drain(..)
            .map(|queued| queued.request)
            .collect();
        for request in waiting {
            reply(request, SshDecision::DENY);
        }
    }

    #[must_use]
    pub fn pending_ssh_requests(&self) -> usize {
        let queue = self.ssh.borrow();
        queue.pending.len() + usize::from(queue.current.is_some())
    }
}
