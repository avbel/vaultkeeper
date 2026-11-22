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

use std::{collections::VecDeque, sync::Arc, time::Duration};

use slint::{ComponentHandle, SharedString, Timer};
use tokio::sync::oneshot;
use vk_ipc::SshDecision;
use vk_vault::{
    VaultService,
    model::{ItemId, SessionState},
};
use zeroize::Zeroizing;

use super::{App, handler, hide, retire, show};
use crate::{hooks::TypingTarget, settings::SshApproval, ui::SshPrompt, viewmodel};

pub const SSH_TIMEOUT: Duration = Duration::from_secs(30);

/// What the integration step builds from a `vk_ssh::ApprovalRequest` plus the vault's key data.
#[derive(Debug)]
pub struct SshApprovalRequest {
    pub process: String,
    pub pid: Option<u32>,
    pub key_name: String,
    pub fingerprint: String,
    /// The vault item behind the key, to look up and record its master password confirmation.
    pub cipher_id: String,
    /// The item asks for the master password: approving needs a verified one.
    pub reprompt: bool,
    /// e.g. "git commit signing" or "agent forwarding".
    pub purpose: Option<String>,
    /// The app in front when the request arrived; it gets the front back after the answer.
    pub return_to: Option<TypingTarget>,
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
                // This unlock is for the prompt only: a Manager the lock closed earlier stays
                // closed. A Touch ID prompt already up keeps the window it was started for.
                if !self.right_away_pending() {
                    self.target.set(super::Target::None);
                }
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
        window.set_biometric_required(self.settings.borrow().ssh_touch_id);
        window.set_allow_remember(
            self.settings.borrow().ssh_approval == SshApproval::RememberUntilLock,
        );
        let seconds = i32::try_from(SSH_TIMEOUT.as_secs()).unwrap_or(30);
        window.set_timeout(seconds);
        window.set_seconds_left(seconds);
        window.set_reprompt(self.ssh_password_required(&request));
        window.on_approve(handler!(self, |app, remember| app.approve_ssh(id, remember)));
        window.on_submit_password(handler!(self, |app, password, remember| {
            app.verify_ssh_password(id, Zeroizing::new(password.to_string()), remember);
        }));
        window.on_deny(handler!(self, |app| app.finish_ssh(id, false, false)));
        // A compositor can close the prompt itself (Sway's `kill`); the client must not wait for
        // the timeout behind a window that is gone.
        window.window().on_close_requested(handler!(
            self,
            slint::CloseRequestResponse::HideWindow,
            |app| {
                app.finish_ssh(id, false, false);
                slint::CloseRequestResponse::HideWindow
            }
        ));
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

    fn ssh_password_required(&self, request: &SshApprovalRequest) -> bool {
        request.reprompt
            && !self
                .reprompt_verified
                .borrow()
                .contains(&ItemId(Arc::from(request.cipher_id.as_str())))
    }

    /// The Approve button and Return come here: a protected key is approved only through
    /// `verify_ssh_password`, whatever the window sends.
    fn approve_ssh(&self, id: u64, remember: bool) {
        let protected = self.ssh.borrow().current.as_ref().is_some_and(|current| {
            current.id == id && self.ssh_password_required(&current.request)
        });
        if protected {
            return;
        }
        self.finish_ssh(id, true, remember);
    }

    fn verify_ssh_password(&self, id: u64, password: Zeroizing<String>, remember: bool) {
        if password.is_empty() {
            return;
        }
        let Some(window) = self
            .ssh_prompt
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
        else {
            return;
        };
        if window.get_busy()
            || self
                .ssh
                .borrow()
                .current
                .as_ref()
                .is_none_or(|current| current.id != id)
        {
            return;
        }
        window.set_password(SharedString::new());
        window.set_password_error(SharedString::new());
        window.set_busy(true);
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.verify_master_password(password).await },
            handler!(self, |app, result| app
                .ssh_password_checked(id, remember, result)),
        );
    }

    /// A result for a prompt that is already gone (answered, timed out, locked) is dropped.
    fn ssh_password_checked(&self, id: u64, remember: bool, result: vk_vault::Result<bool>) {
        let cipher_id = {
            let queue = self.ssh.borrow();
            match queue.current.as_ref() {
                Some(current) if current.id == id => current.request.cipher_id.clone(),
                _ => return,
            }
        };
        let window = self
            .ssh_prompt
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = &window {
            window.set_busy(false);
        }
        match result {
            Ok(true) => {
                self.reprompt_verified
                    .borrow_mut()
                    .insert(ItemId(Arc::from(cipher_id.as_str())));
                self.finish_ssh(id, true, remember);
            }
            Ok(false) => {
                if let Some(window) = &window {
                    window.set_password_error("Wrong master password · try again".into());
                }
            }
            Err(error) => {
                if let Some(window) = &window {
                    window.set_password_error(viewmodel::error_text(&error).into());
                }
            }
        }
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
        let return_to = request
            .as_ref()
            .and_then(|request| request.return_to.clone());
        if let Some(request) = request {
            reply(request, SshDecision { approved, remember });
        }
        if let Some(window) = self.ssh_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
        self.show_next_ssh_prompt();
        // Showing the prompt brought every vaultkeeper window forward, a Manager left open behind
        // the terminal included; the terminal gets the front back, and the Manager stays behind.
        if self.ssh_prompt.borrow().is_none()
            && let Some(app) = return_to
        {
            self.hooks.autotype.give_focus_back(&app);
        }
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
