//! SSH sign approvals: one prompt at a time, auto-deny after 30 s, optional Touch ID.

use std::{collections::HashSet, collections::VecDeque, sync::Arc, time::Duration};

use bwl_vault::VaultService;
use slint::Timer;
use tokio::sync::oneshot;

use super::{App, handler, hide, retire, show};
use crate::ui::SshPrompt;

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
    /// `true` approves; dropping it counts as deny.
    pub reply: oneshot::Sender<bool>,
}

#[derive(Default)]
pub(super) struct SshQueue {
    pending: VecDeque<SshApprovalRequest>,
    current: Option<SshApprovalRequest>,
    /// Fingerprints approved with "Remember for this key until lock".
    remembered: HashSet<String>,
    timeout: Option<Timer>,
}

/// The timer may be the one whose callback is running, so it is dropped later.
fn stop_timer(timer: Option<Timer>) {
    if let Some(timer) = timer {
        timer.stop();
        retire(timer);
    }
}

fn reply(request: SshApprovalRequest, approved: bool) {
    if request.reply.send(approved).is_err() {
        tracing::debug!(
            key = request.key_name,
            "SSH requester went away before the answer"
        );
    }
}

impl<S: VaultService> App<S> {
    /// Entry point for the agent's approval channel.
    pub fn request_ssh_approval(&self, request: SshApprovalRequest) {
        if self.ssh.borrow().remembered.contains(&request.fingerprint) {
            reply(request, true);
            return;
        }
        self.ssh.borrow_mut().pending.push_back(request);
        self.show_next_ssh_prompt();
    }

    fn show_next_ssh_prompt(&self) {
        if self.ssh.borrow().current.is_some() {
            return;
        }
        let Some(request) = self.ssh.borrow_mut().pending.pop_front() else {
            return;
        };
        let window = match SshPrompt::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create the SSH prompt; denying");
                reply(request, false);
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
        let seconds = i32::try_from(SSH_TIMEOUT.as_secs()).unwrap_or(30);
        window.set_timeout(seconds);
        window.set_seconds_left(seconds);
        window.on_approve(handler!(self, |app, remember| app.approve_ssh(remember)));
        window.on_deny(handler!(self, |app| app.finish_ssh(false, false)));
        let timeout = Timer::default();
        timeout.start(
            slint::TimerMode::SingleShot,
            SSH_TIMEOUT,
            handler!(self, |app| {
                tracing::info!("SSH approval timed out");
                app.finish_ssh(false, false);
            }),
        );
        {
            let mut queue = self.ssh.borrow_mut();
            queue.current = Some(request);
            queue.timeout = Some(timeout);
        }
        show(&window, "SSH prompt");
        *self.ssh_prompt.borrow_mut() = Some(window);
    }

    fn approve_ssh(&self, remember: bool) {
        if !self.settings.borrow().ssh_touch_id {
            self.finish_ssh(true, remember);
            return;
        }
        if let Some(window) = self.ssh_prompt.borrow().as_ref() {
            window.set_busy(true);
        }
        let biometrics = Arc::clone(&self.hooks.biometrics);
        self.exec.spawn_blocking(
            move || biometrics.authenticate("approve an SSH signature"),
            handler!(self, |app, result| {
                if let Err(error) = &result {
                    tracing::warn!(%error, "Touch ID refused the SSH approval");
                }
                app.finish_ssh(result.is_ok(), remember);
            }),
        );
    }

    fn finish_ssh(&self, approved: bool, remember: bool) {
        let request = {
            let mut queue = self.ssh.borrow_mut();
            stop_timer(queue.timeout.take());
            let request = queue.current.take();
            if let Some(request) = &request
                && approved
                && remember
            {
                queue.remembered.insert(request.fingerprint.clone());
            }
            request
        };
        if let Some(request) = request {
            reply(request, approved);
        }
        if let Some(window) = self.ssh_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
        self.show_next_ssh_prompt();
    }

    /// Lock, logout and account switch: deny everything pending and forget remembered keys.
    pub(super) fn deny_all_ssh(&self) {
        let requests: Vec<SshApprovalRequest> = {
            let mut queue = self.ssh.borrow_mut();
            queue.remembered.clear();
            stop_timer(queue.timeout.take());
            queue
                .current
                .take()
                .into_iter()
                .chain(queue.pending.drain(..))
                .collect()
        };
        for request in requests {
            reply(request, false);
        }
        if let Some(window) = self.ssh_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
    }

    #[must_use]
    pub fn pending_ssh_requests(&self) -> usize {
        let queue = self.ssh.borrow();
        queue.pending.len() + usize::from(queue.current.is_some())
    }
}
