use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

use vk_ipc::{
    UiCommand,
    cli_access::{self, Listener, Request, Response},
};
use vk_vault::{Error, VaultService};

use super::{Daemon, guard};
use crate::os::layout::CLI_SOCKET;

const UNLOCK_PROMPT_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(super) struct CliAccessState {
    listener: Mutex<Option<Listener>>,
    last_prompt: Mutex<Option<Instant>>,
}

impl CliAccessState {
    pub(super) fn stop(&self) {
        guard(&self.listener).take();
    }
}

impl Daemon {
    pub(super) fn reconcile_cli_access(self: &Arc<Self>) {
        let mut listener = guard(&self.cli_access.listener);
        if !self.settings().cli_access || self.quitting.load(Ordering::SeqCst) {
            listener.take();
            return;
        }
        if listener.is_some() {
            return;
        }
        let daemon = Arc::downgrade(self);
        let _runtime = self.runtime.enter();
        match cli_access::serve(
            self.data_dir.join(CLI_SOCKET),
            self.vault.changes(),
            move |request| {
                daemon.upgrade().map_or(Response::Unavailable, |daemon| {
                    daemon.read_cli_access(request)
                })
            },
        ) {
            Ok(started) => *listener = Some(started),
            Err(error) => tracing::error!(%error, "cannot start the CLI listener"),
        }
    }

    fn read_cli_access(self: &Arc<Self>, request: Request) -> Response {
        let settings = self.settings.borrow();
        if !settings.cli_access || self.quitting.load(Ordering::SeqCst) {
            return Response::Unavailable;
        }
        let result = match request {
            Request::ListKeys => self.vault.cli_login_keys().map(Response::Keys),
            Request::GetFields { key } => self.vault.cli_login_fields(&key).map(Response::Fields),
            Request::GetValue {
                key,
                field,
                allow_private,
            } => self
                .vault
                .cli_login_value(&key, &field, allow_private)
                .map(|value| value.map_or(Response::PrivateField, Response::Value)),
        };
        drop(settings);
        match result {
            Ok(response) => response,
            Err(Error::Locked) => {
                self.prompt_for_cli_unlock();
                Response::Locked
            }
            Err(Error::LoggedOut) => Response::LoggedOut,
            Err(Error::NotFound) => Response::NotFound,
            Err(Error::NoSuchField) => Response::NoSuchField,
            Err(_) => Response::Unavailable,
        }
    }

    fn prompt_for_cli_unlock(self: &Arc<Self>) {
        let mut last_prompt = guard(&self.cli_access.last_prompt);
        let now = Instant::now();
        if !prompt_due(*last_prompt, now) {
            return;
        }
        if self.settings().cli_access && !self.quitting.load(Ordering::SeqCst) {
            *last_prompt = Some(now);
            self.send_command(UiCommand::ShowUnlock);
        }
    }
}

/// A burst of locked CLI calls (a script reading several fields) raises one unlock prompt.
fn prompt_due(last_prompt: Option<Instant>, now: Instant) -> bool {
    last_prompt.is_none_or(|time| now.duration_since(time) >= UNLOCK_PROMPT_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_calls_prompt_once_per_interval() {
        let start = Instant::now();
        assert!(prompt_due(None, start));
        assert!(!prompt_due(Some(start), start));
        let just_before = UNLOCK_PROMPT_INTERVAL.saturating_sub(Duration::from_millis(1));
        assert!(!prompt_due(Some(start), start + just_before));
        assert!(prompt_due(Some(start), start + UNLOCK_PROMPT_INTERVAL));
    }
}
