//! Restarts an SSH agent that stopped serving on its own while the setting is on.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use super::{Daemon, guard};
use crate::daemon::ssh::Revival;

/// Checks after each wake-up or interval; the backoff inside `SshControl` paces the restarts, so
/// a wake-up never brings one forward.
pub(super) async fn ssh_watch_loop(daemon: Arc<Daemon>) {
    loop {
        let wait = daemon.watch_ssh_agent().await;
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = daemon.ssh.woken() => {}
        }
    }
}

impl Daemon {
    async fn watch_ssh_agent(self: &Arc<Self>) -> std::time::Duration {
        let (revival, next) = self.ssh.revive(Instant::now());
        match revival {
            Revival::Idle => {}
            Revival::Restarted => {
                // A failure reported earlier no longer holds; replaying it would turn a working
                // agent off when Settings opens.
                guard(&self.setup_issues).ssh_agent = None;
                self.ssh.refresh(&self.vault).await;
            }
            Revival::Failed { error, report } => {
                if report && self.ssh.is_wanted() && !self.quitting.load(Ordering::SeqCst) {
                    self.ssh_start_failed(&error);
                }
            }
        }
        next
    }
}
