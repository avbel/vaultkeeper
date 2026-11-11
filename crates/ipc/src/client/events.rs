use tokio::sync::{mpsc, oneshot};

use crate::protocol::{BrowserPrompt, BrowserReply, SshDecision, SshPrompt, UiCommand};

/// What the daemon pushes to the UI process, besides cache refreshes (those surface through
/// `VaultService::changes`).
#[derive(Debug)]
pub enum UiEvent {
    Command {
        seq: u64,
        command: UiCommand,
    },
    SshApproval(SshApproval),
    BrowserPrompt(BrowserPromptEvent),
    /// The daemon withdrew its event `seq` before it got here; nothing to show.
    Skipped(u64),
    /// The UI shows or dismisses the "Offline mode" toast.
    OfflineChanged(bool),
    /// The daemon is quitting; the UI process should exit.
    Shutdown,
}

impl UiEvent {
    /// The daemon's number for this event, which the UI acknowledges with
    /// [`crate::UiNotice::Alive`] once its main loop got to it; `None` for events nobody waits on.
    #[must_use]
    pub const fn seq(&self) -> Option<u64> {
        match self {
            Self::Command { seq, .. } | Self::Skipped(seq) => Some(*seq),
            Self::SshApproval(approval) => Some(approval.seq),
            Self::BrowserPrompt(prompt) => Some(prompt.seq),
            Self::OfflineChanged(_) | Self::Shutdown => None,
        }
    }
}

/// An SSH sign/list request waiting for the user.
#[derive(Debug)]
pub struct SshApproval {
    pub seq: u64,
    pub request_id: u64,
    pub prompt: SshPrompt,
    /// Dropping it counts as deny.
    pub reply: oneshot::Sender<SshDecision>,
}

#[derive(Debug)]
pub struct BrowserPromptEvent {
    pub seq: u64,
    pub request_id: u64,
    pub prompt: BrowserPrompt,
    pub reply: oneshot::Sender<BrowserReply>,
}

/// Events from the daemon. Ends (`next` returns `None`) when the connection is gone, which is
/// the UI process's cue to exit.
#[derive(Debug)]
pub struct EventStream {
    events: mpsc::UnboundedReceiver<UiEvent>,
}

impl EventStream {
    pub(super) const fn new(events: mpsc::UnboundedReceiver<UiEvent>) -> Self {
        Self { events }
    }

    pub async fn next(&mut self) -> Option<UiEvent> {
        self.events.recv().await
    }

    /// For bridging into another channel or a `Stream` adapter.
    #[must_use]
    pub fn into_receiver(self) -> mpsc::UnboundedReceiver<UiEvent> {
        self.events
    }
}
