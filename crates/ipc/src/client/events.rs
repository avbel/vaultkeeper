use tokio::sync::{mpsc, oneshot};

use crate::protocol::{SshDecision, SshPrompt, UiCommand};

/// What the daemon pushes to the UI process, besides cache refreshes (those surface through
/// `VaultService::changes`).
#[derive(Debug)]
pub enum UiEvent {
    Command(UiCommand),
    SshApproval(SshApproval),
    /// The UI shows or dismisses the "Offline mode" toast.
    OfflineChanged(bool),
    /// The daemon is quitting; the UI process should exit.
    Shutdown,
}

/// An SSH sign/list request waiting for the user.
#[derive(Debug)]
pub struct SshApproval {
    pub request_id: u64,
    pub prompt: SshPrompt,
    /// Dropping it counts as deny.
    pub reply: oneshot::Sender<SshDecision>,
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
