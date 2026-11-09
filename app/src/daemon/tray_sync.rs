//! The tray's "Sync now". Unlike the timer, websocket and unlock syncs, the user waits for this
//! one, so the tray menu shows it running and how it ended.

use std::time::SystemTime;

use tokio::sync::watch;

use crate::viewmodel;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub message: String,
    pub at: SystemTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraySync {
    pub running: bool,
    pub failed: Option<Failure>,
}

impl TraySync {
    /// The failure still worth showing: no sync of any kind has succeeded since.
    #[must_use]
    pub fn failure(&self, last_sync: Option<SystemTime>) -> Option<&str> {
        self.failed
            .as_ref()
            .filter(|failure| last_sync.is_none_or(|last| last < failure.at))
            .map(|failure| failure.message.as_str())
    }
}

/// Marks a sync as running; `false` when one already is.
pub(super) fn start(status: &watch::Sender<TraySync>) -> bool {
    status.send_if_modified(|current| {
        if current.running {
            return false;
        }
        *current = TraySync {
            running: true,
            failed: None,
        };
        true
    })
}

/// Records how the sync ended and returns the error text for the UI.
pub(super) fn finish(
    status: &watch::Sender<TraySync>,
    result: &bwl_vault::Result<()>,
) -> Option<String> {
    let message = result.as_ref().err().map(viewmodel::error_text);
    status.send_replace(TraySync {
        running: false,
        failed: message.clone().map(|message| Failure {
            message,
            at: SystemTime::now(),
        }),
    });
    message
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_second_start_while_running_is_refused() {
        let status = watch::Sender::new(TraySync::default());
        assert!(start(&status));
        assert!(!start(&status));
        assert_eq!(finish(&status, &Ok(())), None);
        assert!(!status.borrow().running);
        assert!(start(&status));
    }

    #[test]
    fn a_failure_shows_until_a_later_sync_succeeds() {
        let status = watch::Sender::new(TraySync::default());
        start(&status);
        let message = finish(&status, &Err(bwl_vault::Error::Offline));
        assert!(message.is_some());
        let current = status.borrow().clone();
        let at = current
            .failed
            .as_ref()
            .map(|failure| failure.at)
            .expect("failed");
        assert_eq!(current.failure(None), message.as_deref());
        assert_eq!(
            current.failure(Some(at - Duration::from_secs(60))),
            message.as_deref()
        );
        assert_eq!(current.failure(Some(at + Duration::from_secs(1))), None);
    }
}
