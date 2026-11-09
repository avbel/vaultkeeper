//! The real side effects behind [`crate::hooks`] for the `--ui` process: bwl-platform, bwl-ssh,
//! bwl-gen, AppKit and rfd. Settings and SSH agent changes reach the daemon as IPC notices.

pub mod appkit;
pub mod autotype;
mod biometrics;
mod clipboard;
pub mod fs;
pub mod layout;
pub mod log_file;
mod misc;
pub mod settings_file;

use std::{path::Path, sync::Arc};

use bwl_ipc::{RemoteVault, UiNotice};

pub use biometrics::{
    DaemonBiometrics, DaemonTouchId, EnrolmentFiles, INVALIDATED as TOUCH_ID_INVALIDATED, TouchId,
};
pub use clipboard::{ClipboardKeeper, DaemonClipboard, Keeper, NoClipboard};
pub use misc::{
    AgentSocket, BrowserOpener, FilePanels, Generator, HotkeyBinding, LaunchAgent, SshKeys, web_url,
};
pub use settings_file::SettingsFile;

use crate::hooks::{Hooks, SystemClock};

/// Sends a notice to the daemon; failures are only logged (the daemon re-reads on its own start).
pub type Notifier = Arc<dyn Fn(UiNotice) + Send + Sync>;

impl Hooks {
    /// Production hooks for the UI process. `notify` and Touch ID reach the daemon.
    #[must_use]
    pub fn system(data_dir: &Path, notify: &Notifier, daemon: &Arc<RemoteVault>) -> Self {
        let settings_notify = Arc::clone(notify);
        Self {
            clipboard: Arc::new(DaemonClipboard::new(Arc::clone(daemon))),
            biometrics: Arc::new(DaemonTouchId::new(data_dir.to_owned(), Arc::clone(daemon))),
            autostart: Arc::new(LaunchAgent),
            hotkey: Arc::new(HotkeyBinding {
                notify: Arc::clone(notify),
            }),
            opener: Arc::new(BrowserOpener),
            files: Arc::new(FilePanels {
                notify: Arc::clone(notify),
            }),
            generator: Arc::new(Generator),
            settings: Arc::new(SettingsFile::with_after_save(
                data_dir.join(layout::SETTINGS_FILE),
                Arc::new(move || settings_notify(UiNotice::SettingsChanged)),
            )),
            dock: Arc::new(appkit::AppKitDock),
            ssh_agent: Arc::new(AgentSocket {
                path: data_dir.join(layout::SSH_SOCKET),
            }),
            ssh_keys: Arc::new(SshKeys),
            placement: Arc::new(appkit::CursorScreen),
            clock: Arc::new(SystemClock),
            autotype: Arc::new(autotype::SystemAutoType),
        }
    }
}
