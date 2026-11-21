//! The real side effects behind [`crate::hooks`] for the `--ui` process: vk-platform, vk-ssh,
//! vk-gen, AppKit and rfd. Settings and SSH agent changes reach the daemon as IPC notices.

pub mod appkit;
pub mod autotype;
mod biometrics;
pub mod browser;
mod clipboard;
pub mod console;
#[cfg(any(target_os = "linux", test))]
pub mod desktop_entry;
pub mod detached;
pub mod early_log;
pub mod fs;
pub mod layout;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod log_file;
mod misc;
pub mod security_gate;
mod security_key;
pub mod security_requirements;
pub mod settings_file;
pub mod startup_check;
pub mod taskbar;
pub mod ui_window;
pub mod windows_shell;

use std::{path::Path, sync::Arc};

use vk_ipc::{RemoteVault, UiNotice};

pub use biometrics::{
    DaemonBiometrics, DaemonTouchId, EnrolmentFiles, INVALIDATED as TOUCH_ID_INVALIDATED,
    LABEL as BIOMETRIC_LABEL, TouchId,
};
pub use clipboard::{ClipboardKeeper, DaemonClipboard, Keeper, NoClipboard};
pub use misc::{
    AgentSocket, BrowserOpener, FilePanels, Generator, HotkeyBinding, LaunchAgent, SshKeys,
    open_in_browser, web_url,
};
pub use settings_file::SettingsFile;

use crate::hooks::{
    GeneratedDto, GeneratedPasswords, HookError, HookFuture, Hooks, IconLookup, SecurityReportDto,
    SecurityStatus, SiteIcon, SiteIconSource, SystemClock,
};
use zeroize::Zeroizing;

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
            dock: {
                #[cfg(target_os = "macos")]
                {
                    Arc::new(appkit::AppKitDock)
                }
                #[cfg(windows)]
                {
                    Arc::new(windows_shell::WindowsDock)
                }
                #[cfg(target_os = "linux")]
                {
                    Arc::new(linux::shell::LinuxDock)
                }
            },
            browsers: Arc::new(browser::BrowserFiles {
                app_support: crate::daemon::browser::manifests::root(data_dir),
                store: data_dir.join(layout::BROWSER_PAIRINGS_FILE),
                notify: Arc::clone(notify),
            }),
            ssh_agent: Arc::new(AgentSocket {
                endpoint: layout::ssh_endpoint(data_dir),
            }),
            ssh_keys: Arc::new(SshKeys),
            placement: {
                #[cfg(target_os = "macos")]
                {
                    Arc::new(appkit::CursorScreen)
                }
                #[cfg(windows)]
                {
                    Arc::new(windows_shell::WindowsPlacement)
                }
                #[cfg(target_os = "linux")]
                {
                    Arc::new(linux::shell::CompositorPlacement)
                }
            },
            clock: Arc::new(SystemClock),
            autotype: Arc::new(autotype::SystemAutoType),
            site_icons: Arc::new(DaemonSiteIcons(Arc::clone(daemon))),
            generated: Arc::new(DaemonGenerated(Arc::clone(daemon))),
            security: Arc::new(DaemonSecurity(Arc::clone(daemon))),
            security_keys: Arc::new(security_key::UsbSecurityKeys),
        }
    }
}

struct DaemonGenerated(Arc<RemoteVault>);

fn failed(error: &vk_vault::Error) -> HookError {
    HookError::Failed(error.to_string())
}

impl GeneratedPasswords for DaemonGenerated {
    fn list(&self) -> HookFuture<Vec<GeneratedDto>> {
        let daemon = Arc::clone(&self.0);
        Box::pin(async move { daemon.generated_passwords().await.map_err(|e| failed(&e)) })
    }

    fn reveal(&self, id: u64) -> HookFuture<Zeroizing<String>> {
        let daemon = Arc::clone(&self.0);
        Box::pin(async move { daemon.reveal_generated(id).await.map_err(|e| failed(&e)) })
    }

    fn save(&self, id: u64) -> HookFuture<()> {
        let daemon = Arc::clone(&self.0);
        Box::pin(async move {
            daemon
                .save_generated(id)
                .await
                .map(|_| ())
                .map_err(|e| failed(&e))
        })
    }

    fn forget(&self, id: u64) -> HookFuture<()> {
        let daemon = Arc::clone(&self.0);
        Box::pin(async move { daemon.forget_generated(id).await.map_err(|e| failed(&e)) })
    }
}

struct DaemonSecurity(Arc<RemoteVault>);

impl SecurityStatus for DaemonSecurity {
    fn report(&self) -> HookFuture<SecurityReportDto> {
        let daemon = Arc::clone(&self.0);
        Box::pin(async move { daemon.security_status().await.map_err(|e| failed(&e)) })
    }
}

struct DaemonSiteIcons(Arc<RemoteVault>);

impl SiteIconSource for DaemonSiteIcons {
    fn fetch(&self, host: &str) -> IconLookup {
        let daemon = Arc::clone(&self.0);
        let host = host.to_owned();
        Box::pin(async move {
            daemon
                .site_icon(&host)
                .await
                .inspect_err(|error| tracing::debug!(%error, "no site icon from the daemon"))
                .unwrap_or(SiteIcon::Unavailable)
        })
    }
}
