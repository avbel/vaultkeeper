//! Side effects the UI needs from the OS, behind small traits. The integration step wires them to
//! `bwl-platform`, `bwl-ssh` and `global-hotkey`; until then the logging stubs below stand in.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bwl_gen::generator::{PassphraseOptions, PasswordOptions};
use zeroize::Zeroizing;

use crate::settings::Settings;

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("{0} is not available")]
    Unavailable(&'static str),
    #[error("cancelled")]
    Cancelled,
    #[error("{0}")]
    Failed(String),
}

pub type HookResult<T> = Result<T, HookError>;

pub trait Clipboard: Send + Sync {
    /// Puts a secret on the clipboard (concealed) and clears it after `clear_after` if it still
    /// holds this value.
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> HookResult<()>;
    /// Clears the clipboard now if it still holds the last value we copied.
    fn clear_if_ours(&self);
}

/// Touch ID, keyed by account so each account has its own Secure Enclave wrap.
pub trait Biometrics: Send + Sync {
    fn is_available(&self) -> bool;
    fn is_enrolled(&self, account_id: &str) -> bool;
    fn enroll(&self, account_id: &str, user_key: &[u8]) -> HookResult<()>;
    /// Shows the Touch ID prompt; blocking, so callers run it off the UI thread.
    fn unlock(&self, account_id: &str, reason: &str) -> HookResult<Zeroizing<Vec<u8>>>;
    fn unenroll(&self, account_id: &str) -> HookResult<()>;
    /// Plain presence check for SSH approvals; blocking.
    fn authenticate(&self, reason: &str) -> HookResult<()>;
}

pub trait Autostart: Send + Sync {
    fn set_enabled(&self, enabled: bool) -> HookResult<()>;
}

/// Registers the Quick Panel accelerator. The integration calls `App::toggle_quick_panel` when it
/// fires and `App::lock` for ⌘⇧L.
pub trait GlobalHotkey: Send + Sync {
    fn register(&self, accelerator: &str) -> HookResult<()>;
}

pub trait UrlOpener: Send + Sync {
    fn open(&self, url: &str) -> HookResult<()>;
}

/// Native file pickers. `None` means the user cancelled.
pub trait FileDialogs: Send + Sync {
    fn save_file(&self, suggested_name: &str) -> Option<PathBuf>;
    fn open_file(&self) -> Option<PathBuf>;
}

pub trait PasswordGenerator: Send + Sync {
    fn password(&self, options: &PasswordOptions) -> HookResult<Zeroizing<String>>;
    fn passphrase(&self, options: &PassphraseOptions) -> HookResult<Zeroizing<String>>;
}

pub trait SettingsStore: Send + Sync {
    fn load(&self) -> Settings;
    fn save(&self, settings: &Settings) -> HookResult<()>;
}

/// macOS activation policy: a Dock icon only while the Manager window is open.
pub trait DockIcon: Send + Sync {
    fn set_visible(&self, visible: bool);
}

pub trait SshAgentControl: Send + Sync {
    fn set_enabled(&self, enabled: bool) -> HookResult<()>;
    fn socket_path(&self) -> String;
}

/// "New SSH key" support: `(private OpenSSH PEM, public key line, SHA256 fingerprint)`.
pub trait SshKeyTool: Send + Sync {
    fn generate(&self) -> HookResult<(Zeroizing<String>, String, String)>;
}

/// Window placement that needs the screen list: the Quick Panel is centred on the cursor's screen
/// with its top at 22% of the screen height. `None` leaves placement to the OS.
pub trait WindowPlacement: Send + Sync {
    fn quick_panel_origin(&self, width: f32, height: f32) -> Option<slint::LogicalPosition>;
}

pub trait Clock: Send + Sync {
    fn unix_now(&self) -> u64;
}

#[derive(Clone)]
pub struct Hooks {
    pub clipboard: Arc<dyn Clipboard>,
    pub biometrics: Arc<dyn Biometrics>,
    pub autostart: Arc<dyn Autostart>,
    pub hotkey: Arc<dyn GlobalHotkey>,
    pub opener: Arc<dyn UrlOpener>,
    pub files: Arc<dyn FileDialogs>,
    pub generator: Arc<dyn PasswordGenerator>,
    pub settings: Arc<dyn SettingsStore>,
    pub dock: Arc<dyn DockIcon>,
    pub ssh_agent: Arc<dyn SshAgentControl>,
    pub ssh_keys: Arc<dyn SshKeyTool>,
    pub placement: Arc<dyn WindowPlacement>,
    pub clock: Arc<dyn Clock>,
}

impl Hooks {
    /// Logging stubs for every side effect; `generator` and `ssh_keys` produce fake values.
    #[must_use]
    pub fn logging() -> Self {
        Self {
            clipboard: Arc::new(LogClipboard),
            biometrics: Arc::new(LogBiometrics::default()),
            autostart: Arc::new(LogAutostart),
            hotkey: Arc::new(LogHotkey),
            opener: Arc::new(LogOpener),
            files: Arc::new(LogFileDialogs),
            generator: Arc::new(crate::mock::MockGenerator::default()),
            settings: Arc::new(MemorySettings::default()),
            dock: Arc::new(LogDock),
            ssh_agent: Arc::new(LogSshAgent),
            ssh_keys: Arc::new(crate::mock::MockSshKeys),
            placement: Arc::new(OsPlacement),
            clock: Arc::new(SystemClock),
        }
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

struct OsPlacement;

impl WindowPlacement for OsPlacement {
    fn quick_panel_origin(&self, _width: f32, _height: f32) -> Option<slint::LogicalPosition> {
        None
    }
}

struct LogClipboard;

impl Clipboard for LogClipboard {
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> HookResult<()> {
        tracing::info!(
            chars = text.chars().count(),
            ?clear_after,
            "clipboard copy (stub)"
        );
        Ok(())
    }

    fn clear_if_ours(&self) {
        tracing::info!("clipboard clear_if_ours (stub)");
    }
}

/// Keeps enrolled user keys in memory so the mock's Touch ID flows work end to end.
#[derive(Default)]
struct LogBiometrics {
    enrolled: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl Biometrics for LogBiometrics {
    fn is_available(&self) -> bool {
        true
    }

    fn is_enrolled(&self, account_id: &str) -> bool {
        self.enrolled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(account_id)
    }

    fn enroll(&self, account_id: &str, user_key: &[u8]) -> HookResult<()> {
        tracing::info!(account_id, "Touch ID enroll (stub)");
        self.enrolled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(account_id.to_owned(), Zeroizing::new(user_key.to_vec()));
        Ok(())
    }

    fn unlock(&self, account_id: &str, reason: &str) -> HookResult<Zeroizing<Vec<u8>>> {
        tracing::info!(account_id, reason, "Touch ID unlock (stub)");
        self.enrolled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(account_id)
            .cloned()
            .ok_or(HookError::Unavailable("Touch ID enrolment"))
    }

    fn unenroll(&self, account_id: &str) -> HookResult<()> {
        tracing::info!(account_id, "Touch ID unenroll (stub)");
        self.enrolled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(account_id);
        Ok(())
    }

    fn authenticate(&self, reason: &str) -> HookResult<()> {
        tracing::info!(reason, "Touch ID authenticate (stub)");
        Ok(())
    }
}

struct LogAutostart;

impl Autostart for LogAutostart {
    fn set_enabled(&self, enabled: bool) -> HookResult<()> {
        tracing::info!(enabled, "autostart (stub)");
        Ok(())
    }
}

struct LogHotkey;

impl GlobalHotkey for LogHotkey {
    fn register(&self, accelerator: &str) -> HookResult<()> {
        tracing::info!(accelerator, "global hotkey register (stub)");
        Ok(())
    }
}

struct LogOpener;

impl UrlOpener for LogOpener {
    fn open(&self, url: &str) -> HookResult<()> {
        tracing::info!(url, "open URL (stub)");
        Ok(())
    }
}

struct LogFileDialogs;

impl FileDialogs for LogFileDialogs {
    fn save_file(&self, suggested_name: &str) -> Option<PathBuf> {
        tracing::info!(suggested_name, "save dialog (stub): cancelled");
        None
    }

    fn open_file(&self) -> Option<PathBuf> {
        tracing::info!("open dialog (stub): cancelled");
        None
    }
}

#[derive(Default)]
struct MemorySettings {
    saved: Mutex<Option<Settings>>,
}

impl SettingsStore for MemorySettings {
    fn load(&self) -> Settings {
        self.saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_default()
    }

    fn save(&self, settings: &Settings) -> HookResult<()> {
        tracing::info!("settings saved (stub, in memory)");
        *self.saved.lock().unwrap_or_else(PoisonError::into_inner) = Some(settings.clone());
        Ok(())
    }
}

struct LogDock;

impl DockIcon for LogDock {
    fn set_visible(&self, visible: bool) {
        tracing::debug!(visible, "dock icon (stub)");
    }
}

struct LogSshAgent;

impl SshAgentControl for LogSshAgent {
    fn set_enabled(&self, enabled: bool) -> HookResult<()> {
        tracing::info!(enabled, "SSH agent (stub)");
        Ok(())
    }

    fn socket_path(&self) -> String {
        "~/Library/Application Support/bw-lite/ssh-agent.sock".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_biometrics_round_trips_enrolled_key() {
        let bio = LogBiometrics::default();
        assert!(!bio.is_enrolled("a"));
        assert!(matches!(
            bio.unlock("a", "r"),
            Err(HookError::Unavailable(_))
        ));
        bio.enroll("a", &[1, 2, 3]).expect("enroll");
        assert!(bio.is_enrolled("a"));
        assert_eq!(bio.unlock("a", "r").expect("unlock").as_slice(), &[1, 2, 3]);
        bio.unenroll("a").expect("unenroll");
        assert!(!bio.is_enrolled("a"));
    }

    #[test]
    fn memory_settings_returns_last_saved() {
        let store = MemorySettings::default();
        assert_eq!(store.load(), Settings::default());
        let changed = Settings {
            start_at_login: true,
            ..Settings::default()
        };
        store.save(&changed).expect("save");
        assert_eq!(store.load(), changed);
    }

    #[test]
    fn system_clock_is_after_2025() {
        assert!(SystemClock.unix_now() > 1_735_689_600);
    }
}
