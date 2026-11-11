//! Side effects the UI needs from the OS, behind small traits. [`crate::os`] wires them to
//! `vk-platform`, `vk-ssh`, AppKit and the daemon; `--mock` and the UI tests use the logging
//! stubs below.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use vk_gen::generator::{PassphraseOptions, PasswordOptions};
pub use vk_ipc::SiteIcon;
use zeroize::Zeroizing;

use vk_vault::VaultService;

use crate::{
    autotype::Stroke,
    daemon::browser::{manifests::ManifestBrowser, pairing::PairingEntry},
    mock::MockVault,
    settings::Settings,
};

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

/// Touch ID, keyed by account so each account has its own Secure Enclave wrap. The user key never
/// passes through here: whoever holds the vault (the daemon) wraps and unwraps it.
pub trait Biometrics: Send + Sync {
    fn is_available(&self) -> bool;
    fn is_enrolled(&self, account_id: &str) -> bool;
    /// Wraps the unlocked vault's key for the active `account_id`; blocking.
    fn enroll(&self, account_id: &str) -> HookResult<()>;
    /// Shows the Touch ID prompt and unlocks the vault for `account_id`; blocking, so callers run
    /// it off the UI thread.
    fn unlock(&self, account_id: &str) -> HookResult<()>;
    fn unenroll(&self, account_id: &str) -> HookResult<()>;
}

pub trait Autostart: Send + Sync {
    fn set_enabled(&self, enabled: bool) -> HookResult<()>;
}

/// Registers the Quick Panel accelerator. The integration calls `App::toggle_quick_panel` when it
/// fires and `App::lock` for ⌘⇧L.
pub trait GlobalHotkey: Send + Sync {
    fn register(&self, accelerator: &str) -> HookResult<()>;
    /// A Settings shortcut recorder started (`true`) or stopped waiting for a key; the daemon's
    /// hotkeys are off meanwhile, so a press of one reaches the recorder.
    fn pause(&self, recording: bool) {
        let _ = recording;
    }
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
    /// True once after an unreadable settings file was reset to defaults (and kept aside), so the
    /// user is told about it a single time.
    fn take_reset_notice(&self) -> bool {
        false
    }
}

/// macOS activation policy: a Dock icon only while the Manager window is open.
pub trait DockIcon: Send + Sync {
    fn set_visible(&self, visible: bool);
    /// Brings the app to the front, so a window shown for a hotkey or tray click gets the keys.
    fn activate(&self) {}
    /// The last window closed: give up the front, so a windowless vaultkeeper is never the active
    /// app (the next Quick Panel hotkey would find nothing to type into).
    fn hide(&self) {}
}

pub trait SshAgentControl: Send + Sync {
    fn set_enabled(&self, enabled: bool) -> HookResult<()>;
    fn socket_path(&self) -> String;
}

/// Browser integration state that lives outside the settings file: which browsers are installed
/// and the pairings in the daemon's `browsers.json`.
pub trait BrowserPairings: Send + Sync {
    fn installed(&self) -> Vec<ManifestBrowser>;
    fn paired(&self) -> Vec<PairingEntry>;
    /// Removes the pairing with `public_key` (base64) and tells the daemon to drop its sessions.
    fn remove(&self, public_key: &str) -> HookResult<()>;
}

/// "New SSH key" support: `(private OpenSSH PEM, public key line, SHA256 fingerprint)`.
pub trait SshKeyTool: Send + Sync {
    fn generate(&self) -> HookResult<(Zeroizing<String>, String, String)>;
    /// Converts a pasted private key (OpenSSH, PKCS#8, RSA or EC PEM) to the stored OpenSSH form
    /// with its public key and fingerprint. `None` keeps the text as typed.
    fn import(&self, private_key: &str) -> HookResult<Option<(Zeroizing<String>, String, String)>> {
        let _ = private_key;
        Ok(None)
    }
}

/// Window placement that needs the screen list: the Quick Panel is centred on the cursor's screen
/// with its top at 22% of the screen height. `None` leaves placement to the OS.
pub trait WindowPlacement: Send + Sync {
    fn quick_panel_origin(&self, width: f32, height: f32) -> Option<slint::LogicalPosition>;
}

pub trait Clock: Send + Sync {
    fn unix_now(&self) -> u64;
}

/// The daemon reads it and sends it with the Quick Panel commands, so one type serves both sides.
pub use vk_ipc::TypingTarget;

/// Runs on the UI thread once typing finished or stopped.
pub type AutoTypeDone = Box<dyn FnOnce(HookResult<()>)>;

/// Synthesized keystrokes into another app (Quick Panel ⌘⇧↩).
pub trait AutoType: Send + Sync {
    /// The frontmost app, `None` when it is vaultkeeper itself or unknown. Only `--mock` asks: the
    /// UI process activates itself before it sees a command, so the daemon reads the target
    /// there and sends it along.
    fn frontmost(&self) -> Option<TypingTarget>;
    /// Whether macOS lets this process post keystrokes (Accessibility). With `prompt`, macOS
    /// shows its own permission dialog when it does not.
    fn is_trusted(&self, prompt: bool) -> bool;
    /// Brings `target` back to the front, waits for it and types `strokes` without blocking the
    /// UI thread. Stops when `target` does not come forward or another app takes the front.
    fn start(&self, target: TypingTarget, strokes: Vec<Stroke>, done: AutoTypeDone);
    /// Stops typing that is still running (the vault locked); `done` reports it as cancelled.
    fn cancel(&self) {}
    /// The Quick Panel was dismissed without typing: bring `target` back to the front, like
    /// Spotlight does, unless the user already moved on to another app.
    fn give_focus_back(&self, target: &TypingTarget) {
        let _ = target;
    }
}

pub type IconLookup = std::pin::Pin<Box<dyn std::future::Future<Output = SiteIcon> + Send>>;

/// Website icons by host. The UI process asks the daemon, which fetches and caches them.
pub trait SiteIconSource: Send + Sync {
    fn fetch(&self, host: &str) -> IconLookup;
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
    pub browsers: Arc<dyn BrowserPairings>,
    pub ssh_keys: Arc<dyn SshKeyTool>,
    pub placement: Arc<dyn WindowPlacement>,
    pub clock: Arc<dyn Clock>,
    pub autotype: Arc<dyn AutoType>,
    pub site_icons: Arc<dyn SiteIconSource>,
}

impl Hooks {
    /// Logging stubs for every side effect; `generator` and `ssh_keys` produce fake values.
    /// Touch ID enrols but never unlocks: there is no vault to unlock.
    #[must_use]
    pub fn logging() -> Self {
        Self::with_biometrics(Arc::new(LogBiometrics::default()))
    }

    /// [`Hooks::logging`] whose Touch ID works against `vault` like the daemon's does: enrol reads
    /// the vault's user key, unlock hands it back. `enrolled` accounts start enrolled.
    #[must_use]
    pub fn mock(vault: &Arc<MockVault>, enrolled: &[&str]) -> Self {
        let keys = enrolled
            .iter()
            .map(|&account| (account.to_owned(), crate::mock::mock_user_key(account)))
            .collect();
        Self::with_biometrics(Arc::new(LogBiometrics {
            enrolled: Mutex::new(keys),
            vault: Some(Arc::clone(vault)),
        }))
    }

    fn with_biometrics(biometrics: Arc<dyn Biometrics>) -> Self {
        Self {
            clipboard: Arc::new(LogClipboard),
            biometrics,
            autostart: Arc::new(LogAutostart),
            hotkey: Arc::new(LogHotkey),
            opener: Arc::new(LogOpener),
            files: Arc::new(LogFileDialogs),
            generator: Arc::new(crate::mock::MockGenerator::default()),
            settings: Arc::new(MemorySettings::default()),
            dock: Arc::new(LogDock),
            ssh_agent: Arc::new(LogSshAgent),
            browsers: Arc::new(LogBrowserPairings::default()),
            ssh_keys: Arc::new(crate::mock::MockSshKeys),
            placement: Arc::new(OsPlacement),
            clock: Arc::new(SystemClock),
            autotype: Arc::new(LogAutoType),
            site_icons: Arc::new(NoSiteIcons),
        }
    }
}

/// `--mock` and the UI tests stay offline: every host has no icon.
pub struct NoSiteIcons;

impl SiteIconSource for NoSiteIcons {
    fn fetch(&self, _host: &str) -> IconLookup {
        Box::pin(async { SiteIcon::Missing })
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
    vault: Option<Arc<MockVault>>,
}

impl LogBiometrics {
    fn keys(&self) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<Vec<u8>>>> {
        self.enrolled.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn vault_error(error: &vk_vault::Error) -> HookError {
    HookError::Failed(crate::viewmodel::error_text(error))
}

impl Biometrics for LogBiometrics {
    fn is_available(&self) -> bool {
        true
    }

    fn is_enrolled(&self, account_id: &str) -> bool {
        self.keys().contains_key(account_id)
    }

    fn enroll(&self, account_id: &str) -> HookResult<()> {
        tracing::info!(account_id, "Touch ID enroll (stub)");
        let key = match &self.vault {
            Some(vault) => vault.user_key().map_err(|error| vault_error(&error))?,
            None => Zeroizing::new(Vec::new()),
        };
        self.keys().insert(account_id.to_owned(), key);
        Ok(())
    }

    fn unlock(&self, account_id: &str) -> HookResult<()> {
        tracing::info!(account_id, "Touch ID unlock (stub)");
        let key = self
            .keys()
            .get(account_id)
            .cloned()
            .ok_or(HookError::Unavailable("Touch ID enrolment"))?;
        let vault = self
            .vault
            .as_ref()
            .ok_or(HookError::Unavailable("Touch ID"))?;
        vault
            .unlock_with_user_key(key)
            .map_err(|error| vault_error(&error))
    }

    fn unenroll(&self, account_id: &str) -> HookResult<()> {
        tracing::info!(account_id, "Touch ID unenroll (stub)");
        self.keys().remove(account_id);
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

/// Two fake pairings so the Settings section can be tried in `--mock` and in UI tests.
struct LogBrowserPairings {
    paired: Mutex<Vec<PairingEntry>>,
}

impl Default for LogBrowserPairings {
    fn default() -> Self {
        let entry = |browser, caller: &str, fingerprint: &str, added| PairingEntry {
            public_key: fingerprint.to_owned(),
            browser,
            caller: caller.to_owned(),
            added,
            fingerprint: fingerprint.to_owned(),
        };
        Self {
            paired: Mutex::new(vec![
                entry(
                    vk_ipc::browser::protocol::KnownBrowser::Firefox,
                    "browser-extension@vaultkeeper",
                    "A1B2-C3D4-E5F6-0718",
                    1,
                ),
                entry(
                    vk_ipc::browser::protocol::KnownBrowser::Chrome,
                    "chrome-extension://stub/",
                    "1F2E-3D4C-5B6A-7089",
                    2,
                ),
            ]),
        }
    }
}

impl BrowserPairings for LogBrowserPairings {
    fn installed(&self) -> Vec<ManifestBrowser> {
        vec![ManifestBrowser::Chrome, ManifestBrowser::Firefox]
    }

    fn paired(&self) -> Vec<PairingEntry> {
        self.paired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn remove(&self, public_key: &str) -> HookResult<()> {
        tracing::info!(public_key, "browser pairing remove (stub)");
        self.paired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|entry| entry.public_key != public_key);
        Ok(())
    }
}

struct LogSshAgent;

impl SshAgentControl for LogSshAgent {
    fn set_enabled(&self, enabled: bool) -> HookResult<()> {
        tracing::info!(enabled, "SSH agent (stub)");
        Ok(())
    }

    fn socket_path(&self) -> String {
        "~/Library/Application Support/vaultkeeper/ssh-agent.sock".to_owned()
    }
}

struct LogAutoType;

impl AutoType for LogAutoType {
    fn frontmost(&self) -> Option<TypingTarget> {
        None
    }

    fn is_trusted(&self, prompt: bool) -> bool {
        tracing::info!(prompt, "accessibility check (stub): trusted");
        true
    }

    fn start(&self, target: TypingTarget, strokes: Vec<Stroke>, done: AutoTypeDone) {
        tracing::info!(
            app = target.name,
            strokes = strokes.len(),
            "auto-type (stub)"
        );
        done(Ok(()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_biometrics_without_a_vault_enrols_but_cannot_unlock() {
        let bio = LogBiometrics::default();
        assert!(!bio.is_enrolled("a"));
        assert!(matches!(bio.unlock("a"), Err(HookError::Unavailable(_))));
        bio.enroll("a").expect("enroll");
        assert!(bio.is_enrolled("a"));
        assert!(matches!(bio.unlock("a"), Err(HookError::Unavailable(_))));
        bio.unenroll("a").expect("unenroll");
        assert!(!bio.is_enrolled("a"));
    }

    #[test]
    fn mock_biometrics_unlock_the_vault_with_the_key_read_at_enrolment() {
        let vault = Arc::new(MockVault::new(&crate::mock::MockConfig {
            latency: Duration::ZERO,
            ..crate::mock::MockConfig::default()
        }));
        let hooks = Hooks::mock(&vault, &[]);
        let account = vault
            .accounts()
            .into_iter()
            .find(|account| account.active)
            .expect("active account");
        assert!(
            matches!(
                hooks.biometrics.enroll(&account.id),
                Err(HookError::Failed(_))
            ),
            "a locked vault has no key to enrol"
        );
        assert!(!hooks.biometrics.is_enrolled(&account.id));
        vault
            .unlock_with_user_key(crate::mock::mock_user_key(&account.id))
            .expect("unlock");
        hooks.biometrics.enroll(&account.id).expect("enroll");
        vault.lock();
        hooks
            .biometrics
            .unlock(&account.id)
            .expect("Touch ID unlock");
        assert!(matches!(
            vault.state(),
            vk_vault::model::SessionState::Unlocked { .. }
        ));
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
