//! The small hooks: autostart, generator, SSH key tool, URL opener, file panels, the hotkey and SSH
//! agent controls (both owned by the daemon; the UI only validates and saves the setting).

use std::{path::PathBuf, process::Command, str::FromStr};

use bwl_gen::generator::{
    PassphraseOptions, PasswordOptions, generate_passphrase, generate_password,
};
use bwl_ipc::UiNotice;
use zeroize::Zeroizing;

use super::Notifier;
use crate::hooks::{
    Autostart, FileDialogs, GlobalHotkey, HookError, HookResult, PasswordGenerator,
    SshAgentControl, SshKeyTool, UrlOpener,
};

pub struct LaunchAgent;

impl Autostart for LaunchAgent {
    fn set_enabled(&self, enabled: bool) -> HookResult<()> {
        bwl_platform::autostart::set_enabled(enabled)
            .map_err(|error| HookError::Failed(error.to_string()))
    }
}

pub struct Generator;

impl PasswordGenerator for Generator {
    fn password(&self, options: &PasswordOptions) -> HookResult<Zeroizing<String>> {
        generate_password(options).map_err(|error| HookError::Failed(error.to_string()))
    }

    fn passphrase(&self, options: &PassphraseOptions) -> HookResult<Zeroizing<String>> {
        generate_passphrase(options).map_err(|error| HookError::Failed(error.to_string()))
    }
}

pub struct SshKeys;

impl SshKeyTool for SshKeys {
    fn generate(&self) -> HookResult<(Zeroizing<String>, String, String)> {
        bwl_ssh::generate_ed25519().map_err(|error| HookError::Failed(error.to_string()))
    }

    fn import(&self, private_key: &str) -> HookResult<Option<(Zeroizing<String>, String, String)>> {
        bwl_ssh::import_key(private_key, None)
            .map(Some)
            .map_err(|error| HookError::Failed(format!("Not a usable private key: {error}")))
    }
}

/// Opens web links in the default browser; any other scheme (`file:`, custom app handlers) is
/// refused, since URIs come from vault items that other people may have shared.
pub struct BrowserOpener;

pub fn web_url(text: &str) -> HookResult<url::Url> {
    let url = url::Url::parse(text.trim())
        .map_err(|_| HookError::Failed(format!("Not a web address: {text}")))?;
    if matches!(url.scheme(), "http" | "https") && url.host().is_some() {
        Ok(url)
    } else {
        Err(HookError::Failed(format!(
            "Only http and https links open: {}",
            url.scheme()
        )))
    }
}

impl UrlOpener for BrowserOpener {
    fn open(&self, url: &str) -> HookResult<()> {
        let url = web_url(url)?;
        let mut child = Command::new("/usr/bin/open")
            .arg(url.as_str())
            .spawn()
            .map_err(|error| HookError::Failed(format!("Cannot open the link: {error}")))?;
        // Reaped off the UI thread; `open` returns as soon as it handed the URL over.
        std::thread::spawn(move || {
            if let Err(error) = child.wait() {
                tracing::debug!(%error, "open(1) wait failed");
            }
        });
        Ok(())
    }
}

/// Native panels (rfd); they run modally on the main thread, where the UI calls them.
/// Native open/save panels. They run modally on the main thread, so the daemon is told while one
/// is open: its hang watchdog must not kill a UI the user is busy with.
pub struct FilePanels {
    pub notify: Notifier,
}

impl FilePanels {
    fn modal<T>(&self, show: impl FnOnce() -> T) -> T {
        (self.notify)(UiNotice::Modal(true));
        let picked = show();
        (self.notify)(UiNotice::Modal(false));
        picked
    }
}

impl FileDialogs for FilePanels {
    fn save_file(&self, suggested_name: &str) -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            self.modal(|| {
                rfd::FileDialog::new()
                    .set_file_name(suggested_name)
                    .save_file()
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = suggested_name;
            None
        }
    }

    fn open_file(&self) -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            self.modal(|| rfd::FileDialog::new().pick_file())
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }
}

/// The daemon registers the shortcut; here it is only checked, before the setting is saved.
pub struct HotkeyBinding {
    pub notify: Notifier,
}

impl GlobalHotkey for HotkeyBinding {
    fn register(&self, accelerator: &str) -> HookResult<()> {
        global_hotkey::hotkey::HotKey::from_str(accelerator)
            .map(drop)
            .map_err(|error| HookError::Failed(format!("Not a shortcut: {error}")))
    }

    fn pause(&self, recording: bool) {
        (self.notify)(UiNotice::ShortcutRecording(recording));
    }
}

/// The daemon starts and stops the agent when it re-reads the saved setting.
pub struct AgentSocket {
    pub path: PathBuf,
}

impl SshAgentControl for AgentSocket {
    fn set_enabled(&self, _enabled: bool) -> HookResult<()> {
        Ok(())
    }

    fn socket_path(&self) -> String {
        self.path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_web_links_open() {
        assert_eq!(
            web_url(" https://github.com/login ")
                .expect("https")
                .as_str(),
            "https://github.com/login"
        );
        assert!(web_url("http://vault.lan:8080/").is_ok());
        for refused in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ssh://host",
            "x-apple.systempreferences:com.apple.preference",
            "github.com",
            "",
        ] {
            assert!(web_url(refused).is_err(), "{refused}");
        }
    }

    fn binding() -> (
        HotkeyBinding,
        std::sync::Arc<std::sync::Mutex<Vec<UiNotice>>>,
    ) {
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&sent);
        let notify: Notifier = std::sync::Arc::new(move |notice| {
            log.lock().expect("log").push(notice);
        });
        (HotkeyBinding { notify }, sent)
    }

    #[test]
    fn hotkeys_are_validated_with_the_daemon_parser() {
        let (binding, sent) = binding();
        assert!(binding.register("Cmd+Shift+Space").is_ok());
        assert!(binding.register("cmd+alt+k").is_ok());
        assert!(binding.register("Cmd+Nope").is_err());
        assert!(binding.register("").is_err());
        assert!(
            sent.lock().expect("log").is_empty(),
            "checking tells the daemon nothing"
        );
    }

    #[test]
    fn a_recording_pause_is_sent_to_the_daemon() {
        let (binding, sent) = binding();
        binding.pause(true);
        binding.pause(false);
        assert_eq!(
            *sent.lock().expect("log"),
            [
                UiNotice::ShortcutRecording(true),
                UiNotice::ShortcutRecording(false)
            ]
        );
    }

    #[test]
    fn generated_keys_import_back_to_the_same_fingerprint() {
        let (private, public, fingerprint) = SshKeys.generate().expect("generate");
        assert!(public.starts_with("ssh-ed25519 "));
        assert!(fingerprint.starts_with("SHA256:"));
        let (_, again_public, again_fingerprint) = SshKeys
            .import(&private)
            .expect("import")
            .expect("converted");
        assert_eq!((again_public, again_fingerprint), (public, fingerprint));
        assert!(SshKeys.import("not a key").is_err());
    }

    #[test]
    fn the_generator_follows_the_options() {
        let password = Generator
            .password(&PasswordOptions::default())
            .expect("password");
        assert_eq!(
            password.chars().count(),
            14,
            "the documented default length"
        );
        assert!(
            Generator
                .password(&PasswordOptions {
                    length: 2,
                    ..PasswordOptions::default()
                })
                .is_err()
        );
    }
}
