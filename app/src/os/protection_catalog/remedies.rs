//! The "How to turn it on" disclosure of a row: numbered steps, extra notes and the one string
//! the Copy button puts on the clipboard. An Active row has none, and a row without wording here
//! shows nothing rather than a generic hint.

use vk_ipc::ChainDto;

use super::{
    Level,
    rows::{SandboxKind, creds_mechanism, creds_why, sandbox_kind, why},
};
use crate::os::{
    security_gate::Distro,
    tray_way::{session_desktop, tray_way},
};
use vk_platform::creds::{Backend, UNREACHABLE_BY_HAND_WHY, UNREACHABLE_WHY};

#[derive(Debug, Default)]
pub struct Remedy {
    pub title: String,
    pub steps: Vec<String>,
    pub notes: Vec<String>,
    pub copy: String,
}

impl Remedy {
    fn steps(title: &str, steps: &[&str], copy: &str) -> Self {
        Self {
            title: title.to_owned(),
            steps: steps.iter().map(|step| (*step).to_owned()).collect(),
            notes: Vec::new(),
            copy: copy.to_owned(),
        }
    }

    fn notes(title: &str, notes: &[&str]) -> Self {
        Self {
            title: title.to_owned(),
            steps: Vec::new(),
            notes: notes.iter().map(|note| (*note).to_owned()).collect(),
            copy: String::new(),
        }
    }

    fn with_notes(mut self, notes: &[&str]) -> Self {
        self.notes
            .extend(notes.iter().map(|note| (*note).to_owned()));
        self
    }
}

/// The command step 1 of the sandbox remedy copies.
pub const SANDBOX_COMMAND: &str = "mkdir -p ~/.config/environment.d && echo VAULTKEEPER_LANDLOCK=1 > ~/.config/environment.d/vaultkeeper.conf";

pub fn remedy(chain: &ChainDto, level: Level, distro: Distro) -> Remedy {
    if level == Level::Active {
        return Remedy::default();
    }
    let active = chain.active_id.as_deref().unwrap_or("");
    match chain.id.as_str() {
        "sandbox" => sandbox(chain),
        "secret-files" => secret_files(chain),
        "key-memory" => key_memory(chain, distro),
        "kernel" => kernel(distro),
        "memory-read" => Remedy::notes(
            "How to fix it",
            &["Close the debugger or program named above and restart Vaultkeeper."],
        ),
        "wayland" => Remedy {
            title: "How to fix it".to_owned(),
            notes: chain
                .fix
                .as_deref()
                .map(|fix| format!("{}.", capitalised(fix)))
                .into_iter()
                .collect(),
            ..Remedy::default()
        },
        "runtime-dir" => Remedy::notes(
            "How to fix it",
            &[
                "Log in through your normal login screen, or set XDG_RUNTIME_DIR=/run/user/$(id -u) before starting Vaultkeeper.",
            ],
        ),
        "lock-sleep" if active == "screensaver" => Remedy::notes(
            "Nothing to do",
            &["Nothing to do on this desktop; \"Lock after\" covers sleep."],
        ),
        "lock-sleep" => Remedy::steps(
            "How to fix it",
            &[
                "On Sway or Hyprland, make the idle tool lock through the system: loginctl lock-session",
                "See \"Lock on Linux\" in the guide.",
            ],
            "loginctl lock-session",
        ),
        "clipboard" => Remedy::notes(
            "How to fix it",
            &[
                "Use a desktop with secret-aware clipboard support (KDE, Sway, Hyprland), or on GNOME allow the clipboard permission prompt the next time you copy.",
            ],
        ),
        "portal" => Remedy::steps(
            "How to fix it",
            &[
                "Install xdg-desktop-portal and the backend for your desktop (-gnome, -kde, -hyprland or -wlr).",
                "Log out and back in.",
            ],
            "",
        ),
        "tray" => Remedy::notes("How to get a tray icon", &[&tray_sentence(distro)]),
        "notifications" => Remedy::notes(
            "How to fix it",
            &[if distro == Distro::Omarchy {
                "Restart the Omarchy shell, which hosts the notification service."
            } else {
                "Run a notification service (mako or dunst on Sway and Hyprland)."
            }],
        ),
        _ => Remedy::default(),
    }
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn tray_sentence(distro: Distro) -> String {
    let way = tray_way(distro, &session_desktop());
    format!("{}.", capitalised(way))
}

fn sandbox(chain: &ChainDto) -> Remedy {
    match sandbox_kind(chain) {
        SandboxKind::Full => Remedy::default(),
        SandboxKind::NotRequested => Remedy::steps(
            "Turn the sandbox on",
            &[
                "Create the file ~/.config/environment.d/vaultkeeper.conf with one line: VAULTKEEPER_LANDLOCK=1",
                "Log out and back in.",
                "Open this list again: App sandbox should read Active.",
            ],
            SANDBOX_COMMAND,
        )
        .with_notes(&[
            "To try it once first, quit Vaultkeeper and run: VAULTKEEPER_LANDLOCK=1 vaultkeeper",
            "With the sandbox on, attach files from inside ~/.cache or Vaultkeeper's own folders.",
            "On Sway, also add \"export VAULTKEEPER_LANDLOCK=1\" to ~/.profile.",
        ]),
        SandboxKind::Partial => Remedy::notes(
            "Update the kernel",
            &["Update to a newer kernel to get the full sandbox. Nothing else to do: the rules this kernel knows are enforced."],
        ),
        SandboxKind::NoLandlock => Remedy::steps(
            "How to fix it",
            &[
                "Check: cat /sys/kernel/security/lsm (the list should contain \"landlock\")",
                "If it is missing, add lsm=landlock,<the current list> to the kernel command line, or use your distribution's stock kernel.",
                "Restart the computer.",
            ],
            "cat /sys/kernel/security/lsm",
        ),
        SandboxKind::Failed => Remedy {
            title: "How to fix it".to_owned(),
            steps: Vec::new(),
            notes: vec![
                format!(
                    "Nothing to change in the system. Restart Vaultkeeper; if it repeats, send the log. {}",
                    why(chain)
                )
                .trim_end()
                .to_owned(),
            ],
            copy: String::new(),
        },
    }
}

fn secret_files(chain: &ChainDto) -> Remedy {
    let why = creds_why(chain);
    if why == UNREACHABLE_WHY {
        return Remedy::notes(
            "How to fix it",
            &[
                "Vaultkeeper restarts by itself a few minutes after you lock the vault and close its windows; or quit and start it again.",
            ],
        );
    }
    if why == UNREACHABLE_BY_HAND_WHY {
        return Remedy::notes("How to fix it", &["Quit and start Vaultkeeper again."]);
    }
    if creds_mechanism(chain) != Some(Backend::Host.mechanism()) {
        return Remedy::default();
    }
    Remedy::steps(
        "Seal it to a security chip",
        &[
            "Check for a chip: systemd-creds has-tpm2",
            "If it says the firmware has one but it is off, enable \"TPM 2.0\" (also called fTPM or PTT) in the UEFI setup. In a virtual machine, add a virtual TPM.",
            "Restart Vaultkeeper: it looks for the chip only at start. Data already on disk keeps its old key until it is saved again, so sign out and in to re-seal it now.",
        ],
        "systemd-creds has-tpm2",
    )
    .with_notes(&[
        "No chip at all: nothing to do. Your data stays encrypted; full-disk encryption covers what a chip would add.",
    ])
}

fn key_memory(chain: &ChainDto, distro: Distro) -> Remedy {
    if !matches!(chain.active_id.as_deref(), Some("keyctl" | "mlock")) {
        return Remedy::default();
    }
    let mut text = String::from(
        "Secret memory is not available on this kernel. Remove secretmem.enable=0 from the kernel command line, or use a kernel built with CONFIG_SECRETMEM, then restart.",
    );
    if distro == Distro::Omarchy {
        text.push_str(" On Omarchy: edit KERNEL_CMDLINE in /etc/default/limine, then run sudo omarchy-refresh-limine.");
    }
    Remedy::notes("How to fix it", &[&text])
}

fn kernel(distro: Distro) -> Remedy {
    match distro {
        Distro::Omarchy => Remedy::steps(
            "Update the kernel",
            &[
                "Update to kernel 6.13 or newer: boot linux-omarchy, linux or linux-lts with sudo omarchy kernel set linux-omarchy",
            ],
            "sudo omarchy kernel set linux-omarchy",
        ),
        Distro::Ubuntu | Distro::Fedora => Remedy::notes(
            "Update the kernel",
            &["Update to kernel 6.13 or newer: boot the distribution's stock kernel."],
        ),
        Distro::OtherArch | Distro::Other => {
            Remedy::notes("Update the kernel", &["Update to kernel 6.13 or newer."])
        }
    }
}
