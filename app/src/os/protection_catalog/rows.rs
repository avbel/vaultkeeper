//! The wording of every Linux row: title, what it protects against, how it is used here and the
//! technical name. Strings follow docs/USAGE.md "System protection".

use vk_ipc::ChainDto;
use vk_platform::creds::Backend;

use super::{Group, Level, landlock_abi_label};
use crate::os::self_protection::{NO_LANDLOCK, NOT_REQUESTED};

pub struct RowText {
    pub group: Group,
    pub title: String,
    pub protects: String,
    pub detail: String,
    pub technical: String,
}

/// Chain ids in the order a group lists them.
const ORDER: [&str; 13] = [
    "key-memory",
    "memory-read",
    "secret-files",
    "sandbox",
    "kernel",
    "runtime-dir",
    "wayland",
    "clipboard",
    "lock-sleep",
    "tray",
    "portal",
    "notifications",
    "hotkey",
];

pub fn position(id: &str) -> usize {
    ORDER
        .iter()
        .position(|known| *known == id)
        .unwrap_or(ORDER.len())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxKind {
    Full,
    Partial,
    NotRequested,
    NoLandlock,
    Failed,
}

pub fn sandbox_kind(chain: &ChainDto) -> SandboxKind {
    if chain.active_id.as_deref() == Some("landlock") {
        return if chain.note.is_some() {
            SandboxKind::Partial
        } else {
            SandboxKind::Full
        };
    }
    match skip_why(chain, "landlock") {
        Some(NOT_REQUESTED) => SandboxKind::NotRequested,
        Some(NO_LANDLOCK) => SandboxKind::NoLandlock,
        _ => SandboxKind::Failed,
    }
}

fn skip_why<'a>(chain: &'a ChainDto, link: &str) -> Option<&'a str> {
    chain
        .skipped
        .iter()
        .find(|skipped| skipped.link == link)
        .map(|skipped| skipped.why.as_str())
}

/// The probe's own reason: the first skipped link's, else the note.
pub fn why(chain: &ChainDto) -> String {
    chain
        .skipped
        .first()
        .map(|skipped| skipped.why.clone())
        .or_else(|| chain.note.clone())
        .unwrap_or_default()
}

fn with_why(sentence: &str, why: &str) -> String {
    if why.is_empty() {
        sentence.to_owned()
    } else {
        format!("{sentence} {why}")
    }
}

/// A sentence that ends the reason with a full stop, for "Not in effect: {why}.".
fn stopped(sentence: &str, why: &str) -> String {
    format!("{sentence} {}.", why.trim_end_matches('.'))
}

fn row(group: Group, title: &str, protects: &str, detail: String, technical: &str) -> RowText {
    RowText {
        group,
        title: title.to_owned(),
        protects: protects.to_owned(),
        detail,
        technical: technical.to_owned(),
    }
}

pub fn text(chain: &ChainDto, level: Level) -> RowText {
    let id = chain.active_id.as_deref().unwrap_or("");
    let why = why(chain);
    match chain.id.as_str() {
        "key-memory" => key_memory(id, level, &why),
        "memory-read" => memory_read(level, &why),
        "secret-files" => secret_files(chain, &why),
        "sandbox" => sandbox(chain, &why),
        "kernel" => kernel(id, level, &why),
        "runtime-dir" => runtime_dir(level, &why),
        "wayland" => wayland(level, &why),
        "clipboard" => clipboard(id, level, &why),
        "lock-sleep" => lock_sleep(id, level),
        "tray" => tray(level),
        "portal" => portal(level),
        "notifications" => notifications(level),
        "hotkey" => hotkey(id),
        _ => unknown(chain, level),
    }
}

fn key_memory(id: &str, level: Level, why: &str) -> RowText {
    let (detail, technical) = match (level, id) {
        (Level::Missing | Level::Off, _) => (
            with_why("No protected memory could be obtained.", why),
            "",
        ),
        (_, "memfd-secret") => (
            "Keys live in memory that even the kernel's own tools can't read.".to_owned(),
            "memfd_secret",
        ),
        (_, "keyctl") => (
            "Keys are held by the kernel keyring: safe from swap, but not as isolated as secret memory."
                .to_owned(),
            "keyctl",
        ),
        _ => (
            "Keys are locked in normal memory: kept out of swap only.".to_owned(),
            "mlock",
        ),
    };
    row(
        Group::Memory,
        "Encryption keys in memory",
        "Keeps your vault keys out of reach of other programs, swap and crash dumps while the vault is unlocked.",
        detail,
        technical,
    )
}

fn memory_read(level: Level, why: &str) -> RowText {
    let (detail, technical) = if level == Level::Active {
        (
            "Vaultkeeper is closed to debuggers and memory dumps.".to_owned(),
            "non-dumpable, no tracer",
        )
    } else {
        (stopped("Not in effect:", why), "non-dumpable, no tracer")
    };
    row(
        Group::Memory,
        "Memory reading by other programs",
        "Stops other programs running as you from reading Vaultkeeper's memory or attaching a debugger.",
        detail,
        technical,
    )
}

/// The `systemd-creds` mechanism text the chain reports, if the stacking link applied.
pub fn creds_mechanism(chain: &ChainDto) -> Option<&str> {
    chain
        .stacked
        .iter()
        .map(String::as_str)
        .find(|text| text.starts_with("systemd-creds"))
}

fn secret_files(chain: &ChainDto, why: &str) -> RowText {
    let creds = creds_mechanism(chain);
    let technical = creds.map_or_else(
        || "AES-256-GCM".to_owned(),
        |mechanism| format!("AES-256-GCM + {mechanism}"),
    );
    let detail = match creds {
        Some(mechanism)
            if mechanism == Backend::TpmAndHost.mechanism()
                || mechanism == Backend::Tpm.mechanism() =>
        {
            "Encrypted, and the key is locked to this computer's security chip (TPM).".to_owned()
        }
        Some(mechanism) if mechanism == Backend::Host.mechanism() => {
            "Encrypted, with the key tied to this system installation, not to a security chip. A copy of the whole disk still contains the key."
                .to_owned()
        }
        Some(_) => with_why(
            "Encrypted and tied to this computer, but the key type could not be read.",
            why,
        ),
        None => with_why(
            "Encrypted, but not tied to this computer: systemd-creds is not usable.",
            &creds_why(chain),
        ),
    };
    RowText {
        technical,
        ..row(
            Group::StoredSecrets,
            "Sign-in data on disk",
            "Keeps the saved sign-in tokens unreadable if someone copies your files or your disk.",
            detail,
            "",
        )
    }
}

fn creds_why(chain: &ChainDto) -> String {
    skip_why(chain, super::CREDS_LINK)
        .unwrap_or_default()
        .to_owned()
}

fn sandbox(chain: &ChainDto, why: &str) -> RowText {
    let (detail, technical) = match sandbox_kind(chain) {
        SandboxKind::Full => (
            "On. Vaultkeeper can only reach its own files and the system.".to_owned(),
            "Landlock".to_owned(),
        ),
        SandboxKind::Partial => {
            let abi = landlock_abi_label(chain);
            (
                format!(
                    "On, but this kernel enforces only part of the rules (Landlock ABI {abi})."
                ),
                format!("Landlock (ABI {abi})"),
            )
        }
        SandboxKind::NotRequested => (
            "Off. It is optional for now because it also blocks opening files outside Vaultkeeper's folders."
                .to_owned(),
            "Landlock, not requested".to_owned(),
        ),
        SandboxKind::NoLandlock => (
            "You asked for it, but this kernel has no Landlock.".to_owned(),
            "Landlock unavailable".to_owned(),
        ),
        SandboxKind::Failed => (
            stopped("You asked for it, but it could not be applied:", why),
            "Landlock".to_owned(),
        ),
    };
    RowText {
        technical,
        ..row(
            Group::Isolation,
            "App sandbox",
            "Limits which files and programs Vaultkeeper itself can touch, so a bug in it can't be used to reach your SSH keys or browser profile.",
            detail,
            "",
        )
    }
}

fn kernel(id: &str, level: Level, why: &str) -> RowText {
    let (detail, technical) = match (level, id) {
        (Level::Missing | Level::Off, _) => (
            with_why("This kernel can't identify connecting programs.", why),
            "",
        ),
        (_, "peer-pidfd") => (
            "Programs are identified with an older kernel check (kernel older than 6.13)."
                .to_owned(),
            "SO_PEERPIDFD",
        ),
        _ => (
            "Each connecting program is identified directly by the kernel.".to_owned(),
            "PIDFD_GET_INFO",
        ),
    };
    row(
        Group::Isolation,
        "Who is connecting",
        "Checks which program is on the other end of every connection (browser, command line, SSH), so nothing can pose as Vaultkeeper's own parts.",
        detail,
        technical,
    )
}

fn runtime_dir(level: Level, why: &str) -> RowText {
    let (detail, technical) = if level == Level::Active {
        (
            "Using your session's private runtime folder.".to_owned(),
            "XDG_RUNTIME_DIR",
        )
    } else {
        (with_why("No private runtime folder.", why), "")
    };
    row(
        Group::Isolation,
        "Private folder for connections",
        "Keeps Vaultkeeper's internal connections in a folder only your account can open, erased at logout.",
        detail,
        technical,
    )
}

fn wayland(level: Level, why: &str) -> RowText {
    let (detail, technical) = if level == Level::Active {
        ("Running in a Wayland session.".to_owned(), "Wayland")
    } else {
        (with_why("Not a Wayland session.", why), "")
    };
    row(
        Group::Isolation,
        "Screen and keyboard isolation",
        "Other apps can't record your keystrokes or read Vaultkeeper's windows, which the old X11 display system allowed.",
        detail,
        technical,
    )
}

fn clipboard(id: &str, level: Level, why: &str) -> RowText {
    let (detail, technical) = match (level, id) {
        (Level::Off | Level::Missing, _) => (with_why("Copying is unavailable.", why), ""),
        (_, "ext-data-control") => (
            "Copies are marked as secret, so clipboard managers skip them.".to_owned(),
            "Wayland data-control, secret hint",
        ),
        (_, "portal-clipboard") => (
            "Copies go through the desktop's clipboard permission.".to_owned(),
            "RemoteDesktop + Clipboard portal",
        ),
        _ => (
            "Copies use the normal clipboard: a clipboard history app may record them. They are still cleared on time."
                .to_owned(),
            "plain clipboard",
        ),
    };
    row(
        Group::Isolation,
        "Copied passwords",
        "Keeps copied passwords out of clipboard history and clears them after the time you set.",
        detail,
        technical,
    )
}

fn lock_sleep(id: &str, level: Level) -> RowText {
    let (detail, technical) = match (level, id) {
        (Level::Off | Level::Missing, _) => (
            "No lock or sleep signal reaches Vaultkeeper. The \"Lock after\" timer still works."
                .to_owned(),
            "",
        ),
        (_, "screensaver") => (
            "Vaultkeeper hears the screen lock only, not sleep or shutdown.".to_owned(),
            "ScreenSaver service",
        ),
        _ => (
            "Vaultkeeper hears sleep, shutdown and screen lock.".to_owned(),
            "systemd-logind",
        ),
    };
    row(
        Group::Session,
        "Locking with your computer",
        "Locks the vault when the computer sleeps, shuts down or the screen locks, so it is never left open.",
        detail,
        technical,
    )
}

fn tray(level: Level) -> RowText {
    let (detail, technical) = if level == Level::Active {
        ("Shown in your panel's tray.", "StatusNotifierItem")
    } else {
        (
            "This desktop has no tray. Use the shortcut or the app launcher.",
            "",
        )
    };
    row(
        Group::Desktop,
        "Tray icon",
        "Quick access from the panel.",
        detail.to_owned(),
        technical,
    )
}

fn portal(level: Level) -> RowText {
    let (detail, technical) = if level == Level::Active {
        ("Connected.", "xdg-desktop-portal")
    } else {
        (
            "Not running: links, shortcuts and file dialogs may not work.",
            "",
        )
    };
    row(
        Group::Desktop,
        "Desktop portal",
        "Opens links and file dialogs and registers shortcuts through the desktop.",
        detail.to_owned(),
        technical,
    )
}

fn notifications(level: Level) -> RowText {
    let (detail, technical) = if level == Level::Active {
        ("Shown as desktop notifications.", "Notification daemon")
    } else {
        (
            "No notification service: refusals show only in the window and the log.",
            "",
        )
    };
    row(
        Group::Desktop,
        "Notifications",
        "Tells you when Vaultkeeper refused a request.",
        detail.to_owned(),
        technical,
    )
}

fn hotkey(id: &str) -> RowText {
    let (detail, technical) = if id == "compositor-binding" {
        (
            "Set by you in the compositor config (see Shortcuts above).",
            "compositor binding",
        )
    } else {
        ("Registered with the desktop.", "GlobalShortcuts portal")
    };
    row(
        Group::Desktop,
        "Global shortcuts",
        "Opens Vaultkeeper from any app.",
        detail.to_owned(),
        technical,
    )
}

fn unknown(chain: &ChainDto, level: Level) -> RowText {
    let detail = match (&chain.note, level) {
        (Some(note), _) => note.clone(),
        (None, Level::Active) => "In use.".to_owned(),
        (None, _) => why(chain),
    };
    RowText {
        group: Group::Isolation,
        title: chain.name.clone(),
        protects: String::new(),
        detail,
        technical: chain
            .active
            .iter()
            .chain(&chain.stacked)
            .cloned()
            .collect::<Vec<_>>()
            .join(" + "),
    }
}
