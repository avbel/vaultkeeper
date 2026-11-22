//! The startup security baseline (linux-plan.md 1c, linux-ideas.md §9): the chains of
//! `vk_platform::security` built from probe facts, and the decision whether this start may go on.
//!
//! Only chains whose mechanism is active today are registered. Anti memory read (C3) and the
//! self-sandbox (C6) are applied by the daemon after its instance lock, later than the startup
//! gate, so their rows come from [`super::self_protection`] and show in the daemon's report
//! (Settings) only: a `security status` process cannot see what another process did to itself.
//! macOS and Windows get no chains, so `enforce` never refuses there.

use std::{
    fmt::Write as _,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};
use vk_platform::security::{Chain, Link, Probe, Report, Required};

use super::tray_way::{session_desktop, tray_way};

/// `--skip-security-issues`, set once in `main` for every role; the daemon passes it on to the
/// UI child. Never read from the environment: an inherited variable would skip by accident.
static SKIP: AtomicBool = AtomicBool::new(false);

pub const SKIP_FLAG: &str = "--skip-security-issues";

pub fn set_skip(skip: bool) {
    SKIP.store(skip, Ordering::Relaxed);
}

#[must_use]
pub fn skip() -> bool {
    SKIP.load(Ordering::Relaxed)
}

/// `EX_CONFIG`: the CLI's exit status when a start is refused.
pub const REFUSED_EXIT: i32 = 78;

/// Which process is starting; the CLI and the browser host need no display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A `--daemon` or `--tray` start before the instance lock: the chains that can refuse and
    /// nothing that spawns a tool or asks the bus, so a launch that only forwards its command
    /// to the running daemon neither waits for those probes nor depends on them.
    Launch,
    Daemon,
    Ui,
    Cli,
}

/// The distribution, only for the fix texts (never to skip a probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Ubuntu,
    Fedora,
    Omarchy,
    OtherArch,
    Other,
}

/// What the probes found, as plain data so the chain rules test on any host. `Err` holds the
/// probe's reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub distro: Distro,
    pub peer_pidfd: Result<(), String>,
    pub pidfd_get_info: Result<(), String>,
    pub wayland: Result<(), String>,
    pub runtime_dir: Result<(), String>,
    /// The secure_memory backend name: "memfd_secret", "keyctl" or "mlock".
    pub key_backend: &'static str,
    /// Which key `systemd-creds` binds the stored tokens to, or why it is unavailable (C1 link 5).
    pub creds: vk_platform::creds::Backend,
    /// The GlobalShortcuts portal's state as the daemon found it; `None` while unknown.
    pub global_shortcuts: Option<Result<(), String>>,
    pub desktop: Desktop,
    /// Whether the daemon is non-dumpable and untraced; `None` until it hardened itself.
    pub memory_read: Option<Result<(), String>>,
    /// The Landlock outcome; `None` until the daemon decided it.
    pub sandbox: Option<super::self_protection::Sandbox>,
}

/// What the D-Bus name probes found; only the daemon asks (the CLI never pays for a bus round
/// trip, and the UI reads the daemon's report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desktop {
    pub portal: Result<(), String>,
    pub notifications: Result<(), String>,
    pub tray_watcher: Result<(), String>,
    pub logind: Result<(), String>,
    pub screensaver: Result<(), String>,
}

impl Desktop {
    #[must_use]
    pub fn not_probed() -> Self {
        let skipped = || Err("not probed in this process".to_owned());
        Self {
            portal: skipped(),
            notifications: skipped(),
            tray_watcher: skipped(),
            logind: skipped(),
            screensaver: skipped(),
        }
    }

    #[cfg(target_os = "linux")]
    fn probe() -> Self {
        let names = vk_platform::dbus_names::desktop_names();
        let unit = |probe: &Probe| match probe {
            Probe::Available => Ok(()),
            Probe::Degraded(why) | Probe::Unavailable(why) => Err(why.clone()),
        };
        Self {
            portal: unit(&names.portal),
            notifications: unit(&names.notifications),
            tray_watcher: unit(&names.tray_watcher),
            logind: unit(&names.logind),
            screensaver: unit(&names.screensaver),
        }
    }
}

/// The issues a user accepted with `vaultkeeper security accept`, stored in settings.json.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    pub fingerprint: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing refused; `warn` says whether a badge and log line are due.
    Proceed {
        warn: bool,
    },
    /// Refused, but `--skip-security-issues` or an accepted set lets it start with the badge.
    Overridden,
    Refuse,
}

fn link(id: &'static str, mechanism: &'static str, result: &Result<(), String>) -> Link {
    let probe = match result {
        Ok(()) => Probe::Available,
        Err(why) => Probe::Unavailable(why.clone()),
    };
    Link::new(id, mechanism, move || probe.clone())
}

fn always(id: &'static str, mechanism: &'static str) -> Link {
    Link::new(id, mechanism, || Probe::Available)
}

/// The baseline chains for `role`, strongest link first.
#[must_use]
pub fn chains(facts: &Facts, role: Role) -> Vec<Chain> {
    let mut chains = vec![
        Chain {
            id: "kernel",
            name: "Kernel",
            required: Required::Refuse,
            minimum: 0,
            links: vec![
                link("pidfd-info", "PIDFD_GET_INFO", &facts.pidfd_get_info),
                link("peer-pidfd", "SO_PEERPIDFD", &facts.peer_pidfd),
            ],
            fix: Some(fix(facts.distro, Item::Kernel)),
        },
        Chain {
            id: "runtime-dir",
            name: "Runtime directory",
            required: Required::Refuse,
            minimum: 0,
            links: vec![link(
                "xdg-runtime-dir",
                "XDG_RUNTIME_DIR",
                &facts.runtime_dir,
            )],
            fix: Some(fix(facts.distro, Item::RuntimeDir)),
        },
    ];
    if role != Role::Cli {
        chains.push(Chain {
            id: "wayland",
            name: "Wayland session",
            required: Required::Refuse,
            minimum: 0,
            links: vec![link("wayland", "Wayland", &facts.wayland)],
            fix: Some(fix(facts.distro, Item::Wayland)),
        });
        if role == Role::Daemon {
            chains.push(Chain {
                id: "secret-files",
                name: "Secret files at rest",
                required: Required::Status,
                minimum: 0,
                links: vec![always("sealing", "AES-256-GCM sealing"), facts.creds.link()],
                fix: None,
            });
            chains.extend(desktop_chains(&facts.desktop, facts.distro));
        }
        let backend = facts.key_backend;
        let key_link = |id, mechanism| {
            if backend == mechanism {
                always(id, mechanism)
            } else {
                Link::new(id, mechanism, || {
                    Probe::Unavailable("not chosen".to_owned())
                })
            }
        };
        chains.push(Chain {
            // secure_memory holds the vault's user and organization keys and the SSH agent's keys.
            id: "key-memory",
            name: "Keys in memory",
            required: Required::Refuse,
            minimum: 0,
            links: vec![
                key_link("memfd-secret", "memfd_secret"),
                key_link("keyctl", "keyctl"),
                always("mlock", "mlock"),
            ],
            fix: Some(fix(facts.distro, Item::SecretMem)),
        });
    }
    if role == Role::Daemon {
        chains.extend(hotkey_chain(facts));
        chains.extend(
            facts
                .memory_read
                .as_ref()
                .map(super::self_protection::memory_chain),
        );
        chains.extend(
            facts
                .sandbox
                .as_ref()
                .map(super::self_protection::sandbox_chain),
        );
    }
    chains
}

/// C9: the portal binds the shortcuts (Full); otherwise the user pastes the compositor lines
/// Settings shows (Standard). Left out until the daemon has tried the portal.
fn hotkey_chain(facts: &Facts) -> Option<Chain> {
    let portal = facts.global_shortcuts.as_ref()?;
    Some(Chain {
        id: "hotkey",
        name: "Global shortcuts",
        required: Required::Status,
        minimum: 1,
        links: vec![
            link("global-shortcuts", "GlobalShortcuts portal", portal),
            always("compositor-binding", "compositor binding"),
        ],
        fix: None,
    })
}

/// The Status chains for the desktop services behind the D-Bus names: they only describe what
/// the session lacks and never refuse a start.
fn desktop_chains(desktop: &Desktop, distro: Distro) -> Vec<Chain> {
    vec![
        tray_chain(&desktop.tray_watcher, distro, &session_desktop()),
        lock_sleep_chain(desktop, distro),
        portal_chain(&desktop.portal, distro),
        notifications_chain(&desktop.notifications, distro),
    ]
}

/// C14: logind carries sleep, shutdown and the session lock; the ScreenSaver names carry the lock
/// alone. With neither, Sway and Hyprland lockers reach us only through `loginctl lock-session`.
fn lock_sleep_chain(desktop: &Desktop, distro: Distro) -> Chain {
    Chain {
        id: "lock-sleep",
        name: "Lock and sleep events",
        required: Required::Status,
        minimum: 0,
        links: vec![
            link(
                "logind",
                "logind (sleep, shutdown, session lock)",
                &desktop.logind,
            ),
            link(
                "screensaver",
                "ScreenSaver (screen lock only)",
                &desktop.screensaver,
            ),
        ],
        fix: Some(fix(distro, Item::LockSleep)),
    }
}

/// The portal serves the global shortcut, link opening and file dialogs on every desktop; the
/// clipboard has its own chain because GNOME reaches it through the portal and KDE does not.
fn portal_chain(portal: &Result<(), String>, distro: Distro) -> Chain {
    Chain {
        id: "portal",
        name: "Desktop portal",
        required: Required::Status,
        minimum: 0,
        links: vec![link(
            "portal",
            "xdg-desktop-portal (links, shortcuts, file dialogs)",
            portal,
        )],
        fix: Some(fix(distro, Item::Portal)),
    }
}

/// The refusal notification needs a notification daemon; without one it shows in the window and
/// the log only.
fn notifications_chain(notifications: &Result<(), String>, distro: Distro) -> Chain {
    Chain {
        id: "notifications",
        name: "Notifications",
        required: Required::Status,
        minimum: 0,
        links: vec![
            link(
                "notification-daemon",
                "Notification daemon (refusal notice)",
                notifications,
            ),
            always("window-and-log", "Window and log only"),
        ],
        fix: Some(fix(distro, Item::Notifications)),
    }
}

#[derive(Debug, Clone, Copy)]
enum Item {
    LockSleep,
    Portal,
    Notifications,
    Kernel,
    RuntimeDir,
    Wayland,
    SecretMem,
}

/// C13: a StatusNotifierWatcher on the session bus, which the tray needs. Never refuses: without
/// one the shortcut and the launcher entry still work, and Settings shows the fix.
#[must_use]
pub fn tray_chain(watcher: &Result<(), String>, distro: Distro, desktop: &str) -> Chain {
    Chain {
        id: "tray",
        name: "Tray",
        required: Required::Status,
        minimum: 0,
        links: vec![
            link("status-notifier", "StatusNotifierItem", watcher),
            always("none", "No tray"),
        ],
        fix: Some(format!(
            "no tray on this desktop; use the shortcut or the launcher entry, or {}",
            tray_way(distro, desktop)
        )),
    }
}

/// `<fix>` of the `<item>: <what the probe saw> — <fix>` line, for the detected distribution.
fn fix(distro: Distro, item: Item) -> String {
    let text = match (item, distro) {
        (Item::Kernel, Distro::Omarchy) => {
            "boot linux-omarchy, linux or linux-lts (6.13 or newer): sudo omarchy kernel set linux-omarchy"
        }
        (Item::Kernel, Distro::Ubuntu | Distro::Fedora) => {
            "boot the distribution's stock kernel (6.13 or newer)"
        }
        (Item::Kernel, _) => "boot a kernel 6.13 or newer",
        (Item::RuntimeDir, _) => {
            "log in through a session manager (logind) or export XDG_RUNTIME_DIR=/run/user/$(id -u)"
        }
        (Item::Wayland, Distro::Ubuntu) => "log in to the \"Ubuntu\" (Wayland) session",
        (Item::Wayland, Distro::Omarchy) => "start Hyprland through UWSM (the Omarchy default)",
        (Item::Wayland, _) => "log in to a Wayland session; X11 is not supported",
        (Item::LockSleep, _) => {
            "no lock or sleep events reach Vaultkeeper; on Sway or Hyprland run `loginctl lock-session` from swayidle or hypridle (see \"Lock on Linux\" in docs/USAGE.md)"
        }
        (Item::Portal, _) => {
            "start xdg-desktop-portal with your desktop's backend (xdg-desktop-portal-gnome, -kde, -hyprland or -wlr); links, shortcuts, the GNOME clipboard and file dialogs need it"
        }
        (Item::Notifications, Distro::Omarchy) => {
            "no notification daemon; refusals show only in the window and the log; restart the Omarchy shell, which hosts it"
        }
        (Item::Notifications, _) => {
            "no notification daemon; refusals show only in the window and the log; run one (mako or dunst on Sway and Hyprland, stock on GNOME and KDE)"
        }
        (Item::SecretMem, Distro::Omarchy | Distro::OtherArch) => {
            "remove secretmem.enable=0 from KERNEL_CMDLINE in /etc/default/limine and run sudo omarchy-refresh-limine"
        }
        (Item::SecretMem, _) => {
            "remove secretmem.enable=0 from the kernel command line, or use a kernel with CONFIG_SECRETMEM"
        }
    };
    text.to_owned()
}

/// Proceed, proceed despite a refusal, or refuse. An accepted set covers a refusal only when every
/// refused id is in it, so a new issue refuses again.
#[must_use]
pub fn decide(report: &Report, skip: bool, accepted: Option<&Accepted>) -> Decision {
    let refusals = report.refusals();
    if refusals.is_empty() {
        return Decision::Proceed {
            warn: !report.warnings().is_empty(),
        };
    }
    let covered = accepted.is_some_and(|accepted| {
        refusals
            .iter()
            .all(|chain| accepted.issues.contains(&chain.id))
    });
    if skip || covered {
        Decision::Overridden
    } else {
        Decision::Refuse
    }
}

/// What `security accept` stores for this report.
#[must_use]
pub fn accept(report: &Report) -> Accepted {
    Accepted {
        fingerprint: report.fingerprint(),
        issues: report
            .refusals()
            .iter()
            .map(|chain| chain.id.clone())
            .collect(),
    }
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn detect_distro() -> Distro {
    match vk_linux::distro::detect() {
        vk_linux::distro::Distro::Ubuntu => Distro::Ubuntu,
        vk_linux::distro::Distro::Fedora => Distro::Fedora,
        vk_linux::distro::Distro::Omarchy => Distro::Omarchy,
        vk_linux::distro::Distro::OtherArch => Distro::OtherArch,
        vk_linux::distro::Distro::Other => Distro::Other,
    }
}

/// The tray's C13 report, set by the daemon's shell once it knows whether a watcher exists and
/// read by the Settings security section (3l) next to [`report`]'s chains.
#[cfg(target_os = "linux")]
static TRAY_REPORT: std::sync::Mutex<Option<vk_platform::security::ChainReport>> =
    std::sync::Mutex::new(None);

#[cfg(target_os = "linux")]
pub fn set_tray_report(report: vk_platform::security::ChainReport) {
    *TRAY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn tray_report() -> Option<vk_platform::security::ChainReport> {
    TRAY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

impl Facts {
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn probe(role: Role) -> Self {
        use vk_linux::probes;
        let unit = |result: vk_linux::ProbeResult| result.map(drop);
        Self {
            distro: detect_distro(),
            peer_pidfd: unit(probes::peer_pidfd()),
            pidfd_get_info: unit(probes::pidfd_get_info()),
            wayland: unit(probes::wayland()),
            runtime_dir: probes::runtime_dir().map(drop),
            key_backend: secure_memory::backend().name(),
            // Only the daemon stores tokens, so only it pays for the systemd-creds round trip.
            creds: if role == Role::Daemon {
                vk_platform::creds::Detection::cached().backend().clone()
            } else {
                vk_platform::creds::Backend::Unavailable("not probed in this process".to_owned())
            },
            global_shortcuts: crate::os::linux::hotkey_status::get(),
            desktop: if role == Role::Daemon {
                Desktop::probe()
            } else {
                Desktop::not_probed()
            },
            memory_read: super::self_protection::memory_read(),
            sandbox: super::self_protection::sandbox(),
        }
    }
}

/// The daemon's report from startup, whose activations are already applied.
static STARTUP: std::sync::OnceLock<Report> = std::sync::OnceLock::new();

/// The daemon's chains probed again for Settings' Re-check. Activation is not repeated: the
/// links were applied at startup, and one that failed to apply then stays failed.
#[must_use]
pub fn recheck() -> Report {
    #[cfg(target_os = "linux")]
    {
        let startup = STARTUP.get().cloned().unwrap_or_default();
        Report::reevaluate(&chains(&Facts::probe(Role::Daemon), Role::Daemon), &startup)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Report::default()
    }
}

/// The baseline report for this process, recomputed (`security status` prints it).
#[must_use]
pub fn report(role: Role) -> Report {
    #[cfg(target_os = "linux")]
    {
        Report::evaluate(&chains(&Facts::probe(role), role))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = role;
        Report::default()
    }
}

/// Runs the baseline for `role` and returns the report, or an error carrying the refusal text.
/// The accepted set comes from settings.json in `data_dir`.
pub fn enforce(role: Role, data_dir: &Path) -> anyhow::Result<Report> {
    let report = report(role);
    let settings = crate::os::settings_file::SettingsFile::read(
        &data_dir.join(crate::os::layout::SETTINGS_FILE),
    );
    match decide(&report, skip(), settings.security_accepted.as_ref()) {
        Decision::Proceed { warn: false } => {}
        Decision::Proceed { warn: true } => {
            tracing::warn!(table = %report.table(), "security baseline below its minimum");
        }
        Decision::Overridden => {
            tracing::warn!(table = %report.table(), "starting despite refused security issues");
        }
        Decision::Refuse => {
            let text = refusal_text(&report);
            tracing::error!(%text, "security baseline refused this start");
            anyhow::bail!(text);
        }
    }
    if role == Role::Daemon {
        let _ = STARTUP.set(report.clone());
    }
    Ok(report)
}

/// The refusal text: one `<item>: <seen> — <fix>` line per refused chain, then the ways out.
#[must_use]
pub fn refusal_text(report: &Report) -> String {
    let mut text =
        String::from("Vaultkeeper will not start: a required protection is missing.\n\n");
    for chain in report.refusals() {
        let seen = chain
            .skipped
            .first()
            .map_or("not available", |skipped| skipped.why.as_str());
        let _ = write!(text, "{}: {seen}", chain.name);
        if let Some(fix) = &chain.fix {
            let _ = write!(text, " — {fix}");
        }
        text.push('\n');
    }
    text.push_str(
        "\nStart anyway once with `vaultkeeper --skip-security-issues`, or accept these issues \
         for every start with `vaultkeeper security accept`.\n",
    );
    text
}

#[cfg(test)]
mod tests {
    use vk_platform::security::ChainStatus;

    use super::*;

    fn good() -> Facts {
        Facts {
            distro: Distro::Ubuntu,
            peer_pidfd: Ok(()),
            pidfd_get_info: Ok(()),
            wayland: Ok(()),
            runtime_dir: Ok(()),
            key_backend: "memfd_secret",
            creds: vk_platform::creds::Backend::Host,
            global_shortcuts: None,
            desktop: Desktop {
                portal: Ok(()),
                notifications: Ok(()),
                tray_watcher: Ok(()),
                logind: Ok(()),
                screensaver: Ok(()),
            },
            memory_read: None,
            sandbox: None,
        }
    }

    fn chain_of(report: &Report, id: &str) -> vk_platform::security::ChainReport {
        report
            .chains
            .iter()
            .find(|chain| chain.id == id)
            .cloned()
            .expect("chain present")
    }

    fn gone() -> Result<(), String> {
        Err("nothing owns the name".to_owned())
    }

    fn evaluate(facts: &Facts, role: Role) -> Report {
        Report::evaluate(&chains(facts, role))
    }

    #[test]
    fn a_missing_tray_watcher_is_reduced_with_the_notice_and_never_refuses() {
        let missing = Err("org.kde.StatusNotifierWatcher has no owner".to_owned());
        let report = Report::evaluate(&[tray_chain(&missing, Distro::Fedora, "GNOME")]);
        let chain = &report.chains[0];
        assert_eq!(chain.status, vk_platform::security::ChainStatus::Reduced);
        assert_eq!(chain.active.as_deref(), Some("No tray"));
        assert!(
            chain
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains("gnome-shell-extension-appindicator"))
        );
        assert_eq!(report.refusals().len(), 0);
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );
    }

    #[test]
    fn a_tray_watcher_makes_the_tray_chain_full() {
        let report = Report::evaluate(&[tray_chain(&Ok(()), Distro::Ubuntu, "ubuntu:GNOME")]);
        assert_eq!(
            report.chains[0].status,
            vk_platform::security::ChainStatus::Full
        );
        assert!(report.chains[0].fix.is_none());
    }

    #[test]
    fn a_stock_session_proceeds_without_warnings() {
        let report = evaluate(&good(), Role::Daemon);
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );
    }

    #[test]
    fn a_launch_checks_every_chain_that_can_refuse_the_daemon_and_no_other() {
        let ids = |role| -> Vec<&'static str> {
            chains(&good(), role)
                .iter()
                .filter(|chain| role == Role::Launch || chain.required == Required::Refuse)
                .map(|chain| chain.id)
                .collect()
        };
        assert_eq!(ids(Role::Launch), ids(Role::Daemon));
        assert_eq!(
            ids(Role::Launch),
            ["kernel", "runtime-dir", "wayland", "key-memory"]
        );
    }

    #[test]
    fn the_daemon_rows_for_its_own_process_join_once_known() {
        use crate::os::self_protection::Sandbox;
        let has = |report: &Report, id: &str| report.chains.iter().any(|chain| chain.id == id);
        let before = evaluate(&good(), Role::Daemon);
        assert!(!has(&before, "memory-read") && !has(&before, "sandbox"));

        let facts = Facts {
            memory_read: Some(Ok(())),
            sandbox: Some(Sandbox::Failed("the install path is unknown".to_owned())),
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        assert_eq!(chain_of(&report, "memory-read").status, ChainStatus::Full);
        let sandbox = chain_of(&report, "sandbox");
        assert_eq!(sandbox.status, ChainStatus::Reduced);
        assert_eq!(
            sandbox.note.as_deref(),
            Some("requested but not applied: the install path is unknown")
        );
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );
        assert!(!has(&evaluate(&facts, Role::Ui), "sandbox"));
    }

    #[test]
    fn old_kernel_without_pidfd_info_still_starts() {
        let facts = Facts {
            pidfd_get_info: Err("kernel 6.8".to_owned()),
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        assert!(matches!(
            decide(&report, false, None),
            Decision::Proceed { .. }
        ));
    }

    #[test]
    fn missing_runtime_dir_refuses_with_the_fix() {
        let facts = Facts {
            runtime_dir: Err("XDG_RUNTIME_DIR is not set".to_owned()),
            ..good()
        };
        let report = evaluate(&facts, Role::Cli);
        assert_eq!(decide(&report, false, None), Decision::Refuse);
        let text = refusal_text(&report);
        assert!(text.contains(
            "Runtime directory: XDG_RUNTIME_DIR is not set — log in through a session manager"
        ));
        assert!(text.contains("--skip-security-issues"));
    }

    #[test]
    fn the_cli_needs_no_wayland() {
        let facts = Facts {
            wayland: Err("WAYLAND_DISPLAY is not set".to_owned()),
            ..good()
        };
        assert_eq!(
            decide(&evaluate(&facts, Role::Cli), false, None),
            Decision::Proceed { warn: false }
        );
        assert_eq!(
            decide(&evaluate(&facts, Role::Ui), false, None),
            Decision::Refuse
        );
    }

    #[test]
    fn skip_and_accepted_subsets_override_but_new_issues_refuse() {
        let no_wayland = Facts {
            wayland: Err("unset".to_owned()),
            ..good()
        };
        let report = evaluate(&no_wayland, Role::Daemon);
        assert_eq!(decide(&report, true, None), Decision::Overridden);
        let accepted = accept(&report);
        assert_eq!(accepted.issues, ["wayland"]);
        assert_eq!(
            decide(&report, false, Some(&accepted)),
            Decision::Overridden
        );

        let worse = Facts {
            runtime_dir: Err("unset".to_owned()),
            ..no_wayland
        };
        let report = evaluate(&worse, Role::Daemon);
        assert_eq!(decide(&report, false, Some(&accepted)), Decision::Refuse);
    }

    #[test]
    fn the_key_chain_reports_the_backend_in_use() {
        let facts = Facts {
            key_backend: "keyctl",
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        let key = report
            .chains
            .iter()
            .find(|chain| chain.id == "key-memory")
            .expect("key chain");
        assert_eq!(key.active.as_deref(), Some("keyctl"));
        assert_eq!(key.fallback.as_deref(), Some("mlock"));
    }

    fn hotkey_status(facts: &Facts, role: Role) -> Option<ChainStatus> {
        evaluate(facts, role)
            .chains
            .iter()
            .find(|chain| chain.id == "hotkey")
            .map(|chain| chain.status)
    }

    #[test]
    fn the_hotkey_chain_follows_the_portal_and_never_warns() {
        let facts = |global_shortcuts| Facts {
            global_shortcuts,
            ..good()
        };
        assert_eq!(hotkey_status(&facts(None), Role::Daemon), None);
        assert_eq!(
            hotkey_status(&facts(Some(Ok(()))), Role::Daemon),
            Some(ChainStatus::Full)
        );
        let missing = facts(Some(Err("no portal".to_owned())));
        assert_eq!(
            hotkey_status(&missing, Role::Daemon),
            Some(ChainStatus::Standard)
        );
        assert_eq!(hotkey_status(&missing, Role::Ui), None);
        assert_eq!(
            decide(&evaluate(&missing, Role::Daemon), false, None),
            Decision::Proceed { warn: false }
        );
    }

    #[test]
    fn the_secret_files_chain_lists_systemd_creds_and_never_warns_without_it() {
        let facts = Facts {
            creds: vk_platform::creds::Backend::Unavailable("not installed".to_owned()),
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        let files = report
            .chains
            .iter()
            .find(|chain| chain.id == "secret-files")
            .expect("secret files chain");
        assert_eq!(files.stacked.len(), 0);
        assert_eq!(files.skipped[0].link, "systemd-creds");
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );

        assert!(
            !evaluate(&facts, Role::Ui)
                .chains
                .iter()
                .any(|chain| chain.id == "secret-files")
        );

        let with = evaluate(&good(), Role::Daemon);
        let files = with
            .chains
            .iter()
            .find(|chain| chain.id == "secret-files")
            .expect("secret files chain");
        assert_eq!(files.stacked, ["systemd-creds (host key only)"]);
    }

    #[test]
    fn the_portal_row_names_no_desktop_specific_clipboard() {
        let report = evaluate(&good(), Role::Daemon);
        let portal = chain_of(&report, "portal");
        let text = portal.active.expect("portal active");
        assert!(!text.contains("GNOME"), "{text}");
    }

    #[test]
    fn a_host_only_key_makes_the_secret_files_row_standard_and_a_tpm_key_full() {
        use vk_platform::{creds::Backend, security::ChainStatus};
        let host = evaluate(&good(), Role::Daemon);
        let files = chain_of(&host, "secret-files");
        assert_eq!(files.status, ChainStatus::Standard);
        assert_eq!(
            files.note.as_deref(),
            Some("host key only, not sealed to a TPM2")
        );

        let tpm = Facts {
            creds: Backend::TpmAndHost,
            ..good()
        };
        let report = evaluate(&tpm, Role::Daemon);
        assert_eq!(chain_of(&report, "secret-files").status, ChainStatus::Full);
    }

    #[test]
    fn a_full_desktop_makes_every_desktop_chain_full_with_one_tray_row() {
        use vk_platform::security::ChainStatus::Full;
        let report = evaluate(&good(), Role::Daemon);
        for id in ["tray", "lock-sleep", "portal", "notifications"] {
            assert_eq!(chain_of(&report, id).status, Full, "{id}");
        }
        assert_eq!(report.chains.iter().filter(|c| c.id == "tray").count(), 1);
        assert_eq!(
            chain_of(&report, "lock-sleep").active.as_deref(),
            Some("logind (sleep, shutdown, session lock)")
        );
    }

    #[test]
    fn only_the_daemon_gets_desktop_chains() {
        for role in [Role::Cli, Role::Ui] {
            let report = evaluate(&good(), role);
            assert!(
                !report.chains.iter().any(|chain| [
                    "tray",
                    "lock-sleep",
                    "portal",
                    "notifications"
                ]
                .contains(&chain.id.as_str())),
                "{role:?}"
            );
        }
    }

    #[test]
    fn a_missing_tray_watcher_probe_reduces_the_one_tray_row() {
        let facts = Facts {
            desktop: Desktop {
                tray_watcher: gone(),
                ..good().desktop
            },
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        let tray = chain_of(&report, "tray");
        assert_eq!(tray.status, vk_platform::security::ChainStatus::Reduced);
        assert_eq!(tray.active.as_deref(), Some("No tray"));
        assert_eq!(report.chains.iter().filter(|c| c.id == "tray").count(), 1);
    }

    #[test]
    fn lock_and_sleep_falls_from_logind_to_screensaver_to_off() {
        use vk_platform::security::ChainStatus::{Off, Reduced};
        let screensaver_only = Facts {
            desktop: Desktop {
                logind: gone(),
                ..good().desktop
            },
            ..good()
        };
        let chain = chain_of(&evaluate(&screensaver_only, Role::Daemon), "lock-sleep");
        assert_eq!(chain.status, Reduced);
        assert_eq!(
            chain.active.as_deref(),
            Some("ScreenSaver (screen lock only)")
        );
        assert_eq!(chain.skipped[0].link, "logind");

        let none = Facts {
            desktop: Desktop {
                logind: gone(),
                screensaver: gone(),
                ..good().desktop
            },
            ..good()
        };
        let report = evaluate(&none, Role::Daemon);
        let chain = chain_of(&report, "lock-sleep");
        assert_eq!(chain.status, Off);
        assert!(chain.active.is_none());
        let fix = chain.fix.expect("fix text");
        assert!(fix.contains("loginctl lock-session") && fix.contains("swayidle"));
        assert!(fix.contains("Lock on Linux"));
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );
    }

    #[test]
    fn a_missing_portal_is_off_and_names_what_needs_it() {
        let facts = Facts {
            desktop: Desktop {
                portal: gone(),
                ..good().desktop
            },
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        let portal = chain_of(&report, "portal");
        assert_eq!(portal.status, vk_platform::security::ChainStatus::Off);
        let fix = portal.fix.expect("fix text");
        for needs in ["links", "shortcuts", "GNOME clipboard", "file dialogs"] {
            assert!(fix.contains(needs), "{needs}");
        }
        let full = chain_of(&evaluate(&good(), Role::Daemon), "portal");
        let mechanism = full.active.expect("active");
        assert!(mechanism.contains("shortcuts") && mechanism.contains("file dialogs"));
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );
    }

    #[test]
    fn a_missing_notification_daemon_reduces_to_window_and_log_and_never_refuses() {
        let facts = Facts {
            desktop: Desktop {
                notifications: gone(),
                ..good().desktop
            },
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        let chain = chain_of(&report, "notifications");
        assert_eq!(chain.status, vk_platform::security::ChainStatus::Reduced);
        assert_eq!(chain.active.as_deref(), Some("Window and log only"));
        assert!(chain.fix.is_some_and(|fix| fix.contains("mako")));
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );
    }

    #[test]
    fn nothing_probed_still_never_refuses() {
        let facts = Facts {
            desktop: Desktop::not_probed(),
            ..good()
        };
        let report = evaluate(&facts, Role::Daemon);
        assert_eq!(report.refusals().len(), 0);
        assert_eq!(
            decide(&report, false, None),
            Decision::Proceed { warn: false }
        );
    }

    #[test]
    fn fix_texts_follow_the_distribution() {
        assert!(fix(Distro::Omarchy, Item::Kernel).contains("omarchy kernel set"));
        assert!(fix(Distro::Ubuntu, Item::Wayland).contains("\"Ubuntu\""));
        assert!(fix(Distro::Other, Item::Wayland).contains("X11"));
    }
}
