//! The startup security baseline (linux-plan.md 1c, linux-ideas.md §9): the chains of
//! `vk_platform::security` built from probe facts, and the decision whether this start may go on.
//!
//! Only chains whose mechanism is active today are registered. Anti memory read (C3) joins with
//! 2c, which makes the daemon non-dumpable, and the self-sandbox (C6) with 1f, which applies
//! Landlock: listing them earlier would report protection the process does not have yet.
//! macOS and Windows get no chains, so `enforce` never refuses there.

use std::{
    fmt::Write as _,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};
use vk_platform::security::{Chain, Link, Probe, Report, Required};

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
    chains
}

#[derive(Debug, Clone, Copy)]
enum Item {
    Kernel,
    RuntimeDir,
    Wayland,
    SecretMem,
    Tray,
}

/// C13: a StatusNotifierWatcher on the session bus, which the tray needs. Never refuses: without
/// one the shortcut and the launcher entry still work, and Settings shows the fix.
#[must_use]
pub fn tray_chain(watcher: &Result<(), String>, distro: Distro) -> Chain {
    Chain {
        id: "tray",
        name: "Tray",
        required: Required::Status,
        minimum: 0,
        links: vec![
            link("status-notifier", "StatusNotifierItem", watcher),
            always("none", "No tray"),
        ],
        fix: Some(fix(distro, Item::Tray)),
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
        (Item::Tray, Distro::Ubuntu) => {
            "no tray on this desktop; use the shortcut or the launcher entry, or enable the Ubuntu AppIndicator extension in Extensions"
        }
        (Item::Tray, Distro::Fedora) => {
            "no tray on this desktop; use the shortcut or the launcher entry, or install gnome-shell-extension-appindicator (GNOME) or add Waybar's tray module (Sway)"
        }
        (Item::Tray, Distro::Omarchy) => {
            "no tray on this desktop; use the shortcut or the launcher entry, or restart the Omarchy shell, which hosts the tray"
        }
        (Item::Tray, _) => {
            "no tray on this desktop; use the shortcut or the launcher entry, or run a StatusNotifierItem host (a panel tray module or the GNOME AppIndicator extension)"
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
    pub fn probe() -> Self {
        use vk_linux::probes;
        let unit = |result: vk_linux::ProbeResult| result.map(drop);
        Self {
            distro: detect_distro(),
            peer_pidfd: unit(probes::peer_pidfd()),
            pidfd_get_info: unit(probes::pidfd_get_info()),
            wayland: unit(probes::wayland()),
            runtime_dir: probes::runtime_dir().map(drop),
            key_backend: secure_memory::backend().name(),
        }
    }
}

/// The baseline report for this process, recomputed (`security status` prints it).
#[must_use]
pub fn report(role: Role) -> Report {
    #[cfg(target_os = "linux")]
    {
        Report::evaluate(&chains(&Facts::probe(), role))
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
    use super::*;

    fn good() -> Facts {
        Facts {
            distro: Distro::Ubuntu,
            peer_pidfd: Ok(()),
            pidfd_get_info: Ok(()),
            wayland: Ok(()),
            runtime_dir: Ok(()),
            key_backend: "memfd_secret",
        }
    }

    fn evaluate(facts: &Facts, role: Role) -> Report {
        Report::evaluate(&chains(facts, role))
    }

    #[test]
    fn a_missing_tray_watcher_is_reduced_with_the_notice_and_never_refuses() {
        let missing = Err("org.kde.StatusNotifierWatcher has no owner".to_owned());
        let report = Report::evaluate(&[tray_chain(&missing, Distro::Fedora)]);
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
        let report = Report::evaluate(&[tray_chain(&Ok(()), Distro::Ubuntu)]);
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

    #[test]
    fn fix_texts_follow_the_distribution() {
        assert!(fix(Distro::Omarchy, Item::Kernel).contains("omarchy kernel set"));
        assert!(fix(Distro::Ubuntu, Item::Wayland).contains("\"Ubuntu\""));
        assert!(fix(Distro::Other, Item::Wayland).contains("X11"));
    }
}
