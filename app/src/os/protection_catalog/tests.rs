use vk_ipc::{ChainDto, ChainRequired, ChainState};
use vk_platform::{
    creds::Backend,
    sandbox::Enforcement,
    security::{Chain, Link, Probe, Report, Required},
};

use super::*;
use crate::{
    daemon::security::to_dto,
    os::{
        security_gate::{Desktop, Distro, Facts, Role, chains},
        self_protection::{Sandbox, memory_chain, sandbox_chain},
    },
};

fn facts(creds: Backend) -> Facts {
    Facts {
        distro: Distro::Ubuntu,
        peer_pidfd: Ok(()),
        pidfd_get_info: Ok(()),
        wayland: Ok(()),
        runtime_dir: Ok(()),
        key_backend: "memfd_secret",
        creds,
        global_shortcuts: Some(Ok(())),
        desktop: Desktop {
            portal: Ok(()),
            notifications: Ok(()),
            tray_watcher: Ok(()),
            logind: Ok(()),
            screensaver: Ok(()),
        },
        memory_read: Some(Ok(())),
        sandbox: Some(Sandbox::NotRequested),
    }
}

fn clipboard(active: &'static str) -> Chain {
    let link = |id: &'static str| {
        Link::new(id, id, move || {
            if id == active || id == "plain" {
                Probe::Available
            } else {
                Probe::Unavailable("off".to_owned())
            }
        })
    };
    Chain {
        id: "clipboard",
        name: "Clipboard",
        required: Required::Status,
        minimum: 1,
        links: vec![
            link("ext-data-control"),
            link("portal-clipboard"),
            link("plain"),
        ],
        fix: None,
    }
}

fn rows(facts: &Facts) -> Vec<ProtectionRow> {
    let mut all = chains(facts, Role::Daemon);
    all.push(clipboard("ext-data-control"));
    let report = Report::evaluate(&all);
    describe_all(&to_dto(&report).chains, facts.distro)
}

fn line(facts: &Facts) -> String {
    summarize(&rows(facts)).expect("summary").text
}

fn row<'a>(rows: &'a [ProtectionRow], id: &str) -> &'a ProtectionRow {
    rows.iter().find(|row| row.id == id).expect("row")
}

fn with_sandbox(creds: Backend, sandbox: Sandbox) -> Facts {
    Facts {
        sandbox: Some(sandbox),
        ..facts(creds)
    }
}

fn applied(enforcement: Enforcement) -> Sandbox {
    Sandbox::Applied {
        enforcement,
        abi: Some(7),
    }
}

fn dto(id: &str, active_id: &str, state: ChainState) -> ChainDto {
    ChainDto {
        id: id.to_owned(),
        name: id.to_owned(),
        state,
        active: Some(active_id.to_owned()),
        stacked: Vec::new(),
        fallback: None,
        note: None,
        fix: None,
        active_id: Some(active_id.to_owned()),
        stacked_ids: Vec::new(),
        required: ChainRequired::Status,
        skipped: Vec::new(),
    }
}

#[test]
fn the_summary_line_follows_the_spec_table() {
    assert_eq!(
        line(&facts(Backend::Host)),
        "7 of 9 protections active · 1 limited · 1 off",
        "KDE, no TPM, defaults"
    );
    assert_eq!(
        line(&facts(Backend::TpmAndHost)),
        "8 of 9 protections active · 1 off",
        "GNOME with a TPM, defaults"
    );
    assert_eq!(
        line(&with_sandbox(
            Backend::TpmAndHost,
            applied(Enforcement::Full)
        )),
        "All 9 protections active"
    );
    assert_eq!(
        line(&with_sandbox(
            Backend::TpmAndHost,
            applied(Enforcement::Partial)
        )),
        "8 of 9 protections active · 1 limited"
    );
    assert_eq!(
        line(&with_sandbox(Backend::Host, applied(Enforcement::None))),
        "7 of 9 protections active · 1 limited · 1 off"
    );
}

#[test]
fn a_missing_required_protection_reads_missing_and_red() {
    let facts = Facts {
        wayland: Err("DISPLAY is set".to_owned()),
        ..with_sandbox(Backend::TpmAndHost, applied(Enforcement::Full))
    };
    let rows = rows(&facts);
    let wayland = row(&rows, "wayland");
    assert_eq!(wayland.level, Level::Missing);
    assert_eq!(wayland.tone, Tone::Red);
    assert_eq!(wayland.detail, "Not a Wayland session. DISPLAY is set");
    assert_eq!(
        summarize(&rows).expect("summary").text,
        "8 of 9 protections active · 1 missing"
    );
}

#[test]
fn the_sandbox_off_by_default_is_off_and_yellow_not_active() {
    let rows = rows(&facts(Backend::TpmAndHost));
    let sandbox = row(&rows, "sandbox");
    assert_eq!(sandbox.level, Level::Off);
    assert_eq!(sandbox.tone, Tone::Yellow);
    assert_eq!(sandbox.technical, "Landlock, not requested");
    assert_eq!(sandbox.steps_title, "Turn the sandbox on");
    assert_eq!(sandbox.steps.len(), 3);
    assert_eq!(
        sandbox.copy,
        "mkdir -p ~/.config/environment.d && echo VAULTKEEPER_LANDLOCK=1 > ~/.config/environment.d/vaultkeeper.conf"
    );
}

#[test]
fn a_sandbox_that_was_asked_for_and_is_not_enforced_is_red() {
    let none = rows(&with_sandbox(Backend::Host, applied(Enforcement::None)));
    let sandbox = row(&none, "sandbox");
    assert_eq!((sandbox.level, sandbox.tone), (Level::Off, Tone::Red));
    assert_eq!(
        sandbox.detail,
        "You asked for it, but this kernel has no Landlock."
    );

    let failed = rows(&with_sandbox(
        Backend::Host,
        Sandbox::Failed("the install path is unknown".to_owned()),
    ));
    let sandbox = row(&failed, "sandbox");
    assert_eq!((sandbox.level, sandbox.tone), (Level::Off, Tone::Red));
    assert_eq!(
        sandbox.detail,
        "You asked for it, but it could not be applied: the install path is unknown."
    );
}

#[test]
fn a_partial_sandbox_names_its_abi() {
    let rows = rows(&with_sandbox(Backend::Host, applied(Enforcement::Partial)));
    let sandbox = row(&rows, "sandbox");
    assert_eq!(sandbox.level, Level::Limited);
    assert_eq!(sandbox.technical, "Landlock (ABI 7)");
}

#[test]
fn stored_secrets_follow_the_key_that_protects_them() {
    let host = rows(&facts(Backend::Host));
    let files = row(&host, "secret-files");
    assert_eq!(files.level, Level::Limited);
    assert_eq!(
        files.technical,
        "AES-256-GCM + systemd-creds (host key only)"
    );
    assert_eq!(files.copy, "systemd-creds has-tpm2");

    let tpm = rows(&facts(Backend::TpmAndHost));
    let files = row(&tpm, "secret-files");
    assert_eq!(files.level, Level::Active);
    assert_eq!(
        files.technical,
        "AES-256-GCM + systemd-creds (TPM2 + host key)"
    );
    assert!(files.steps.is_empty() && files.notes.is_empty());

    let none = rows(&facts(Backend::Unavailable("not installed".to_owned())));
    let files = row(&none, "secret-files");
    assert_eq!(
        files.level,
        Level::Limited,
        "a skipped stacking link still caps the chain"
    );
    assert_eq!(files.technical, "AES-256-GCM");
    assert_eq!(
        files.detail,
        "Encrypted, but not tied to this computer: systemd-creds is not usable. not installed"
    );
}

#[test]
fn an_unreachable_creds_service_says_it_waits_for_a_restart() {
    let rows = rows(&facts(Backend::Unreachable { by_hand: false }));
    let files = row(&rows, "secret-files");
    assert_eq!(files.level, Level::Limited);
    assert_eq!(
        files.detail,
        "The system credential service (systemd-creds) restarted; Vaultkeeper can reach it again once Vaultkeeper restarts."
    );
    assert_eq!(
        files.notes,
        [
            "Vaultkeeper restarts by itself a few minutes after you lock the vault and close its windows; or quit and start it again."
        ]
    );
}

#[test]
fn without_a_systemd_manager_the_fix_is_to_restart_by_hand() {
    let rows = rows(&facts(Backend::Unreachable { by_hand: true }));
    let files = row(&rows, "secret-files");
    assert_eq!(
        files.detail,
        "The system credential service (systemd-creds) restarted; Vaultkeeper can reach it again once you restart Vaultkeeper."
    );
    assert_eq!(files.notes, ["Quit and start Vaultkeeper again."]);
}

#[test]
fn a_creds_tool_that_fails_at_runtime_says_tokens_cannot_be_read_or_saved() {
    let rows = rows(&facts(Backend::Failing("exit status 1".to_owned())));
    let files = row(&rows, "secret-files");
    assert_eq!(files.level, Level::Limited);
    assert_eq!(
        files.detail,
        "Sign-in tokens cannot be read or saved right now. systemd-creds stopped working since Vaultkeeper started: exit status 1"
    );
}

#[test]
fn a_missing_tray_is_off_and_neutral_and_not_counted() {
    let base = facts(Backend::Host);
    let facts = Facts {
        desktop: Desktop {
            tray_watcher: Err("no watcher".to_owned()),
            ..base.desktop.clone()
        },
        ..base
    };
    let rows = rows(&facts);
    let tray = row(&rows, "tray");
    assert_eq!((tray.level, tray.tone), (Level::Off, Tone::Neutral));
    assert!(!tray.counted());
    assert_eq!(
        summarize(&rows).expect("summary").text,
        "7 of 9 protections active · 1 limited · 1 off"
    );
}

#[test]
fn attention_rows_lead_and_leave_their_group() {
    let rows = rows(&facts(Backend::Host));
    let sections = sections(&rows);
    assert_eq!(sections[0].label, "NEEDS ATTENTION");
    let ids: Vec<&str> = sections[0].rows.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(ids, ["secret-files", "sandbox"], "limited before off");
    assert!(
        sections[1..]
            .iter()
            .flat_map(|section| &section.rows)
            .all(|row| row.id != "sandbox" && row.id != "secret-files")
    );
    assert_eq!(
        sections.last().expect("last").label,
        "DESKTOP INTEGRATION · not counted above"
    );
    assert!(sections.iter().all(|section| !section.rows.is_empty()));
}

#[test]
fn the_header_badge_and_segment_colours() {
    let summary = summarize(&rows(&facts(Backend::Host))).expect("summary");
    assert_eq!(summary.tone, Tone::Yellow);
    let tones: Vec<Tone> = summary.segments.iter().map(|s| s.tone).collect();
    assert_eq!(tones, [Tone::Neutral, Tone::Yellow, Tone::Yellow]);

    let all = summarize(&rows(&with_sandbox(
        Backend::TpmAndHost,
        applied(Enforcement::Full),
    )))
    .expect("summary");
    assert_eq!(all.tone, Tone::Green);

    let red = summarize(&rows(&with_sandbox(
        Backend::Host,
        applied(Enforcement::None),
    )))
    .expect("summary");
    assert_eq!(red.tone, Tone::Red);
    assert_eq!(red.segments.last().expect("segment").tone, Tone::Red);
}

#[test]
fn one_counted_protection_is_singular_and_none_hides_the_header() {
    let one = [describe(
        &dto("kernel", "pidfd-info", ChainState::Full),
        Distro::Other,
    )];
    assert_eq!(
        summarize(&one).expect("summary").text,
        "1 protection active"
    );
    let desktop = [describe(
        &dto("tray", "status-notifier", ChainState::Full),
        Distro::Other,
    )];
    assert_eq!(summarize(&desktop), None);
    assert_eq!(summarize(&[]), None);
}

#[test]
fn memory_reading_off_is_red_with_the_probe_reason() {
    let report = Report::evaluate(&[memory_chain(&Err(
        "process 4312 is tracing Vaultkeeper".to_owned()
    ))]);
    let rows = describe_all(&to_dto(&report).chains, Distro::Other);
    assert_eq!((rows[0].level, rows[0].tone), (Level::Off, Tone::Red));
    assert_eq!(
        rows[0].detail,
        "Not in effect: process 4312 is tracing Vaultkeeper."
    );
}

#[test]
fn weak_links_are_limited_and_nothing_links_are_off() {
    for (chain, link, level) in [
        ("key-memory", "keyctl", Level::Limited),
        ("key-memory", "mlock", Level::Limited),
        ("kernel", "peer-pidfd", Level::Limited),
        ("lock-sleep", "screensaver", Level::Limited),
        ("clipboard", "plain", Level::Limited),
        ("tray", "none", Level::Off),
        ("notifications", "window-and-log", Level::Off),
        ("hotkey", "compositor-binding", Level::Active),
        ("clipboard", "portal-clipboard", Level::Active),
    ] {
        let state = if level == Level::Active {
            ChainState::Full
        } else {
            ChainState::Standard
        };
        assert_eq!(
            describe(&dto(chain, link, state), Distro::Other).level,
            level,
            "{chain}/{link}"
        );
    }
}

#[test]
fn every_registered_link_has_wording() {
    let mut all = chains(&facts(Backend::TpmAndHost), Role::Daemon);
    all.push(clipboard("ext-data-control"));
    all.push(sandbox_chain(&applied(Enforcement::Full)));
    all.push(sandbox_chain(&Sandbox::NotRequested));
    all.push(memory_chain(&Ok(())));
    for chain in &all {
        for link in &chain.links {
            let report = dto(chain.id, link.id, ChainState::Full);
            let row = describe(&report, Distro::Other);
            assert!(
                !row.protects.is_empty(),
                "{}/{}: protects",
                chain.id,
                link.id
            );
            assert!(!row.detail.is_empty(), "{}/{}: detail", chain.id, link.id);
            assert_ne!(row.title, chain.id, "{}: title", chain.id);
        }
    }
}

#[test]
fn the_plain_text_lists_rows_then_the_desktop_group() {
    let text = status_text(&rows(&facts(Backend::Host)));
    assert!(
        text.starts_with("7 of 9 protections active · 1 limited · 1 off\n\n"),
        "{text}"
    );
    assert!(text.contains("Encryption keys in memory"), "{text}");
    assert!(
        text.contains("Limited  AES-256-GCM + systemd-creds (host key only)"),
        "{text}"
    );
    assert!(
        text.contains("    Fix: Check for a chip: systemd-creds has-tpm2"),
        "{text}"
    );
    assert!(
        text.contains("Desktop integration (not counted)\nTray icon"),
        "{text}"
    );
    assert!(!text.contains("reported by the running app"), "{text}");

    let cli = status_text(&describe_all(
        &[dto("kernel", "pidfd-info", ChainState::Full)],
        Distro::Other,
    ));
    assert!(
        cli.ends_with("are reported by the running app: Settings → System protection.\n"),
        "{cli}"
    );
    assert!(
        cli.contains("App sandbox, Memory reading by other programs"),
        "{cli}"
    );
}
