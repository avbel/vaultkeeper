//! Settings: the security summary line and the protections list, rendered from fake daemon
//! reports with the Slint testing backend.

mod common;

use std::sync::{Arc, Mutex, PoisonError};

use common::{Harness, Setup, click, harness, pump};
use slint::ComponentHandle;
use vaultkeeper::{
    hooks::{ChainDto, ChainState, HookFuture, SecurityReportDto, SecurityStatus, SettingsStore},
    os::security_gate::Accepted,
    settings::Settings,
    ui::SettingsWindow,
};

#[derive(Default)]
struct FakeDaemon {
    reports: Mutex<Vec<SecurityReportDto>>,
}

impl FakeDaemon {
    fn with(reports: Vec<SecurityReportDto>) -> Arc<Self> {
        Arc::new(Self {
            reports: Mutex::new(reports),
        })
    }
}

impl SecurityStatus for FakeDaemon {
    fn report(&self) -> HookFuture<SecurityReportDto> {
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        let next = if reports.len() > 1 {
            reports.remove(0)
        } else {
            reports.first().cloned().unwrap_or_default()
        };
        Box::pin(async { Ok(next) })
    }
}

fn chain(id: &str, name: &str, state: ChainState, active: Option<&str>) -> ChainDto {
    ChainDto {
        id: id.to_owned(),
        name: name.to_owned(),
        state,
        active: active.map(str::to_owned),
        stacked: Vec::new(),
        fallback: None,
        note: None,
        fix: None,
    }
}

fn full_report() -> SecurityReportDto {
    SecurityReportDto {
        chains: vec![
            ChainDto {
                fallback: Some("PIDFD".to_owned()),
                ..chain("bpf", "BPF LSM", ChainState::Full, Some("BPF LSM"))
            },
            ChainDto {
                stacked: vec!["Landlock 11".to_owned()],
                note: Some("swap is on".to_owned()),
                ..chain(
                    "key-memory",
                    "Keys in memory",
                    ChainState::Full,
                    Some("memfd_secret"),
                )
            },
        ],
    }
}

fn open(report: Vec<SecurityReportDto>, settings: Settings) -> (Harness, SettingsWindow) {
    let h = harness(Setup {
        settings,
        security: Some(FakeDaemon::with(report)),
        ..Setup::default()
    });
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings");
    window
        .window()
        .set_size(slint::LogicalSize::new(520.0, 1600.0));
    pump();
    (h, window)
}

#[test]
fn security_ctl_the_summary_line_names_the_status_and_the_mechanisms() {
    let (_h, window) = open(vec![full_report()], Settings::default());
    assert_eq!(
        window.get_security_summary(),
        "Security: Full · BPF LSM · memfd_secret · Landlock 11"
    );
    assert!(!window.get_security_open(), "the list starts closed");
}

#[test]
fn security_ctl_clicking_the_summary_lists_every_chain() {
    let (_h, window) = open(vec![full_report()], Settings::default());
    click(
        &window,
        "Security: Full · BPF LSM · memfd_secret · Landlock 11",
    );
    assert!(window.get_security_open());
    let rows = window.get_security_chains();
    assert_eq!(slint::Model::row_count(&rows), 2);
    let keys = slint::Model::row_data(&rows, 1).expect("row");
    assert_eq!(keys.name, "Keys in memory");
    assert_eq!(keys.state, "Full");
    assert_eq!(keys.using, "memfd_secret + Landlock 11");
    assert_eq!(keys.note, "swap is on");
    let bpf = slint::Model::row_data(&rows, 0).expect("row");
    assert_eq!(bpf.next, "PIDFD");
    common::find(&window, "Re-check");
    common::find(&window, "Keys in memory");
}

#[test]
fn security_ctl_re_check_replaces_the_report() {
    let reduced = SecurityReportDto {
        chains: vec![ChainDto {
            fix: Some("remove secretmem.enable=0".to_owned()),
            ..chain(
                "key-memory",
                "Keys in memory",
                ChainState::Reduced,
                Some("mlock"),
            )
        }],
    };
    let (_h, window) = open(vec![full_report(), reduced], Settings::default());
    click(
        &window,
        "Security: Full · BPF LSM · memfd_secret · Landlock 11",
    );
    click(&window, "Re-check");
    assert_eq!(window.get_security_summary(), "Security: Reduced · mlock");
    let row = slint::Model::row_data(&window.get_security_chains(), 0).expect("row");
    assert_eq!(row.fix, "remove secretmem.enable=0");
}

#[test]
fn security_ctl_forget_drops_one_accepted_issue_and_saves() {
    let accepted = Accepted {
        fingerprint: "f".to_owned(),
        issues: vec!["wayland".to_owned()],
    };
    let off = SecurityReportDto {
        chains: vec![chain("wayland", "Wayland session", ChainState::Off, None)],
    };
    let (h, window) = open(
        vec![off],
        Settings {
            security_accepted: Some(accepted),
            ..Settings::default()
        },
    );
    assert_eq!(window.get_security_summary(), "Security: Off");
    click(&window, "Security: Off");
    let issues = window.get_security_accepted();
    assert_eq!(slint::Model::row_count(&issues), 1);
    assert_eq!(
        slint::Model::row_data(&issues, 0).expect("row").name,
        "Wayland session"
    );
    click(&window, "Forget Wayland session");
    assert_eq!(slint::Model::row_count(&window.get_security_accepted()), 0);
    assert_eq!(h.settings.load().security_accepted, None);
}

#[test]
fn security_ctl_the_bpf_row_offers_install_and_copies_the_command() {
    let missing = SecurityReportDto {
        chains: vec![ChainDto {
            fix: Some("sudo vaultkeeper-bpf install".to_owned()),
            ..chain("bpf", "BPF LSM", ChainState::Off, None)
        }],
    };
    let (h, window) = open(vec![missing], Settings::default());
    click(&window, "Security: Off");
    click(&window, "Install… BPF LSM");
    assert_eq!(
        h.clipboard.last().as_deref(),
        Some("sudo vaultkeeper-bpf install")
    );
}

#[test]
fn security_ctl_without_chains_nothing_shows() {
    let (_h, window) = open(vec![SecurityReportDto::default()], Settings::default());
    assert_eq!(window.get_security_summary(), "");
    assert_eq!(slint::Model::row_count(&window.get_security_chains()), 0);
}
