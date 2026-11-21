//! Settings: the security summary line and the protections list, rendered from fake daemon
//! reports with the Slint testing backend.

mod common;

use std::sync::{Arc, Mutex, PoisonError};

use common::{Harness, Setup, click, harness, pump};
use slint::ComponentHandle;
use vaultkeeper::{
    hooks::{
        ChainDto, ChainState, HookError, HookFuture, SecurityReportDto, SecurityStatus,
        SettingsStore,
    },
    os::security_gate::Accepted,
    settings::Settings,
    ui::SettingsWindow,
};

#[derive(Default)]
struct FakeDaemon {
    reports: Mutex<Vec<SecurityReportDto>>,
    /// Answers `Err` while set.
    failing: std::sync::atomic::AtomicBool,
}

impl FakeDaemon {
    fn with(reports: Vec<SecurityReportDto>) -> Arc<Self> {
        Arc::new(Self {
            reports: Mutex::new(reports),
            failing: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

impl SecurityStatus for FakeDaemon {
    fn report(&self) -> HookFuture<SecurityReportDto> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Box::pin(async { Err(HookError::Failed("the daemon is gone".to_owned())) });
        }
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
    open_with(&FakeDaemon::with(report), settings)
}

fn open_with(daemon: &Arc<FakeDaemon>, settings: Settings) -> (Harness, SettingsWindow) {
    let h = harness(Setup {
        settings,
        security: Some(Arc::clone(daemon) as Arc<dyn SecurityStatus>),
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

#[test]
fn security_ctl_a_failed_re_check_shows_the_error_and_a_good_one_clears_it() {
    let daemon = FakeDaemon::with(vec![full_report()]);
    let (_h, window) = open_with(&daemon, Settings::default());
    assert_eq!(window.get_error_text(), "");
    click(
        &window,
        "Security: Full · BPF LSM · memfd_secret · Landlock 11",
    );
    daemon
        .failing
        .store(true, std::sync::atomic::Ordering::SeqCst);
    click(&window, "Re-check");
    assert!(window.get_error_text().contains("the daemon is gone"));
    assert_eq!(
        window.get_security_summary(),
        "Security: Full · BPF LSM · memfd_secret · Landlock 11",
        "the last good report stays"
    );
    daemon
        .failing
        .store(false, std::sync::atomic::Ordering::SeqCst);
    click(&window, "Re-check");
    assert_eq!(window.get_error_text(), "");
}

#[test]
fn security_ctl_forget_keeps_issues_the_cli_accepted_meanwhile() {
    let accepted = |issues: &[&str]| Accepted {
        fingerprint: "f".to_owned(),
        issues: issues.iter().map(|issue| (*issue).to_owned()).collect(),
    };
    let report = SecurityReportDto {
        chains: vec![chain("wayland", "Wayland session", ChainState::Off, None)],
    };
    let (h, window) = open(
        vec![report],
        Settings {
            security_accepted: Some(accepted(&["wayland"])),
            ..Settings::default()
        },
    );
    click(&window, "Security: Off");
    h.settings
        .save(&Settings {
            security_accepted: Some(accepted(&["wayland", "kernel"])),
            ..Settings::default()
        })
        .expect("save");
    click(&window, "Forget Wayland session");
    assert_eq!(
        h.settings.load().security_accepted,
        Some(accepted(&["kernel"]))
    );
}

type Nested = Box<dyn Fn()>;

thread_local! {
    /// Starts a second check from inside the first one's request; a Slint callback cannot be
    /// re-entered, so this goes through the app instead.
    static NESTED: std::cell::RefCell<Option<Nested>> = const { std::cell::RefCell::new(None) };
}

/// Answers its first armed request only after a second request was made and answered, as a slow
/// daemon reply would arrive.
struct Overtaken {
    reports: Mutex<Vec<SecurityReportDto>>,
    armed: std::sync::atomic::AtomicBool,
}

impl SecurityStatus for Overtaken {
    fn report(&self) -> HookFuture<SecurityReportDto> {
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        let mine = if reports.len() > 1 {
            reports.remove(0)
        } else {
            reports[0].clone()
        };
        drop(reports);
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            NESTED.with(|nested| (nested.borrow().as_ref().expect("nested check"))());
        }
        Box::pin(async { Ok(mine) })
    }
}

fn single(mechanism: &str) -> SecurityReportDto {
    SecurityReportDto {
        chains: vec![chain("keys", "Keys", ChainState::Full, Some(mechanism))],
    }
}

#[test]
fn security_ctl_a_stale_reply_does_not_overwrite_a_newer_one() {
    let daemon = Arc::new(Overtaken {
        reports: Mutex::new(vec![single("opening"), single("stale"), single("newest")]),
        armed: std::sync::atomic::AtomicBool::new(false),
    });
    let h = harness(Setup {
        security: Some(Arc::clone(&daemon) as Arc<dyn SecurityStatus>),
        ..Setup::default()
    });
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings");
    pump();
    assert_eq!(window.get_security_summary(), "Security: Full · opening");
    let app = std::rc::Rc::clone(&h.app);
    NESTED.with(|slot| *slot.borrow_mut() = Some(Box::new(move || app.open_settings())));
    daemon
        .armed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    window.invoke_security_recheck();
    pump();
    assert_eq!(window.get_security_summary(), "Security: Full · newest");
    NESTED.with(|slot| slot.borrow_mut().take());
}

#[test]
fn security_ctl_a_good_check_leaves_an_unrelated_error_alone() {
    let daemon = FakeDaemon::with(vec![full_report()]);
    let (_h, window) = open_with(&daemon, Settings::default());
    window.set_error_text("Settings not saved".into());
    click(
        &window,
        "Security: Full · BPF LSM · memfd_secret · Landlock 11",
    );
    click(&window, "Re-check");
    assert_eq!(window.get_error_text(), "Settings not saved");
}
