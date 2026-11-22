//! Settings: the System protection section, rendered from fake daemon reports with the Slint
//! testing backend. The section is Linux-only, so the rendering tests run there.

mod common;

use std::sync::{Arc, Mutex, PoisonError};

#[cfg(target_os = "linux")]
use common::click;
use common::{Harness, Setup, harness, pump};
use slint::ComponentHandle;
use vaultkeeper::{
    hooks::{
        ChainDto, ChainRequired, ChainState, HookError, HookFuture, SecurityReportDto,
        SecurityStatus,
    },
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

fn chain(id: &str, name: &str, state: ChainState, active_id: Option<&str>) -> ChainDto {
    ChainDto {
        id: id.to_owned(),
        name: name.to_owned(),
        state,
        active: active_id.map(str::to_owned),
        stacked: Vec::new(),
        fallback: None,
        note: None,
        fix: None,
        active_id: active_id.map(str::to_owned),
        stacked_ids: Vec::new(),
        required: ChainRequired::Status,
        skipped: Vec::new(),
    }
}

/// Two healthy chains and the sandbox in its default, not-requested state.
fn report() -> SecurityReportDto {
    SecurityReportDto {
        chains: vec![
            chain("kernel", "Kernel", ChainState::Full, Some("pidfd-info")),
            chain(
                "key-memory",
                "Keys in memory",
                ChainState::Full,
                Some("memfd-secret"),
            ),
            ChainDto {
                note: Some("off unless Vaultkeeper starts with VAULTKEEPER_LANDLOCK=1".to_owned()),
                skipped: vec![vaultkeeper::hooks::SkippedDto {
                    link: "landlock".to_owned(),
                    why: "not requested".to_owned(),
                }],
                ..chain(
                    "sandbox",
                    "Self-sandbox",
                    ChainState::Standard,
                    Some("no-sandbox"),
                )
            },
        ],
    }
}

#[cfg(target_os = "linux")]
const SUMMARY: &str = "2 of 3 protections active · 1 off";

#[cfg(target_os = "linux")]
fn opened() -> Settings {
    Settings {
        protection_open: true,
        ..Settings::default()
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
        .set_size(slint::LogicalSize::new(520.0, 6000.0));
    pump();
    (h, window)
}

fn rows(window: &SettingsWindow) -> Vec<vaultkeeper::ui::ProtectionRow> {
    let model = window.get_security_rows();
    (0..slint::Model::row_count(&model))
        .filter_map(|index| slint::Model::row_data(&model, index))
        .collect()
}

#[cfg(not(target_os = "linux"))]
#[test]
fn security_ctl_other_systems_show_no_section_even_with_chains() {
    let (_h, window) = open(vec![report()], Settings::default());
    assert_eq!(window.get_security_summary(), "");
    assert_eq!(rows(&window).len(), 0);
}

#[cfg(target_os = "linux")]
mod linux {
    use vaultkeeper::{hooks::SettingsStore, os::security_gate::Accepted};

    use super::*;

    #[test]
    fn security_ctl_the_header_counts_protections_and_starts_closed() {
        let (_h, window) = open(vec![report()], Settings::default());
        assert_eq!(window.get_security_summary(), SUMMARY);
        assert!(!window.get_security_open(), "the section starts closed");
        let segments = window.get_security_segments();
        assert_eq!(slint::Model::row_count(&segments), 2);
        assert_eq!(
            slint::Model::row_data(&segments, 1).expect("segment").tone,
            "yellow"
        );
        assert_eq!(window.get_security_badge_tone(), "yellow");
    }

    #[test]
    fn security_ctl_opening_lists_the_attention_row_first_and_remembers_the_state() {
        let (h, window) = open(vec![report()], Settings::default());
        click(&window, &format!("System protection: {SUMMARY}"));
        assert!(window.get_security_open());
        assert!(h.settings.load().protection_open, "the open state is saved");

        let rows = rows(&window);
        assert_eq!(rows[0].section, "NEEDS ATTENTION");
        assert_eq!(rows[0].title, "App sandbox");
        assert_eq!(rows[0].level, "Off");
        assert_eq!(rows[0].tone, "yellow");
        assert_eq!(rows[0].steps_title, "Turn the sandbox on");
        assert_eq!(rows[1].section, "MEMORY");
        assert_eq!(rows[1].title, "Encryption keys in memory");
        assert_eq!(rows[1].level, "Active");
        assert_eq!(rows[1].technical, "memfd_secret");
        common::find(&window, "Re-check");
        common::find(&window, "Copy details");
        common::find(&window, "Learn more");
    }

    #[test]
    fn security_ctl_a_saved_open_state_opens_the_section() {
        let (_h, window) = open(vec![report()], opened());
        assert!(window.get_security_open());
        click(&window, &format!("System protection: {SUMMARY}"));
        assert!(!window.get_security_open());
    }

    #[test]
    fn security_ctl_re_check_replaces_the_report() {
        let healthy = SecurityReportDto {
            chains: vec![chain(
                "kernel",
                "Kernel",
                ChainState::Full,
                Some("pidfd-info"),
            )],
        };
        let (_h, window) = open(vec![report(), healthy], opened());
        click(&window, "Re-check");
        assert_eq!(window.get_security_summary(), "1 protection active");
        assert_eq!(rows(&window).len(), 1);
    }

    #[test]
    fn security_ctl_copy_puts_the_sandbox_command_on_the_clipboard() {
        let (h, window) = open(vec![report()], opened());
        let command = rows(&window)[0].copy.to_string();
        assert!(window.invoke_security_copy(command.as_str().into()));
        assert_eq!(h.clipboard.last().as_deref(), Some(command.as_str()));
        assert!(command.ends_with("> ~/.config/environment.d/vaultkeeper.conf"));
    }

    #[test]
    fn security_ctl_copy_details_has_the_headline_and_the_rows() {
        let (h, window) = open(vec![report()], opened());
        window.invoke_security_copy_details();
        pump();
        let text = h.clipboard.last().expect("copied");
        assert!(text.starts_with(&format!("{SUMMARY}\n\n")), "{text}");
        assert!(text.contains("App sandbox"), "{text}");
        assert!(text.contains("Landlock, not requested"), "{text}");
        assert!(text.contains("Vaultkeeper "), "{text}");
        assert!(text.contains("Kernel: "), "{text}");
    }

    #[test]
    fn security_ctl_forget_drops_one_accepted_issue_and_saves() {
        let accepted = Accepted {
            fingerprint: "f".to_owned(),
            issues: vec!["wayland".to_owned()],
        };
        let off = SecurityReportDto {
            chains: vec![ChainDto {
                required: ChainRequired::Refuse,
                ..chain("wayland", "Wayland session", ChainState::Off, None)
            }],
        };
        let (h, window) = open(
            vec![off],
            Settings {
                security_accepted: Some(accepted),
                ..opened()
            },
        );
        assert_eq!(
            window.get_security_summary(),
            "0 of 1 protection active · 1 missing"
        );
        assert_eq!(rows(&window)[0].level, "Missing");
        let issues = window.get_security_accepted();
        assert_eq!(slint::Model::row_count(&issues), 1);
        click(&window, "Forget Wayland session");
        assert_eq!(slint::Model::row_count(&window.get_security_accepted()), 0);
        assert_eq!(h.settings.load().security_accepted, None);
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
                ..opened()
            },
        );
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

    #[test]
    fn security_ctl_the_bpf_row_offers_install_and_copies_the_command() {
        let missing = SecurityReportDto {
            chains: vec![ChainDto {
                fix: Some("sudo vaultkeeper-bpf install".to_owned()),
                ..chain("bpf", "BPF LSM", ChainState::Off, None)
            }],
        };
        let (h, window) = open(vec![missing], opened());
        click(&window, "Install… BPF LSM");
        assert_eq!(
            h.clipboard.last().as_deref(),
            Some("sudo vaultkeeper-bpf install")
        );
    }

    #[test]
    fn security_ctl_without_chains_nothing_shows() {
        let (_h, window) = open(vec![SecurityReportDto::default()], opened());
        assert_eq!(window.get_security_summary(), "");
        assert_eq!(rows(&window).len(), 0);
    }

    #[test]
    fn security_ctl_a_failed_re_check_shows_the_error_and_a_good_one_clears_it() {
        let daemon = FakeDaemon::with(vec![report()]);
        let (_h, window) = open_with(&daemon, opened());
        assert_eq!(window.get_error_text(), "");
        daemon
            .failing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        click(&window, "Re-check");
        assert!(window.get_error_text().contains("the daemon is gone"));
        assert!(!window.get_security_checking());
        assert_eq!(
            window.get_security_summary(),
            SUMMARY,
            "the last good report stays"
        );
        daemon
            .failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        click(&window, "Re-check");
        assert_eq!(window.get_error_text(), "");
    }

    #[test]
    fn security_ctl_a_good_check_leaves_an_unrelated_error_alone() {
        let daemon = FakeDaemon::with(vec![report()]);
        let (_h, window) = open_with(&daemon, opened());
        window.set_error_text("Settings not saved".into());
        click(&window, "Re-check");
        assert_eq!(window.get_error_text(), "Settings not saved");
    }

    type Nested = Box<dyn Fn()>;

    thread_local! {
        /// Starts a second check from inside the first one's request; a Slint callback cannot be
        /// re-entered, so this goes through the app instead.
        static NESTED: std::cell::RefCell<Option<Nested>> = const { std::cell::RefCell::new(None) };
    }

    /// Answers its first armed request only after a second request was made and answered, as a
    /// slow daemon reply would arrive.
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

    fn single(active_id: &str) -> SecurityReportDto {
        SecurityReportDto {
            chains: vec![chain("kernel", "Kernel", ChainState::Full, Some(active_id))],
        }
    }

    #[test]
    fn security_ctl_a_stale_reply_does_not_overwrite_a_newer_one() {
        let daemon = Arc::new(Overtaken {
            reports: Mutex::new(vec![
                single("pidfd-info"),
                single("peer-pidfd"),
                single("pidfd-info"),
            ]),
            armed: std::sync::atomic::AtomicBool::new(false),
        });
        let h = harness(Setup {
            security: Some(Arc::clone(&daemon) as Arc<dyn SecurityStatus>),
            ..Setup::default()
        });
        h.app.open_settings();
        let window = h.app.settings_window().expect("settings");
        pump();
        assert_eq!(window.get_security_summary(), "1 protection active");
        let app = std::rc::Rc::clone(&h.app);
        NESTED.with(|slot| *slot.borrow_mut() = Some(Box::new(move || app.open_settings())));
        daemon
            .armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        window.invoke_security_recheck();
        pump();
        assert_eq!(
            window.get_security_summary(),
            "1 protection active",
            "the newest answer (pidfd-info) wins over the stale peer-pidfd one"
        );
        assert_eq!(rows(&window)[0].technical, "PIDFD_GET_INFO");
        NESTED.with(|slot| slot.borrow_mut().take());
    }
}
