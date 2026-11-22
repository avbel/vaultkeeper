//! Settings: the summary line and the protections list filled from the protection
//! chains the daemon last reported.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicBool, Ordering},
};

use slint::{ModelRc, SharedString, VecModel};
use vk_vault::VaultService;
use zeroize::Zeroizing;

use super::{App, handler};
use crate::{
    hooks::{HookResult, SecurityReportDto},
    os::{
        protection_catalog::{ProtectionRow, Tone, describe_all, plain_text, sections, summarize},
        security_gate::Distro,
    },
    settings::Settings,
    ui::{AcceptedIssueRow, ProtectionRow as SlintProtectionRow, SettingsWindow, SummarySegment},
};

static START_OVERRIDDEN: AtomicBool = AtomicBool::new(false);

/// Records that this process started although a required protection is missing (a refusal
/// covered by `--skip-security-issues` or an accepted set), so its windows carry the badge.
/// `enforce` only returns a report with refusals when the start was overridden.
pub fn note_start(report: &vk_platform::security::Report) {
    START_OVERRIDDEN.store(!report.refusals().is_empty(), Ordering::Relaxed);
}

pub(super) fn start_overridden() -> bool {
    START_OVERRIDDEN.load(Ordering::Relaxed)
}

/// Where "Learn more" leads.
const GUIDE_URL: &str =
    "https://github.com/avbel/vaultkeeper/blob/main/docs/USAGE.md#system-protection";

/// The section is Linux-only: no other system registers protection chains, and none should show
/// rows made of Linux wording if some are added.
fn catalog_rows(report: &SecurityReportDto) -> Vec<ProtectionRow> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    describe_all(&report.chains, current_distro())
}

#[cfg(target_os = "linux")]
fn current_distro() -> Distro {
    crate::os::security_gate::detect_distro()
}

#[cfg(not(target_os = "linux"))]
const fn current_distro() -> Distro {
    Distro::Other
}

fn slint_row(section: &str, row: &ProtectionRow) -> SlintProtectionRow {
    let strings = |items: &[String]| {
        ModelRc::new(VecModel::from(
            items
                .iter()
                .map(|item| item.as_str().into())
                .collect::<Vec<SharedString>>(),
        ))
    };
    SlintProtectionRow {
        id: row.id.as_str().into(),
        section: section.into(),
        title: row.title.as_str().into(),
        protects: row.protects.as_str().into(),
        level: row.level.word().into(),
        tone: row.tone.name().into(),
        detail: row.detail.as_str().into(),
        technical: row.technical.as_str().into(),
        steps_title: row.steps_title.as_str().into(),
        steps: strings(&row.steps),
        notes: strings(&row.notes),
        copy: row.copy.as_str().into(),
        action: row.action.as_str().into(),
        label: row.accessible_label().into(),
    }
}

/// The sections flattened into one list, each group's name riding on its first row.
fn slint_rows(rows: &[ProtectionRow]) -> Vec<SlintProtectionRow> {
    sections(rows)
        .iter()
        .flat_map(|section| {
            section
                .rows
                .iter()
                .enumerate()
                .map(|(index, row)| slint_row(if index == 0 { &section.label } else { "" }, row))
        })
        .collect()
}

/// The icon kind of the header badge: the worst state's.
fn badge_kind(tone: Tone) -> &'static str {
    match tone {
        Tone::Red => "Missing",
        Tone::Yellow => "Limited",
        Tone::Green | Tone::Neutral => "Active",
    }
}

fn accepted_rows(settings: &Settings, report: &SecurityReportDto) -> Vec<AcceptedIssueRow> {
    let Some(accepted) = &settings.security_accepted else {
        return Vec::new();
    };
    accepted
        .issues
        .iter()
        .map(|id| AcceptedIssueRow {
            id: id.clone().into(),
            name: report
                .chains
                .iter()
                .find(|chain| &chain.id == id)
                .map_or(id.as_str(), |chain| chain.name.as_str())
                .into(),
        })
        .collect()
}

impl<S: VaultService> App<S> {
    pub(super) fn fill_security(&self, window: &SettingsWindow) {
        let report = self.security.borrow();
        let rows = catalog_rows(&report);
        let summary = summarize(&rows);
        let segments: Vec<SummarySegment> = summary
            .iter()
            .flat_map(|summary| &summary.segments)
            .map(|segment| SummarySegment {
                text: segment.text.as_str().into(),
                tone: segment.tone.name().into(),
            })
            .collect();
        let tone = summary
            .as_ref()
            .map_or(Tone::Neutral, |summary| summary.tone);
        window.set_security_summary(
            summary
                .map(|summary| summary.text)
                .unwrap_or_default()
                .into(),
        );
        window.set_security_segments(ModelRc::new(VecModel::from(segments)));
        window.set_security_badge_tone(tone.name().into());
        window.set_security_badge_icon(badge_kind(tone).into());
        window.set_security_rows(ModelRc::new(VecModel::from(slint_rows(&rows))));
        window.set_security_open(self.settings.borrow().protection_open);
        window.set_security_accepted(ModelRc::new(VecModel::from(accepted_rows(
            &self.settings.borrow(),
            &report,
        ))));
    }

    pub(super) fn recheck_security(&self) {
        self.check_security(false);
    }

    fn check_security(&self, announce: bool) {
        let seq = self.security_seq.get() + 1;
        self.security_seq.set(seq);
        if let Some(window) = self.settings_window() {
            window.set_security_checking(true);
        }
        let report = self.hooks.security.report();
        self.exec.spawn(
            report,
            handler!(self, |app, result| app
                .security_checked(seq, announce, result)),
        );
    }

    /// A reply older than the newest request is dropped, so a slow first check cannot overwrite
    /// the answer to a later Re-check.
    fn security_checked(&self, seq: u64, announce: bool, result: HookResult<SecurityReportDto>) {
        if seq != self.security_seq.get() {
            return;
        }
        if let Some(window) = self.settings_window() {
            window.set_security_checking(false);
        }
        match result {
            Ok(report) => {
                *self.security.borrow_mut() = report;
                if let Some(window) = self.settings_window() {
                    self.clear_security_error(&window);
                    self.fill_security(&window);
                }
                if announce {
                    self.toast("Protection status updated", false);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot read the security status from the daemon");
                *self.security_error.borrow_mut() = error.to_string();
                self.report(Err(error));
            }
        }
    }

    /// Clears the error text only while it is still the one a failed check set, so a good check
    /// never wipes an unrelated message such as "Settings not saved".
    fn clear_security_error(&self, window: &SettingsWindow) {
        let ours = self.security_error.take();
        if !ours.is_empty() && window.get_error_text() == ours.as_str() {
            self.report(Ok(()));
        }
    }

    pub(super) fn bind_security(&self, window: &SettingsWindow) {
        window.on_security_recheck(handler!(self, |app| app.check_security(true)));
        window.on_security_action(handler!(self, |app, id| app.copy_security_fix(&id)));
        window.on_security_copy(handler!(self, false, |app, text| app
            .copy_text("that command", &Zeroizing::new(text.to_string()))));
        window.on_security_copy_details(handler!(self, |app| app.copy_security_details()));
        window.on_security_learn_more(handler!(self, |app| {
            if let Err(error) = app.hooks.opener.open(GUIDE_URL) {
                app.toast(&error.to_string(), true);
            }
        }));
        window.on_security_open_changed(handler!(self, |app, open| {
            app.update_settings(|settings| settings.protection_open = open);
        }));
        window.on_security_forget(handler!(self, |app, id| app.forget_accepted(&id)));
    }

    fn copy_security_fix(&self, id: &str) {
        let fix = self
            .security
            .borrow()
            .chains
            .iter()
            .find(|chain| chain.id == id)
            .and_then(|chain| chain.fix.clone());
        if let Some(fix) = fix {
            self.copy_text("the install command", &Zeroizing::new(fix));
        }
    }

    fn copy_security_details(&self) {
        let rows = catalog_rows(&self.security.borrow());
        let mut text = plain_text(&rows);
        let _ = write!(
            text,
            "\nVaultkeeper {}\n{}",
            env!("CARGO_PKG_VERSION"),
            system_line()
        );
        self.copy_text("protection details", &Zeroizing::new(text));
    }

    fn forget_accepted(&self, id: &str) {
        // `vaultkeeper security accept` may have written the file since this window loaded it.
        let stored = self.hooks.settings.load().security_accepted;
        self.update_settings(|settings| {
            settings.security_accepted = stored;
            if let Some(accepted) = settings.security_accepted.as_mut() {
                accepted.issues.retain(|issue| issue != id);
            }
            if settings
                .security_accepted
                .as_ref()
                .is_some_and(|accepted| accepted.issues.is_empty())
            {
                settings.security_accepted = None;
            }
        });
        if let Some(window) = self.settings_window() {
            self.fill_security(&window);
        }
    }
}

/// The distribution and kernel, so a pasted report says what it was taken on.
fn system_line() -> String {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    format!("Distribution: {:?}\nKernel: {kernel}\n", current_distro())
}
