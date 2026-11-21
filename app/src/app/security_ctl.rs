//! Settings: the summary line and the protections list (linux-plan.md 3l), filled from the
//! protection chains the daemon last reported.

use slint::{ModelRc, SharedString, VecModel};
use vk_vault::VaultService;
use zeroize::Zeroizing;

use super::{App, handler};
use crate::{
    hooks::{ChainDto, ChainState, HookResult, SecurityReportDto},
    settings::Settings,
    ui::{AcceptedIssueRow, SecurityChainRow, SettingsWindow},
};

/// The chain whose Install… button prints the privileged helper's command (step 4c).
const BPF_CHAIN: &str = "bpf";

/// "Security: Full · BPF LSM · memfd_secret": the weakest chain's status, then every mechanism in
/// use. Empty without chains (macOS, Windows), which hides the line.
fn summary(report: &SecurityReportDto) -> String {
    let Some(overall) = report.chains.iter().map(|chain| chain.state).min() else {
        return String::new();
    };
    let mut mechanisms: Vec<&str> = Vec::new();
    for mechanism in report
        .chains
        .iter()
        .flat_map(|chain| chain.active.iter().chain(&chain.stacked))
    {
        if !mechanisms.contains(&mechanism.as_str()) {
            mechanisms.push(mechanism);
        }
    }
    let mut line = format!("Security: {}", overall.label());
    for mechanism in mechanisms {
        line.push_str(" · ");
        line.push_str(mechanism);
    }
    line
}

fn row(chain: &ChainDto) -> SecurityChainRow {
    let using: Vec<&str> = chain
        .active
        .iter()
        .chain(&chain.stacked)
        .map(String::as_str)
        .collect();
    let installable = chain.id == BPF_CHAIN && chain.state != ChainState::Full;
    SecurityChainRow {
        id: chain.id.clone().into(),
        name: chain.name.clone().into(),
        state: chain.state.label().into(),
        using: using.join(" + ").into(),
        next: chain.fallback.clone().unwrap_or_default().into(),
        note: chain.note.clone().unwrap_or_default().into(),
        fix: chain.fix.clone().unwrap_or_default().into(),
        action: if installable && chain.fix.is_some() {
            "Install…".into()
        } else {
            SharedString::new()
        },
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
        let rows: Vec<SecurityChainRow> = report.chains.iter().map(row).collect();
        window.set_security_summary(summary(&report).into());
        window.set_security_chains(ModelRc::new(VecModel::from(rows)));
        window.set_security_accepted(ModelRc::new(VecModel::from(accepted_rows(
            &self.settings.borrow(),
            &report,
        ))));
    }

    /// Asks the daemon to probe again; the window fills when the answer arrives.
    pub(super) fn recheck_security(&self) {
        let report = self.hooks.security.report();
        self.exec.spawn(
            report,
            handler!(self, |app, result| app.security_checked(result)),
        );
    }

    fn security_checked(&self, result: HookResult<SecurityReportDto>) {
        match result {
            Ok(report) => {
                *self.security.borrow_mut() = report;
                if let Some(window) = self.settings_window() {
                    self.fill_security(&window);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot read the security status from the daemon");
                self.report(Err(error));
            }
        }
    }

    pub(super) fn bind_security(&self, window: &SettingsWindow) {
        window.on_security_recheck(handler!(self, |app| app.recheck_security()));
        window.on_security_action(handler!(self, |app, id| app.copy_security_fix(&id)));
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

    fn forget_accepted(&self, id: &str) {
        self.update_settings(|settings| {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(id: &str, state: ChainState, active: &str) -> ChainDto {
        ChainDto {
            id: id.to_owned(),
            name: id.to_uppercase(),
            state,
            active: Some(active.to_owned()),
            stacked: Vec::new(),
            fallback: None,
            note: None,
            fix: None,
        }
    }

    #[test]
    fn the_summary_names_the_weakest_status_and_each_mechanism_once() {
        let report = SecurityReportDto {
            chains: vec![
                chain("bpf", ChainState::Full, "BPF LSM"),
                ChainDto {
                    stacked: vec!["Landlock 11".to_owned()],
                    ..chain("keys", ChainState::Standard, "memfd_secret")
                },
                chain("peer", ChainState::Full, "pidfd"),
                chain("again", ChainState::Full, "pidfd"),
            ],
        };
        assert_eq!(
            summary(&report),
            "Security: Standard · BPF LSM · memfd_secret · Landlock 11 · pidfd"
        );
    }

    #[test]
    fn no_chains_means_no_summary() {
        assert_eq!(summary(&SecurityReportDto::default()), "");
    }

    #[test]
    fn only_a_bpf_chain_with_a_fix_offers_install() {
        let mut bpf = chain("bpf", ChainState::Off, "none");
        assert_eq!(row(&bpf).action, "");
        bpf.fix = Some("sudo vaultkeeper-bpf install".to_owned());
        assert_eq!(row(&bpf).action, "Install…");
        let mut other = chain("keys", ChainState::Off, "none");
        other.fix = Some("fix".to_owned());
        assert_eq!(row(&other).action, "");
    }
}
