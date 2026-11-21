//! The IPC side of the protection chains: Settings in the UI process shows what the daemon
//! probed (linux-plan.md 3l).

use vk_ipc::{ChainDto, ChainState, SecurityFuture, SecurityHost, SecurityReportDto};
use vk_platform::security::{ChainReport, ChainStatus, Report};

use crate::os::security_gate;

pub struct SecurityReports;

impl SecurityHost for SecurityReports {
    fn report(&self) -> SecurityFuture {
        Box::pin(async {
            // Probes read /proc, /sys and sockets; keep them off the async workers.
            tokio::task::spawn_blocking(|| to_dto(&daemon_report()))
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "the security probes did not finish");
                    SecurityReportDto::default()
                })
        })
    }
}

/// The chains probed again, with the tray row the shell reports (it tracks the watcher coming
/// and going) in place of the name-probe row, so Settings shows one C13.
fn daemon_report() -> Report {
    #[cfg(target_os = "linux")]
    {
        with_live_tray(security_gate::recheck(), security_gate::tray_report())
    }
    #[cfg(not(target_os = "linux"))]
    {
        security_gate::recheck()
    }
}

#[cfg(any(target_os = "linux", test))]
fn with_live_tray(report: Report, live: Option<ChainReport>) -> Report {
    let Some(live) = live else {
        return report;
    };
    let mut live = Some(live);
    let mut chains: Vec<ChainReport> = report
        .chains
        .into_iter()
        .map(|chain| match &live {
            Some(tray) if tray.id == chain.id => live.take().unwrap_or(chain),
            _ => chain,
        })
        .collect();
    chains.extend(live);
    Report { chains }
}

fn state(status: ChainStatus) -> ChainState {
    match status {
        ChainStatus::Off => ChainState::Off,
        ChainStatus::Reduced => ChainState::Reduced,
        ChainStatus::Standard => ChainState::Standard,
        ChainStatus::Full => ChainState::Full,
    }
}

fn chain(chain: &ChainReport) -> ChainDto {
    ChainDto {
        id: chain.id.clone(),
        name: chain.name.clone(),
        state: state(chain.status),
        active: chain.active.clone(),
        stacked: chain.stacked.clone(),
        fallback: chain.fallback.clone(),
        note: chain.note.clone(),
        fix: chain.fix.clone(),
    }
}

#[must_use]
pub fn to_dto(report: &Report) -> SecurityReportDto {
    SecurityReportDto {
        chains: report.chains.iter().map(chain).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_report_keeps_its_fields_on_the_wire() {
        let report = Report {
            chains: vec![ChainReport {
                id: "key-memory".to_owned(),
                name: "Keys in memory".to_owned(),
                required: vk_platform::security::Required::Refuse,
                status: ChainStatus::Reduced,
                active: Some("mlock".to_owned()),
                stacked: vec!["MDWE".to_owned()],
                fallback: None,
                skipped: Vec::new(),
                note: Some("swap".to_owned()),
                fix: Some("fix it".to_owned()),
            }],
        };
        let dto = to_dto(&report);
        assert_eq!(dto.chains[0].state, ChainState::Reduced);
        assert_eq!(dto.chains[0].active.as_deref(), Some("mlock"));
        assert_eq!(dto.chains[0].stacked, ["MDWE"]);
        assert_eq!(dto.chains[0].fix.as_deref(), Some("fix it"));
    }

    #[test]
    fn the_live_tray_row_replaces_the_probed_one_in_place() {
        let row = |id: &str, status| ChainReport {
            id: id.to_owned(),
            name: id.to_owned(),
            required: vk_platform::security::Required::Status,
            status,
            active: None,
            stacked: Vec::new(),
            fallback: None,
            skipped: Vec::new(),
            note: None,
            fix: None,
        };
        let report = Report {
            chains: vec![
                row("kernel", ChainStatus::Full),
                row("tray", ChainStatus::Reduced),
                row("portal", ChainStatus::Full),
            ],
        };
        let merged = with_live_tray(report.clone(), Some(row("tray", ChainStatus::Full)));
        let ids: Vec<_> = merged.chains.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["kernel", "tray", "portal"]);
        assert_eq!(merged.chains[1].status, ChainStatus::Full);
        assert_eq!(with_live_tray(report.clone(), None), report);
    }
}
