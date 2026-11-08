//! Daemon events → the app's `UiCommand`s.

use bwl_ipc::{SshApprovalKind, UiEvent};

use crate::app::{SshApprovalRequest, UiCommand};

#[derive(Debug)]
pub enum Bridged {
    Command(UiCommand),
    /// The daemon is quitting: exit now.
    Quit,
    Ignore,
}

#[must_use]
pub fn bridge(event: UiEvent) -> Bridged {
    match event {
        UiEvent::Command(command) => Bridged::Command(command_for(command)),
        UiEvent::SshApproval(approval) => match approval.prompt.kind {
            SshApprovalKind::Sign => {
                let prompt = approval.prompt;
                Bridged::Command(UiCommand::ShowSshApproval(SshApprovalRequest {
                    process: prompt.process,
                    pid: prompt.pid,
                    key_name: prompt.key_name,
                    fingerprint: prompt.fingerprint,
                    purpose: prompt.purpose,
                    reply: approval.reply,
                }))
            }
            // The daemon settles list requests itself; dropping the reply denies a stray one.
            SshApprovalKind::List => Bridged::Ignore,
        },
        UiEvent::OfflineChanged(offline) => Bridged::Command(UiCommand::OfflineChanged(offline)),
        UiEvent::Shutdown => Bridged::Quit,
    }
}

#[must_use]
pub const fn command_for(command: bwl_ipc::UiCommand) -> UiCommand {
    match command {
        bwl_ipc::UiCommand::ShowManager => UiCommand::ShowManager,
        bwl_ipc::UiCommand::ShowQuickPanel => UiCommand::ShowQuickPanel,
        bwl_ipc::UiCommand::ToggleQuickPanel => UiCommand::ToggleQuickPanel,
        bwl_ipc::UiCommand::ShowUnlock => UiCommand::ShowUnlock,
        bwl_ipc::UiCommand::ShowLogin => UiCommand::ShowLogin,
        bwl_ipc::UiCommand::ShowSettings => UiCommand::ShowSettings,
        bwl_ipc::UiCommand::ShowGenerator => UiCommand::ShowGenerator,
        bwl_ipc::UiCommand::UnlockInTray => UiCommand::UnlockInTray,
        bwl_ipc::UiCommand::ReloadSettings => UiCommand::ReloadSettings,
    }
}

#[cfg(test)]
mod tests {
    use bwl_ipc::{SshApproval, SshDecision, SshPrompt};
    use tokio::sync::oneshot;

    use super::*;

    fn prompt(kind: SshApprovalKind) -> SshPrompt {
        SshPrompt {
            kind,
            process: "git".to_owned(),
            pid: Some(7),
            key_name: "deploy".to_owned(),
            fingerprint: "SHA256:abc".to_owned(),
            purpose: Some("git commit signing".to_owned()),
        }
    }

    #[test]
    fn every_daemon_command_has_its_app_command() {
        let pairs = [
            (bwl_ipc::UiCommand::ShowManager, "ShowManager"),
            (bwl_ipc::UiCommand::ShowQuickPanel, "ShowQuickPanel"),
            (bwl_ipc::UiCommand::ToggleQuickPanel, "ToggleQuickPanel"),
            (bwl_ipc::UiCommand::ShowUnlock, "ShowUnlock"),
            (bwl_ipc::UiCommand::ShowLogin, "ShowLogin"),
            (bwl_ipc::UiCommand::ShowSettings, "ShowSettings"),
            (bwl_ipc::UiCommand::ShowGenerator, "ShowGenerator"),
            (bwl_ipc::UiCommand::UnlockInTray, "UnlockInTray"),
            (bwl_ipc::UiCommand::ReloadSettings, "ReloadSettings"),
        ];
        for (daemon, app) in pairs {
            assert_eq!(format!("{:?}", command_for(daemon)), app);
        }
    }

    #[test]
    fn sign_requests_become_prompts_whose_answer_reaches_the_daemon() {
        let (reply, answer) = oneshot::channel();
        let event = UiEvent::SshApproval(SshApproval {
            request_id: 1,
            prompt: prompt(SshApprovalKind::Sign),
            reply,
        });
        let Bridged::Command(UiCommand::ShowSshApproval(request)) = bridge(event) else {
            panic!("expected an approval prompt");
        };
        assert_eq!(
            (
                request.process.as_str(),
                request.pid,
                request.key_name.as_str()
            ),
            ("git", Some(7), "deploy")
        );
        assert_eq!(request.fingerprint, "SHA256:abc");
        request
            .reply
            .send(SshDecision::approve(false))
            .expect("daemon side waits");
        assert_eq!(answer.blocking_recv(), Ok(SshDecision::approve(false)));
    }

    #[test]
    fn stray_list_requests_are_denied_and_shutdown_quits() {
        let (reply, answer) = oneshot::channel();
        let event = UiEvent::SshApproval(SshApproval {
            request_id: 2,
            prompt: prompt(SshApprovalKind::List),
            reply,
        });
        assert!(matches!(bridge(event), Bridged::Ignore));
        assert!(answer.blocking_recv().is_err(), "dropped, so denied");
        assert!(matches!(bridge(UiEvent::Shutdown), Bridged::Quit));
        assert!(matches!(
            bridge(UiEvent::OfflineChanged(true)),
            Bridged::Command(UiCommand::OfflineChanged(true))
        ));
    }
}
