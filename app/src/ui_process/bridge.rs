//! Daemon events → the app's `UiCommand`s.

use vk_ipc::{SshApprovalKind, UiEvent};

use crate::app::{BrowserPromptRequest, SshApprovalRequest, UiCommand};

#[derive(Debug)]
// Avoid a heap allocation for every UI event; commands are short-lived.
#[allow(clippy::large_enum_variant)]
pub enum Bridged {
    Command(UiCommand),
    /// The daemon is quitting: exit now.
    Quit,
    Ignore,
}

#[must_use]
pub fn bridge(event: UiEvent) -> Bridged {
    match event {
        UiEvent::Command { command, .. } => Bridged::Command(command_for(command)),
        UiEvent::SshApproval(approval) => match approval.prompt.kind {
            SshApprovalKind::Sign => {
                let prompt = approval.prompt;
                Bridged::Command(UiCommand::ShowSshApproval(SshApprovalRequest {
                    process: prompt.process,
                    pid: prompt.pid,
                    key_name: prompt.key_name,
                    fingerprint: prompt.fingerprint,
                    purpose: prompt.purpose,
                    return_to: prompt.return_to,
                    reply: approval.reply,
                }))
            }
            // The daemon settles list requests itself; dropping the reply denies a stray one.
            SshApprovalKind::List => Bridged::Ignore,
        },
        UiEvent::BrowserPrompt(event) => {
            Bridged::Command(UiCommand::ShowBrowserPrompt(BrowserPromptRequest {
                prompt: event.prompt,
                reply: event.reply,
            }))
        }
        UiEvent::OfflineChanged(offline) => Bridged::Command(UiCommand::OfflineChanged(offline)),
        UiEvent::Skipped(_) => Bridged::Ignore,
        UiEvent::Shutdown => Bridged::Quit,
    }
}

#[must_use]
pub fn command_for(command: vk_ipc::UiCommand) -> UiCommand {
    match command {
        vk_ipc::UiCommand::ShowManager => UiCommand::ShowManager,
        vk_ipc::UiCommand::ShowQuickPanel { target } => UiCommand::ShowQuickPanel { target },
        vk_ipc::UiCommand::ToggleQuickPanel { target } => UiCommand::ToggleQuickPanel { target },
        vk_ipc::UiCommand::ShowUnlock => UiCommand::ShowUnlock,
        vk_ipc::UiCommand::ShowLogin => UiCommand::ShowLogin,
        vk_ipc::UiCommand::ShowSettings => UiCommand::ShowSettings,
        vk_ipc::UiCommand::ShowGenerator => UiCommand::ShowGenerator,
        vk_ipc::UiCommand::UnlockInTray => UiCommand::UnlockInTray,
        vk_ipc::UiCommand::ReloadSettings => UiCommand::ReloadSettings,
        vk_ipc::UiCommand::SyncFinished { error } => UiCommand::SyncFinished(error),
        vk_ipc::UiCommand::Toast { text, error } => UiCommand::Toast { text, error },
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;
    use vk_ipc::{SshApproval, SshDecision, SshPrompt};

    use super::*;

    fn prompt(kind: SshApprovalKind) -> SshPrompt {
        SshPrompt {
            kind,
            process: "git".to_owned(),
            pid: Some(7),
            key_name: "deploy".to_owned(),
            fingerprint: "SHA256:abc".to_owned(),
            purpose: Some("git commit signing".to_owned()),
            return_to: Some(vk_ipc::TypingTarget {
                pid: 377,
                name: "Terminal".to_owned(),
            }),
        }
    }

    #[test]
    fn every_daemon_command_has_its_app_command() {
        let pairs = [
            (vk_ipc::UiCommand::ShowManager, "ShowManager"),
            (
                vk_ipc::UiCommand::ShowQuickPanel { target: None },
                "ShowQuickPanel { target: None }",
            ),
            (
                vk_ipc::UiCommand::ToggleQuickPanel {
                    target: Some(vk_ipc::TypingTarget {
                        pid: 812,
                        name: "Safari".to_owned(),
                    }),
                },
                r#"ToggleQuickPanel { target: Some(TypingTarget { pid: 812, name: "Safari" }) }"#,
            ),
            (vk_ipc::UiCommand::ShowUnlock, "ShowUnlock"),
            (vk_ipc::UiCommand::ShowLogin, "ShowLogin"),
            (vk_ipc::UiCommand::ShowSettings, "ShowSettings"),
            (vk_ipc::UiCommand::ShowGenerator, "ShowGenerator"),
            (vk_ipc::UiCommand::UnlockInTray, "UnlockInTray"),
            (vk_ipc::UiCommand::ReloadSettings, "ReloadSettings"),
            (
                vk_ipc::UiCommand::SyncFinished {
                    error: Some("offline".to_owned()),
                },
                r#"SyncFinished(Some("offline"))"#,
            ),
            (
                vk_ipc::UiCommand::Toast {
                    text: "saved".to_owned(),
                    error: true,
                },
                r#"Toast { text: "saved", error: true }"#,
            ),
        ];
        for (daemon, app) in pairs {
            assert_eq!(format!("{:?}", command_for(daemon)), app);
        }
    }

    #[test]
    fn sign_requests_become_prompts_whose_answer_reaches_the_daemon() {
        let (reply, answer) = oneshot::channel();
        let event = UiEvent::SshApproval(SshApproval {
            seq: 1,
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
        assert_eq!(
            request.return_to.as_ref().map(|app| app.pid),
            Some(377),
            "the app to return to after the answer"
        );
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
            seq: 2,
            request_id: 2,
            prompt: prompt(SshApprovalKind::List),
            reply,
        });
        assert!(matches!(bridge(event), Bridged::Ignore));
        assert!(answer.blocking_recv().is_err(), "dropped, so denied");
        assert!(
            matches!(bridge(UiEvent::Skipped(3)), Bridged::Ignore),
            "a withdrawn request shows nothing"
        );
        assert!(matches!(bridge(UiEvent::Shutdown), Bridged::Quit));
        assert!(matches!(
            bridge(UiEvent::OfflineChanged(true)),
            Bridged::Command(UiCommand::OfflineChanged(true))
        ));
    }
}
