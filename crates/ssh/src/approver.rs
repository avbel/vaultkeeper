use std::time::Duration;

use anyhow::anyhow;
use ssh_agent::{ApprovalError, ApprovalRequester, SIGNamespace, SignApprovalRequest};
use tokio::sync::{mpsc, oneshot};

use crate::{ApprovalKind, ApprovalRequest};

/// Forwards agent approvals to the UI over a channel and waits for the answer on a oneshot.
pub(crate) struct ChannelApprover {
    approvals: mpsc::Sender<ApprovalRequest>,
    timeout: Duration,
}

impl ChannelApprover {
    pub(crate) fn new(approvals: mpsc::Sender<ApprovalRequest>, timeout: Duration) -> Self {
        Self { approvals, timeout }
    }

    // The timeout covers queueing too, so a UI that stopped draining the channel cannot pin the
    // connection forever. Dropping the oneshot receiver on expiry lets the UI see `reply.closed()`.
    async fn ask(&self, kind: ApprovalKind) -> Result<bool, ApprovalError> {
        let (reply, answer) = oneshot::channel();
        let exchange = async {
            self.approvals
                .send(ApprovalRequest { kind, reply })
                .await
                .map_err(|_| {
                    ApprovalError::HandlerFailed(anyhow!("the approval channel is closed"))
                })?;
            Ok(answer.await.unwrap_or(false))
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_elapsed| ApprovalError::Timeout)?
    }
}

#[async_trait::async_trait]
impl ApprovalRequester for ChannelApprover {
    async fn request_sign_approval(
        &self,
        request: SignApprovalRequest,
    ) -> Result<bool, ApprovalError> {
        self.ask(sign_kind(request)).await
    }

    async fn request_list_approval(&self) -> Result<bool, ApprovalError> {
        self.ask(ApprovalKind::List).await
    }
}

fn sign_kind(request: SignApprovalRequest) -> ApprovalKind {
    let SignApprovalRequest {
        sign_request,
        cipher_id,
    } = request;
    let connection = sign_request.connection;
    ApprovalKind::Sign {
        cipher_id,
        process_name: connection.process_name,
        is_forwarding: connection
            .session_bind
            .is_some_and(|bind| bind.is_forwarding),
        namespace: sign_request.namespace.as_ref().map(namespace_name),
    }
}

fn namespace_name(namespace: &SIGNamespace) -> String {
    match namespace {
        SIGNamespace::Git => "git",
        SIGNamespace::File => "file",
        SIGNamespace::Unsupported => "other",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use ssh_agent::{ConnectionContext, PublicKey, SessionBindContext, SignRequest};

    use super::*;

    const SHORT: Duration = Duration::from_millis(80);

    fn sign_request(
        process_name: Option<&str>,
        session_bind: Option<SessionBindContext>,
        namespace: Option<SIGNamespace>,
    ) -> SignApprovalRequest {
        SignApprovalRequest {
            sign_request: SignRequest {
                public_key: PublicKey {
                    alg: "ssh-ed25519".to_owned(),
                    blob: vec![1, 2, 3],
                },
                namespace,
                connection: ConnectionContext {
                    process_name: process_name.map(str::to_owned),
                    session_bind,
                },
            },
            cipher_id: Some("cipher-1".to_owned()),
        }
    }

    fn approver(timeout: Duration) -> (ChannelApprover, mpsc::Receiver<ApprovalRequest>) {
        let (tx, rx) = mpsc::channel(4);
        (ChannelApprover::new(tx, timeout), rx)
    }

    async fn answer_with(mut rx: mpsc::Receiver<ApprovalRequest>, verdict: bool) -> ApprovalKind {
        let request = rx.recv().await.expect("a request is queued");
        request.reply.send(verdict).expect("the agent is waiting");
        request.kind
    }

    #[tokio::test]
    async fn sign_approved_carries_process_forwarding_and_namespace() {
        let (approver, rx) = approver(Duration::from_secs(5));
        let ui = tokio::spawn(answer_with(rx, true));
        let bind = SessionBindContext {
            is_forwarding: true,
            host_fingerprint: "SHA256:host".to_owned(),
        };

        let verdict = approver
            .request_sign_approval(sign_request(
                Some("ssh-keygen"),
                Some(bind),
                Some(SIGNamespace::Git),
            ))
            .await;

        assert!(matches!(verdict, Ok(true)));
        let ApprovalKind::Sign {
            cipher_id,
            process_name,
            is_forwarding,
            namespace,
        } = ui.await.expect("ui task")
        else {
            panic!("expected a sign request");
        };
        assert_eq!(cipher_id.as_deref(), Some("cipher-1"));
        assert_eq!(process_name.as_deref(), Some("ssh-keygen"));
        assert!(is_forwarding);
        assert_eq!(namespace.as_deref(), Some("git"));
    }

    #[tokio::test]
    async fn sign_without_session_bind_or_namespace_is_a_plain_login() {
        let (approver, rx) = approver(Duration::from_secs(5));
        let ui = tokio::spawn(answer_with(rx, true));

        approver
            .request_sign_approval(sign_request(None, None, None))
            .await
            .expect("approved");

        let ApprovalKind::Sign {
            process_name,
            is_forwarding,
            namespace,
            ..
        } = ui.await.expect("ui task")
        else {
            panic!("expected a sign request");
        };
        assert_eq!(process_name, None);
        assert!(!is_forwarding);
        assert_eq!(namespace, None);
    }

    #[test]
    fn namespaces_map_to_their_sshsig_names() {
        assert_eq!(namespace_name(&SIGNamespace::Git), "git");
        assert_eq!(namespace_name(&SIGNamespace::File), "file");
        assert_eq!(namespace_name(&SIGNamespace::Unsupported), "other");
    }

    #[tokio::test]
    async fn sign_denied_by_the_ui_is_false() {
        let (approver, rx) = approver(Duration::from_secs(5));
        let ui = tokio::spawn(answer_with(rx, false));

        let verdict = approver
            .request_sign_approval(sign_request(None, None, None))
            .await;

        assert!(matches!(verdict, Ok(false)));
        ui.await.expect("ui task");
    }

    #[tokio::test]
    async fn dropped_reply_sender_counts_as_deny() {
        let (approver, mut rx) = approver(Duration::from_secs(5));
        let ui = tokio::spawn(async move { drop(rx.recv().await) });

        let verdict = approver
            .request_sign_approval(sign_request(None, None, None))
            .await;

        assert!(matches!(verdict, Ok(false)));
        ui.await.expect("ui task");
    }

    #[tokio::test]
    async fn unanswered_request_times_out_and_closes_the_reply() {
        let (approver, mut rx) = approver(SHORT);

        let verdict = approver
            .request_sign_approval(sign_request(None, None, None))
            .await;

        assert!(matches!(verdict, Err(ApprovalError::Timeout)));
        let request = rx.recv().await.expect("the request was queued");
        assert!(request.reply.is_closed(), "the UI can see the expiry");
    }

    #[tokio::test]
    async fn full_channel_times_out_instead_of_blocking() {
        let (tx, _rx) = mpsc::channel(1);
        let approver = ChannelApprover::new(tx, SHORT);
        let first = approver.request_list_approval().await;
        assert!(matches!(first, Err(ApprovalError::Timeout)));

        let second = approver.request_list_approval().await;

        assert!(matches!(second, Err(ApprovalError::Timeout)));
    }

    #[tokio::test]
    async fn closed_channel_is_a_handler_failure() {
        let (approver, rx) = approver(Duration::from_secs(5));
        drop(rx);

        let verdict = approver.request_list_approval().await;

        assert!(matches!(verdict, Err(ApprovalError::HandlerFailed(_))));
    }

    #[tokio::test]
    async fn list_request_is_forwarded_as_list() {
        let (approver, rx) = approver(Duration::from_secs(5));
        let ui = tokio::spawn(answer_with(rx, true));

        let verdict = approver.request_list_approval().await;

        assert!(matches!(verdict, Ok(true)));
        assert!(matches!(ui.await.expect("ui task"), ApprovalKind::List));
    }
}
