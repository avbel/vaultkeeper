//! Mock Sends: sample data and the list rows derived from a draft, as the real vault derives
//! them from the server's answer.

use std::sync::Arc;

use vk_vault::model::{SendDraft, SendKind, SendSummary};
use zeroize::Zeroizing;

const DAY: i64 = 86_400;

pub struct MockSend {
    pub summary: SendSummary,
    pub draft: SendDraft,
}

impl MockSend {
    pub fn new(id: &str, draft: SendDraft, access_count: u32) -> Self {
        Self {
            summary: summarize(id, &draft, access_count),
            draft,
        }
    }
}

#[must_use]
pub fn summarize(id: &str, draft: &SendDraft, access_count: u32) -> SendSummary {
    SendSummary {
        id: Arc::from(id),
        kind: SendKind::Text,
        name: Arc::from(draft.name.trim()),
        file_name: None,
        file_size: None,
        has_password: draft.has_password,
        hidden: draft.hidden,
        disabled: draft.disabled,
        hide_email: draft.hide_email,
        access_count,
        max_access_count: draft.max_access_count,
        deletion_date: draft.deletion_date,
        expiration_date: draft.expiration_date,
    }
}

fn text(name: &str, body: &str, days: i64, now: i64) -> SendDraft {
    SendDraft {
        name: name.to_owned(),
        text: Zeroizing::new(body.to_owned()),
        hidden: false,
        notes: Zeroizing::default(),
        deletion_date: now + days * DAY,
        expiration_date: None,
        max_access_count: None,
        hide_email: false,
        disabled: false,
        password: None,
        has_password: false,
    }
}

/// Alice's Sends: a plain one, a password-protected one with a view limit, one used up and a
/// file Send made elsewhere.
#[must_use]
pub fn samples(now: i64) -> Vec<MockSend> {
    let guest = SendDraft {
        hidden: true,
        has_password: true,
        max_access_count: Some(3),
        notes: Zeroizing::new("Given to the plumber".to_owned()),
        ..text("Door code", "4711#", 2, now)
    };
    let used_up = SendDraft {
        max_access_count: Some(1),
        ..text("Server recovery key", "ABCD-EFGH-IJKL-MNOP", 5, now)
    };
    let mut file = MockSend::new("send-report", text("Quarterly report", "", 14, now), 4);
    file.summary.kind = SendKind::File;
    file.summary.file_name = Some(Arc::from("q3-report.pdf"));
    file.summary.file_size = Some(Arc::from("1.2 MB"));
    vec![
        MockSend::new(
            "send-wifi",
            text(
                "Guest Wi-Fi",
                "SSID: Acme-Guest\nPassword: correct horse battery",
                7,
                now,
            ),
            2,
        ),
        MockSend::new("send-door", guest, 1),
        MockSend::new("send-recovery", used_up, 1),
        file,
    ]
}
