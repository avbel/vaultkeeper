//! Wire mirrors of the Send views. The draft carries the decrypted text and wipes itself on drop
//! like the item draft; the summary holds no secrets.

use std::{mem, sync::Arc};

use serde::{Deserialize, Serialize};
use vk_vault::model::{SendDraft, SendKind, SendSummary};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendKindDto {
    Text,
    File,
    Unsupported(u8),
}

impl From<SendKind> for SendKindDto {
    fn from(kind: SendKind) -> Self {
        match kind {
            SendKind::Text => Self::Text,
            SendKind::File => Self::File,
            SendKind::Unsupported(raw) => Self::Unsupported(raw),
        }
    }
}

impl From<SendKindDto> for SendKind {
    fn from(kind: SendKindDto) -> Self {
        match kind {
            SendKindDto::Text => Self::Text,
            SendKindDto::File => Self::File,
            SendKindDto::Unsupported(raw) => Self::Unsupported(raw),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendSummaryDto {
    pub id: Arc<str>,
    pub kind: SendKindDto,
    pub name: Arc<str>,
    pub file_name: Option<Arc<str>>,
    pub file_size: Option<Arc<str>>,
    pub has_password: bool,
    pub hidden: bool,
    pub disabled: bool,
    pub hide_email: bool,
    pub access_count: u32,
    pub max_access_count: Option<u32>,
    pub deletion_date: i64,
    pub expiration_date: Option<i64>,
}

impl From<SendSummary> for SendSummaryDto {
    fn from(send: SendSummary) -> Self {
        Self {
            id: send.id,
            kind: send.kind.into(),
            name: send.name,
            file_name: send.file_name,
            file_size: send.file_size,
            has_password: send.has_password,
            hidden: send.hidden,
            disabled: send.disabled,
            hide_email: send.hide_email,
            access_count: send.access_count,
            max_access_count: send.max_access_count,
            deletion_date: send.deletion_date,
            expiration_date: send.expiration_date,
        }
    }
}

impl From<SendSummaryDto> for SendSummary {
    fn from(send: SendSummaryDto) -> Self {
        Self {
            id: send.id,
            kind: send.kind.into(),
            name: send.name,
            file_name: send.file_name,
            file_size: send.file_size,
            has_password: send.has_password,
            hidden: send.hidden,
            disabled: send.disabled,
            hide_email: send.hide_email,
            access_count: send.access_count,
            max_access_count: send.max_access_count,
            deletion_date: send.deletion_date,
            expiration_date: send.expiration_date,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SendDraftDto {
    pub name: String,
    pub text: Zeroizing<String>,
    pub hidden: bool,
    pub notes: Zeroizing<String>,
    pub deletion_date: i64,
    pub expiration_date: Option<i64>,
    pub max_access_count: Option<u32>,
    pub hide_email: bool,
    pub disabled: bool,
    pub password: Option<Zeroizing<String>>,
    pub has_password: bool,
}

impl From<SendDraft> for SendDraftDto {
    fn from(draft: SendDraft) -> Self {
        Self {
            name: draft.name,
            text: draft.text,
            hidden: draft.hidden,
            notes: draft.notes,
            deletion_date: draft.deletion_date,
            expiration_date: draft.expiration_date,
            max_access_count: draft.max_access_count,
            hide_email: draft.hide_email,
            disabled: draft.disabled,
            password: draft.password,
            has_password: draft.has_password,
        }
    }
}

impl From<SendDraftDto> for SendDraft {
    fn from(mut draft: SendDraftDto) -> Self {
        Self {
            name: mem::take(&mut draft.name),
            text: mem::take(&mut draft.text),
            hidden: draft.hidden,
            notes: mem::take(&mut draft.notes),
            deletion_date: draft.deletion_date,
            expiration_date: draft.expiration_date,
            max_access_count: draft.max_access_count,
            hide_email: draft.hide_email,
            disabled: draft.disabled,
            password: draft.password.take(),
            has_password: draft.has_password,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{HEADER_LEN, decode, encode};

    fn over_the_wire<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        let frame = encode(value).expect("encode");
        decode(&frame[HEADER_LEN..]).expect("decode")
    }

    #[test]
    fn summaries_and_drafts_survive_the_socket() {
        let summary = SendSummary {
            id: "s1".into(),
            kind: SendKind::File,
            name: "Report".into(),
            file_name: Some("report.pdf".into()),
            file_size: Some("1.2 MB".into()),
            has_password: true,
            hidden: false,
            disabled: true,
            hide_email: true,
            access_count: 2,
            max_access_count: Some(5),
            deletion_date: 1_794_157_259,
            expiration_date: Some(1_794_000_000),
        };
        let back = SendSummary::from(over_the_wire(&SendSummaryDto::from(summary.clone())));
        assert_eq!(back, summary);

        let draft = SendDraft {
            name: "Wi-Fi".into(),
            text: Zeroizing::new("hunter2".into()),
            hidden: true,
            notes: Zeroizing::new("for the guests".into()),
            deletion_date: 1_794_157_259,
            expiration_date: None,
            max_access_count: Some(1),
            hide_email: false,
            disabled: false,
            password: Some(Zeroizing::new("open".into())),
            has_password: false,
        };
        let back = SendDraft::from(over_the_wire(&SendDraftDto::from(draft.clone())));
        assert!(back == draft);
    }
}
