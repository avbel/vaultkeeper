//! Pure mappings for Sends: list rows, the detail pane's text, deletion presets and the edit
//! form's validation. Times are unix seconds from the app clock.

use std::fmt::Write as _;

use chrono::{DateTime, Local};
use slint::SharedString;
use vk_vault::model::{SendDraft, SendKind, SendSummary};
use zeroize::Zeroizing;

use crate::ui::{RowData, SendDetail};

/// The row button and Return copy the link; the value is fixed by `row.slint`.
pub const LINK_CODE: i32 = 11;
/// Index of "Send" in the "+ New" menu, after the five item kinds.
pub const NEW_SEND_INDEX: i32 = 5;
const KIND_CODE: i32 = 6;

const HOUR: i64 = 3600;
const DAY: i64 = 86_400;

/// The official clients' choices; the server allows at most 31 days.
pub const DELETION_PRESETS: [(&str, i64); 7] = [
    ("1 hour", HOUR),
    ("1 day", DAY),
    ("2 days", 2 * DAY),
    ("3 days", 3 * DAY),
    ("7 days", 7 * DAY),
    ("14 days", 14 * DAY),
    ("30 days", 30 * DAY),
];
/// 7 days, the official default.
pub const DEFAULT_PRESET: usize = 4;

/// "3 days", "5 h", "12 min": how long until `seconds` from now have passed.
#[must_use]
pub fn span(seconds: i64) -> String {
    match seconds {
        ..60 => "under a minute".to_owned(),
        60..HOUR => format!("{} min", seconds / 60),
        HOUR..DAY => format!("{} h", seconds / HOUR),
        _ if seconds / DAY == 1 => "1 day".to_owned(),
        _ => format!("{} days", seconds / DAY),
    }
}

#[must_use]
pub fn local_date(unix: i64) -> String {
    DateTime::from_timestamp(unix, 0).map_or_else(String::new, |date| {
        date.with_timezone(&Local)
            .format("%-d %b %Y, %H:%M")
            .to_string()
    })
}

/// Why the link no longer opens, or `None` while it does (same rules as the server).
#[must_use]
pub fn unavailable_reason(send: &SendSummary, now: i64) -> Option<&'static str> {
    if send.disabled {
        Some("Disabled")
    } else if now >= send.deletion_date {
        Some("Pending deletion")
    } else if send.expiration_date.is_some_and(|expires| now >= expires) {
        Some("Expired")
    } else if send
        .max_access_count
        .is_some_and(|max| send.access_count >= max)
    {
        Some("View limit reached")
    } else {
        None
    }
}

#[must_use]
pub fn views(send: &SendSummary) -> String {
    match send.max_access_count {
        Some(max) => format!("{} of {max}", send.access_count),
        None if send.access_count == 1 => "1 view".to_owned(),
        None => format!("{} views", send.access_count),
    }
}

/// The list subtitle: what is wrong with the link, or when it goes away plus its limits.
#[must_use]
pub fn subtitle(send: &SendSummary, now: i64) -> String {
    if let Some(reason) = unavailable_reason(send, now) {
        return reason.to_owned();
    }
    let mut text = format!("Deletes in {}", span(send.deletion_date - now));
    if let Some(max) = send.max_access_count {
        let _ = write!(text, " · {}/{max} views", send.access_count);
    }
    if send.has_password {
        text.push_str(" · password");
    }
    text
}

#[must_use]
pub fn to_row(send: &SendSummary, now: i64) -> RowData {
    RowData {
        kind: KIND_CODE,
        name: send.name.as_ref().into(),
        subtitle: subtitle(send, now).into(),
        b1: LINK_CODE,
        b2: -1,
        b1_label: "Copy link".into(),
        ..RowData::default()
    }
}

const fn kind_label(kind: SendKind) -> &'static str {
    match kind {
        SendKind::Text => "Text Send",
        SendKind::File => "File Send",
        SendKind::Unsupported(_) => "Send",
    }
}

const MASK: &str = "••••••••";

/// The detail pane. `text` is the decrypted text of a text Send (from its draft); a hidden one
/// shows a mask until `revealed`.
#[must_use]
pub fn detail(
    send: &SendSummary,
    draft: Option<&SendDraft>,
    revealed: bool,
    now: i64,
) -> SendDetail {
    let reason = unavailable_reason(send, now);
    let text: SharedString = match draft {
        Some(draft) if !send.hidden || revealed => draft.text.as_str().into(),
        Some(_) => MASK.into(),
        None => SharedString::new(),
    };
    let deletion = if now < send.deletion_date {
        format!(
            "{} (in {})",
            local_date(send.deletion_date),
            span(send.deletion_date - now)
        )
    } else {
        local_date(send.deletion_date)
    };
    SendDetail {
        name: send.name.as_ref().into(),
        is_text: send.kind == SendKind::Text && draft.is_some(),
        kind_label: kind_label(send.kind).into(),
        text,
        text_secret: send.hidden,
        text_revealed: revealed,
        file_name: send.file_name.as_deref().unwrap_or_default().into(),
        file_size: send.file_size.as_deref().unwrap_or_default().into(),
        notes: draft.map_or_else(SharedString::new, |draft| draft.notes.as_str().into()),
        status: reason.unwrap_or("Link works").into(),
        available: reason.is_none(),
        deletion: deletion.into(),
        expiration: send
            .expiration_date
            .map_or_else(String::new, local_date)
            .into(),
        views: views(send).into(),
        has_password: send.has_password,
        hide_email: send.hide_email,
    }
}

/// Deletion choices for the form, with the unix time each one stands for. An edit offers to keep
/// the current date first, so opening and saving a Send never moves it.
#[must_use]
pub fn deletion_options(current: Option<i64>, now: i64) -> (Vec<SharedString>, Vec<i64>) {
    let keep = current.map(|date| (format!("Keep · {}", local_date(date)), date));
    keep.into_iter()
        .chain(
            DELETION_PRESETS
                .iter()
                .map(|&(label, after)| (label.to_owned(), now + after)),
        )
        .map(|(label, date)| (SharedString::from(label), date))
        .unzip()
}

/// What the edit form holds, read back from the window.
pub struct SendForm {
    pub name: String,
    pub is_file: bool,
    pub text: Zeroizing<String>,
    pub hidden: bool,
    pub deletion_date: i64,
    pub password: Zeroizing<String>,
    pub max_views: String,
    pub hide_email: bool,
    pub notes: Zeroizing<String>,
}

/// Checks the form and builds the draft to save. `base` is the draft being edited; what the form
/// does not show (expiration, disabled) is carried over from it.
pub fn build_draft(form: SendForm, base: Option<&SendDraft>) -> Result<SendDraft, &'static str> {
    if form.name.trim().is_empty() {
        return Err("Give the Send a name");
    }
    if !form.is_file && form.text.is_empty() {
        return Err("Enter the text to share");
    }
    let max_access_count = parse_max_views(&form.max_views)?;
    let password = Some(form.password).filter(|password| !password.is_empty());
    Ok(SendDraft {
        name: form.name.trim().to_owned(),
        text: form.text,
        hidden: form.hidden,
        notes: form.notes,
        deletion_date: form.deletion_date,
        expiration_date: base.and_then(|base| base.expiration_date),
        max_access_count,
        hide_email: form.hide_email,
        disabled: base.is_some_and(|base| base.disabled),
        password,
        has_password: base.is_some_and(|base| base.has_password),
    })
}

/// Empty means no limit.
pub fn parse_max_views(text: &str) -> Result<Option<u32>, &'static str> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    match text.parse::<u32>() {
        Ok(0) | Err(_) => Err("Maximum views must be a whole number of at least 1"),
        Ok(count) => Ok(Some(count)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const NOW: i64 = 1_794_157_259;

    fn summary() -> SendSummary {
        SendSummary {
            id: Arc::from("s1"),
            kind: SendKind::Text,
            name: Arc::from("Door code"),
            file_name: None,
            file_size: None,
            has_password: false,
            hidden: false,
            disabled: false,
            hide_email: false,
            access_count: 1,
            max_access_count: None,
            deletion_date: NOW + 7 * DAY,
            expiration_date: None,
        }
    }

    fn draft() -> SendDraft {
        SendDraft {
            name: "Door code".into(),
            text: Zeroizing::new("4711".into()),
            hidden: true,
            notes: Zeroizing::new("for the plumber".into()),
            deletion_date: NOW + 7 * DAY,
            expiration_date: Some(NOW + DAY),
            max_access_count: Some(3),
            hide_email: false,
            disabled: true,
            password: None,
            has_password: true,
        }
    }

    fn form() -> SendForm {
        SendForm {
            name: " Door code ".into(),
            is_file: false,
            text: Zeroizing::new("0815".into()),
            hidden: false,
            deletion_date: NOW + DAY,
            password: Zeroizing::default(),
            max_views: String::new(),
            hide_email: true,
            notes: Zeroizing::default(),
        }
    }

    #[test]
    fn spans_read_as_the_largest_whole_unit() {
        assert_eq!(span(30), "under a minute");
        assert_eq!(span(59 * 60), "59 min");
        assert_eq!(span(5 * HOUR + 59), "5 h");
        assert_eq!(span(DAY + HOUR), "1 day");
        assert_eq!(span(7 * DAY), "7 days");
    }

    #[test]
    fn the_subtitle_names_the_deletion_and_the_limits() {
        let mut send = summary();
        assert_eq!(subtitle(&send, NOW), "Deletes in 7 days");
        send.max_access_count = Some(3);
        send.has_password = true;
        assert_eq!(
            subtitle(&send, NOW),
            "Deletes in 7 days · 1/3 views · password"
        );
    }

    #[test]
    fn an_unusable_link_says_why_in_the_server_s_order() {
        let mut send = summary();
        send.max_access_count = Some(1);
        assert_eq!(unavailable_reason(&send, NOW), Some("View limit reached"));
        send.expiration_date = Some(NOW);
        assert_eq!(unavailable_reason(&send, NOW), Some("Expired"));
        send.deletion_date = NOW;
        assert_eq!(unavailable_reason(&send, NOW), Some("Pending deletion"));
        send.disabled = true;
        assert_eq!(subtitle(&send, NOW), "Disabled");
    }

    #[test]
    fn rows_offer_only_the_link() {
        let row = to_row(&summary(), NOW);
        assert_eq!((row.kind, row.b1, row.b2), (6, LINK_CODE, -1));
        assert_eq!(row.name, "Door code");
        assert!(!row.has_totp);
    }

    #[test]
    fn hidden_text_is_masked_until_revealed() {
        let mut send = summary();
        send.hidden = true;
        let draft = draft();
        let masked = detail(&send, Some(&draft), false, NOW);
        assert_eq!(masked.text, MASK);
        assert!(masked.is_text && masked.text_secret);
        assert_eq!(masked.notes, "for the plumber");
        assert_eq!(detail(&send, Some(&draft), true, NOW).text, "4711");
        let file = SendSummary {
            kind: SendKind::File,
            file_name: Some(Arc::from("q3.pdf")),
            ..send
        };
        let file = detail(&file, None, false, NOW);
        assert!(!file.is_text);
        assert_eq!(file.text, "");
        assert_eq!(file.file_name, "q3.pdf");
    }

    #[test]
    fn an_edit_offers_to_keep_the_current_deletion_date_first() {
        let (labels, dates) = deletion_options(None, NOW);
        assert_eq!(labels.len(), DELETION_PRESETS.len());
        assert_eq!(labels[DEFAULT_PRESET], "7 days");
        assert_eq!(dates[DEFAULT_PRESET], NOW + 7 * DAY);
        let (labels, dates) = deletion_options(Some(NOW + 5), NOW);
        assert!(labels[0].starts_with("Keep · "));
        assert_eq!(dates[0], NOW + 5);
        assert_eq!(dates[1], NOW + HOUR);
    }

    #[test]
    fn the_form_needs_a_name_text_and_a_sane_view_limit() {
        let rejected = |change: fn(&mut SendForm)| {
            let mut form = form();
            change(&mut form);
            build_draft(form, None).is_err()
        };
        assert!(rejected(|form| form.name = " ".into()));
        assert!(rejected(|form| form.text = Zeroizing::default()));
        assert!(rejected(|form| form.max_views = "0".into()));
        assert!(rejected(|form| form.max_views = "-2".into()));
        assert!(rejected(|form| form.max_views = "two".into()));
        assert_eq!(parse_max_views(" 5 "), Ok(Some(5)));
    }

    #[test]
    fn a_new_draft_takes_the_form_and_an_edit_keeps_what_the_form_hides() {
        let new = build_draft(form(), None).expect("a valid form");
        assert_eq!(new.name, "Door code");
        assert_eq!(new.password, None, "an empty password field sets none");
        assert!(new.hide_email && !new.disabled && new.expiration_date.is_none());

        let mut changed = form();
        changed.password = Zeroizing::new("open".into());
        changed.max_views = "2".into();
        let base = draft();
        let edit = build_draft(changed, Some(&base)).expect("a valid edit");
        assert_eq!(edit.password.as_deref().map(String::as_str), Some("open"));
        assert_eq!(edit.max_access_count, Some(2));
        assert_eq!(edit.expiration_date, base.expiration_date);
        assert!(edit.disabled && edit.has_password);
    }
}
