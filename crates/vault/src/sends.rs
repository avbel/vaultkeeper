//! Sends: the decrypted list, drafts, share links and write requests.
//!
//! A Send's `key` is its 16-byte seed wrapped by the user key; the content key is derived from
//! the seed ([`SendKey`]) whenever it is needed, never kept.

use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use url::Url;
use vk_api::models::{SendItem, SendRequest, SendTextRequest, send_type};
use vk_crypto::{EncString, SendKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Error, Result,
    keys::{KeyRing, decrypt_text, encrypt_opt, encrypt_text, parse},
    model::{SendDraft, SendKind, SendSummary},
};

/// Vaultwarden refuses a deletion date more than 31 days ahead; the official presets end at 30.
pub const MAX_DELETION_DAYS: i64 = 31;
const SECONDS_PER_DAY: i64 = 86_400;
const UNDECRYPTABLE: &str = "[cannot decrypt]";

pub(crate) struct SendEntry {
    pub send: SendItem,
    pub summary: SendSummary,
    /// Lowercase name, computed once so sorting and inserting allocate nothing per comparison.
    sort_key: Zeroizing<String>,
}

impl SendEntry {
    fn new(send: SendItem, keys: &KeyRing) -> Self {
        let summary = summary(&send, keys);
        let sort_key = Zeroizing::new(summary.name.to_lowercase());
        Self {
            send,
            summary,
            sort_key,
        }
    }
}

impl Drop for SendEntry {
    fn drop(&mut self) {
        wipe_shared(&mut self.summary.name);
        if let Some(file_name) = &mut self.summary.file_name {
            wipe_shared(file_name);
        }
    }
}

fn wipe_shared(text: &mut Arc<str>) {
    if let Some(owned) = Arc::get_mut(text) {
        owned.zeroize();
    }
}

/// Every Send of the account, sorted by lowercase name.
#[derive(Default)]
pub(crate) struct SendList {
    entries: Vec<SendEntry>,
}

impl SendList {
    pub(crate) fn build(sends: Vec<SendItem>, keys: &KeyRing) -> Self {
        let mut entries: Vec<SendEntry> = sends
            .into_iter()
            .map(|send| SendEntry::new(send, keys))
            .collect();
        entries.sort_by(|a, b| a.sort_key.as_str().cmp(b.sort_key.as_str()));
        Self { entries }
    }

    pub(crate) fn get(&self, id: &str) -> Option<&SendEntry> {
        self.entries.iter().find(|entry| entry.send.id == id)
    }

    pub(crate) fn summaries(&self) -> Vec<SendSummary> {
        self.entries
            .iter()
            .map(|entry| entry.summary.clone())
            .collect()
    }

    pub(crate) fn items(&self) -> impl Iterator<Item = &SendItem> {
        self.entries.iter().map(|entry| &entry.send)
    }

    pub(crate) fn upsert(&mut self, send: SendItem, keys: &KeyRing) -> SendSummary {
        self.remove(&send.id);
        let entry = SendEntry::new(send, keys);
        let summary = entry.summary.clone();
        let position = self
            .entries
            .partition_point(|known| known.sort_key.as_str() <= entry.sort_key.as_str());
        self.entries.insert(position, entry);
        summary
    }

    pub(crate) fn remove(&mut self, id: &str) {
        self.entries.retain(|entry| entry.send.id != id);
    }
}

pub(crate) const fn kind_of(raw: u8) -> SendKind {
    match raw {
        send_type::TEXT => SendKind::Text,
        send_type::FILE => SendKind::File,
        other => SendKind::Unsupported(other),
    }
}

/// Sends are always the owner's, so the seed is wrapped by the user key, never an org key.
pub(crate) fn send_key(send: &SendItem, keys: &KeyRing) -> Result<SendKey> {
    let wrapped_seed = parse(&send.key)?.decrypt(keys.user())?;
    Ok(SendKey::from_seed(&wrapped_seed)?)
}

pub(crate) fn summary(send: &SendItem, keys: &KeyRing) -> SendSummary {
    let decrypted = send_key(send, keys).and_then(|key| {
        let name = decrypt_text(send.name.as_deref(), key.key())?;
        let file_name = match send.file.as_ref() {
            Some(file) => Some(decrypt_text(file.file_name.as_deref(), key.key())?),
            None => None,
        };
        Ok((name, file_name))
    });
    let (name, file_name) = decrypted.unwrap_or_else(|error| {
        tracing::warn!(%error, "could not decrypt a Send for the list");
        (Zeroizing::new(UNDECRYPTABLE.to_owned()), None)
    });
    SendSummary {
        id: Arc::from(send.id.as_str()),
        kind: kind_of(send.r#type),
        name: Arc::from(name.as_str()),
        file_name: file_name.map(|file_name| Arc::from(file_name.as_str())),
        file_size: send
            .file
            .as_ref()
            .and_then(|file| file.size_name.as_deref())
            .map(Arc::from),
        has_password: send.password.is_some(),
        hidden: send.text.as_ref().is_some_and(|text| text.hidden),
        disabled: send.disabled,
        hide_email: send.hide_email,
        access_count: send.access_count,
        max_access_count: send.max_access_count,
        deletion_date: parse_date(&send.deletion_date).unwrap_or(0),
        expiration_date: send.expiration_date.as_deref().and_then(parse_date),
    }
}

pub(crate) fn draft(send: &SendItem, keys: &KeyRing) -> Result<SendDraft> {
    if send.r#type != send_type::TEXT {
        return Err(Error::unsupported("Only text Sends can be edited here"));
    }
    let key = send_key(send, keys)?;
    let text = send.text.as_ref();
    Ok(SendDraft {
        name: decrypt_text(send.name.as_deref(), key.key())?.to_string(),
        text: decrypt_text(text.and_then(|text| text.text.as_deref()), key.key())?,
        hidden: text.is_some_and(|text| text.hidden),
        notes: decrypt_text(send.notes.as_deref(), key.key())?,
        deletion_date: parse_date(&send.deletion_date).unwrap_or(0),
        expiration_date: send.expiration_date.as_deref().and_then(parse_date),
        max_access_count: send.max_access_count,
        hide_email: send.hide_email,
        disabled: send.disabled,
        password: None,
        has_password: send.password.is_some(),
    })
}

/// `{server}/#/send/{accessId}/{seed}`, the web vault's Send page. Vaultwarden serves the web
/// vault at the server URL; the fragment, and with it the seed, never reaches any server.
pub(crate) fn link(send: &SendItem, keys: &KeyRing, server: &Url) -> Result<Zeroizing<String>> {
    if send.access_id.is_empty() {
        return Err(Error::protocol("the Send has no access id"));
    }
    let key = send_key(send, keys)?;
    let base = server.as_str().trim_end_matches('/');
    let url_key = key.url_key();
    let mut link = Zeroizing::new(String::with_capacity(
        base.len() + send.access_id.len() + url_key.len() + 9,
    ));
    link.push_str(base);
    link.push_str("/#/send/");
    link.push_str(&send.access_id);
    link.push('/');
    link.push_str(&url_key);
    Ok(link)
}

/// Encrypts `draft` into a request. An update keeps `base`'s seed and sends its wrapped key back
/// unchanged: a new seed would break every link already shared. Runs PBKDF2 when a new password
/// is set, so call it off the async workers.
pub(crate) fn prepare(
    draft: &SendDraft,
    base: Option<&SendItem>,
    keys: &KeyRing,
    now: i64,
) -> Result<SendRequest> {
    validate(draft, base.is_some(), now)?;
    let (key, wrapped) = if let Some(base) = base {
        if base.r#type != send_type::TEXT {
            return Err(Error::unsupported("Only text Sends can be edited here"));
        }
        (send_key(base, keys)?, base.key.clone())
    } else {
        let key = SendKey::generate();
        let wrapped = EncString::encrypt(key.seed(), keys.user())?.to_string();
        (key, wrapped)
    };
    let password = draft
        .password
        .as_ref()
        .filter(|password| !password.is_empty())
        .map(|password| key.password_hash(password));
    Ok(SendRequest {
        r#type: send_type::TEXT,
        name: encrypt_text(draft.name.trim(), key.key())?,
        notes: encrypt_opt(&draft.notes, key.key())?,
        key: wrapped,
        max_access_count: draft.max_access_count,
        expiration_date: draft.expiration_date.map(format_date),
        deletion_date: format_date(draft.deletion_date),
        text: SendTextRequest {
            text: encrypt_text(&draft.text, key.key())?,
            hidden: draft.hidden,
        },
        password,
        disabled: draft.disabled,
        hide_email: draft.hide_email,
    })
}

fn validate(draft: &SendDraft, update: bool, now: i64) -> Result<()> {
    if draft.name.trim().is_empty() {
        return Err(Error::unsupported("Give the Send a name"));
    }
    if draft.text.is_empty() {
        return Err(Error::unsupported("Enter the text to share"));
    }
    if draft.max_access_count == Some(0) {
        return Err(Error::unsupported(
            "The maximum view count must be at least 1",
        ));
    }
    // An edit may keep a date that is now in the past only if it was already there; the server
    // would accept it, but a new Send that is deleted on arrival is a mistake.
    if !update && draft.deletion_date <= now {
        return Err(Error::unsupported(
            "The deletion date must be in the future",
        ));
    }
    if draft.deletion_date > now + MAX_DELETION_DAYS * SECONDS_PER_DAY {
        return Err(Error::unsupported(
            "The deletion date can be at most 31 days from now",
        ));
    }
    Ok(())
}

pub(crate) fn parse_date(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|date| date.timestamp())
}

pub(crate) fn format_date(unix: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use vk_api::models::{SendFile, SendText};

    use super::*;
    use crate::testutil::{enc, ring};

    const NOW: i64 = 1_794_157_259;
    const DAY: i64 = SECONDS_PER_DAY;

    /// A text Send encrypted with vk-crypto directly, as another client would store it.
    fn stored(id: &str, name: &str, text: &str, keys: &KeyRing) -> (SendItem, SendKey) {
        let key = SendKey::generate();
        let send = SendItem {
            id: id.into(),
            access_id: format!("access-{id}"),
            r#type: send_type::TEXT,
            name: enc(name, key.key()),
            text: Some(SendText {
                text: enc(text, key.key()),
                hidden: true,
                ..SendText::default()
            }),
            key: EncString::encrypt(key.seed(), keys.user())
                .unwrap()
                .to_string(),
            max_access_count: Some(2),
            access_count: 2,
            password: Some("server-hash".into()),
            revision_date: "2026-11-08T17:00:59.321Z".into(),
            deletion_date: "2026-11-15T17:00:59.321Z".into(),
            ..SendItem::default()
        };
        (send, key)
    }

    fn new_draft() -> SendDraft {
        SendDraft {
            name: " Wi-Fi ".into(),
            text: Zeroizing::new("hunter2".into()),
            hidden: false,
            notes: Zeroizing::default(),
            deletion_date: NOW + 7 * DAY,
            expiration_date: None,
            max_access_count: None,
            hide_email: true,
            disabled: false,
            password: None,
            has_password: false,
        }
    }

    fn decrypt(field: Option<&str>, key: &SendKey) -> String {
        decrypt_text(field, key.key()).unwrap().to_string()
    }

    #[test]
    fn the_list_shows_names_and_state_but_no_text() {
        let keys = ring();
        let (send, _) = stored("s1", "Door code", "4711", &keys);
        let list = SendList::build(vec![send], &keys);
        let summary = &list.summaries()[0];
        assert_eq!(&*summary.name, "Door code");
        assert_eq!(summary.kind, SendKind::Text);
        assert!(summary.has_password && summary.hidden);
        assert_eq!(summary.deletion_date, NOW + 7 * DAY);
        assert!(!summary.is_available(NOW), "both views are used up");
    }

    #[test]
    fn file_sends_list_their_file_and_refuse_a_draft() {
        let keys = ring();
        let (mut send, key) = stored("f1", "Report", "", &keys);
        send.r#type = send_type::FILE;
        send.text = None;
        send.file = Some(SendFile {
            file_name: enc("report.pdf", key.key()),
            size_name: Some("1.2 MB".into()),
            ..SendFile::default()
        });
        let list = SendList::build(vec![send], &keys);
        let summary = &list.summaries()[0];
        assert_eq!(summary.kind, SendKind::File);
        assert_eq!(summary.file_name.as_deref(), Some("report.pdf"));
        assert_eq!(summary.file_size.as_deref(), Some("1.2 MB"));
        assert!(draft(&list.get("f1").unwrap().send, &keys).is_err());
    }

    #[test]
    fn the_link_carries_the_access_id_and_the_seed_in_the_fragment() {
        let keys = ring();
        let (send, key) = stored("s1", "n", "t", &keys);
        let server = Url::parse("https://vault.example.com/").unwrap();
        let link = link(&send, &keys, &server).unwrap();
        let expected = format!(
            "https://vault.example.com/#/send/access-s1/{}",
            URL_SAFE_NO_PAD.encode(key.seed())
        );
        assert_eq!(link.as_str(), expected);

        let under_path = Url::parse("https://example.com/vault/").unwrap();
        let link = super::link(&send, &keys, &under_path).unwrap();
        assert!(link.starts_with("https://example.com/vault/#/send/access-s1/"));
    }

    #[test]
    fn a_new_send_gets_a_fresh_seed_wrapped_by_the_user_key() {
        let keys = ring();
        let mut draft = new_draft();
        draft.password = Some(Zeroizing::new("open sesame".into()));
        let request = prepare(&draft, None, &keys, NOW).unwrap();
        let seed = parse(&request.key).unwrap().decrypt(keys.user()).unwrap();
        let key = SendKey::from_seed(&seed).unwrap();
        assert_eq!(decrypt(Some(&request.name), &key), "Wi-Fi");
        assert_eq!(decrypt(Some(&request.text.text), &key), "hunter2");
        assert_eq!(request.notes, None);
        assert_eq!(request.password, Some(key.password_hash("open sesame")));
        assert_eq!(request.deletion_date, "2026-11-15T17:00:59.000Z");
        assert!(request.hide_email);
    }

    #[test]
    fn an_edit_keeps_the_seed_so_shared_links_still_open() {
        let keys = ring();
        let (send, key) = stored("s1", "Door code", "4711", &keys);
        let mut draft = draft(&send, &keys).unwrap();
        assert_eq!(draft.text.as_str(), "4711");
        assert!(draft.has_password && draft.password.is_none());
        draft.text = Zeroizing::new("0815".into());
        let request = prepare(&draft, Some(&send), &keys, NOW).unwrap();
        assert_eq!(request.key, send.key);
        assert_eq!(decrypt(Some(&request.text.text), &key), "0815");
        assert_eq!(request.password, None, "no new password keeps the old one");
        assert_eq!(request.max_access_count, Some(2));
    }

    #[test]
    fn drafts_without_name_or_text_or_with_bad_dates_are_refused() {
        let keys = ring();
        let check = |change: fn(&mut SendDraft)| {
            let mut draft = new_draft();
            change(&mut draft);
            prepare(&draft, None, &keys, NOW).is_err()
        };
        assert!(check(|draft| draft.name = "  ".into()));
        assert!(check(|draft| draft.text = Zeroizing::default()));
        assert!(check(|draft| draft.max_access_count = Some(0)));
        assert!(check(|draft| draft.deletion_date = NOW));
        assert!(check(|draft| draft.deletion_date = NOW + 31 * DAY + 1));
        assert!(!check(|draft| draft.deletion_date = NOW + 31 * DAY));

        // An edit may keep a date that has passed meanwhile; only a new Send must be in the future.
        let (stored, _) = stored("s1", "n", "t", &keys);
        let mut past = draft(&stored, &keys).unwrap();
        past.deletion_date = NOW - DAY;
        assert!(prepare(&past, Some(&stored), &keys, NOW).is_ok());
    }

    #[test]
    fn dates_round_trip_through_the_wire_format() {
        assert_eq!(parse_date("2026-11-08T17:00:59.321234Z"), Some(NOW));
        assert_eq!(parse_date(&format_date(NOW)), Some(NOW));
        assert_eq!(parse_date("not a date"), None);
    }

    #[test]
    fn upsert_keeps_name_order_and_replaces_by_id() {
        let keys = ring();
        let (b, _) = stored("b", "Beta", "t", &keys);
        let (a, _) = stored("a", "alpha", "t", &keys);
        let mut list = SendList::build(vec![b], &keys);
        list.upsert(a, &keys);
        let (renamed, _) = stored("b", "Aardvark", "t", &keys);
        list.upsert(renamed, &keys);
        let names: Vec<_> = list
            .summaries()
            .iter()
            .map(|s| s.name.to_string())
            .collect();
        assert_eq!(names, ["Aardvark", "alpha"]);
        list.remove("a");
        assert_eq!(list.summaries().len(), 1);
    }
}
