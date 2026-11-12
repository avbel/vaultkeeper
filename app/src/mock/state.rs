//! Mock vault internals: account and item lookups, search matching and fake secrets.

use std::sync::Arc;

use vk_vault::{
    Error, Result, TotpCode,
    model::{CopyField, Filter, ItemData, ItemId},
};
use zeroize::Zeroizing;

use super::{
    Account, Inner,
    data::{AccountData, MockItem},
    fake::fnv1a,
    sends::MockSend,
};

/// What the real vault returns when the server can't be reached (`Error::is_offline` is true).
pub(super) const fn unreachable() -> Error {
    Error::Offline
}

pub(super) fn not_bitwarden() -> Error {
    Error::Api(vk_api::Error::Server {
        status: 404,
        message: "Not Found".to_owned(),
    })
}

pub(super) fn user_key(account: &Account) -> Zeroizing<Vec<u8>> {
    super::mock_user_key(&account.id)
}

impl Inner {
    pub(super) fn active(&self) -> Result<&Account> {
        let account = self
            .active
            .and_then(|index| self.accounts.get(index))
            .ok_or(Error::LoggedOut)?;
        if self.adding || !account.logged_in {
            return Err(Error::LoggedOut);
        }
        Ok(account)
    }

    pub(super) fn data(&self) -> Result<&AccountData> {
        let account = self.active()?;
        if !self.unlocked {
            return Err(Error::Locked);
        }
        Ok(&account.data)
    }

    pub(super) fn data_mut(&mut self) -> Result<&mut AccountData> {
        self.data()?;
        let index = self.active.ok_or(Error::LoggedOut)?;
        Ok(&mut self.accounts[index].data)
    }

    pub(super) fn item(&self, id: &ItemId) -> Result<&MockItem> {
        self.data()?
            .items
            .iter()
            .find(|item| &item.summary.id == id)
            .ok_or(Error::NotFound)
    }

    pub(super) fn item_mut(&mut self, id: &ItemId) -> Result<&mut MockItem> {
        self.data_mut()?
            .items
            .iter_mut()
            .find(|item| &item.summary.id == id)
            .ok_or(Error::NotFound)
    }

    pub(super) fn send(&self, id: &str) -> Result<&MockSend> {
        self.data()?
            .sends
            .iter()
            .find(|send| &*send.summary.id == id)
            .ok_or(Error::NotFound)
    }

    pub(super) fn send_mut(&mut self, id: &str) -> Result<&mut MockSend> {
        self.data_mut()?
            .sends
            .iter_mut()
            .find(|send| &*send.summary.id == id)
            .ok_or(Error::NotFound)
    }

    pub(super) const fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    pub(super) fn activate(&mut self, index: usize) {
        let now = self.tick();
        self.accounts[index].last_used = now;
        self.active = Some(index);
        self.unlocked = false;
        self.adding = false;
    }
}

pub(super) fn matches(item: &MockItem, filter: &Filter) -> bool {
    let summary = &item.summary;
    summary.deleted == filter.trash
        && filter.kind.is_none_or(|kind| summary.kind == kind)
        && filter
            .folder
            .as_ref()
            .is_none_or(|folder| &summary.folder_id == folder)
        && filter
            .organization
            .as_ref()
            .is_none_or(|organization| &summary.organization_id == organization)
        && (!filter.favorites_only || summary.favorite)
        && filter
            .collection
            .as_ref()
            .is_none_or(|collection| item.draft.collection_ids.iter().any(|id| id == collection))
}

/// Lower is better; `None` means no match.
pub(super) fn rank(item: &MockItem, query: &str) -> Option<u8> {
    let name = &item.name_lower;
    if name.starts_with(query) {
        Some(0)
    } else if name
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| word.starts_with(query))
    {
        Some(1)
    } else if name.contains(query) {
        Some(2)
    } else if item.subtitle_lower.contains(query) {
        Some(3)
    } else if item.uri_lower.contains(query) {
        Some(4)
    } else {
        None
    }
}

/// Fake but stable TOTP: a hash of the item id and the 30 s window.
pub(super) fn fake_totp(id: &ItemId, unix_time: u64) -> TotpCode {
    const PERIOD: u64 = 30;
    let window = unix_time / PERIOD;
    let value = (fnv1a(&id.0) ^ window.wrapping_mul(0x9E37_79B9_7F4A_7C15)) % 1_000_000;
    TotpCode {
        code: Zeroizing::new(format!("{value:06}")),
        period: 30,
        remaining: u32::try_from(PERIOD - unix_time % PERIOD).unwrap_or(30),
    }
}

pub(super) fn field_value(
    item: &MockItem,
    field: CopyField,
    unix_time: u64,
) -> Option<Zeroizing<String>> {
    let draft = &item.draft;
    let value = match (&draft.data, field) {
        (_, CopyField::Notes) => draft.notes.as_str(),
        (_, CopyField::Custom(index)) => draft.fields.get(index)?.value.as_str(),
        (ItemData::Login { username, .. }, CopyField::Username) => username.as_str(),
        (ItemData::Login { password, .. }, CopyField::Password) => password.as_str(),
        (ItemData::Login { totp, .. }, CopyField::Totp) if !totp.is_empty() => {
            return Some(fake_totp(&item.summary.id, unix_time).code);
        }
        (ItemData::Login { uris, .. }, CopyField::Uri) => uris.first()?.as_str(),
        (ItemData::Card { number, .. }, CopyField::CardNumber) => number.as_str(),
        (ItemData::Card { code, .. }, CopyField::CardCode) => code.as_str(),
        (ItemData::Identity(identity), CopyField::Email) => identity.email.as_str(),
        (ItemData::Identity(identity), CopyField::Phone) => identity.phone.as_str(),
        (ItemData::SshKey { public_key, .. }, CopyField::SshPublicKey) => public_key.as_str(),
        (ItemData::SshKey { private_key, .. }, CopyField::SshPrivateKey) => private_key.as_str(),
        _ => return None,
    };
    (!value.is_empty()).then(|| Zeroizing::new(value.to_owned()))
}

pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Mirrors the real vault's rules: writable collections of one organization, read-only ones the
/// item is in stay, and no way out of an organization.
pub(super) fn assign_collections(
    inner: &mut Inner,
    id: &ItemId,
    organization_id: &str,
    picked: &[Arc<str>],
) -> Result<()> {
    let data = inner.data_mut()?;
    let writable = |id: &Arc<str>| {
        data.collections.iter().any(|collection| {
            collection.id == *id
                && &*collection.organization_id == organization_id
                && !collection.read_only
        })
    };
    if picked.is_empty() || !picked.iter().all(writable) {
        return Err(Error::ReadOnly);
    }
    let read_only: Vec<Arc<str>> = data
        .collections
        .iter()
        .filter(|collection| collection.read_only)
        .map(|collection| Arc::clone(&collection.id))
        .collect();
    let organization = data
        .organizations
        .iter()
        .find(|organization| &*organization.id == organization_id)
        .map(|organization| Arc::clone(&organization.id))
        .ok_or(Error::NotFound)?;
    let item = data
        .items
        .iter_mut()
        .find(|item| &item.summary.id == id)
        .ok_or(Error::NotFound)?;
    if !item.summary.editable {
        return Err(Error::ReadOnly);
    }
    if item
        .draft
        .organization_id
        .as_ref()
        .is_some_and(|current| *current != organization)
    {
        return Err(Error::ReadOnly);
    }
    let kept = item
        .draft
        .collection_ids
        .iter()
        .filter(|id| read_only.contains(id) && !picked.contains(id))
        .cloned();
    item.draft.collection_ids = picked.iter().cloned().chain(kept).collect();
    item.draft.organization_id = Some(Arc::clone(&organization));
    item.summary.organization_id = Some(organization);
    Ok(())
}

pub(super) fn set_deleted(inner: &mut Inner, id: &ItemId, deleted: bool) -> Result<()> {
    let item = inner.item_mut(id)?;
    if !item.summary.editable {
        return Err(Error::ReadOnly);
    }
    item.summary.deleted = deleted;
    Ok(())
}
