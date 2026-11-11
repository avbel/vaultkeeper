use super::Vault;
use crate::{
    Result,
    index::Entry,
    model::{CopyField, ItemId, ItemSummary},
    reveal,
    uri_match::{self, DefaultMatch, PageUrl},
};
use std::sync::Arc;
use zeroize::Zeroizing;

/// An opaque view of one unlocked session and index revision.
#[derive(Clone, Copy)]
pub struct BrowserSnapshot {
    epoch: u64,
    revision: u64,
}

impl BrowserSnapshot {
    /// True when both snapshots come from the same unlocked session, whatever the index did since.
    #[must_use]
    pub fn same_session(self, other: Self) -> bool {
        self.epoch == other.epoch
    }
}

#[derive(Clone, Copy)]
pub struct BrowserFields {
    pub username: bool,
    pub password: bool,
}

pub struct BrowserCredentials {
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
    /// The item matched the page by its own URIs, with no other-site confirmation needed.
    pub matched: bool,
    pub reprompt: bool,
    pub has_totp: bool,
}

pub struct LoginMatch {
    pub summary: ItemSummary,
    pub matched_uri: Arc<str>,
}
fn matched_uri(entry: &Entry, page: &PageUrl, default: DefaultMatch) -> Option<Arc<str>> {
    entry
        .match_uris
        .iter()
        .find(|(uri, rule)| uri_match::matches(uri, *rule, default, page))
        .map(|(uri, _)| Arc::from(uri.as_str()))
}
impl Vault {
    /// Capture the unlocked session and index version before displaying a browser prompt.
    pub fn browser_snapshot(&self) -> Result<BrowserSnapshot> {
        let state = self.inner.read_state();
        let active = state.active.as_ref().ok_or(crate::Error::LoggedOut)?;
        let unlocked = active.unlocked.as_ref().ok_or(crate::Error::Locked)?;
        Ok(BrowserSnapshot {
            epoch: state.epoch,
            revision: unlocked.revision,
        })
    }

    /// Revalidate and reveal both requested fields under one vault read lock.
    /// `other_site_confirmed` must come from the prompt for this snapshot and item.
    pub fn browser_reveal(
        &self,
        snapshot: BrowserSnapshot,
        id: &ItemId,
        page: &PageUrl,
        default: DefaultMatch,
        other_site_confirmed: bool,
        fields: BrowserFields,
    ) -> Result<BrowserCredentials> {
        let state = self.inner.read_state();
        let active = state.active.as_ref().ok_or(crate::Error::LoggedOut)?;
        let unlocked = active.unlocked.as_ref().ok_or(crate::Error::Locked)?;
        if state.epoch != snapshot.epoch || unlocked.revision != snapshot.revision {
            return Err(crate::Error::Conflict);
        }
        let entry = unlocked
            .data
            .browser_entries()
            .find(|entry| entry.summary.id == *id)
            .ok_or(crate::Error::NotFound)?;
        let matched = matched_uri(entry, page, default).is_some();
        if !other_site_confirmed && !matched {
            return Err(crate::Error::NotFound);
        }
        let field = |requested: bool, field| {
            if !requested {
                return Ok(None);
            }
            match reveal::reveal(&entry.cipher, &unlocked.keys, field, 0) {
                Ok(value) => Ok(Some(value)),
                Err(crate::Error::NoSuchField) => Ok(None),
                Err(error) => Err(error),
            }
        };
        Ok(BrowserCredentials {
            username: field(fields.username, CopyField::Username)?,
            password: field(fields.password, CopyField::Password)?,
            matched,
            reprompt: entry.summary.reprompt,
            has_totp: entry.summary.has_totp,
        })
    }

    /// Non-deleted logins, favourites first then by name. Requires an unlocked vault.
    pub fn logins_for(&self, page: &PageUrl, default: DefaultMatch) -> Result<Vec<LoginMatch>> {
        self.inner.read_unlocked(|_, unlocked| {
            let mut found: Vec<_> = unlocked
                .data
                .browser_entries()
                .filter_map(|entry| {
                    Some(LoginMatch {
                        summary: entry.summary.clone(),
                        matched_uri: matched_uri(entry, page, default)?,
                    })
                })
                .collect();
            // The index is already sorted by name; preserve that order within each group.
            found.sort_by_key(|item| !item.summary.favorite);
            Ok(found)
        })
    }
    /// Validate a picker selection against the current unlocked index.
    pub fn login_matches(
        &self,
        id: &ItemId,
        page: &PageUrl,
        default: DefaultMatch,
    ) -> Result<bool> {
        self.inner.read_unlocked(|_, unlocked| {
            Ok(unlocked.data.browser_entries().any(|entry| {
                entry.summary.id == *id && matched_uri(entry, page, default).is_some()
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, MemorySecretStore, VaultConfig, VaultService, index::VaultData, testutil};

    fn assert_atomic_reveal(vault: &Vault, page: &PageUrl) {
        let snapshot = vault.browser_snapshot().unwrap();
        let fields = vault
            .browser_reveal(
                snapshot,
                &ItemId("a".into()),
                page,
                DefaultMatch::Domain,
                false,
                BrowserFields {
                    username: true,
                    password: true,
                },
            )
            .unwrap();
        assert_eq!(fields.username.as_deref().map(String::as_str), Some("u"));
        assert_eq!(fields.password.as_deref().map(String::as_str), Some("p"));
        let username_only = vault
            .browser_reveal(
                snapshot,
                &ItemId("a".into()),
                page,
                DefaultMatch::Domain,
                false,
                BrowserFields {
                    username: true,
                    password: false,
                },
            )
            .unwrap();
        assert_eq!(
            username_only.username.as_deref().map(String::as_str),
            Some("u")
        );
        assert!(username_only.password.is_none());
        let other = PageUrl::new("https://other.org", "/").unwrap();
        assert!(matches!(
            vault.browser_reveal(
                snapshot,
                &ItemId("a".into()),
                &other,
                DefaultMatch::Domain,
                false,
                BrowserFields {
                    username: true,
                    password: true
                }
            ),
            Err(Error::NotFound)
        ));
        assert!(
            vault
                .browser_reveal(
                    snapshot,
                    &ItemId("a".into()),
                    &other,
                    DefaultMatch::Domain,
                    true,
                    BrowserFields {
                        username: false,
                        password: false
                    }
                )
                .is_ok()
        );
        assert!(matches!(
            vault.browser_reveal(
                snapshot,
                &ItemId("d".into()),
                page,
                DefaultMatch::Domain,
                true,
                BrowserFields {
                    username: true,
                    password: true
                }
            ),
            Err(Error::NotFound)
        ));
        assert_snapshot_invalidation(vault, page, snapshot);
    }

    fn assert_snapshot_invalidation(vault: &Vault, page: &PageUrl, snapshot: BrowserSnapshot) {
        let context = vault.inner.unlocked_ctx().unwrap();
        vault.inner.apply(&context, |_, _| {});
        assert!(matches!(
            vault.browser_reveal(
                snapshot,
                &ItemId("a".into()),
                page,
                DefaultMatch::Domain,
                false,
                BrowserFields {
                    username: true,
                    password: true
                }
            ),
            Err(Error::Conflict)
        ));
        let snapshot = vault.browser_snapshot().unwrap();
        vault.inner.write_state().epoch += 1;
        assert!(matches!(
            vault.browser_reveal(
                snapshot,
                &ItemId("a".into()),
                page,
                DefaultMatch::Domain,
                false,
                BrowserFields {
                    username: true,
                    password: true
                }
            ),
            Err(Error::Conflict)
        ));
    }

    #[tokio::test]
    async fn browser_lookup_filters_orders_and_requires_unlock() {
        let dir = std::env::temp_dir().join(format!("vk-browser-{}", uuid::Uuid::new_v4()));
        let account_dir = dir.join("accounts").join(testutil::USER_ID);
        std::fs::create_dir_all(&account_dir).unwrap();
        std::fs::write(
            dir.join("accounts.json"),
            serde_json::json!({"accounts": [{
                "id": testutil::USER_ID, "server": "https://example.com", "email": "a@example.com"
            }]})
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            account_dir.join("account.json"),
            serde_json::json!({
                "id": testutil::USER_ID, "server": "https://example.com", "email": "a@example.com",
                "kdf": {"kind": 0, "iterations": 600_000}, "key": "unused"
            })
            .to_string(),
        )
        .unwrap();
        let config = VaultConfig::new(
            dir.clone(),
            vk_api::DeviceInfo {
                identifier: uuid::Uuid::new_v4(),
                name: "test".into(),
                device_type: 7,
            },
            tokio::runtime::Handle::current(),
        );
        let vault = Vault::open(config, Arc::new(MemorySecretStore::new())).unwrap();
        let page = PageUrl::new("https://sub.second.example.org", "/").unwrap();
        assert!(matches!(
            vault.logins_for(&page, DefaultMatch::Domain),
            Err(Error::Locked)
        ));
        let keys = testutil::ring();
        let a = testutil::login("a", "Alpha", "u", "p", &keys);
        let mut b = testutil::login("b", "Beta", "u", "p", &keys);
        b.favorite = true;
        let mut deleted = testutil::login("d", "Deleted", "u", "p", &keys);
        deleted.deleted_date = Some("2026-11-10".into());
        let data = VaultData::build(
            testutil::sync(
                vec![a, b, deleted, testutil::card("c", "Card", &keys)],
                vec![],
            ),
            &keys,
        );
        vault.inner.write_state().active.as_mut().unwrap().unlocked =
            Some(super::super::Unlocked::new(keys, data));
        assert_atomic_reveal(&vault, &page);
        let found = vault.logins_for(&page, DefaultMatch::Domain).unwrap();
        assert_eq!(
            found.iter().map(|m| &*m.summary.id.0).collect::<Vec<_>>(),
            ["b", "a"]
        );
        assert_eq!(&*found[0].matched_uri, "https://second.example.org");
        for (id, expected) in [
            ("a", true),
            ("b", true),
            ("d", false),
            ("c", false),
            ("missing", false),
        ] {
            assert_eq!(
                vault
                    .login_matches(&ItemId(id.into()), &page, DefaultMatch::Domain)
                    .unwrap(),
                expected
            );
        }
        let exact = PageUrl::new("https://example.com", "/login").unwrap();
        assert!(
            vault
                .login_matches(&ItemId("a".into()), &exact, DefaultMatch::Host)
                .unwrap()
        );
        let other = PageUrl::new("https://example.com", "/other").unwrap();
        assert!(
            !vault
                .login_matches(&ItemId("a".into()), &other, DefaultMatch::Domain)
                .unwrap()
        );
        vault.lock();
        assert!(matches!(
            vault.login_matches(&ItemId("a".into()), &page, DefaultMatch::Domain),
            Err(Error::Locked)
        ));
        drop(vault);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
