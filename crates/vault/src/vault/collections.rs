//! Collection assignment, as the official clients' "Assign collections": a personal item moves
//! into an organization through `/share` (re-encrypted for the org key); an organization item
//! gets its collection set replaced through `/collections_v2`. Neither direction can be undone
//! from here: the server has no way back to the personal vault or to another organization.

use std::{collections::HashSet, sync::Arc};

use vk_api::models::{CipherRequest, OptionalCipher};

use super::{Inner, writes::stale_revision_as_conflict};
use crate::{
    Error, Result, encrypt,
    index::VaultData,
    model::{CollectionView, ItemId},
    reveal,
};

enum Assignment {
    Share(Box<CipherRequest>),
    Replace,
}

/// Every picked collection belongs to `organization_id` and lets the user add items.
fn check_writable(
    views: &[CollectionView],
    organization_id: &str,
    picked: &[Arc<str>],
) -> Result<()> {
    if picked.is_empty() {
        return Err(Error::unsupported("Pick at least one collection"));
    }
    let writable = |id: &Arc<str>| {
        views.iter().any(|view| {
            view.id == *id && &*view.organization_id == organization_id && !view.read_only
        })
    };
    if picked.iter().all(writable) {
        Ok(())
    } else {
        Err(Error::ReadOnly)
    }
}

/// `picked` plus the read-only collections the item is already in: the user can't take it out of
/// those, and Vaultwarden refuses the whole update if they are missing.
fn with_read_only(
    views: &[CollectionView],
    current: &[String],
    picked: &[Arc<str>],
) -> Vec<String> {
    let read_only = current.iter().filter(|id| {
        views
            .iter()
            .any(|view| view.read_only && &*view.id == id.as_str())
    });
    let mut seen = HashSet::new();
    picked
        .iter()
        .map(ToString::to_string)
        .chain(read_only.cloned())
        .filter(|id| seen.insert(id.clone()))
        .collect()
}

fn plan(
    data: &VaultData,
    keys: &crate::keys::KeyRing,
    id: &ItemId,
    organization_id: &str,
    picked: &[Arc<str>],
) -> Result<(Assignment, Vec<String>)> {
    let entry = data.entry(&id.0).ok_or(Error::NotFound)?;
    let cipher = &entry.cipher;
    if !cipher.edit {
        return Err(Error::ReadOnly);
    }
    let views = data.collection_views();
    check_writable(&views, organization_id, picked)?;
    match cipher.organization_id.as_deref() {
        None => {
            let draft = reveal::draft(cipher, keys)?;
            let request = encrypt::prepare_share(&draft, cipher, organization_id, keys)?;
            let ids = picked.iter().map(ToString::to_string).collect();
            Ok((Assignment::Share(Box::new(request)), ids))
        }
        Some(current) if current == organization_id => Ok((
            Assignment::Replace,
            with_read_only(&views, &cipher.collection_ids, picked),
        )),
        Some(_) => Err(Error::unsupported(
            "Items can't be moved to another organization",
        )),
    }
}

impl Inner {
    pub(crate) async fn assign_collections(
        self: &Arc<Self>,
        id: &ItemId,
        organization_id: &str,
        collection_ids: &[Arc<str>],
    ) -> Result<()> {
        let ctx = self.writable_ctx()?;
        // A share re-encrypts the stored cipher, like an update.
        self.ensure_complete_ciphers().await?;
        let (assignment, ids) = self.read_unlocked(|_, unlocked| {
            plan(
                &unlocked.data,
                &unlocked.keys,
                id,
                organization_id,
                collection_ids,
            )
        })?;

        let serial = self.sync_lock.lock().await;
        let ids = ids.as_slice();
        let outcome = match &assignment {
            Assignment::Share(request) => {
                let request = request.as_ref();
                self.call(&ctx, |client, token| async move {
                    client.share_cipher(&token, &id.0, request, ids).await
                })
                .await
                .map(|cipher| OptionalCipher {
                    unavailable: false,
                    cipher: Some(cipher),
                })
            }
            Assignment::Replace => {
                self.call(&ctx, |client, token| async move {
                    client.update_cipher_collections(&token, &id.0, ids).await
                })
                .await
            }
        };
        let outcome = match outcome.map_err(stale_revision_as_conflict) {
            Err(Error::Conflict) => {
                drop(serial);
                self.request_sync();
                return Err(Error::Conflict);
            }
            other => other?,
        };
        self.apply(&ctx, |data, keys| match outcome {
            OptionalCipher {
                unavailable: true, ..
            } => {
                data.remove_cipher(&id.0);
            }
            OptionalCipher {
                cipher: Some(mut cipher),
                ..
            } => {
                // Bitwarden's share answer has no `collectionIds`; the request's are the truth.
                cipher.collection_ids = ids.to_vec();
                data.upsert_cipher(cipher, keys);
            }
            OptionalCipher { cipher: None, .. } => {}
        });
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(id: &str, organization_id: &str, read_only: bool) -> CollectionView {
        CollectionView {
            id: id.into(),
            organization_id: organization_id.into(),
            name: id.into(),
            read_only,
        }
    }

    fn ids(list: &[&str]) -> Vec<Arc<str>> {
        list.iter().map(|id| Arc::from(*id)).collect()
    }

    #[test]
    fn only_writable_collections_of_the_organization_can_be_picked() {
        let views = [
            view("a", "org", false),
            view("ro", "org", true),
            view("other", "org2", false),
        ];
        assert!(check_writable(&views, "org", &ids(&["a"])).is_ok());
        assert!(matches!(
            check_writable(&views, "org", &ids(&["ro"])),
            Err(Error::ReadOnly)
        ));
        assert!(matches!(
            check_writable(&views, "org", &ids(&["a", "other"])),
            Err(Error::ReadOnly)
        ));
        assert!(matches!(
            check_writable(&views, "org", &ids(&["unknown"])),
            Err(Error::ReadOnly)
        ));
        assert!(matches!(
            check_writable(&views, "org", &[]),
            Err(Error::Api(vk_api::Error::Server { status: 400, .. }))
        ));
    }

    #[test]
    fn read_only_collections_the_item_is_in_are_kept() {
        let views = [
            view("a", "org", false),
            view("b", "org", false),
            view("ro", "org", true),
            view("ro2", "org", true),
        ];
        let current = vec!["a".to_owned(), "ro".to_owned()];
        assert_eq!(
            with_read_only(&views, &current, &ids(&["b"])),
            vec!["b".to_owned(), "ro".to_owned()]
        );
        assert_eq!(
            with_read_only(&views, &current, &ids(&["a", "b"])),
            vec!["a".to_owned(), "b".to_owned(), "ro".to_owned()]
        );
    }
}
