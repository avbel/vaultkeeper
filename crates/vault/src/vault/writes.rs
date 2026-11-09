//! Writes: encrypt, send with `lastKnownRevisionDate`, update local state, persist, then sync.

use std::sync::Arc;

use super::{Ctx, Inner};
use crate::{
    Error, Result, encrypt,
    keys::encrypt_text,
    model::{FolderView, ItemDraft, ItemId},
    util::now_rfc3339,
};

/// Vaultwarden's refusal of a `lastKnownRevisionDate` older than its copy (`ciphers.rs`:
/// "The client copy of this cipher is out of date. Resync the client and try again.").
pub(super) fn stale_revision_as_conflict(error: Error) -> Error {
    match &error {
        Error::Api(vk_api::Error::Server {
            status: 400,
            message,
        }) if message.contains("out of date") => Error::Conflict,
        _ => error,
    }
}

impl Inner {
    /// Writes need the server; while offline they are refused before anything is encrypted.
    pub(crate) fn writable_ctx(&self) -> Result<Ctx> {
        let ctx = self.unlocked_ctx()?;
        if self.is_offline() {
            return Err(Error::Offline);
        }
        Ok(ctx)
    }

    /// The tail of every write: persist the new local state and ask for a confirming sync.
    pub(super) async fn finish_write(self: &Arc<Self>, ctx: &Ctx) -> Result<()> {
        let persisted = self.persist_vault(ctx).await;
        self.request_sync();
        persisted
    }

    /// An update is built from the stored cipher, so one from a cache older than lossless ciphers
    /// would delete what that cache lost (passkeys). Fetch the server's copy first.
    pub(super) async fn ensure_complete_ciphers(self: &Arc<Self>) -> Result<()> {
        let complete = || self.read_unlocked(|_, unlocked| Ok(unlocked.data.is_complete()));
        if complete()? {
            return Ok(());
        }
        self.sync_now(None).await?;
        if complete()? {
            Ok(())
        } else {
            Err(Error::unsupported(
                "Sync the vault before editing: the local copy is from an older version",
            ))
        }
    }

    fn editable_cipher(&self, id: &str) -> Result<()> {
        self.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(id).ok_or(Error::NotFound)?;
            if entry.cipher.edit {
                Ok(())
            } else {
                Err(Error::ReadOnly)
            }
        })
    }

    pub(crate) async fn save(
        self: &Arc<Self>,
        id: Option<ItemId>,
        draft: ItemDraft,
    ) -> Result<ItemId> {
        let ctx = self.writable_ctx()?;
        if id.is_some() {
            self.ensure_complete_ciphers().await?;
        }
        let prepared = self.read_unlocked(|_, unlocked| {
            let base = match &id {
                Some(id) => Some(&unlocked.data.entry(&id.0).ok_or(Error::NotFound)?.cipher),
                None => None,
            };
            encrypt::prepare(&draft, base, &unlocked.keys)
        })?;
        drop(draft);

        let serial = self.sync_lock.lock().await;
        let prepared = &prepared;
        let cipher = match &id {
            None => {
                self.call(&ctx, |client, token| async move {
                    client
                        .create_cipher(&token, &prepared.request, &prepared.collection_ids)
                        .await
                })
                .await?
            }
            Some(id) => {
                let updated = self
                    .call(&ctx, |client, token| async move {
                        client.update_cipher(&token, &id.0, &prepared.request).await
                    })
                    .await;
                match updated.map_err(stale_revision_as_conflict) {
                    Err(Error::Conflict) => {
                        drop(serial);
                        self.request_sync();
                        return Err(Error::Conflict);
                    }
                    other => other?,
                }
            }
        };
        let saved = ItemId(Arc::from(cipher.id.as_str()));
        self.apply(&ctx, |data, keys| data.upsert_cipher(cipher, keys));
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished.map(|()| saved)
    }

    pub(crate) async fn trash(self: &Arc<Self>, id: &ItemId) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.editable_cipher(&id.0)?;
        let serial = self.sync_lock.lock().await;
        self.call(&ctx, |client, token| async move {
            client.trash_cipher(&token, &id.0).await
        })
        .await?;
        let deleted_at = now_rfc3339();
        self.apply(&ctx, |data, keys| {
            if let Some(entry) = data.entry(&id.0) {
                let mut cipher = entry.cipher.clone();
                cipher.deleted_date = Some(deleted_at);
                data.upsert_cipher(cipher, keys);
            }
        });
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }

    pub(crate) async fn restore(self: &Arc<Self>, id: &ItemId) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.editable_cipher(&id.0)?;
        let serial = self.sync_lock.lock().await;
        let cipher = self
            .call(&ctx, |client, token| async move {
                client.restore_cipher(&token, &id.0).await
            })
            .await?;
        self.apply(&ctx, |data, keys| data.upsert_cipher(cipher, keys));
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }

    pub(crate) async fn delete_permanently(self: &Arc<Self>, id: &ItemId) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.editable_cipher(&id.0)?;
        let serial = self.sync_lock.lock().await;
        self.call(&ctx, |client, token| async move {
            client.delete_cipher(&token, &id.0).await
        })
        .await?;
        self.apply(&ctx, |data, _| {
            data.remove_cipher(&id.0);
        });
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }

    pub(crate) async fn create_folder(self: &Arc<Self>, name: &str) -> Result<FolderView> {
        let ctx = self.writable_ctx()?;
        let encrypted = encrypt_text(name, ctx.keys.user())?;
        let serial = self.sync_lock.lock().await;
        let encrypted = encrypted.as_str();
        let folder = self
            .call(&ctx, |client, token| async move {
                client.create_folder(&token, encrypted).await
            })
            .await?;
        let view = FolderView {
            id: Arc::from(folder.id.as_str()),
            name: Arc::from(name),
        };
        self.apply(&ctx, |data, keys| data.upsert_folder(folder, keys));
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished.map(|()| view)
    }

    pub(crate) async fn rename_folder(self: &Arc<Self>, id: &str, name: &str) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.existing_folder(id)?;
        let encrypted = encrypt_text(name, ctx.keys.user())?;
        let serial = self.sync_lock.lock().await;
        let encrypted = encrypted.as_str();
        let folder = self
            .call(&ctx, |client, token| async move {
                client.update_folder(&token, id, encrypted).await
            })
            .await?;
        self.apply(&ctx, |data, keys| data.upsert_folder(folder, keys));
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }

    pub(crate) async fn delete_folder(self: &Arc<Self>, id: &str) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.existing_folder(id)?;
        let serial = self.sync_lock.lock().await;
        self.call(&ctx, |client, token| async move {
            client.delete_folder(&token, id).await
        })
        .await?;
        self.apply(&ctx, |data, _| data.remove_folder(id));
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }

    fn existing_folder(&self, id: &str) -> Result<()> {
        self.read_unlocked(|_, unlocked| {
            if unlocked.data.has_folder(id) {
                Ok(())
            } else {
                Err(Error::NotFound)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(status: u16, message: &str) -> Error {
        Error::Api(vk_api::Error::Server {
            status,
            message: message.to_owned(),
        })
    }

    #[test]
    fn only_the_out_of_date_refusal_is_a_conflict() {
        let stale = server(
            400,
            "The client copy of this cipher is out of date. Resync the client and try again.",
        );
        assert!(matches!(stale_revision_as_conflict(stale), Error::Conflict));
        let other = stale_revision_as_conflict(server(400, "Invalid folder"));
        assert!(matches!(
            other,
            Error::Api(vk_api::Error::Server { status: 400, .. })
        ));
        let gone = stale_revision_as_conflict(server(404, "out of date"));
        assert!(matches!(gone, Error::Api(_)));
    }
}
