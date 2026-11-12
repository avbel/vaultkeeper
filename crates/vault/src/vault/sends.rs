//! Send reads and writes. Writes follow `writes.rs`: encrypt, call under `sync_lock`, apply,
//! persist, then ask for a confirming sync.

use std::sync::Arc;

use zeroize::Zeroizing;

use super::Inner;
use crate::{
    Error, Result,
    model::{SendDraft, SendSummary},
    sends,
    util::unix_now,
};

fn now() -> i64 {
    i64::try_from(unix_now()).unwrap_or(i64::MAX)
}

impl Inner {
    pub(crate) fn send_summaries(&self) -> Result<Vec<SendSummary>> {
        self.read_unlocked(|_, unlocked| Ok(unlocked.data.sends.summaries()))
    }

    pub(crate) fn send_draft(&self, id: &str) -> Result<SendDraft> {
        self.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.sends.get(id).ok_or(Error::NotFound)?;
            sends::draft(&entry.send, &unlocked.keys)
        })
    }

    pub(crate) fn send_link(&self, id: &str) -> Result<Zeroizing<String>> {
        self.read_unlocked(|active, unlocked| {
            let entry = unlocked.data.sends.get(id).ok_or(Error::NotFound)?;
            sends::link(&entry.send, &unlocked.keys, &active.record.server)
        })
    }

    pub(crate) async fn save_send(
        self: &Arc<Self>,
        id: Option<Arc<str>>,
        draft: SendDraft,
    ) -> Result<SendSummary> {
        let ctx = self.writable_ctx()?;
        let base = match &id {
            Some(id) => Some(self.read_unlocked(|_, unlocked| {
                let entry = unlocked.data.sends.get(id).ok_or(Error::NotFound)?;
                Ok(entry.send.clone())
            })?),
            None => None,
        };
        // A new password means PBKDF2 with 100 000 rounds: keep it off the async workers.
        let keys = Arc::clone(&ctx.keys);
        let request = self
            .config
            .runtime
            .spawn_blocking(move || sends::prepare(&draft, base.as_ref(), &keys, now()))
            .await
            .map_err(Error::task)??;

        let serial = self.sync_lock.lock().await;
        let request = &request;
        let saved = match &id {
            None => {
                self.call(&ctx, |client, token| async move {
                    client.create_send(&token, request).await
                })
                .await?
            }
            Some(id) => {
                self.call(&ctx, |client, token| async move {
                    client.update_send(&token, id, request).await
                })
                .await?
            }
        };
        let summary = self.apply_send(&ctx, saved);
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished.map(|()| summary)
    }

    pub(crate) async fn delete_send(self: &Arc<Self>, id: &str) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.existing_send(id)?;
        let serial = self.sync_lock.lock().await;
        self.call(&ctx, |client, token| async move {
            client.delete_send(&token, id).await
        })
        .await?;
        self.apply(&ctx, |data, _| data.sends.remove(id));
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }

    pub(crate) async fn remove_send_password(self: &Arc<Self>, id: &str) -> Result<()> {
        let ctx = self.writable_ctx()?;
        self.existing_send(id)?;
        let serial = self.sync_lock.lock().await;
        let saved = self
            .call(&ctx, |client, token| async move {
                client.remove_send_password(&token, id).await
            })
            .await?;
        self.apply_send(&ctx, saved);
        let finished = self.finish_write(&ctx).await;
        drop(serial);
        finished
    }

    /// Stores the server's answer and returns its list row. The row is built from the answer
    /// itself, so it exists even when the session moved on and nothing was stored.
    fn apply_send(&self, ctx: &super::Ctx, saved: vk_api::models::SendItem) -> SendSummary {
        let summary = sends::summary(&saved, &ctx.keys);
        self.apply(ctx, |data, keys| {
            data.sends.upsert(saved, keys);
        });
        summary
    }

    fn existing_send(&self, id: &str) -> Result<()> {
        self.read_unlocked(|_, unlocked| {
            unlocked.data.sends.get(id).map(drop).ok_or(Error::NotFound)
        })
    }
}
