//! Full sync, access tokens (refresh once on 401) and writing the cache.

use std::{future::Future, sync::Arc, sync::atomic::Ordering, time::SystemTime};

use bwl_api::{Client, models::SyncResponse};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::{AccessToken, Ctx, Inner, lock, secret_error, session::token_expiry};
use crate::{
    Error, Result, index::VaultData, keys::KeyRing, secrets::refresh_token_key,
    store::AccountRecord,
};

impl Inner {
    /// One full sync of the active, unlocked account. `expected` drops a background request that
    /// was made for an earlier session.
    pub(crate) async fn sync_now(self: &Arc<Self>, expected: Option<u64>) -> Result<()> {
        if self.asleep() {
            return Ok(());
        }
        let ctx = self.unlocked_ctx()?;
        if expected.is_some_and(|epoch| epoch != ctx.epoch) {
            return Ok(());
        }
        let _serial = self.sync_lock.lock().await;
        let response = self
            .call(
                &ctx,
                |client, token| async move { client.sync(&token).await },
            )
            .await?;
        // Locked while the request was in flight: don't decrypt a whole vault copy to drop it.
        if !self.is_current(ctx.epoch) {
            return Ok(());
        }
        let previous = Arc::clone(&ctx.keys);
        let (keys, data) = self
            .config
            .runtime
            .spawn_blocking(move || build_synced(response, &previous))
            .await
            .map_err(Error::task)??;
        if let Some(record) = self.install_synced(&ctx, keys, data) {
            let inner = Arc::clone(self);
            self.config
                .runtime
                .spawn_blocking(move || inner.store.save_account(&record))
                .await
                .map_err(Error::task)??;
        }
        self.persist_vault(&ctx).await?;
        self.syncs.fetch_add(1, Ordering::Relaxed);
        self.set_offline(false);
        Ok(())
    }

    /// Swaps in the new data; returns the account record when the protected keys changed
    /// (a password change elsewhere), so offline unlock keeps working with the new password.
    fn install_synced(&self, ctx: &Ctx, keys: KeyRing, data: VaultData) -> Option<AccountRecord> {
        let (previous, ssh_changed, record) = {
            let mut state = self.write_state();
            if state.epoch != ctx.epoch {
                return None;
            }
            let active = state.active.as_mut()?;
            let unlocked = active.unlocked.as_mut()?;
            let digest = data.ssh_digest();
            let ssh_changed = digest != unlocked.ssh_digest;
            unlocked.ssh_digest = digest;
            unlocked.keys = Arc::new(keys);
            let profile = &data.profile;
            let record = match &profile.key {
                Some(key)
                    if *key != active.record.key
                        || profile.private_key != active.record.private_key =>
                {
                    active.record.key.clone_from(key);
                    active.record.private_key.clone_from(&profile.private_key);
                    Some(active.record.clone())
                }
                _ => None,
            };
            let previous = std::mem::replace(&mut unlocked.data, data);
            (previous, ssh_changed, record)
        };
        drop(previous);
        // Before the bump, so whoever reacts to it (the UI's status line) reads the new time.
        *lock(&self.last_sync) = Some(SystemTime::now());
        self.bump();
        if ssh_changed {
            self.bump_ssh();
        }
        record
    }

    /// Writes `vault.json` from the current in-memory state. The snapshot is taken under the
    /// store's write lock, so concurrent persists can only ever leave the newest one on disk.
    pub(crate) async fn persist_vault(self: &Arc<Self>, ctx: &Ctx) -> Result<()> {
        let inner = Arc::clone(self);
        let epoch = ctx.epoch;
        let id = Arc::clone(&ctx.account_id);
        self.config
            .runtime
            .spawn_blocking(move || -> Result<()> {
                let _writes = inner.store.lock_writes();
                let bytes = {
                    let state = inner.read_state();
                    if state.epoch != epoch {
                        return Ok(());
                    }
                    let Some(unlocked) = state.active.as_ref().and_then(|a| a.unlocked.as_ref())
                    else {
                        return Ok(());
                    };
                    unlocked.data.to_json()?
                };
                inner.store.save_vault_locked(&id, &bytes)
            })
            .await
            .map_err(Error::task)?
    }

    /// Runs `op` with a valid access token; on 401 refreshes once and retries. A network failure
    /// switches the vault to offline mode.
    pub(crate) async fn call<T, F, Fut>(self: &Arc<Self>, ctx: &Ctx, op: F) -> Result<T>
    where
        F: Fn(Arc<Client>, Zeroizing<String>) -> Fut,
        Fut: Future<Output = bwl_api::Result<T>>,
    {
        let result = self.call_once_refreshed(ctx, op).await;
        if let Err(error) = &result
            && error.is_offline()
        {
            self.went_offline(ctx);
        }
        result
    }

    async fn call_once_refreshed<T, F, Fut>(&self, ctx: &Ctx, op: F) -> Result<T>
    where
        F: Fn(Arc<Client>, Zeroizing<String>) -> Fut,
        Fut: Future<Output = bwl_api::Result<T>>,
    {
        let token = self.access_token(ctx, None).await?;
        match op(Arc::clone(&ctx.client), token.clone()).await {
            Err(bwl_api::Error::Unauthorized) => {
                let fresh = self.access_token(ctx, Some(&token)).await?;
                Ok(op(Arc::clone(&ctx.client), fresh).await?)
            }
            other => Ok(other?),
        }
    }

    fn current_token(&self, ctx: &Ctx) -> Option<Zeroizing<String>> {
        let state = self.read_state();
        let active = state.active.as_ref().filter(|a| a.id == ctx.account_id)?;
        let token = active.token.as_ref()?;
        let margin = self.config.timings.token_refresh_margin;
        (token.expires_at > Instant::now() + margin).then(|| token.value.clone())
    }

    /// A cached token unless it is about to expire or the server just `rejected` it.
    pub(crate) async fn access_token(
        &self,
        ctx: &Ctx,
        rejected: Option<&Zeroizing<String>>,
    ) -> Result<Zeroizing<String>> {
        if rejected.is_none()
            && let Some(token) = self.current_token(ctx)
        {
            return Ok(token);
        }
        let _refreshing = self.token_lock.lock().await;
        if let Some(token) = self.current_token(ctx)
            && rejected.is_none_or(|rejected| **rejected != *token)
        {
            return Ok(token);
        }
        self.refresh(ctx).await
    }

    /// A refresh token the server rejects is deleted: the user has to log in again.
    async fn refresh(&self, ctx: &Ctx) -> Result<Zeroizing<String>> {
        let key = refresh_token_key(&ctx.account_id);
        let stored = self
            .secrets
            .get(&key)
            .map_err(secret_error)?
            .ok_or(Error::Api(bwl_api::Error::Unauthorized))?;
        let refresh = std::str::from_utf8(&stored)
            .map_err(|_| Error::protocol("the stored refresh token is not text"))?;
        let response = match ctx.client.refresh(refresh).await {
            Ok(response) => response,
            Err(bwl_api::Error::Unauthorized) => {
                self.secrets.delete(&key).map_err(secret_error)?;
                return Err(Error::Api(bwl_api::Error::Unauthorized));
            }
            Err(error) => return Err(error.into()),
        };
        let access = Zeroizing::new(response.access_token);
        if let Some(rotated) = response.refresh_token.map(Zeroizing::new)
            && rotated.as_bytes() != stored.as_slice()
        {
            self.store_rotated(ctx, &key, &stored, &rotated)?;
        }
        let mut state = self.write_state();
        if let Some(active) = state.active.as_mut().filter(|a| a.id == ctx.account_id) {
            active.token = Some(AccessToken {
                value: access.clone(),
                expires_at: token_expiry(response.expires_in),
            });
        }
        Ok(access)
    }

    /// Log out drops the account from the index before it takes `refresh_secret` to wipe the
    /// secrets, and a new login stores a different token under that lock, so a refresh that raced
    /// either must not write its rotated token back. The state lock is held only for the index
    /// check, never across keychain calls.
    fn store_rotated(
        &self,
        ctx: &Ctx,
        key: &str,
        used: &[u8],
        rotated: &Zeroizing<String>,
    ) -> Result<()> {
        let _secrets = lock(&self.refresh_secret);
        if self.read_state().index.find(&ctx.account_id).is_none() {
            return Ok(());
        }
        let current = self.secrets.get(key).map_err(secret_error)?;
        if current.is_none_or(|current| current.as_slice() != used) {
            return Ok(());
        }
        self.secrets
            .set(key, rotated.as_bytes())
            .map_err(secret_error)
    }

    pub(crate) fn set_offline(&self, offline: bool) {
        let changed = self.offline.send_if_modified(|current| {
            let changed = *current != offline;
            *current = offline;
            changed
        });
        if changed {
            self.bump();
        }
    }

    pub(crate) fn went_offline(self: &Arc<Self>, ctx: &Ctx) {
        // The socket died with the network; the probe restarts it once the server answers.
        self.websocket_connected.store(false, Ordering::SeqCst);
        self.set_offline(true);
        self.ensure_probe(ctx.epoch, false);
    }
}

fn build_synced(response: SyncResponse, previous: &KeyRing) -> Result<(KeyRing, VaultData)> {
    let keys = KeyRing::build(
        previous.user_key_copy()?,
        response.profile.private_key.as_deref(),
        &response.profile.organizations,
        Some(previous),
    )?;
    let data = VaultData::build(response, &keys);
    Ok((keys, data))
}
