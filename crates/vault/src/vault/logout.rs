//! Log out wipes everything the account left on this machine. Every step runs even when an
//! earlier one failed; the failures are collected and reported together.

use std::sync::Arc;

use super::{Inner, lock, locked_active, secret_error};
use crate::{Error, Result, error::LogoutErrors};

impl Inner {
    pub(crate) async fn logout(self: &Arc<Self>) -> Result<()> {
        let (previous, index) = {
            let mut state = self.write_state();
            let previous = state.active.take().ok_or(Error::LoggedOut)?;
            state.epoch += 1;
            state.index.remove(&previous.id);
            (previous, state.index.clone())
        };
        let id = Arc::clone(&previous.id);

        // 1. Background work stops before anything is deleted, so nothing writes into the
        //    account directory afterwards (later writes never recreate it).
        for handle in self.stop_background() {
            let _ = handle.await;
        }
        // 2. Keys, decrypted rows, MRU and the access token zeroize on drop. The SSH agent and
        //    UI learn through the change channels below; the app clears the clipboard.
        drop(previous);
        self.clear_pending();
        self.set_offline(false);
        lock(&self.last_sync).remove(&id);

        let mut errors = Vec::new();
        // 3. Every secret stored under the user id: refresh token, remember-device token, and
        //    whatever the app keeps there (the Touch ID key).
        let wiped = {
            let _secrets = lock(&self.refresh_secret);
            self.secrets.delete_all_for(&id)
        };
        if let Err(error) = wiped {
            errors.push(secret_error(error));
        }
        // 4. `accounts/<id>/`: cache, settings, Touch ID blob, attachment temp files.
        let inner = Arc::clone(self);
        let removed_id = Arc::clone(&id);
        match self
            .config
            .runtime
            .spawn_blocking(move || inner.store.remove_account(&removed_id))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(error),
            Err(error) => errors.push(Error::task(error)),
        }
        if let Err(error) = self.store.save_index(&index) {
            errors.push(error);
        }
        // 5. The most recently used remaining account becomes active (locked).
        if let Some(next) = index.accounts.first() {
            match locked_active(&self.store, &self.config, next) {
                Ok(active) => {
                    let mut state = self.write_state();
                    if state.active.is_none() {
                        state.epoch += 1;
                        state.active = Some(active);
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        self.bump();
        self.bump_ssh();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(LogoutErrors(errors).into())
        }
    }
}
