//! Browser pairings and installed browsers as the UI process sees them.

use std::path::PathBuf;

use vk_ipc::UiNotice;

use super::Notifier;
use crate::{
    browser_status,
    daemon::browser::{
        manifests::ManifestBrowser,
        pairing::{PairingEntry, PairingStore},
    },
    hooks::{BrowserPairings, HookError, HookResult},
};

pub struct BrowserFiles {
    pub app_support: PathBuf,
    pub store: PathBuf,
    pub notify: Notifier,
}

impl BrowserPairings for BrowserFiles {
    fn installed(&self) -> Vec<ManifestBrowser> {
        browser_status::installed_browsers(&self.app_support)
    }

    fn paired(&self) -> Vec<PairingEntry> {
        match PairingStore::load(&self.store) {
            Ok(store) => store.entries(),
            Err(error) => {
                tracing::warn!(%error, "cannot read the paired browsers");
                Vec::new()
            }
        }
    }

    fn remove(&self, public_key: &str) -> HookResult<()> {
        let removed = PairingStore::remove_key(&self.store, public_key).map_err(|error| {
            tracing::warn!(%error, "cannot remove a paired browser");
            HookError::Failed("Cannot update the paired browsers".to_owned())
        })?;
        if removed {
            // The daemon reloads the store on this notice and drops the key's live sessions.
            (self.notify)(UiNotice::SettingsChanged);
        }
        Ok(())
    }
}
