//! The concrete [`Vault`]: one shared [`Inner`] behind an `Arc`, background tasks owned by it.
//!
//! Lock order (never acquire in the other direction):
//! `Store::lock_writes` → `Inner::state` → `Unlocked::mru`, and `Inner::tasks` → `Inner::state`.
//! No std lock is held across an `.await`; async work snapshots a [`Ctx`] first and re-checks the
//! session `epoch` before applying its result, so a late answer never resurrects a locked or
//! logged-out session.

mod attachments;
mod background;
mod collections;
mod logout;
mod probe;
mod service_impl;
mod session;
mod sync;
mod writes;

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::SystemTime,
};

use bwl_api::Client;
use tokio::{sync::Notify, time::Instant};
use zeroize::Zeroizing;

pub use self::background::BackgroundStatus;
use self::{background::Tasks, session::PendingLogin};
use crate::{
    Error, Result,
    config::VaultConfig,
    index::VaultData,
    keys::KeyRing,
    model::ItemId,
    secrets::{SecretStore, SecretStoreError},
    store::{AccountRecord, AccountsIndex, IndexEntry, Store},
};

/// The real vault. Create one per process with [`Vault::open`]; dropping it cancels every
/// background task it started.
pub struct Vault {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    config: VaultConfig,
    store: Store,
    secrets: Arc<dyn SecretStore>,
    state: RwLock<State>,
    changes: tokio::sync::watch::Sender<u64>,
    ssh_changes: tokio::sync::watch::Sender<u64>,
    offline: tokio::sync::watch::Sender<bool>,
    tasks: Mutex<Tasks>,
    /// One sync or write at a time, so a sync can't overwrite a write it did not see.
    sync_lock: tokio::sync::Mutex<()>,
    /// One token refresh at a time; the others wait and reuse its result.
    token_lock: tokio::sync::Mutex<()>,
    /// Serializes refresh-token writes with log out's wipe and a new login's write. Separate from
    /// the state lock, which must never wait on the keychain (an access prompt would freeze
    /// every reader, the UI included).
    refresh_secret: Mutex<()>,
    sync_wanted: Notify,
    probe_wake: Notify,
    pending: Mutex<Option<Arc<PendingLogin>>>,
    asleep: AtomicBool,
    syncs: AtomicU64,
    websocket_connected: AtomicBool,
    last_sync: Mutex<Option<SystemTime>>,
}

pub(crate) struct State {
    /// Bumped on every lock, unlock, login, switch and log out.
    epoch: u64,
    index: AccountsIndex,
    active: Option<Active>,
}

pub(crate) struct Active {
    id: Arc<str>,
    record: AccountRecord,
    client: Arc<Client>,
    token: Option<AccessToken>,
    unlocked: Option<Unlocked>,
}

pub(crate) struct Unlocked {
    keys: Arc<KeyRing>,
    data: VaultData,
    mru: Mutex<VecDeque<ItemId>>,
    ssh_digest: u64,
}

impl Unlocked {
    fn new(keys: KeyRing, data: VaultData) -> Self {
        Self {
            ssh_digest: data.ssh_digest(),
            keys: Arc::new(keys),
            data,
            mru: Mutex::new(VecDeque::new()),
        }
    }
}

pub(crate) struct AccessToken {
    value: Zeroizing<String>,
    expires_at: Instant,
}

/// What an async operation needs from the session, captured once so no lock spans an await.
#[derive(Clone)]
pub(crate) struct Ctx {
    epoch: u64,
    account_id: Arc<str>,
    client: Arc<Client>,
    keys: Arc<KeyRing>,
}

impl Vault {
    /// Loads the saved accounts; the most recently used one becomes active and locked.
    pub fn open(config: VaultConfig, secrets: Arc<dyn SecretStore>) -> Result<Self> {
        let store = Store::open(config.data_dir.clone())?;
        let mut index = store.load_index()?;
        index
            .accounts
            .retain(|entry| matches!(store.load_account(&entry.id), Ok(Some(_))));
        let active = match index.accounts.first() {
            Some(entry) => Some(locked_active(&store, &config, entry)?),
            None => None,
        };
        let inner = Inner {
            store,
            secrets,
            state: RwLock::new(State {
                epoch: 0,
                index,
                active,
            }),
            changes: tokio::sync::watch::Sender::new(0),
            ssh_changes: tokio::sync::watch::Sender::new(0),
            offline: tokio::sync::watch::Sender::new(false),
            tasks: Mutex::new(Tasks::default()),
            sync_lock: tokio::sync::Mutex::new(()),
            token_lock: tokio::sync::Mutex::new(()),
            refresh_secret: Mutex::new(()),
            sync_wanted: Notify::new(),
            probe_wake: Notify::new(),
            pending: Mutex::new(None),
            asleep: AtomicBool::new(false),
            syncs: AtomicU64::new(0),
            websocket_connected: AtomicBool::new(false),
            last_sync: Mutex::new(None),
            config,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The system is going to sleep: stop the websocket, the sync timer and the offline probe.
    pub fn on_sleep(&self) {
        self.inner.on_sleep();
    }

    /// Back from sleep: reconnect the websocket and sync right away.
    pub fn on_wake(&self) {
        self.inner.on_wake();
    }

    /// The network path changed: an offline vault probes the server at once.
    pub fn on_network_change(&self) {
        self.inner.on_network_change();
    }

    /// Asks the background worker for a sync; bursts within the debounce window merge into one.
    pub fn request_sync(&self) {
        self.inner.request_sync();
    }

    /// Bumped when the active account's SSH keys change, including lock and log out; re-read
    /// [`crate::VaultService::ssh_keys`] and push the result to the agent.
    #[must_use]
    pub fn ssh_key_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.ssh_changes.subscribe()
    }

    #[must_use]
    pub fn offline_changes(&self) -> tokio::sync::watch::Receiver<bool> {
        self.inner.offline.subscribe()
    }

    #[must_use]
    pub fn background(&self) -> BackgroundStatus {
        self.inner.background_status()
    }

    /// Successful full syncs since the vault was opened.
    #[must_use]
    pub fn sync_count(&self) -> u64 {
        self.inner.syncs.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn last_sync(&self) -> Option<SystemTime> {
        *lock(&self.inner.last_sync)
    }

    /// The user id of the active account, which also prefixes its secret-store keys.
    #[must_use]
    pub fn active_account_id(&self) -> Option<Arc<str>> {
        let state = self.inner.read_state();
        state.active.as_ref().map(|active| Arc::clone(&active.id))
    }

    /// The app's per-account preferences stored in `account.json`.
    pub fn account_settings(&self) -> Result<serde_json::Value> {
        let state = self.inner.read_state();
        let active = state.active.as_ref().ok_or(Error::LoggedOut)?;
        Ok(active.record.settings.clone())
    }

    pub async fn set_account_settings(&self, settings: serde_json::Value) -> Result<()> {
        self.inner.set_account_settings(settings).await
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        drop(self.inner.stop_background());
    }
}

fn locked_active(store: &Store, config: &VaultConfig, entry: &IndexEntry) -> Result<Active> {
    let record = store.load_account(&entry.id)?.ok_or(Error::NotFound)?;
    let client = Client::with_timeouts(
        record.server.clone(),
        config.device.clone(),
        config.timings.http,
    )?;
    Ok(Active {
        id: Arc::from(record.id.as_str()),
        record,
        client: Arc::new(client),
        token: None,
        unlocked: None,
    })
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn secret_error(error: SecretStoreError) -> Error {
    Error::Io(std::io::Error::other(error))
}

impl Inner {
    fn read_state(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn bump(&self) {
        self.changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    fn bump_ssh(&self) {
        self.ssh_changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    fn is_offline(&self) -> bool {
        *self.offline.borrow()
    }

    fn asleep(&self) -> bool {
        self.asleep.load(Ordering::SeqCst)
    }

    fn is_current(&self, epoch: u64) -> bool {
        let state = self.read_state();
        state.epoch == epoch && state.active.as_ref().is_some_and(|a| a.unlocked.is_some())
    }

    fn read_unlocked<T>(&self, read: impl FnOnce(&Active, &Unlocked) -> Result<T>) -> Result<T> {
        let state = self.read_state();
        let active = state.active.as_ref().ok_or(Error::LoggedOut)?;
        let unlocked = active.unlocked.as_ref().ok_or(Error::Locked)?;
        read(active, unlocked)
    }

    fn unlocked_ctx(&self) -> Result<Ctx> {
        let state = self.read_state();
        let active = state.active.as_ref().ok_or(Error::LoggedOut)?;
        let unlocked = active.unlocked.as_ref().ok_or(Error::Locked)?;
        Ok(Ctx {
            epoch: state.epoch,
            account_id: Arc::clone(&active.id),
            client: Arc::clone(&active.client),
            keys: Arc::clone(&unlocked.keys),
        })
    }

    /// Runs `change` on the unlocked data if the session is still the one `ctx` came from, then
    /// tells the UI (and the SSH agent, when its keys changed).
    fn apply(&self, ctx: &Ctx, change: impl FnOnce(&mut VaultData, &KeyRing)) {
        let ssh_changed = {
            let mut state = self.write_state();
            if state.epoch != ctx.epoch {
                return;
            }
            let Some(unlocked) = state.active.as_mut().and_then(|a| a.unlocked.as_mut()) else {
                return;
            };
            change(&mut unlocked.data, &unlocked.keys);
            let digest = unlocked.data.ssh_digest();
            let changed = digest != unlocked.ssh_digest;
            unlocked.ssh_digest = digest;
            changed
        };
        self.bump();
        if ssh_changed {
            self.bump_ssh();
        }
    }

    fn clear_pending(&self) {
        lock(&self.pending).take();
    }

    async fn set_account_settings(self: &Arc<Self>, settings: serde_json::Value) -> Result<()> {
        let record = {
            let mut state = self.write_state();
            let active = state.active.as_mut().ok_or(Error::LoggedOut)?;
            active.record.settings = settings;
            active.record.clone()
        };
        let inner = Arc::clone(self);
        self.config
            .runtime
            .spawn_blocking(move || inner.store.save_account(&record))
            .await
            .map_err(Error::task)?
    }
}
