//! In-memory `VaultService` for `--mock` and the UI tests.
//!
//! Master password for every mock account: [`MOCK_MASTER_PASSWORD`]. Emails containing "2fa" ask
//! for a second factor ([`MOCK_2FA_CODE`]); emails containing "newdevice" ask for a device OTP
//! ([`MOCK_DEVICE_CODE`]). Server hosts containing "unreachable" fail like a dead network and
//! hosts containing "notbitwarden" answer like a non-Bitwarden server.

mod data;
mod fake;
mod service;
mod state;

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bwl_vault::model::{ItemDraft, ItemId};
use tokio::sync::watch;
use url::Url;

pub use fake::{MockGenerator, MockSshKeys, Prng};

use data::AccountData;

pub const MOCK_MASTER_PASSWORD: &str = "mock";

/// The user key the mock vault accepts in `unlock_with_user_key` for `account_id`, so `--mock`
/// can pre-enrol Touch ID.
#[must_use]
pub fn mock_user_key(account_id: &str) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(format!("mock-user-key:{account_id}").into_bytes())
}
pub const MOCK_2FA_CODE: &str = "123456";
/// What the mock's server probe reports, like Vaultwarden's `/api/version`.
pub const MOCK_SERVER_VERSION: &str = "1.37.5";
pub const MOCK_DEVICE_CODE: &str = "654321";

/// Calls with side effects, recorded so tests can assert what the UI asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockCall {
    Save {
        id: Option<ItemId>,
        name: String,
    },
    Trash(ItemId),
    Restore(ItemId),
    DeletePermanently(ItemId),
    Download {
        item: ItemId,
        attachment: String,
        dest: PathBuf,
    },
    Upload {
        item: ItemId,
        source: PathBuf,
    },
    DeleteAttachment {
        item: ItemId,
        attachment: String,
    },
    CreateFolder(String),
    RenameFolder {
        id: String,
        name: String,
    },
    DeleteFolder(String),
    SwitchAccount(String),
    BeginAddAccount,
    Logout,
    Sync,
    Login {
        server: String,
        email: String,
    },
}

#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Delay added to every async operation; zero in tests.
    pub latency: Duration,
    pub offline: bool,
    /// Start with the first account already unlocked.
    pub unlocked: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(250),
            offline: false,
            unlocked: false,
        }
    }
}

struct Account {
    id: Arc<str>,
    server: Url,
    email: Arc<str>,
    logged_in: bool,
    last_used: u64,
    data: AccountData,
}

struct Inner {
    accounts: Vec<Account>,
    active: Option<usize>,
    unlocked: bool,
    /// `begin_add_account` was called: state is `LoggedOut` until the next login.
    adding: bool,
    clock: u64,
    next_id: u64,
}

pub struct MockVault {
    inner: Mutex<Inner>,
    offline: AtomicBool,
    latency: Duration,
    changes: watch::Sender<u64>,
    calls: Mutex<Vec<MockCall>>,
    last_saved: Mutex<Option<ItemDraft>>,
}

fn account(id: &str, server: &str, email: &str, logged_in: bool, data: AccountData) -> Account {
    Account {
        id: Arc::from(id),
        server: Url::parse(server).unwrap_or_else(|_| unreachable_url()),
        email: Arc::from(email),
        logged_in,
        last_used: 0,
        data,
    }
}

fn unreachable_url() -> Url {
    Url::parse("https://invalid.example").expect("static URL parses")
}

impl MockVault {
    /// Three accounts: alice (≈400 items, active), bob (locked, small vault), carol (logged out).
    #[must_use]
    pub fn new(config: &MockConfig) -> Self {
        let accounts = vec![
            account(
                "acc-alice",
                "https://vault.example.com",
                "alice@example.com",
                true,
                data::alice(),
            ),
            account(
                "acc-bob",
                "https://vault.work.example.org",
                "bob@work.example.org",
                true,
                data::bob(),
            ),
            account(
                "acc-carol",
                "http://192.168.1.10:8000",
                "carol@home.example.net",
                false,
                AccountData::default(),
            ),
        ];
        Self {
            inner: Mutex::new(Inner {
                accounts,
                active: Some(0),
                unlocked: config.unlocked,
                adding: false,
                // Above the seeded MRU ranks in `data::seed_mru`.
                clock: 10_000,
                next_id: 0,
            }),
            offline: AtomicBool::new(config.offline),
            latency: config.latency,
            changes: watch::channel(0).0,
            calls: Mutex::new(Vec::new()),
            last_saved: Mutex::new(None),
        }
    }

    pub fn set_offline(&self, offline: bool) {
        self.offline.store(offline, Ordering::SeqCst);
        self.bump();
    }

    #[must_use]
    pub fn calls(&self) -> Vec<MockCall> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The draft passed to the most recent `save`.
    #[must_use]
    pub fn last_saved(&self) -> Option<ItemDraft> {
        self.last_saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Another device renames `id`: its revision moves on and the change is announced like a
    /// websocket sync, so a draft read before is now stale.
    pub fn edit_elsewhere(&self, id: &ItemId, name: &str) -> bwl_vault::Result<()> {
        {
            let mut inner = self.guard();
            let revision = format!("mock-rev-{}", inner.tick());
            let item = inner.item_mut(id)?;
            let draft = ItemDraft {
                name: name.to_owned(),
                revision_date: Some(Arc::from(revision)),
                ..item.draft.clone()
            };
            let (editable, deleted, last_used) =
                (item.summary.editable, item.summary.deleted, item.last_used);
            *item = data::MockItem::new(id, draft, editable, deleted);
            item.last_used = last_used;
        }
        self.bump();
        Ok(())
    }

    /// Every item name of the account with this email, for leak checks in tests.
    #[must_use]
    pub fn item_names(&self, email: &str) -> Vec<String> {
        self.guard()
            .accounts
            .iter()
            .filter(|account| account.email.as_ref() == email)
            .flat_map(|account| {
                account
                    .data
                    .items
                    .iter()
                    .map(|item| item.summary.name.to_string())
            })
            .collect()
    }

    fn guard(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, call: MockCall) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }

    fn bump(&self) {
        self.changes.send_modify(|version| *version += 1);
    }

    async fn delay(&self) {
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
    }
}
