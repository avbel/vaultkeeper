use std::{future::Future, sync::Arc};

use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::{
    Result, TotpCode,
    model::{
        CollectionView, CopyField, Filter, FolderView, ItemDraft, ItemId, ItemSummary,
        LoginRequest, LoginStep, OrganizationView, SessionState, SshKeyMaterial, TwoFactorAnswer,
    },
};

/// The UI-facing vault API. Implemented by the real vault (step 7) and by the UI mock.
///
/// Cheap, synchronous calls (list, search, reveal) read in-memory state; anything that hits the
/// network or runs the KDF is async. Network calls return [`crate::Error::Locked`] when locked.
pub trait VaultService: Send + Sync + 'static {
    fn state(&self) -> SessionState;

    /// Bumped on every state or data change; the UI re-reads what it shows when it changes.
    fn changes(&self) -> watch::Receiver<u64>;

    /// First round: prelogin + password grant. Repeat with `two_factor` / `new_device_otp`
    /// when the previous call asked for them.
    fn login(
        &self,
        request: LoginRequest,
        two_factor: Option<TwoFactorAnswer>,
        new_device_otp: Option<String>,
    ) -> impl Future<Output = Result<LoginStep>> + Send;

    fn send_email_code(&self) -> impl Future<Output = Result<()>> + Send;

    /// Offline: derives the master key from the cached KDF settings.
    fn unlock_with_password(
        &self,
        password: Zeroizing<String>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Touch ID path: the platform layer returns the user key it unwrapped.
    fn unlock_with_user_key(&self, user_key: Zeroizing<Vec<u8>>) -> Result<()>;

    /// For Touch ID enrolment. Fails when locked.
    fn user_key(&self) -> Result<Zeroizing<Vec<u8>>>;

    /// Re-prompt check for items with `reprompt`; does not change the session.
    fn verify_master_password(
        &self,
        password: Zeroizing<String>,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// Zeroizes keys and decrypted views; the encrypted cache stays on disk.
    fn lock(&self);

    /// Deletes the cache and tokens.
    fn logout(&self) -> impl Future<Output = Result<()>> + Send;

    /// Runs on unlock, every 30 minutes, on demand and after every write. A network failure leaves
    /// the cached vault usable and flips [`VaultService::is_offline`]; the next success clears it.
    fn sync(&self) -> impl Future<Output = Result<()>> + Send;

    /// True while the server is unreachable; the UI shows an "offline mode" toast when it opens.
    /// Writes fail with an API error while offline.
    fn is_offline(&self) -> bool;

    /// Most-recently-used first when `query` is empty; otherwise ranked by name/subtitle/URI match.
    fn search(&self, query: &str, filter: &Filter) -> Result<Arc<[ItemSummary]>>;

    fn folders(&self) -> Result<Vec<FolderView>>;
    fn organizations(&self) -> Result<Vec<OrganizationView>>;
    fn collections(&self) -> Result<Vec<CollectionView>>;

    /// Decrypts one field on demand and records the item as recently used.
    fn reveal(&self, id: &ItemId, field: CopyField) -> Result<Zeroizing<String>>;

    /// Current code for the item's TOTP secret at `unix_time`.
    fn totp(&self, id: &ItemId, unix_time: u64) -> Result<TotpCode>;

    fn draft(&self, id: &ItemId) -> Result<ItemDraft>;

    /// Creates (id `None`) or updates an item; returns its id.
    fn save(
        &self,
        id: Option<ItemId>,
        draft: ItemDraft,
    ) -> impl Future<Output = Result<ItemId>> + Send;

    fn trash(&self, id: &ItemId) -> impl Future<Output = Result<()>> + Send;
    fn restore(&self, id: &ItemId) -> impl Future<Output = Result<()>> + Send;
    fn delete_permanently(&self, id: &ItemId) -> impl Future<Output = Result<()>> + Send;

    fn create_folder(&self, name: &str) -> impl Future<Output = Result<FolderView>> + Send;
    fn rename_folder(&self, id: &str, name: &str) -> impl Future<Output = Result<()>> + Send;
    fn delete_folder(&self, id: &str) -> impl Future<Output = Result<()>> + Send;

    /// All non-deleted SSH key items, for the agent.
    fn ssh_keys(&self) -> Result<Vec<SshKeyMaterial>>;
}
