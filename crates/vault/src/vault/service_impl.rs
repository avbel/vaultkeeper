use std::{path::PathBuf, sync::Arc};

use tokio::sync::watch;
use zeroize::Zeroizing;

use super::{Vault, lock};
use crate::{
    Error, Result, TotpCode, VaultService,
    index::record_recent,
    model::{
        AccountView, AttachmentView, CollectionView, CopyField, Filter, FolderView, ItemDraft,
        ItemId, ItemSummary, LoginRequest, LoginStep, OrganizationView, SendDraft, SendSummary,
        ServerProbe, SessionState, SshKeyMaterial, TwoFactorAnswer,
    },
    reveal,
    util::unix_now,
};

impl VaultService for Vault {
    fn state(&self) -> SessionState {
        self.inner.session_state()
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.inner.changes.subscribe()
    }

    async fn login(
        &self,
        request: LoginRequest,
        two_factor: Option<TwoFactorAnswer>,
        new_device_otp: Option<String>,
    ) -> Result<LoginStep> {
        self.inner.login(request, two_factor, new_device_otp).await
    }

    async fn send_email_code(&self) -> Result<()> {
        self.inner.send_email_code().await
    }

    async fn unlock_with_password(&self, password: Zeroizing<String>) -> Result<()> {
        self.inner.unlock_with_password(password).await
    }

    fn unlock_with_user_key(&self, user_key: Zeroizing<Vec<u8>>) -> Result<()> {
        self.inner.unlock_with_user_key(&user_key)
    }

    fn user_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.inner.user_key()
    }

    async fn verify_master_password(&self, password: Zeroizing<String>) -> Result<bool> {
        self.inner.verify_master_password(password).await
    }

    fn lock(&self) {
        self.inner.lock_session();
    }

    async fn logout(&self) -> Result<()> {
        self.inner.logout().await
    }

    fn accounts(&self) -> Vec<AccountView> {
        self.inner.account_views()
    }

    fn switch_account(&self, account_id: &str) -> Result<()> {
        self.inner.switch_account(account_id)
    }

    fn begin_add_account(&self) {
        self.inner.begin_add_account();
    }

    async fn sync(&self) -> Result<()> {
        self.inner.sync_now(None).await
    }

    fn is_offline(&self) -> bool {
        self.inner.is_offline()
    }

    fn last_sync(&self) -> Option<std::time::SystemTime> {
        self.inner.last_sync()
    }

    async fn probe_server(&self, server: &url::Url) -> Result<ServerProbe> {
        super::probe::probe(server, self.inner.config.timings.probe_timeout).await
    }

    fn search(&self, query: &str, filter: &Filter) -> Result<Arc<[ItemSummary]>> {
        self.inner.read_unlocked(|_, unlocked| {
            let mru = lock(&unlocked.mru);
            Ok(unlocked.data.search(query, filter, &mru))
        })
    }

    fn folders(&self) -> Result<Vec<FolderView>> {
        self.inner
            .read_unlocked(|_, unlocked| Ok(unlocked.data.folder_views()))
    }

    fn organizations(&self) -> Result<Vec<OrganizationView>> {
        self.inner
            .read_unlocked(|_, unlocked| Ok(unlocked.data.org_views()))
    }

    fn collections(&self) -> Result<Vec<CollectionView>> {
        self.inner
            .read_unlocked(|_, unlocked| Ok(unlocked.data.collection_views()))
    }

    fn reveal(&self, id: &ItemId, field: CopyField) -> Result<Zeroizing<String>> {
        self.inner.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(&id.0).ok_or(Error::NotFound)?;
            let value = reveal::reveal(&entry.cipher, &unlocked.keys, field, unix_now())?;
            record_recent(&mut lock(&unlocked.mru), &entry.summary.id);
            Ok(value)
        })
    }

    fn totp(&self, id: &ItemId, unix_time: u64) -> Result<TotpCode> {
        self.inner.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(&id.0).ok_or(Error::NotFound)?;
            reveal::totp(&entry.cipher, &unlocked.keys, unix_time)
        })
    }

    fn draft(&self, id: &ItemId) -> Result<ItemDraft> {
        self.inner.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(&id.0).ok_or(Error::NotFound)?;
            reveal::draft(&entry.cipher, &unlocked.keys)
        })
    }

    async fn save(&self, id: Option<ItemId>, draft: ItemDraft) -> Result<ItemId> {
        self.inner.save(id, draft).await
    }

    fn attachments(&self, id: &ItemId) -> Result<Vec<AttachmentView>> {
        self.inner.attachment_views(id)
    }

    async fn download_attachment(
        &self,
        id: &ItemId,
        attachment_id: &str,
        dest: PathBuf,
    ) -> Result<()> {
        self.inner
            .download_attachment(id, attachment_id, dest)
            .await
    }

    async fn upload_attachment(&self, id: &ItemId, source: PathBuf) -> Result<AttachmentView> {
        self.inner.upload_attachment(id, source).await
    }

    async fn delete_attachment(&self, id: &ItemId, attachment_id: &str) -> Result<()> {
        self.inner.delete_attachment(id, attachment_id).await
    }

    async fn assign_collections(
        &self,
        id: &ItemId,
        organization_id: &str,
        collection_ids: Vec<Arc<str>>,
    ) -> Result<()> {
        self.inner
            .assign_collections(id, organization_id, &collection_ids)
            .await
    }

    async fn trash(&self, id: &ItemId) -> Result<()> {
        self.inner.trash(id).await
    }

    async fn restore(&self, id: &ItemId) -> Result<()> {
        self.inner.restore(id).await
    }

    async fn delete_permanently(&self, id: &ItemId) -> Result<()> {
        self.inner.delete_permanently(id).await
    }

    async fn create_folder(&self, name: &str) -> Result<FolderView> {
        self.inner.create_folder(name).await
    }

    async fn rename_folder(&self, id: &str, name: &str) -> Result<()> {
        self.inner.rename_folder(id, name).await
    }

    async fn delete_folder(&self, id: &str) -> Result<()> {
        self.inner.delete_folder(id).await
    }

    fn sends(&self) -> Result<Vec<SendSummary>> {
        self.inner.send_summaries()
    }

    fn send_draft(&self, id: &str) -> Result<SendDraft> {
        self.inner.send_draft(id)
    }

    fn send_link(&self, id: &str) -> Result<Zeroizing<String>> {
        self.inner.send_link(id)
    }

    async fn save_send(&self, id: Option<Arc<str>>, draft: SendDraft) -> Result<SendSummary> {
        self.inner.save_send(id, draft).await
    }

    async fn delete_send(&self, id: &str) -> Result<()> {
        self.inner.delete_send(id).await
    }

    async fn remove_send_password(&self, id: &str) -> Result<()> {
        self.inner.remove_send_password(id).await
    }

    /// Empty while locked or logged out: the agent serves only the unlocked account's keys.
    fn ssh_keys(&self) -> Result<Vec<SshKeyMaterial>> {
        let state = self.inner.read_state();
        let Some(unlocked) = state.active.as_ref().and_then(|a| a.unlocked.as_ref()) else {
            return Ok(Vec::new());
        };
        // One broken item (no private key, an org key we can't decrypt) is skipped, so the
        // agent still gets every other key and drops deleted ones.
        let keys = unlocked
            .data
            .ssh_entries()
            .filter_map(|entry| {
                match reveal::reveal(&entry.cipher, &unlocked.keys, CopyField::SshPrivateKey, 0) {
                    Ok(private_key) => Some(SshKeyMaterial {
                        cipher_id: entry.summary.id.clone(),
                        name: entry.summary.name.to_string(),
                        private_key,
                    }),
                    Err(error) => {
                        tracing::warn!(%error, item = %entry.summary.id.0, "SSH key item skipped");
                        None
                    }
                }
            })
            .collect();
        Ok(keys)
    }
}
