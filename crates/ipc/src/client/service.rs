use std::{os::unix::ffi::OsStrExt, path::PathBuf, sync::Arc};

use bwl_vault::{
    Error, Result, TotpCode, VaultService,
    model::{
        AccountView, AttachmentView, CollectionView, CopyField, Filter, FolderView, ItemDraft,
        ItemId, ItemSummary, LoginRequest, LoginStep, OrganizationView, ServerProbe, SessionState,
        SshKeyMaterial, TwoFactorAnswer,
    },
};
use tokio::sync::watch;
use zeroize::Zeroizing;

use super::RemoteVault;
use crate::{
    ConvertError, IpcError,
    protocol::{Call, Reply},
};

fn unexpected() -> Error {
    IpcError::Protocol("the reply does not match the call").into()
}

fn invalid(error: ConvertError) -> Error {
    IpcError::Convert(error).into()
}

fn unit(reply: &Reply) -> Result<()> {
    match reply {
        Reply::Unit => Ok(()),
        _ => Err(unexpected()),
    }
}

fn path_bytes(path: &std::path::Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn convert_all<D, T: From<D>>(items: Vec<D>) -> Vec<T> {
    items.into_iter().map(T::from).collect()
}

impl VaultService for RemoteVault {
    fn state(&self) -> SessionState {
        self.cache().state.clone()
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.clone()
    }

    async fn login(
        &self,
        request: LoginRequest,
        two_factor: Option<TwoFactorAnswer>,
        new_device_otp: Option<String>,
    ) -> Result<LoginStep> {
        let call = Call::Login {
            request: request.into(),
            two_factor: two_factor.map(Into::into),
            new_device_otp,
        };
        match self.call(call).await? {
            Reply::LoginStep(step) => step.try_into().map_err(invalid),
            _ => Err(unexpected()),
        }
    }

    async fn send_email_code(&self) -> Result<()> {
        unit(&self.call(Call::SendEmailCode).await?)
    }

    async fn unlock_with_password(&self, password: Zeroizing<String>) -> Result<()> {
        unit(&self.call(Call::UnlockWithPassword(password)).await?)
    }

    fn unlock_with_user_key(&self, user_key: Zeroizing<Vec<u8>>) -> Result<()> {
        unit(&self.call_blocking(Call::UnlockWithUserKey(user_key))?)
    }

    fn user_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self.call_blocking(Call::UserKey)? {
            Reply::UserKey(key) => Ok(key),
            _ => Err(unexpected()),
        }
    }

    async fn verify_master_password(&self, password: Zeroizing<String>) -> Result<bool> {
        match self.call(Call::VerifyMasterPassword(password)).await? {
            Reply::Bool(valid) => Ok(valid),
            _ => Err(unexpected()),
        }
    }

    /// Waits for the daemon so that `state()` reads `Locked` right after; a dead daemon is
    /// logged, as the trait gives no way to report it.
    fn lock(&self) {
        if let Err(error) = self
            .call_blocking(Call::Lock)
            .and_then(|reply| unit(&reply))
        {
            tracing::warn!(%error, "lock over IPC failed");
        }
    }

    async fn logout(&self) -> Result<()> {
        unit(&self.call(Call::Logout).await?)
    }

    fn accounts(&self) -> Vec<AccountView> {
        self.cache().accounts.clone()
    }

    fn switch_account(&self, account_id: &str) -> Result<()> {
        unit(&self.call_blocking(Call::SwitchAccount(account_id.to_owned()))?)
    }

    fn begin_add_account(&self) {
        if let Err(error) = self
            .call_blocking(Call::BeginAddAccount)
            .and_then(|reply| unit(&reply))
        {
            tracing::warn!(%error, "begin_add_account over IPC failed");
        }
    }

    async fn sync(&self) -> Result<()> {
        unit(&self.call(Call::Sync).await?)
    }

    fn is_offline(&self) -> bool {
        self.cache().is_offline
    }

    fn last_sync(&self) -> Option<std::time::SystemTime> {
        self.cache().last_sync
    }

    async fn probe_server(&self, server: &url::Url) -> Result<ServerProbe> {
        match self
            .call(Call::ProbeServer(server.as_str().to_owned()))
            .await?
        {
            Reply::ServerProbe { version } => Ok(ServerProbe { version }),
            _ => Err(unexpected()),
        }
    }

    fn search(&self, query: &str, filter: &Filter) -> Result<Arc<[ItemSummary]>> {
        let call = Call::Search {
            query: query.to_owned(),
            filter: filter.into(),
        };
        match self.call_blocking(call)? {
            Reply::Items(items) => Ok(items.into_iter().map(ItemSummary::from).collect()),
            _ => Err(unexpected()),
        }
    }

    fn folders(&self) -> Result<Vec<FolderView>> {
        self.cache().folders.clone().map_err(Into::into)
    }

    fn organizations(&self) -> Result<Vec<OrganizationView>> {
        self.cache().organizations.clone().map_err(Into::into)
    }

    fn collections(&self) -> Result<Vec<CollectionView>> {
        self.cache().collections.clone().map_err(Into::into)
    }

    fn reveal(&self, id: &ItemId, field: CopyField) -> Result<Zeroizing<String>> {
        let call = Call::Reveal {
            id: Arc::clone(&id.0),
            field: field.into(),
        };
        match self.call_blocking(call)? {
            Reply::Secret(secret) => Ok(secret),
            _ => Err(unexpected()),
        }
    }

    fn totp(&self, id: &ItemId, unix_time: u64) -> Result<TotpCode> {
        let call = Call::Totp {
            id: Arc::clone(&id.0),
            unix_time,
        };
        match self.call_blocking(call)? {
            Reply::Totp(code) => Ok(code.into()),
            _ => Err(unexpected()),
        }
    }

    fn draft(&self, id: &ItemId) -> Result<ItemDraft> {
        match self.call_blocking(Call::Draft(Arc::clone(&id.0)))? {
            Reply::Draft(draft) => Ok((*draft).into()),
            _ => Err(unexpected()),
        }
    }

    async fn save(&self, id: Option<ItemId>, draft: ItemDraft) -> Result<ItemId> {
        let call = Call::Save {
            id: id.map(|id| id.0),
            draft: Box::new(draft.into()),
        };
        match self.call(call).await? {
            Reply::ItemId(id) => Ok(ItemId(id)),
            _ => Err(unexpected()),
        }
    }

    fn attachments(&self, id: &ItemId) -> Result<Vec<AttachmentView>> {
        match self.call_blocking(Call::Attachments(Arc::clone(&id.0)))? {
            Reply::Attachments(list) => Ok(convert_all(list)),
            _ => Err(unexpected()),
        }
    }

    async fn download_attachment(
        &self,
        id: &ItemId,
        attachment_id: &str,
        dest: PathBuf,
    ) -> Result<()> {
        let call = Call::DownloadAttachment {
            id: Arc::clone(&id.0),
            attachment_id: attachment_id.to_owned(),
            dest: path_bytes(&dest),
        };
        unit(&self.call(call).await?)
    }

    async fn upload_attachment(&self, id: &ItemId, source: PathBuf) -> Result<AttachmentView> {
        let call = Call::UploadAttachment {
            id: Arc::clone(&id.0),
            source: path_bytes(&source),
        };
        match self.call(call).await? {
            Reply::Attachment(attachment) => Ok(attachment.into()),
            _ => Err(unexpected()),
        }
    }

    async fn delete_attachment(&self, id: &ItemId, attachment_id: &str) -> Result<()> {
        let call = Call::DeleteAttachment {
            id: Arc::clone(&id.0),
            attachment_id: attachment_id.to_owned(),
        };
        unit(&self.call(call).await?)
    }

    async fn trash(&self, id: &ItemId) -> Result<()> {
        unit(&self.call(Call::Trash(Arc::clone(&id.0))).await?)
    }

    async fn restore(&self, id: &ItemId) -> Result<()> {
        unit(&self.call(Call::Restore(Arc::clone(&id.0))).await?)
    }

    async fn delete_permanently(&self, id: &ItemId) -> Result<()> {
        unit(
            &self
                .call(Call::DeletePermanently(Arc::clone(&id.0)))
                .await?,
        )
    }

    async fn create_folder(&self, name: &str) -> Result<FolderView> {
        match self.call(Call::CreateFolder(name.to_owned())).await? {
            Reply::Folder(folder) => Ok(folder.into()),
            _ => Err(unexpected()),
        }
    }

    async fn rename_folder(&self, id: &str, name: &str) -> Result<()> {
        let call = Call::RenameFolder {
            id: id.to_owned(),
            name: name.to_owned(),
        };
        unit(&self.call(call).await?)
    }

    async fn delete_folder(&self, id: &str) -> Result<()> {
        unit(&self.call(Call::DeleteFolder(id.to_owned())).await?)
    }

    fn ssh_keys(&self) -> Result<Vec<SshKeyMaterial>> {
        match self.call_blocking(Call::SshKeys)? {
            Reply::SshKeys(keys) => Ok(convert_all(keys)),
            _ => Err(unexpected()),
        }
    }
}
