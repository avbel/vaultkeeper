//! Runs one decoded [`Call`] against the real service.

use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf, sync::Arc};

use bwl_vault::{
    VaultService,
    model::{ItemId, LoginRequest, TwoFactorAnswer},
};

use crate::{
    dto::WireError,
    protocol::{Call, Reply},
};

/// Sync service methods run inline when they only read in-memory views, and on the blocking
/// pool when they touch the disk or decrypt in bulk (unlock, account switch, SSH keys), so they
/// cannot stall the daemon's async workers.
pub(super) async fn dispatch<S: VaultService>(
    service: &Arc<S>,
    call: Call,
) -> Result<Reply, WireError> {
    match call {
        Call::State => Ok(Reply::State(service.state().into())),
        Call::Changes => Ok(Reply::Revision(*service.changes().borrow())),
        Call::Login {
            request,
            two_factor,
            new_device_otp,
        } => {
            let request = LoginRequest::try_from(request)?;
            let two_factor = two_factor.map(TwoFactorAnswer::try_from).transpose()?;
            let step = service.login(request, two_factor, new_device_otp).await;
            reply(step, |step| Reply::LoginStep(step.into()))
        }
        Call::SendEmailCode => unit(service.send_email_code().await),
        Call::UnlockWithPassword(password) => unit(service.unlock_with_password(password).await),
        Call::UnlockWithUserKey(key) => {
            unit(blocking(service, move |service| service.unlock_with_user_key(key)).await?)
        }
        Call::UserKey => reply(service.user_key(), Reply::UserKey),
        Call::VerifyMasterPassword(password) => {
            reply(service.verify_master_password(password).await, Reply::Bool)
        }
        Call::Lock => blocking(service, S::lock).await.map(|()| Reply::Unit),
        Call::Logout => unit(service.logout().await),
        Call::Accounts => Ok(Reply::Accounts(convert_all(service.accounts()))),
        Call::SwitchAccount(id) => {
            unit(blocking(service, move |service| service.switch_account(&id)).await?)
        }
        Call::BeginAddAccount => blocking(service, S::begin_add_account)
            .await
            .map(|()| Reply::Unit),
        Call::Sync => unit(service.sync().await),
        Call::IsOffline => Ok(Reply::Bool(service.is_offline())),
        Call::Search { query, filter } => reply(service.search(&query, &filter.into()), |items| {
            Reply::Items(items.iter().map(Into::into).collect())
        }),
        Call::Folders => reply(service.folders(), |list| Reply::Folders(convert_all(list))),
        Call::Organizations => reply(service.organizations(), |list| {
            Reply::Organizations(convert_all(list))
        }),
        Call::Collections => reply(service.collections(), |list| {
            Reply::Collections(convert_all(list))
        }),
        Call::Reveal { id, field } => reply(
            service.reveal(&ItemId(id), field.try_into()?),
            Reply::Secret,
        ),
        Call::Totp { id, unix_time } => reply(service.totp(&ItemId(id), unix_time), |code| {
            Reply::Totp(code.into())
        }),
        Call::Draft(id) => reply(service.draft(&ItemId(id)), |draft| {
            Reply::Draft(Box::new(draft.into()))
        }),
        Call::Save { id, draft } => {
            reply(service.save(id.map(ItemId), (*draft).into()).await, |id| {
                Reply::ItemId(id.0)
            })
        }
        Call::Attachments(id) => reply(service.attachments(&ItemId(id)), |list| {
            Reply::Attachments(convert_all(list))
        }),
        Call::DownloadAttachment {
            id,
            attachment_id,
            dest,
        } => unit(
            service
                .download_attachment(&ItemId(id), &attachment_id, os_path(dest))
                .await,
        ),
        Call::UploadAttachment { id, source } => reply(
            service
                .upload_attachment(&ItemId(id), os_path(source))
                .await,
            |attachment| Reply::Attachment(attachment.into()),
        ),
        Call::DeleteAttachment { id, attachment_id } => {
            unit(service.delete_attachment(&ItemId(id), &attachment_id).await)
        }
        Call::Trash(id) => unit(service.trash(&ItemId(id)).await),
        Call::Restore(id) => unit(service.restore(&ItemId(id)).await),
        Call::DeletePermanently(id) => unit(service.delete_permanently(&ItemId(id)).await),
        Call::CreateFolder(name) => reply(service.create_folder(&name).await, |folder| {
            Reply::Folder(folder.into())
        }),
        Call::RenameFolder { id, name } => unit(service.rename_folder(&id, &name).await),
        Call::DeleteFolder(id) => unit(service.delete_folder(&id).await),
        Call::SshKeys => reply(blocking(service, S::ssh_keys).await?, |keys| {
            Reply::SshKeys(convert_all(keys))
        }),
    }
}

fn reply<T>(
    result: bwl_vault::Result<T>,
    wrap: impl FnOnce(T) -> Reply,
) -> Result<Reply, WireError> {
    result.map(wrap).map_err(|error| WireError::from(&error))
}

fn unit(result: bwl_vault::Result<()>) -> Result<Reply, WireError> {
    reply(result, |()| Reply::Unit)
}

fn convert_all<T, D: From<T>>(items: Vec<T>) -> Vec<D> {
    items.into_iter().map(D::from).collect()
}

fn os_path(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes))
}

async fn blocking<S, T, F>(service: &Arc<S>, work: F) -> Result<T, WireError>
where
    S: VaultService,
    T: Send + 'static,
    F: FnOnce(&S) -> T + Send + 'static,
{
    let service = Arc::clone(service);
    tokio::task::spawn_blocking(move || work(&service))
        .await
        .map_err(|error| WireError::internal(format!("daemon task failed: {error}")))
}
