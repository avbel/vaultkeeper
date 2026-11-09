//! Runs one decoded [`Call`] against the real service.

use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf, sync::Arc, time::Duration};

use bwl_vault::{
    VaultService,
    model::{ItemId, LoginRequest, TwoFactorAnswer},
};

use super::Backends;
use crate::{
    ClipboardHost, TouchIdBackend,
    dto::WireError,
    protocol::{Call, Reply, TouchIdFailure},
};

/// Sync service methods run inline when they only read in-memory views, and on the blocking
/// pool when they touch the disk, decrypt in bulk or wait on Touch ID (unlock, account switch),
/// so they cannot stall the daemon's async workers.
pub(super) async fn dispatch<S: VaultService>(
    service: &Arc<S>,
    backends: Backends,
    call: Call,
) -> Result<Reply, WireError> {
    let Backends {
        touch_id,
        clipboard,
    } = backends;
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
        call @ (Call::EnrollTouchId { .. } | Call::UnlockWithTouchId { .. }) => {
            touch_id_call(service, touch_id, call).await
        }
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
        Call::ProbeServer(server) => probe(service.as_ref(), &server).await,
        call @ (Call::CopyToClipboard { .. } | Call::ClearClipboard) => {
            clipboard_call(clipboard, call).await
        }
    }
}

async fn clipboard_call(
    clipboard: Option<Arc<dyn ClipboardHost>>,
    call: Call,
) -> Result<Reply, WireError> {
    with_clipboard(clipboard, move |clipboard| {
        if let Call::CopyToClipboard {
            text,
            clear_after_secs,
        } = call
        {
            return clipboard
                .copy(&text, clear_after_secs.map(Duration::from_secs))
                .map_err(WireError::internal);
        }
        clipboard.clear_if_ours();
        Ok(())
    })
    .await
}

async fn touch_id_call<S: VaultService>(
    service: &Arc<S>,
    touch_id: Option<Arc<dyn TouchIdBackend>>,
    call: Call,
) -> Result<Reply, WireError> {
    with_touch_id(service, touch_id, move |service, backend| match call {
        Call::EnrollTouchId { account_id } => enroll_touch_id(service, backend, &account_id),
        Call::UnlockWithTouchId { account_id } => {
            unlock_with_touch_id(service, backend, &account_id)
        }
        _ => Err(WireError::internal("not a Touch ID call".to_owned())),
    })
    .await
}

/// Pasteboard access takes a lock and may block, so it runs on the blocking pool.
async fn with_clipboard<F>(
    clipboard: Option<Arc<dyn ClipboardHost>>,
    work: F,
) -> Result<Reply, WireError>
where
    F: FnOnce(&dyn ClipboardHost) -> Result<(), WireError> + Send + 'static,
{
    let Some(clipboard) = clipboard else {
        return Err(WireError::internal(
            "the daemon has no clipboard".to_owned(),
        ));
    };
    tokio::task::spawn_blocking(move || work(clipboard.as_ref()))
        .await
        .map_err(|error| WireError::internal(format!("daemon task failed: {error}")))?
        .map(|()| Reply::Unit)
}

async fn with_touch_id<S, F>(
    service: &Arc<S>,
    backend: Option<Arc<dyn TouchIdBackend>>,
    work: F,
) -> Result<Reply, WireError>
where
    S: VaultService,
    F: FnOnce(&S, &dyn TouchIdBackend) -> Result<Reply, WireError> + Send + 'static,
{
    let Some(backend) = backend else {
        return Ok(Reply::TouchId(Err(TouchIdFailure::Unavailable)));
    };
    blocking(service, move |service| work(service, backend.as_ref())).await?
}

fn is_active<S: VaultService>(service: &S, account_id: &str) -> bool {
    service
        .accounts()
        .iter()
        .any(|account| account.active && account.id.as_ref() == account_id)
}

/// The key is read from the unlocked vault here, so a peer can never hand in a key of its own.
fn enroll_touch_id<S: VaultService>(
    service: &S,
    backend: &dyn TouchIdBackend,
    account_id: &str,
) -> Result<Reply, WireError> {
    if !is_active(service, account_id) {
        return Ok(Reply::TouchId(Err(TouchIdFailure::AccountChanged)));
    }
    let user_key = service
        .user_key()
        .map_err(|error| WireError::from(&error))?;
    Ok(Reply::TouchId(backend.enroll(account_id, &user_key)))
}

fn unlock_with_touch_id<S: VaultService>(
    service: &S,
    backend: &dyn TouchIdBackend,
    account_id: &str,
) -> Result<Reply, WireError> {
    if !is_active(service, account_id) {
        return Ok(Reply::TouchId(Err(TouchIdFailure::AccountChanged)));
    }
    let user_key = match backend.unlock(account_id) {
        Ok(user_key) => user_key,
        Err(failure) => return Ok(Reply::TouchId(Err(failure))),
    };
    // The prompt may have been up for a while: an account switch meanwhile must not get this key.
    if !is_active(service, account_id) {
        return Ok(Reply::TouchId(Err(TouchIdFailure::AccountChanged)));
    }
    service
        .unlock_with_user_key(user_key)
        .map_err(|error| WireError::from(&error))?;
    Ok(Reply::TouchId(Ok(())))
}

async fn probe<S: VaultService>(service: &S, server: &str) -> Result<Reply, WireError> {
    let server = url::Url::parse(server).map_err(crate::ConvertError::Url)?;
    reply(service.probe_server(&server).await, |probe| {
        Reply::ServerProbe {
            version: probe.version,
        }
    })
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
