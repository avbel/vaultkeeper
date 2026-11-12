use std::{
    cmp::Reverse,
    path::PathBuf,
    sync::{Arc, PoisonError, atomic::Ordering},
};

use tokio::sync::watch;
use vk_vault::{
    Error, Result, TotpCode, TwoFactorProvider, VaultService,
    model::{
        AccountView, AttachmentView, CollectionView, CopyField, Filter, FolderView, ItemData,
        ItemDraft, ItemId, ItemSummary, LoginRequest, LoginStep, OrganizationView, SendDraft,
        SendKind, SendSummary, ServerProbe, SessionState, SshKeyMaterial, TwoFactorAnswer,
    },
};
use zeroize::Zeroizing;

use super::{
    Account, Inner, MOCK_2FA_CODE, MOCK_DEVICE_CODE, MOCK_KEY_ID, MOCK_MASTER_PASSWORD,
    MOCK_SERVER_VERSION, MockCall, MockVault,
    data::{self, AccountData, MockItem},
    sends::{MockSend, summarize as summarize_send},
    state::{
        assign_collections, fake_totp, field_value, matches, not_bitwarden, rank, set_deleted,
        unix_now, unreachable, user_key,
    },
};

/// Vaultwarden's login options for the [`super::MockSecurityKey`].
fn mock_key_challenge(server: &url::Url) -> String {
    serde_json::json!({
        "challenge": vk_webauthn::b64::encode(b"mock challenge"),
        "timeout": 60_000,
        "rpId": server.host_str().unwrap_or_default(),
        "allowCredentials": [{"type": "public-key", "id": vk_webauthn::b64::encode(MOCK_KEY_ID)}],
        "userVerification": "discouraged",
    })
    .to_string()
}

fn is_mock_key_answer(token: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(token).is_ok_and(|token| {
        token["id"].as_str() == Some(&vk_webauthn::b64::encode(MOCK_KEY_ID))
            && token["response"]["signature"].is_string()
    })
}

/// A refusal shown verbatim, as the real vault reports what it does not offer.
fn refused(message: &str) -> Error {
    Error::Api(vk_api::Error::Server {
        status: 400,
        message: message.to_owned(),
    })
}

impl MockVault {
    fn online(&self) -> Result<()> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(unreachable());
        }
        Ok(())
    }

    fn write<T>(&self, call: MockCall, apply: impl FnOnce(&mut Inner) -> Result<T>) -> Result<T> {
        self.online()?;
        self.record(call);
        let result = apply(&mut self.guard());
        if result.is_ok() {
            self.bump();
        }
        result
    }

    fn finish_login(&self, request: &LoginRequest) {
        let mut inner = self.guard();
        let existing = inner.accounts.iter().position(|account| {
            account.server == request.server && *account.email == *request.email
        });
        let index = existing.unwrap_or_else(|| {
            inner.next_id += 1;
            let id = format!("acc-new-{}", inner.next_id);
            inner.accounts.push(Account {
                id: Arc::from(id),
                server: request.server.clone(),
                email: Arc::from(request.email.as_str()),
                logged_in: false,
                last_used: 0,
                data: AccountData::default(),
            });
            inner.accounts.len() - 1
        });
        let account = &mut inner.accounts[index];
        if !account.logged_in {
            account.logged_in = true;
            account.data = match account.email.as_ref() {
                "alice@example.com" => data::alice(),
                "bob@work.example.org" => data::bob(),
                email => data::fresh(email),
            };
        }
        inner.activate(index);
        inner.unlocked = true;
    }

    fn check_login(
        request: &LoginRequest,
        two_factor: Option<&TwoFactorAnswer>,
        new_device_otp: Option<&str>,
    ) -> Result<Option<LoginStep>> {
        let host = request.server.host_str().unwrap_or_default();
        if host.contains("unreachable") {
            return Err(unreachable());
        }
        if host.contains("notbitwarden") {
            return Err(not_bitwarden());
        }
        if request.password.as_str() != MOCK_MASTER_PASSWORD {
            return Err(Error::InvalidPassword);
        }
        let security_key = request.email.contains("key");
        if request.email.contains("2fa") || security_key {
            match two_factor {
                None if security_key => {
                    return Ok(Some(LoginStep::TwoFactorRequired {
                        providers: vec![
                            TwoFactorProvider::WebAuthn,
                            TwoFactorProvider::Authenticator,
                            TwoFactorProvider::RecoveryCode,
                        ],
                        webauthn: Some(mock_key_challenge(&request.server)),
                    }));
                }
                None => {
                    return Ok(Some(LoginStep::TwoFactorRequired {
                        providers: vec![
                            TwoFactorProvider::Authenticator,
                            TwoFactorProvider::Email,
                            TwoFactorProvider::RecoveryCode,
                        ],
                        webauthn: None,
                    }));
                }
                Some(answer)
                    if answer.provider == TwoFactorProvider::WebAuthn
                        && is_mock_key_answer(&answer.code) => {}
                Some(answer) if answer.code.trim() != MOCK_2FA_CODE => {
                    return Err(Error::Api(vk_api::Error::Server {
                        status: 400,
                        message: "Two-step token is invalid. Try again.".to_owned(),
                    }));
                }
                Some(_) => {}
            }
        }
        if request.email.contains("newdevice") {
            match new_device_otp {
                None => return Ok(Some(LoginStep::NewDeviceOtpRequired)),
                Some(code) if code.trim() != MOCK_DEVICE_CODE => {
                    return Err(Error::Api(vk_api::Error::Server {
                        status: 400,
                        message: "Invalid new device OTP.".to_owned(),
                    }));
                }
                Some(_) => {}
            }
        }
        Ok(None)
    }
}

impl VaultService for MockVault {
    fn state(&self) -> SessionState {
        let inner = self.guard();
        match inner.active() {
            Err(_) => SessionState::LoggedOut,
            Ok(account) => {
                let (server, email) = (account.server.clone(), account.email.to_string());
                if inner.unlocked {
                    SessionState::Unlocked { server, email }
                } else {
                    SessionState::Locked { server, email }
                }
            }
        }
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    async fn login(
        &self,
        request: LoginRequest,
        two_factor: Option<TwoFactorAnswer>,
        new_device_otp: Option<String>,
    ) -> Result<LoginStep> {
        self.delay().await;
        self.online()?;
        self.record(MockCall::Login {
            server: request.server.to_string(),
            email: request.email.clone(),
        });
        if let Some(step) =
            Self::check_login(&request, two_factor.as_ref(), new_device_otp.as_deref())?
        {
            return Ok(step);
        }
        self.finish_login(&request);
        self.bump();
        Ok(LoginStep::Done)
    }

    async fn send_email_code(&self) -> Result<()> {
        self.delay().await;
        self.online()
    }

    async fn unlock_with_password(&self, password: Zeroizing<String>) -> Result<()> {
        self.delay().await;
        let mut inner = self.guard();
        inner.active()?;
        if password.as_str() != MOCK_MASTER_PASSWORD {
            return Err(Error::InvalidPassword);
        }
        inner.unlocked = true;
        drop(inner);
        self.bump();
        Ok(())
    }

    fn unlock_with_user_key(&self, key: Zeroizing<Vec<u8>>) -> Result<()> {
        let mut inner = self.guard();
        if user_key(inner.active()?) != key {
            return Err(Error::InvalidPassword);
        }
        inner.unlocked = true;
        drop(inner);
        self.bump();
        Ok(())
    }

    fn user_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let inner = self.guard();
        inner.data()?;
        Ok(user_key(inner.active()?))
    }

    async fn verify_master_password(&self, password: Zeroizing<String>) -> Result<bool> {
        self.delay().await;
        self.guard().data()?;
        Ok(password.as_str() == MOCK_MASTER_PASSWORD)
    }

    fn lock(&self) {
        self.guard().unlocked = false;
        self.bump();
    }

    async fn logout(&self) -> Result<()> {
        self.delay().await;
        self.record(MockCall::Logout);
        let mut inner = self.guard();
        let index = inner.active.ok_or(Error::LoggedOut)?;
        let account = &mut inner.accounts[index];
        account.logged_in = false;
        account.data = AccountData::default();
        inner.unlocked = false;
        inner.adding = false;
        let next = inner
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, account)| account.logged_in)
            .max_by_key(|(_, account)| account.last_used)
            .map(|(index, _)| index);
        if let Some(next) = next {
            inner.activate(next);
        }
        drop(inner);
        self.bump();
        Ok(())
    }

    fn accounts(&self) -> Vec<AccountView> {
        let inner = self.guard();
        inner
            .accounts
            .iter()
            .enumerate()
            .map(|(index, account)| AccountView {
                id: Arc::clone(&account.id),
                server: account.server.clone(),
                email: Arc::clone(&account.email),
                active: inner.active == Some(index) && !inner.adding,
                logged_in: account.logged_in,
            })
            .collect()
    }

    fn switch_account(&self, account_id: &str) -> Result<()> {
        self.record(MockCall::SwitchAccount(account_id.to_owned()));
        let mut inner = self.guard();
        let index = inner
            .accounts
            .iter()
            .position(|account| account.id.as_ref() == account_id)
            .ok_or(Error::NotFound)?;
        inner.activate(index);
        drop(inner);
        self.bump();
        Ok(())
    }

    fn begin_add_account(&self) {
        self.record(MockCall::BeginAddAccount);
        let mut inner = self.guard();
        inner.unlocked = false;
        inner.adding = true;
        drop(inner);
        self.bump();
    }

    async fn sync(&self) -> Result<()> {
        self.delay().await;
        self.guard().data()?;
        self.online()?;
        self.record(MockCall::Sync);
        *self
            .last_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(std::time::SystemTime::now());
        self.bump();
        Ok(())
    }

    fn last_sync(&self) -> Option<std::time::SystemTime> {
        *self
            .last_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn is_offline(&self) -> bool {
        self.offline.load(Ordering::SeqCst)
    }

    /// Hosts containing "unreachable" or "notbitwarden" fail like `check_login` does.
    async fn probe_server(&self, server: &url::Url) -> Result<ServerProbe> {
        self.delay().await;
        let host = server.host_str().unwrap_or_default();
        if host.contains("unreachable") {
            return Err(unreachable());
        }
        if host.contains("notbitwarden") {
            return Err(not_bitwarden());
        }
        Ok(ServerProbe {
            version: Some(MOCK_SERVER_VERSION.to_owned()),
        })
    }

    fn search(&self, query: &str, filter: &Filter) -> Result<Arc<[ItemSummary]>> {
        let inner = self.guard();
        let data = inner.data()?;
        let query = query.trim().to_lowercase();
        let mut hits: Vec<(&MockItem, u8)> = data
            .items
            .iter()
            .filter(|item| matches(item, filter))
            .filter_map(|item| {
                if query.is_empty() {
                    Some((item, 0))
                } else {
                    rank(item, &query).map(|score| (item, score))
                }
            })
            .collect();
        if query.is_empty() {
            hits.sort_by(|(a, _), (b, _)| {
                (Reverse(a.last_used), &a.name_lower).cmp(&(Reverse(b.last_used), &b.name_lower))
            });
        } else {
            hits.sort_by(|(a, score_a), (b, score_b)| {
                (score_a, &a.name_lower).cmp(&(score_b, &b.name_lower))
            });
        }
        Ok(hits
            .into_iter()
            .map(|(item, _)| item.summary.clone())
            .collect())
    }

    fn folders(&self) -> Result<Vec<FolderView>> {
        Ok(self.guard().data()?.folders.clone())
    }

    fn organizations(&self) -> Result<Vec<OrganizationView>> {
        Ok(self.guard().data()?.organizations.clone())
    }

    fn collections(&self) -> Result<Vec<CollectionView>> {
        Ok(self.guard().data()?.collections.clone())
    }

    fn reveal(&self, id: &ItemId, field: CopyField) -> Result<Zeroizing<String>> {
        let mut inner = self.guard();
        let value = field_value(inner.item(id)?, field, unix_now()).ok_or(Error::NoSuchField)?;
        let now = inner.tick();
        inner.item_mut(id)?.last_used = now;
        Ok(value)
    }

    fn totp(&self, id: &ItemId, unix_time: u64) -> Result<TotpCode> {
        let inner = self.guard();
        let item = inner.item(id)?;
        if !item.summary.has_totp {
            return Err(Error::NoSuchField);
        }
        Ok(fake_totp(id, unix_time))
    }

    fn draft(&self, id: &ItemId) -> Result<ItemDraft> {
        Ok(self.guard().item(id)?.draft.clone())
    }

    async fn save(&self, id: Option<ItemId>, draft: ItemDraft) -> Result<ItemId> {
        self.delay().await;
        let call = MockCall::Save {
            id: id.clone(),
            name: draft.name.clone(),
        };
        *self
            .last_saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(draft.clone());
        if let Some(id) = &id {
            let inner = self.guard();
            let stored = inner.item(id)?;
            if stored.summary.editable && stored.draft.revision_date != draft.revision_date {
                return Err(Error::Conflict);
            }
        }
        let draft = saved_form(draft);
        self.write(call, |inner| {
            let revision = Some(Arc::from(format!("mock-rev-{}", inner.tick())));
            if let Some(id) = id {
                let item = inner.item_mut(&id)?;
                if !item.summary.editable {
                    return Err(Error::ReadOnly);
                }
                let last_used = item.last_used;
                let draft = ItemDraft {
                    revision_date: revision,
                    ..draft
                };
                *item = MockItem::new(&id, draft, true, item.summary.deleted);
                item.last_used = last_used;
                Ok(id)
            } else {
                inner.next_id += 1;
                let id = ItemId(Arc::from(format!("mock-new-{}", inner.next_id)));
                let now = inner.tick();
                let draft = ItemDraft {
                    revision_date: revision,
                    ..draft
                };
                let mut item = MockItem::new(&id, draft, true, false);
                item.last_used = now;
                inner.data_mut()?.items.push(item);
                Ok(id)
            }
        })
    }

    fn attachments(&self, id: &ItemId) -> Result<Vec<AttachmentView>> {
        let inner = self.guard();
        inner.item(id)?;
        Ok(inner
            .data()?
            .attachments
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    async fn download_attachment(
        &self,
        id: &ItemId,
        attachment_id: &str,
        dest: PathBuf,
    ) -> Result<()> {
        self.delay().await;
        self.online()?;
        let inner = self.guard();
        let found = inner.data()?.attachments.get(id).is_some_and(|list| {
            list.iter()
                .any(|attachment| attachment.id.as_ref() == attachment_id)
        });
        drop(inner);
        if !found {
            return Err(Error::NotFound);
        }
        self.record(MockCall::Download {
            item: id.clone(),
            attachment: attachment_id.to_owned(),
            dest,
        });
        Ok(())
    }

    async fn upload_attachment(&self, id: &ItemId, source: PathBuf) -> Result<AttachmentView> {
        self.delay().await;
        let call = MockCall::Upload {
            item: id.clone(),
            source: source.clone(),
        };
        let file_name = source.file_name().map_or_else(
            || "attachment".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        let size_bytes = std::fs::metadata(&source).map_or(0, |metadata| metadata.len());
        self.write(call, |inner| {
            inner.item(id)?;
            inner.next_id += 1;
            let view = AttachmentView {
                id: Arc::from(format!("att-new-{}", inner.next_id)),
                file_name: Arc::from(file_name),
                size_bytes,
            };
            inner
                .data_mut()?
                .attachments
                .entry(id.clone())
                .or_default()
                .push(view.clone());
            Ok(view)
        })
    }

    async fn delete_attachment(&self, id: &ItemId, attachment_id: &str) -> Result<()> {
        self.delay().await;
        let call = MockCall::DeleteAttachment {
            item: id.clone(),
            attachment: attachment_id.to_owned(),
        };
        self.write(call, |inner| {
            let list = inner
                .data_mut()?
                .attachments
                .get_mut(id)
                .ok_or(Error::NotFound)?;
            let before = list.len();
            list.retain(|attachment| attachment.id.as_ref() != attachment_id);
            if list.len() == before {
                return Err(Error::NotFound);
            }
            Ok(())
        })
    }

    async fn assign_collections(
        &self,
        id: &ItemId,
        organization_id: &str,
        collection_ids: Vec<Arc<str>>,
    ) -> Result<()> {
        self.delay().await;
        let call = MockCall::AssignCollections {
            id: id.clone(),
            organization_id: organization_id.to_owned(),
            collection_ids: collection_ids.clone(),
        };
        self.write(call, |inner| {
            assign_collections(inner, id, organization_id, &collection_ids)
        })
    }

    async fn trash(&self, id: &ItemId) -> Result<()> {
        self.delay().await;
        self.write(MockCall::Trash(id.clone()), |inner| {
            set_deleted(inner, id, true)
        })
    }

    async fn restore(&self, id: &ItemId) -> Result<()> {
        self.delay().await;
        self.write(MockCall::Restore(id.clone()), |inner| {
            set_deleted(inner, id, false)
        })
    }

    async fn delete_permanently(&self, id: &ItemId) -> Result<()> {
        self.delay().await;
        self.write(MockCall::DeletePermanently(id.clone()), |inner| {
            let data = inner.data_mut()?;
            let before = data.items.len();
            data.items.retain(|item| &item.summary.id != id);
            if data.items.len() == before {
                return Err(Error::NotFound);
            }
            data.attachments.remove(id);
            Ok(())
        })
    }

    async fn create_folder(&self, name: &str) -> Result<FolderView> {
        self.delay().await;
        self.write(MockCall::CreateFolder(name.to_owned()), |inner| {
            inner.next_id += 1;
            let folder = FolderView {
                id: Arc::from(format!("folder-new-{}", inner.next_id)),
                name: Arc::from(name),
            };
            inner.data_mut()?.folders.push(folder.clone());
            Ok(folder)
        })
    }

    async fn rename_folder(&self, id: &str, name: &str) -> Result<()> {
        self.delay().await;
        let call = MockCall::RenameFolder {
            id: id.to_owned(),
            name: name.to_owned(),
        };
        self.write(call, |inner| {
            let folder = inner
                .data_mut()?
                .folders
                .iter_mut()
                .find(|folder| folder.id.as_ref() == id)
                .ok_or(Error::NotFound)?;
            folder.name = Arc::from(name);
            Ok(())
        })
    }

    async fn delete_folder(&self, id: &str) -> Result<()> {
        self.delay().await;
        self.write(MockCall::DeleteFolder(id.to_owned()), |inner| {
            let data = inner.data_mut()?;
            let before = data.folders.len();
            data.folders.retain(|folder| folder.id.as_ref() != id);
            if data.folders.len() == before {
                return Err(Error::NotFound);
            }
            for item in data
                .items
                .iter_mut()
                .filter(|item| item.summary.folder_id.as_deref() == Some(id))
            {
                item.draft.folder_id = None;
                item.summary.folder_id = None;
            }
            Ok(())
        })
    }

    fn sends(&self) -> Result<Vec<SendSummary>> {
        let inner = self.guard();
        let mut sends: Vec<SendSummary> = inner
            .data()?
            .sends
            .iter()
            .map(|send| send.summary.clone())
            .collect();
        sends.sort_by_cached_key(|send| send.name.to_lowercase());
        Ok(sends)
    }

    fn send_draft(&self, id: &str) -> Result<SendDraft> {
        let inner = self.guard();
        let send = inner.send(id)?;
        Ok(send.draft.clone())
    }

    fn send_link(&self, id: &str) -> Result<Zeroizing<String>> {
        let inner = self.guard();
        inner.send(id)?;
        let server = inner.active()?.server.as_str().trim_end_matches('/');
        Ok(Zeroizing::new(format!(
            "{server}/#/send/{id}/bW9jay1zZW5kLWtleQ"
        )))
    }

    async fn save_send(&self, id: Option<Arc<str>>, draft: SendDraft) -> Result<SendSummary> {
        self.delay().await;
        if draft.name.trim().is_empty() {
            return Err(refused("Give the Send a name"));
        }
        if draft.text.is_empty() {
            return Err(refused("Enter the text to share"));
        }
        let call = MockCall::SaveSend {
            id: id.clone(),
            name: draft.name.clone(),
        };
        self.write(call, |inner| {
            let mut draft = draft;
            draft.has_password |= draft.password.as_ref().is_some_and(|p| !p.is_empty());
            draft.password = None;
            if let Some(id) = id {
                let send = inner.send_mut(&id)?;
                draft.has_password |= send.draft.has_password;
                send.summary = summarize_send(&id, &draft, send.summary.access_count);
                send.draft = draft;
                return Ok(send.summary.clone());
            }
            inner.next_id += 1;
            let id = format!("send-new-{}", inner.next_id);
            let send = MockSend::new(&id, draft, 0);
            let summary = send.summary.clone();
            inner.data_mut()?.sends.push(send);
            Ok(summary)
        })
    }

    async fn delete_send(&self, id: &str) -> Result<()> {
        self.delay().await;
        self.write(MockCall::DeleteSend(id.to_owned()), |inner| {
            inner.send(id)?;
            inner
                .data_mut()?
                .sends
                .retain(|send| &*send.summary.id != id);
            Ok(())
        })
    }

    async fn create_file_send(&self, mut draft: SendDraft, source: PathBuf) -> Result<SendSummary> {
        self.delay().await;
        let name = source.file_name().unwrap_or_default().to_string_lossy();
        let size = std::fs::metadata(&source)?.len();
        let call = MockCall::CreateFileSend {
            name: draft.name.clone(),
            source: source.clone(),
        };
        self.write(call, |inner| {
            draft.has_password = draft
                .password
                .take()
                .is_some_and(|password| !password.is_empty());
            inner.next_id += 1;
            let id = format!("send-new-{}", inner.next_id);
            let mut send = MockSend::new(&id, draft, 0);
            send.summary.kind = SendKind::File;
            send.summary.file_name = Some(Arc::from(name.as_ref()));
            send.summary.file_size = Some(Arc::from(format!("{size} B")));
            let summary = send.summary.clone();
            inner.data_mut()?.sends.push(send);
            Ok(summary)
        })
    }

    async fn remove_send_password(&self, id: &str) -> Result<()> {
        self.delay().await;
        self.write(MockCall::RemoveSendPassword(id.to_owned()), |inner| {
            let send = inner.send_mut(id)?;
            send.draft.has_password = false;
            send.summary.has_password = false;
            Ok(())
        })
    }

    fn ssh_keys(&self) -> Result<Vec<SshKeyMaterial>> {
        let inner = self.guard();
        Ok(inner
            .data()?
            .items
            .iter()
            .filter(|item| !item.summary.deleted)
            .filter_map(|item| match &item.draft.data {
                ItemData::SshKey { private_key, .. } => Some(SshKeyMaterial {
                    cipher_id: item.summary.id.clone(),
                    name: item.draft.name.clone(),
                    private_key: private_key.clone(),
                }),
                _ => None,
            })
            .collect())
    }
}

/// What the vault stores: blank URI rows the edit form kept for pairing are dropped.
fn saved_form(mut draft: ItemDraft) -> ItemDraft {
    if let ItemData::Login { uris, .. } = &mut draft.data {
        uris.retain(|uri| !uri.trim().is_empty());
    }
    draft
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use url::Url;

    use super::*;
    use crate::mock::MockConfig;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn vault(unlocked: bool) -> MockVault {
        MockVault::new(&MockConfig {
            latency: Duration::ZERO,
            offline: false,
            unlocked,
        })
    }

    fn request(server: &str, email: &str, password: &str) -> LoginRequest {
        LoginRequest {
            server: Url::parse(server).expect("url"),
            email: email.to_owned(),
            password: Zeroizing::new(password.to_owned()),
        }
    }

    #[test]
    fn unlock_requires_the_mock_password() {
        let rt = runtime();
        let vault = vault(false);
        assert!(matches!(vault.state(), SessionState::Locked { .. }));
        assert!(matches!(
            vault.search("", &Filter::default()),
            Err(Error::Locked)
        ));
        let wrong = rt.block_on(vault.unlock_with_password(Zeroizing::new("nope".to_owned())));
        assert!(matches!(wrong, Err(Error::InvalidPassword)));
        rt.block_on(vault.unlock_with_password(Zeroizing::new(MOCK_MASTER_PASSWORD.to_owned())))
            .expect("unlock");
        assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
        vault.lock();
        assert!(matches!(vault.state(), SessionState::Locked { .. }));
    }

    #[test]
    fn search_ranks_name_prefix_first_and_empty_query_is_mru() {
        let vault = vault(true);
        let hits = vault.search("git", &Filter::default()).expect("search");
        assert_eq!(hits[0].name.as_ref(), "GitHub");
        assert!(hits.iter().all(|hit| !hit.deleted));
        let recent = vault.search("", &Filter::default()).expect("recent");
        assert_eq!(recent[0].name.as_ref(), "GitHub");
        assert_eq!(recent[1].name.as_ref(), "AWS Console");
        let trash = vault
            .search(
                "",
                &Filter {
                    trash: true,
                    ..Filter::default()
                },
            )
            .expect("trash");
        assert!(trash.iter().all(|hit| hit.deleted));
        assert!(!trash.is_empty());
    }

    #[test]
    fn reveal_records_use_and_totp_is_stable_within_a_window() {
        let vault = vault(true);
        let notes = vault
            .search("server runbook", &Filter::default())
            .expect("search")[0]
            .id
            .clone();
        assert!(
            vault
                .reveal(&notes, CopyField::Notes)
                .expect("notes")
                .starts_with("Server runbook")
        );
        assert_eq!(
            vault.search("", &Filter::default()).expect("mru")[0].id,
            notes
        );
        let totp_item = vault
            .search("", &Filter::default())
            .expect("all")
            .iter()
            .find(|item| item.has_totp)
            .expect("totp item")
            .id
            .clone();
        // 1_700_000_010 is a multiple of 30, so 1_700_000_020 and 1_700_000_039 share a window.
        let a = vault.totp(&totp_item, 1_700_000_020).expect("totp");
        let b = vault.totp(&totp_item, 1_700_000_039).expect("totp");
        let next = vault.totp(&totp_item, 1_700_000_040).expect("totp");
        assert_ne!(a.code, next.code);
        assert_eq!(next.remaining, 30);
        assert_eq!(a.code, b.code);
        assert_eq!(a.remaining, 20);
        assert!(matches!(
            vault.reveal(&notes, CopyField::Password),
            Err(Error::NoSuchField)
        ));
    }

    #[test]
    fn login_two_factor_and_new_device_steps() {
        let rt = runtime();
        let vault = vault(false);
        let server = "https://vault.example.com";
        let first =
            rt.block_on(vault.login(request(server, "dave+2fa@example.com", "mock"), None, None));
        assert!(
            matches!(first, Ok(LoginStep::TwoFactorRequired { ref providers, webauthn: None }) if providers.len() == 3)
        );
        let answer = |code: &str| TwoFactorAnswer {
            provider: TwoFactorProvider::Authenticator,
            code: code.to_owned(),
            remember: false,
        };
        let wrong = rt.block_on(vault.login(
            request(server, "dave+2fa@example.com", "mock"),
            Some(answer("000000")),
            None,
        ));
        assert!(wrong.is_err());
        let done = rt.block_on(vault.login(
            request(server, "dave+2fa@example.com", "mock"),
            Some(answer(MOCK_2FA_CODE)),
            None,
        ));
        assert!(matches!(done, Ok(LoginStep::Done)));
        assert!(
            matches!(vault.state(), SessionState::Unlocked { ref email, .. } if email == "dave+2fa@example.com")
        );
        let device = rt.block_on(vault.login(
            request(server, "erin+newdevice@example.com", "mock"),
            None,
            None,
        ));
        assert!(matches!(device, Ok(LoginStep::NewDeviceOtpRequired)));
        let bad =
            rt.block_on(vault.login(request(server, "erin@example.com", "wrong"), None, None));
        assert!(matches!(bad, Err(Error::InvalidPassword)));
        let dead = rt.block_on(vault.login(
            request("https://unreachable.example", "a@b.c", "mock"),
            None,
            None,
        ));
        assert!(dead.as_ref().is_err_and(Error::is_offline));
    }

    #[test]
    fn accounts_switch_and_logout() {
        let rt = runtime();
        let vault = vault(true);
        let accounts = vault.accounts();
        assert_eq!(accounts.len(), 3);
        assert!(accounts[0].active && accounts[0].logged_in);
        assert!(!accounts[2].logged_in);
        vault.switch_account("acc-bob").expect("switch");
        assert!(
            matches!(vault.state(), SessionState::Locked { ref email, .. } if email == "bob@work.example.org")
        );
        rt.block_on(vault.logout()).expect("logout");
        assert!(
            matches!(vault.state(), SessionState::Locked { ref email, .. } if email == "alice@example.com")
        );
        rt.block_on(vault.logout()).expect("logout");
        assert!(matches!(vault.state(), SessionState::LoggedOut));
        assert_eq!(vault.item_names("alice@example.com"), Vec::<String>::new());
        vault.begin_add_account();
        assert!(vault.accounts().iter().all(|account| !account.active));
    }

    #[test]
    fn writes_fail_offline_and_folder_delete_moves_items() {
        let rt = runtime();
        let vault = vault(true);
        vault.set_offline(true);
        assert!(rt.block_on(vault.create_folder("New")).is_err());
        assert!(rt.block_on(vault.sync()).is_err());
        vault.set_offline(false);
        let dev = Filter {
            folder: Some(Some(Arc::from("f-dev"))),
            ..Filter::default()
        };
        let in_dev = vault.search("", &dev).expect("dev").len();
        assert!(in_dev > 0);
        rt.block_on(vault.delete_folder("f-dev")).expect("delete");
        assert_eq!(vault.search("", &dev).expect("dev").len(), 0);
        assert!(
            vault
                .folders()
                .expect("folders")
                .iter()
                .all(|folder| folder.id.as_ref() != "f-dev")
        );
        assert_eq!(
            vault.calls().last(),
            Some(&MockCall::DeleteFolder("f-dev".to_owned()))
        );
    }

    #[test]
    fn read_only_org_items_reject_saves() {
        let rt = runtime();
        let vault = vault(true);
        let read_only = vault
            .search("acme", &Filter::default())
            .expect("acme")
            .iter()
            .find(|item| !item.editable)
            .expect("read-only item")
            .id
            .clone();
        let draft = vault.draft(&read_only).expect("draft");
        assert!(matches!(
            rt.block_on(vault.save(Some(read_only), draft)),
            Err(Error::ReadOnly)
        ));
    }
}
