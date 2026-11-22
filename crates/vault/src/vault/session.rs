//! Login, unlock, lock and account switching: the LoggedOut → Locked → Unlocked machine.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::time::Instant;
use url::Url;
use vk_api::{
    Client, LoginOutcome, TwoFactorProvider, TwoFactorToken,
    models::{Profile, SyncResponse, TokenResponse},
};
use vk_crypto::{MasterKey, SymmetricKey};
use zeroize::Zeroizing;

use super::{AccessToken, Active, Inner, Unlocked, lock, locked_active, secret_error};
use crate::{
    Error, Result,
    error::wrong_key_as_invalid_password,
    index::VaultData,
    keys::{KeyRing, parse},
    model::{AccountView, LoginRequest, LoginStep, SessionState, TwoFactorAnswer},
    secrets::{refresh_token_key, remember_token_key},
    store::{AccountRecord, IndexEntry, KdfRecord},
};

/// Vaultwarden and the official server both answer a wrong master password with this text.
const WRONG_PASSWORD_MESSAGE: &str = "username or password is incorrect";

/// How long the typed password and derived key wait for the 2FA / new-device round.
const PENDING_LOGIN_TTL: Duration = Duration::from_mins(10);

/// Kept between the password round and the 2FA / new-device round, so the KDF runs once.
pub(crate) struct PendingLogin {
    server: Url,
    email: String,
    password: Zeroizing<String>,
    hash: Zeroizing<String>,
    master_key: MasterKey,
    kdf: KdfRecord,
    client: Arc<Client>,
    created: Instant,
}

impl PendingLogin {
    fn expired(&self) -> bool {
        self.created.elapsed() >= PENDING_LOGIN_TTL
    }

    fn matches(&self, request: &LoginRequest) -> bool {
        self.server == request.server
            && self.email.eq_ignore_ascii_case(request.email.trim())
            && *self.password == *request.password
    }
}

struct LoginTokens {
    access: Zeroizing<String>,
    expires_in: u64,
    refresh: Option<Zeroizing<String>>,
    key: Option<String>,
    private_key: Option<String>,
    remember: Option<Zeroizing<String>>,
}

impl From<TokenResponse> for LoginTokens {
    fn from(token: TokenResponse) -> Self {
        let TokenResponse {
            access_token,
            expires_in,
            refresh_token,
            key,
            private_key,
            two_factor_token,
        } = token;
        Self {
            access: Zeroizing::new(access_token),
            expires_in,
            refresh: refresh_token.map(Zeroizing::new),
            key,
            private_key,
            remember: two_factor_token.map(Zeroizing::new),
        }
    }
}

/// The server controls `expires_in`; an unbounded value would overflow `Instant` and abort.
const MAX_TOKEN_LIFETIME: Duration = Duration::from_hours(24);

pub(crate) fn token_expiry(expires_in: u64) -> Instant {
    let lifetime = Duration::from_secs(expires_in).min(MAX_TOKEN_LIFETIME);
    Instant::now() + lifetime
}

impl Inner {
    pub(crate) fn session_state(&self) -> SessionState {
        let state = self.read_state();
        match &state.active {
            None => SessionState::LoggedOut,
            Some(active) => {
                let server = active.record.server.clone();
                let email = active.record.email.clone();
                if active.unlocked.is_some() {
                    SessionState::Unlocked { server, email }
                } else {
                    SessionState::Locked { server, email }
                }
            }
        }
    }

    pub(crate) fn account_views(&self) -> Vec<AccountView> {
        let state = self.read_state();
        let active = state.active.as_ref().map(|active| &*active.id);
        state
            .index
            .accounts
            .iter()
            .map(|entry| AccountView {
                id: Arc::from(entry.id.as_str()),
                server: entry.server.clone(),
                email: Arc::from(entry.email.as_str()),
                active: active == Some(entry.id.as_str()),
                logged_in: true,
            })
            .collect()
    }

    /// The typed password and derived key outlive this call only while the server waits for a
    /// second round; after an error (often the real password with a typo) they are wiped at once.
    pub(crate) async fn login(
        self: &Arc<Self>,
        request: LoginRequest,
        two_factor: Option<TwoFactorAnswer>,
        new_device_otp: Option<String>,
    ) -> Result<LoginStep> {
        let step = self.login_round(request, two_factor, new_device_otp).await;
        if !matches!(
            step,
            Ok(LoginStep::TwoFactorRequired { .. } | LoginStep::NewDeviceOtpRequired)
        ) {
            self.clear_pending();
        }
        step
    }

    /// A remember token the current key cannot open (DPAPI profile reset, key rotation) is only a
    /// convenience: drop the file and fall back to a fresh two-factor prompt. One that is only
    /// unreadable for now (its wrapper is missing) is kept and skipped; the next successful
    /// two-factor login overwrites it.
    async fn read_remember_token(
        self: &Arc<Self>,
        user_id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let key = remember_token_key(user_id);
        self.blocking(move |inner| match inner.secrets.get(&key) {
            Err(error) if error.is_undecryptable() => {
                inner.secrets.delete(&key).map_err(secret_error)?;
                Ok(None)
            }
            Err(error) if error.is_unreadable() => {
                tracing::warn!(%error, "the remembered two-factor token cannot be read; asking again");
                Ok(None)
            }
            other => other.map_err(secret_error),
        })
        .await?
    }

    async fn login_round(
        self: &Arc<Self>,
        request: LoginRequest,
        two_factor: Option<TwoFactorAnswer>,
        new_device_otp: Option<String>,
    ) -> Result<LoginStep> {
        let pending = self.pending_login(&request).await?;
        let known_id = {
            let state = self.read_state();
            state
                .index
                .find_by_login(&request.server, &request.email)
                .map(|entry| entry.id.clone())
        };
        let remembered = match (&two_factor, &known_id) {
            (None, Some(id)) => self
                .read_remember_token(id)
                .await?
                .and_then(|token| String::from_utf8(token.to_vec()).ok())
                .map(Zeroizing::new),
            _ => None,
        };
        let factor = match (&two_factor, &remembered) {
            (Some(answer), _) => Some(TwoFactorToken {
                provider: answer.provider,
                token: answer.code.trim().to_owned(),
                remember: answer.remember,
            }),
            (None, Some(token)) => Some(TwoFactorToken {
                provider: TwoFactorProvider::Remember,
                token: token.to_string(),
                remember: false,
            }),
            (None, None) => None,
        };

        let outcome = pending
            .client
            .login(
                &pending.email,
                &pending.hash,
                factor.as_ref(),
                new_device_otp.as_deref().map(str::trim),
            )
            .await
            .map_err(login_error)?;
        match outcome {
            LoginOutcome::Success(token) => {
                self.complete_login(&pending, (*token).into()).await?;
                Ok(LoginStep::Done)
            }
            LoginOutcome::TwoFactorRequired {
                providers,
                webauthn,
            } => {
                if remembered.is_some()
                    && let Some(id) = &known_id
                {
                    // The server no longer honours it; asking again would loop.
                    let key = remember_token_key(id);
                    self.blocking(move |inner| inner.secrets.delete(&key))
                        .await?
                        .map_err(secret_error)?;
                }
                let offered = providers
                    .into_iter()
                    .filter(|provider| *provider != TwoFactorProvider::Remember)
                    .collect();
                Ok(LoginStep::TwoFactorRequired {
                    providers: offered,
                    webauthn,
                })
            }
            LoginOutcome::NewDeviceOtpRequired => Ok(LoginStep::NewDeviceOtpRequired),
        }
    }

    pub(crate) async fn send_email_code(&self) -> Result<()> {
        let pending = self.live_pending().ok_or(Error::LoggedOut)?;
        pending
            .client
            .send_email_login(&pending.email, &pending.hash)
            .await?;
        Ok(())
    }

    /// Reuses the KDF result of the previous round when server, email and password match.
    async fn pending_login(self: &Arc<Self>, request: &LoginRequest) -> Result<Arc<PendingLogin>> {
        if let Some(pending) = self.live_pending()
            && pending.matches(request)
        {
            return Ok(pending);
        }
        let client = Arc::new(Client::with_timeouts(
            request.server.clone(),
            self.config.device.clone(),
            self.config.timings.http,
        )?);
        let email = request.email.trim().to_owned();
        let prelogin = client.prelogin(&email).await?;
        let kdf = KdfRecord::from_prelogin(&prelogin);
        self.refuse_kdf_downgrade(&request.server, &email, &kdf)?;
        let password = request.password.clone();
        let (master_key, hash) = {
            let email = email.clone();
            let password = password.clone();
            self.config
                .runtime
                .spawn_blocking(move || -> Result<(MasterKey, Zeroizing<String>)> {
                    let master_key =
                        MasterKey::derive(password.as_bytes(), &email, &kdf.to_kdf()?)?;
                    let hash = Zeroizing::new(master_key.server_hash(password.as_bytes()));
                    Ok((master_key, hash))
                })
                .await
                .map_err(Error::task)??
        };
        let pending = Arc::new(PendingLogin {
            server: request.server.clone(),
            email,
            password,
            hash,
            master_key,
            kdf,
            client,
            created: Instant::now(),
        });
        self.remember_pending(Arc::clone(&pending), PENDING_LOGIN_TTL);
        Ok(pending)
    }

    /// `live_pending` only notices the TTL when asked, so a login abandoned at the 2FA prompt
    /// would keep the password and master key in memory until the next login, lock or exit.
    /// The timer holds only weak references: it must not keep either alive itself.
    fn remember_pending(self: &Arc<Self>, pending: Arc<PendingLogin>, ttl: Duration) {
        let deadline = pending.created + ttl;
        let stored = Arc::downgrade(&pending);
        *lock(&self.pending) = Some(pending);
        let inner = Arc::downgrade(self);
        self.config.runtime.spawn(async move {
            tokio::time::sleep_until(deadline).await;
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let expired = {
                let mut current = lock(&inner.pending);
                // The weak reference keeps the allocation, so a newer login can't share its address.
                if current
                    .as_ref()
                    .is_some_and(|login| std::ptr::eq(Arc::as_ptr(login), stored.as_ptr()))
                {
                    current.take()
                } else {
                    None
                }
            };
            drop(expired);
        });
    }

    /// A hostile or compromised server could lower the KDF to make the hash it receives cheap to
    /// brute-force; the cached record of a known account is the reference.
    fn refuse_kdf_downgrade(&self, server: &Url, email: &str, kdf: &KdfRecord) -> Result<()> {
        let known_id = {
            let state = self.read_state();
            state
                .index
                .find_by_login(server, email)
                .map(|entry| entry.id.clone())
        };
        let Some(id) = known_id else {
            return Ok(());
        };
        let cached = self.store.load_account(&id)?;
        if cached.is_some_and(|cached| kdf.is_weaker_than(&cached.kdf)) {
            return Err(Error::KdfDowngrade);
        }
        Ok(())
    }

    async fn complete_login(
        self: &Arc<Self>,
        pending: &PendingLogin,
        tokens: LoginTokens,
    ) -> Result<()> {
        let protected = tokens
            .key
            .clone()
            .ok_or(Error::protocol("the server sent no user key"))?;
        let user_key = pending
            .master_key
            .decrypt_user_key(&parse(&protected)?)
            .map_err(wrong_key_as_invalid_password)?;
        let sync = pending.client.sync(&tokens.access).await?;
        let id = sync.profile.id.clone();
        self.store.account_dir(&id)?;
        // The refresh token is sealed under the user key, so the store needs it before
        // `store_login_secrets` writes the token.
        self.secrets
            .provide_key(&id, user_key.to_bytes().as_slice())
            .map_err(secret_error)?;
        let settings = self
            .store
            .load_account(&id)
            .ok()
            .flatten()
            .map(|known| known.settings)
            .unwrap_or_default();
        let record = AccountRecord {
            id: id.clone(),
            server: pending.server.clone(),
            email: sync.profile.email.clone(),
            kdf: pending.kdf,
            key: protected,
            private_key: tokens
                .private_key
                .clone()
                .or_else(|| sync.profile.private_key.clone()),
            settings,
        };

        let (keys, data) = self
            .save_new_account(record.clone(), user_key, sync)
            .await?;
        self.store_login_secrets(&id, &tokens).await?;
        let token = AccessToken {
            value: tokens.access,
            expires_at: token_expiry(tokens.expires_in),
        };
        // The login's own sync counts; set before the activation's bump, which the UI reacts to.
        lock(&self.last_sync).insert(Arc::from(id.as_str()), SystemTime::now());
        self.activate_logged_in(
            record,
            Arc::clone(&pending.client),
            token,
            Unlocked::new(keys, data),
        )
    }

    /// Decrypts the first sync and writes `account.json` + `vault.json` (blocking pool).
    async fn save_new_account(
        self: &Arc<Self>,
        record: AccountRecord,
        user_key: SymmetricKey,
        sync: SyncResponse,
    ) -> Result<(KeyRing, VaultData)> {
        let inner = Arc::clone(self);
        self.config
            .runtime
            .spawn_blocking(move || -> Result<(KeyRing, VaultData)> {
                let keys = KeyRing::build(
                    user_key,
                    record.private_key.as_deref(),
                    &sync.profile.organizations,
                    None,
                )?;
                let data = VaultData::build(sync, &keys);
                inner.store.create_account(&record)?;
                let bytes = data.to_json()?;
                let _writes = inner.store.lock_writes();
                inner.store.save_vault_locked(&record.id, &bytes)?;
                Ok((keys, data))
            })
            .await
            .map_err(Error::task)?
    }

    async fn store_login_secrets(self: &Arc<Self>, id: &str, tokens: &LoginTokens) -> Result<()> {
        let id = id.to_owned();
        let refresh = tokens.refresh.clone();
        let remember = tokens.remember.clone();
        self.blocking(move |inner| -> Result<()> {
            if let Some(refresh) = &refresh {
                let _secrets = lock(&inner.refresh_secret);
                inner
                    .secrets
                    .set(&refresh_token_key(&id), refresh.as_bytes())
                    .map_err(secret_error)?;
            }
            if let Some(remember) = &remember {
                inner
                    .secrets
                    .set(&remember_token_key(&id), remember.as_bytes())
                    .map_err(secret_error)?;
            }
            Ok(())
        })
        .await?
    }

    /// Makes the freshly logged-in account the active, unlocked one; the previous account (if
    /// any) is locked by dropping its session.
    fn activate_logged_in(
        self: &Arc<Self>,
        record: AccountRecord,
        client: Arc<Client>,
        token: AccessToken,
        unlocked: Unlocked,
    ) -> Result<()> {
        let id = record.id.clone();
        let entry = IndexEntry {
            id: id.clone(),
            server: record.server.clone(),
            email: record.email.clone(),
        };
        let active = Active {
            id: Arc::from(id.as_str()),
            record,
            client,
            token: Some(token),
            unlocked: Some(unlocked),
        };
        let (previous, index, epoch) = {
            let mut state = self.write_state();
            state.epoch += 1;
            state.index.touch(entry);
            let previous = state.active.replace(active);
            (previous, state.index.clone(), state.epoch)
        };
        drop(self.stop_background());
        if let Some(previous) = previous {
            // Re-logging into the same account keeps the key just provided; another account's
            // sealed tokens must not stay readable behind its back.
            let forget = *previous.id != *id;
            let previous_id = Arc::clone(&previous.id);
            drop(previous);
            if forget {
                self.secrets.forget_key(&previous_id);
            }
        }
        self.clear_pending();
        self.set_offline(false);
        self.store.save_index(&index)?;
        self.bump();
        self.bump_ssh();
        self.start_background(epoch);
        Ok(())
    }

    pub(crate) async fn unlock_with_password(
        self: &Arc<Self>,
        password: Zeroizing<String>,
    ) -> Result<()> {
        let Some((epoch, record)) = self.locked_record()? else {
            return Ok(());
        };
        let user_key = self.derive_user_key(&record, password).await?;
        let inner = Arc::clone(self);
        self.config
            .runtime
            .spawn_blocking(move || inner.install_unlocked(epoch, &record, user_key))
            .await
            .map_err(Error::task)?
    }

    pub(crate) fn unlock_with_user_key(self: &Arc<Self>, user_key: &[u8]) -> Result<()> {
        let Some((epoch, record)) = self.locked_record()? else {
            return Ok(());
        };
        let key = SymmetricKey::from_bytes(user_key).map_err(|_| Error::InvalidPassword)?;
        self.install_unlocked(epoch, &record, key)
    }

    pub(crate) async fn verify_master_password(
        self: &Arc<Self>,
        password: Zeroizing<String>,
    ) -> Result<bool> {
        let record = {
            let state = self.read_state();
            state
                .active
                .as_ref()
                .ok_or(Error::LoggedOut)?
                .record
                .clone()
        };
        match self.derive_user_key(&record, password).await {
            Ok(_) => Ok(true),
            Err(Error::InvalidPassword) => Ok(false),
            Err(other) => Err(other),
        }
    }

    pub(crate) fn user_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.read_unlocked(|_, unlocked| Ok(unlocked.keys.user().to_bytes()))
    }

    /// `None` when already unlocked.
    fn locked_record(&self) -> Result<Option<(u64, AccountRecord)>> {
        let state = self.read_state();
        let active = state.active.as_ref().ok_or(Error::LoggedOut)?;
        if active.unlocked.is_some() {
            return Ok(None);
        }
        Ok(Some((state.epoch, active.record.clone())))
    }

    /// The KDF runs on the blocking pool: Argon2id with 64 MiB takes long enough to stall a worker.
    async fn derive_user_key(
        &self,
        record: &AccountRecord,
        password: Zeroizing<String>,
    ) -> Result<SymmetricKey> {
        let kdf = record.kdf.to_kdf()?;
        let protected = parse(&record.key)?;
        let email = record.email.clone();
        self.config
            .runtime
            .spawn_blocking(move || {
                let master_key = MasterKey::derive(password.as_bytes(), &email, &kdf)?;
                master_key
                    .decrypt_user_key(&protected)
                    .map_err(wrong_key_as_invalid_password)
            })
            .await
            .map_err(Error::task)?
    }

    /// Decrypts the cached vault with `user_key` and makes the session unlocked.
    fn install_unlocked(
        self: &Arc<Self>,
        epoch: u64,
        record: &AccountRecord,
        user_key: SymmetricKey,
    ) -> Result<()> {
        // A wrong Touch ID key would otherwise only surface as undecryptable rows.
        if let Some(private_key) = &record.private_key {
            parse(private_key)?
                .decrypt(&user_key)
                .map_err(wrong_key_as_invalid_password)?;
        }
        let cached = self.store.load_vault(&record.id)?;
        let profile = match &cached {
            Some(cached) => cached.sync.profile.clone(),
            None => empty_profile(record),
        };
        let user_key_bytes = user_key.to_bytes();
        let keys = KeyRing::build(
            user_key,
            record.private_key.as_deref(),
            &profile.organizations,
            None,
        )?;
        let data = match cached {
            Some(cached) => VaultData::build(cached.sync, &keys).with_complete(cached.complete),
            None => VaultData::empty(profile),
        };
        // The cached vault decrypted with this key, so the sealed token store can read the
        // refresh token from here on.
        self.secrets
            .provide_key(&record.id, user_key_bytes.as_slice())
            .map_err(secret_error)?;
        let unlocked = Unlocked::new(keys, data);
        let epoch = {
            let mut state = self.write_state();
            let active = state.active.as_ref().ok_or(Error::LoggedOut)?;
            if *active.id == *record.id && active.unlocked.is_some() {
                // A concurrent unlock of the same account won the race.
                return Ok(());
            }
            if state.epoch != epoch || *active.id != *record.id {
                return Err(Error::Locked);
            }
            let active = state.active.as_mut().ok_or(Error::LoggedOut)?;
            active.unlocked = Some(unlocked);
            state.epoch += 1;
            state.epoch
        };
        self.bump();
        self.bump_ssh();
        self.start_background(epoch);
        self.request_sync();
        Ok(())
    }

    fn live_pending(&self) -> Option<Arc<PendingLogin>> {
        let mut pending = lock(&self.pending);
        if pending.as_ref().is_some_and(|login| login.expired()) {
            pending.take();
        }
        pending.clone()
    }

    pub(crate) fn lock_session(&self) {
        self.clear_pending();
        let (previous, id) = {
            let mut state = self.write_state();
            let state = &mut *state;
            match state.active.as_mut() {
                Some(active) if active.unlocked.is_some() => {
                    state.epoch += 1;
                    active.token = None;
                    (active.unlocked.take(), Some(Arc::clone(&active.id)))
                }
                _ => (None, None),
            }
        };
        drop(self.stop_background());
        if let Some(previous) = previous {
            drop(previous);
            if let Some(id) = id {
                self.secrets.forget_key(&id);
            }
            self.bump();
            self.bump_ssh();
        }
    }

    pub(crate) fn switch_account(&self, account_id: &str) -> Result<()> {
        let entry = {
            let state = self.read_state();
            state
                .index
                .find(account_id)
                .cloned()
                .ok_or(Error::NotFound)?
        };
        let active = locked_active(&self.store, &self.config, &entry)?;
        let (previous, index) = {
            let mut state = self.write_state();
            state.epoch += 1;
            state.index.touch(entry);
            (state.active.replace(active), state.index.clone())
        };
        drop(self.stop_background());
        if let Some(previous) = previous {
            let id = Arc::clone(&previous.id);
            drop(previous);
            self.secrets.forget_key(&id);
        }
        self.clear_pending();
        self.set_offline(false);
        self.bump();
        self.bump_ssh();
        self.store.save_index(&index)
    }

    pub(crate) fn begin_add_account(&self) {
        let previous = {
            let mut state = self.write_state();
            state.epoch += 1;
            state.active.take()
        };
        drop(self.stop_background());
        if let Some(previous) = previous {
            let id = Arc::clone(&previous.id);
            drop(previous);
            self.secrets.forget_key(&id);
        }
        self.clear_pending();
        self.set_offline(false);
        self.bump();
        self.bump_ssh();
    }
}

fn empty_profile(record: &AccountRecord) -> Profile {
    Profile {
        id: record.id.clone(),
        email: record.email.clone(),
        name: None,
        key: Some(record.key.clone()),
        private_key: record.private_key.clone(),
        organizations: Vec::new(),
    }
}

fn login_error(error: vk_api::Error) -> Error {
    match &error {
        vk_api::Error::Server {
            status: 400,
            message,
        } if message
            .to_ascii_lowercase()
            .contains(WRONG_PASSWORD_MESSAGE) =>
        {
            Error::InvalidPassword
        }
        _ => Error::Api(error),
    }
}

#[cfg(test)]
mod tests;
