//! Login, unlock, lock and account switching: the LoggedOut → Locked → Unlocked machine.

use std::{sync::Arc, time::Duration};

use bwl_api::{
    Client, LoginOutcome, TwoFactorProvider, TwoFactorToken,
    models::{Profile, SyncResponse, TokenResponse},
};
use bwl_crypto::{MasterKey, SymmetricKey};
use tokio::time::Instant;
use url::Url;
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
            Ok(LoginStep::TwoFactorRequired(_) | LoginStep::NewDeviceOtpRequired)
        ) {
            self.clear_pending();
        }
        step
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
                .secrets
                .get(&remember_token_key(id))
                .map_err(secret_error)?
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
            LoginOutcome::TwoFactorRequired(providers) => {
                if remembered.is_some()
                    && let Some(id) = &known_id
                {
                    // The server no longer honours it; asking again would loop.
                    self.secrets
                        .delete(&remember_token_key(id))
                        .map_err(secret_error)?;
                }
                let offered = providers
                    .into_iter()
                    .filter(|provider| *provider != TwoFactorProvider::Remember)
                    .collect();
                Ok(LoginStep::TwoFactorRequired(offered))
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
        let client = Arc::new(Client::new(
            request.server.clone(),
            self.config.device.clone(),
        )?);
        let email = request.email.trim().to_owned();
        let prelogin = client.prelogin(&email).await?;
        let kdf = KdfRecord::from_prelogin(&prelogin);
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
        *lock(&self.pending) = Some(Arc::clone(&pending));
        Ok(pending)
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
        self.store_login_secrets(&id, &tokens)?;
        let token = AccessToken {
            value: tokens.access,
            expires_at: token_expiry(tokens.expires_in),
        };
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

    fn store_login_secrets(&self, id: &str, tokens: &LoginTokens) -> Result<()> {
        if let Some(refresh) = &tokens.refresh {
            self.secrets
                .set(&refresh_token_key(id), refresh.as_bytes())
                .map_err(secret_error)?;
        }
        if let Some(remember) = &tokens.remember {
            self.secrets
                .set(&remember_token_key(id), remember.as_bytes())
                .map_err(secret_error)?;
        }
        Ok(())
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
        let entry = IndexEntry {
            id: record.id.clone(),
            server: record.server.clone(),
            email: record.email.clone(),
        };
        let active = Active {
            id: Arc::from(record.id.as_str()),
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
        drop(previous);
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
        let previous = {
            let mut state = self.write_state();
            let state = &mut *state;
            match state.active.as_mut() {
                Some(active) if active.unlocked.is_some() => {
                    state.epoch += 1;
                    active.token = None;
                    active.unlocked.take()
                }
                _ => None,
            }
        };
        drop(self.stop_background());
        if let Some(previous) = previous {
            drop(previous);
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
        drop(previous);
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
        drop(previous);
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

fn login_error(error: bwl_api::Error) -> Error {
    match &error {
        bwl_api::Error::Server {
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
mod tests {
    use super::*;

    #[test]
    fn hostile_expires_in_is_clamped_instead_of_overflowing() {
        let now = Instant::now();
        for expires_in in [u64::MAX, u64::MAX / 2, 1 << 40] {
            let at = token_expiry(expires_in);
            assert!(at <= now + MAX_TOKEN_LIFETIME + Duration::from_secs(1));
            assert!(at > now);
        }
        let short = token_expiry(60);
        assert!(short < now + Duration::from_secs(61));
    }

    #[test]
    fn wrong_password_message_maps_to_invalid_password() {
        let wrong = bwl_api::Error::Server {
            status: 400,
            message: "Username or password is incorrect. Try again".into(),
        };
        assert!(matches!(login_error(wrong), Error::InvalidPassword));
        let other = bwl_api::Error::Server {
            status: 400,
            message: "Invalid TOTP code!".into(),
        };
        assert!(matches!(login_error(other), Error::Api(_)));
        assert!(matches!(
            login_error(bwl_api::Error::Unauthorized),
            Error::Api(bwl_api::Error::Unauthorized)
        ));
    }
}
