//! Shared harness for the Vaultwarden scenarios (`--features vw-it`, started by scripts/e2e.sh).
//!
//! Accounts are registered through the API with our own crypto, so each scenario starts with a
//! fresh user whose user key the harness knows and can use to check what reached the server.
//! RSA material comes from OpenSSL-generated fixtures (key generation is slow in debug builds).

#![allow(dead_code, clippy::unwrap_used, clippy::missing_panics_doc)]

pub mod proxy;

use std::{
    future::Future,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use vk_api::{Client, DeviceInfo, LoginOutcome, TwoFactorProvider, TwoFactorToken, models::Cipher};
use vk_crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use vk_vault::{
    MemorySecretStore, SecretStore, Timings, Vault, VaultConfig, VaultService,
    model::{LoginRequest, LoginStep},
};
use zeroize::Zeroizing;

pub const RSA_PRIVATE_DER: &[u8] = include_bytes!("../fixtures/rsa_private.der");
pub const RSA_PUBLIC_B64: &str = include_str!("../fixtures/rsa_public.b64");
pub const ORG_KEY: &[u8] = include_bytes!("../fixtures/org_key.bin");
/// `ORG_KEY` wrapped by OpenSSL with RSA-OAEP-SHA1 under the fixture public key.
pub const ORG_KEY_RSA: &str = include_str!("../fixtures/org_key_rsa.txt");

pub const WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(100);

pub struct Env {
    pub vw: Url,
    pub mailpit: Url,
    pub http: reqwest::Client,
}

/// The scenarios are useless without a server, so a missing `VW_URL` fails instead of skipping.
pub fn env() -> Env {
    let vw = std::env::var("VW_URL")
        .expect("VW_URL must point at the e2e Vaultwarden (run scripts/e2e.sh)");
    let mailpit = std::env::var("MAILPIT_URL")
        .expect("MAILPIT_URL must point at the e2e Mailpit (run scripts/e2e.sh)");
    Env {
        vw: Url::parse(&vw).expect("VW_URL is a URL"),
        mailpit: Url::parse(&mailpit).expect("MAILPIT_URL is a URL"),
        http: reqwest::Client::new(),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum KdfChoice {
    /// The server's minimum for PBKDF2 registrations.
    Pbkdf2,
    /// The client's Argon2id minimum (2 iterations, 16 MiB, 1 lane).
    Argon2id,
}

pub struct TestAccount {
    pub email: String,
    pub password: String,
    pub hash: String,
    pub user_key: SymmetricKey,
    pub kdf: Kdf,
}

impl TestAccount {
    pub fn login_request(&self, server: &Url) -> LoginRequest {
        LoginRequest {
            server: server.clone(),
            email: self.email.clone(),
            password: Zeroizing::new(self.password.clone()),
        }
    }
}

pub fn unique_email(tag: &str) -> String {
    format!("{tag}-{}@example.com", Uuid::new_v4().simple())
}

pub async fn register(env: &Env, kdf: KdfChoice) -> TestAccount {
    let email = unique_email("e2e");
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let (kdf, wire) = match kdf {
        KdfChoice::Pbkdf2 => (
            Kdf::from_wire(0, 100_000, None, None).unwrap(),
            json!({ "kdf": 0, "kdfIterations": 100_000 }),
        ),
        KdfChoice::Argon2id => (
            Kdf::from_wire(1, 2, Some(16), Some(1)).unwrap(),
            json!({ "kdf": 1, "kdfIterations": 2, "kdfMemory": 16, "kdfParallelism": 1 }),
        ),
    };
    let master = MasterKey::derive(password.as_bytes(), &email, &kdf).unwrap();
    let hash = master.server_hash(password.as_bytes());
    let user_key = SymmetricKey::generate();
    let protected = EncString::encrypt(&user_key.to_bytes(), &master.stretch()).unwrap();
    let private_key = EncString::encrypt(RSA_PRIVATE_DER, &user_key).unwrap();

    let token = env
        .http
        .post(
            env.vw
                .join("identity/accounts/register/send-verification-email")
                .unwrap(),
        )
        .json(&json!({ "email": email, "name": "E2E" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("signups must be allowed")
        .text()
        .await
        .unwrap();
    let mut body = json!({
        "email": email,
        "masterPasswordHash": hash,
        "key": protected.to_string(),
        "keys": { "encryptedPrivateKey": private_key.to_string(), "publicKey": RSA_PUBLIC_B64.trim() },
        "emailVerificationToken": token.trim().trim_matches('"'),
    });
    merge(&mut body, wire);
    let response = env
        .http
        .post(env.vw.join("identity/accounts/register/finish").unwrap())
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    assert!(
        status.is_success(),
        "register failed: {status} {}",
        response.text().await.unwrap()
    );
    TestAccount {
        email,
        password,
        hash,
        user_key,
        kdf,
    }
}

fn merge(target: &mut Value, extra: Value) {
    if let (Value::Object(target), Value::Object(extra)) = (target, extra) {
        target.extend(extra);
    }
}

pub fn device() -> DeviceInfo {
    DeviceInfo {
        identifier: Uuid::new_v4(),
        name: "e2e".into(),
        device_type: 7,
    }
}

/// Short timings so recovery paths finish in seconds instead of minutes.
pub fn fast_timings() -> Timings {
    let mut timings = Timings {
        sync_debounce: Duration::from_millis(100),
        probe_initial: Duration::from_millis(300),
        probe_max: Duration::from_secs(2),
        probe_timeout: Duration::from_secs(3),
        ..Timings::default()
    };
    timings.notifications.backoff_initial = Duration::from_millis(200);
    timings.notifications.backoff_max = Duration::from_secs(2);
    timings
}

pub struct TestVault {
    pub vault: Vault,
    pub secrets: Arc<MemorySecretStore>,
    pub data_dir: PathBuf,
    pub device: DeviceInfo,
}

impl TestVault {
    pub fn new() -> Self {
        let data_dir = std::env::temp_dir().join(format!("vk-e2e-{}", Uuid::new_v4().simple()));
        Self::open_at(data_dir, device())
    }

    /// Reopens over an existing data directory, as an app restart would.
    pub fn open_at(data_dir: PathBuf, device: DeviceInfo) -> Self {
        let secrets = Arc::new(MemorySecretStore::new());
        Self::open_with(data_dir, device, secrets)
    }

    pub fn open_with(
        data_dir: PathBuf,
        device: DeviceInfo,
        secrets: Arc<MemorySecretStore>,
    ) -> Self {
        Self::open_custom(data_dir, device, secrets, fast_timings())
    }

    pub fn with_timings(timings: Timings) -> Self {
        let data_dir = std::env::temp_dir().join(format!("vk-e2e-{}", Uuid::new_v4().simple()));
        Self::open_custom(
            data_dir,
            device(),
            Arc::new(MemorySecretStore::new()),
            timings,
        )
    }

    pub fn open_custom(
        data_dir: PathBuf,
        device: DeviceInfo,
        secrets: Arc<MemorySecretStore>,
        timings: Timings,
    ) -> Self {
        let vault = open_vault(&data_dir, &device, &secrets, timings);
        Self {
            vault,
            secrets,
            data_dir,
            device,
        }
    }

    /// Replaces the vault with a fresh instance over the same files and secrets (app restart).
    pub fn restart(&mut self) {
        self.vault = open_vault(&self.data_dir, &self.device, &self.secrets, fast_timings());
    }

    pub async fn login(&self, server: &Url, account: &TestAccount) {
        let step = self
            .vault
            .login(account.login_request(server), None, None)
            .await
            .unwrap();
        assert_eq!(step, LoginStep::Done);
    }

    pub fn account_dir(&self, user_id: &str) -> PathBuf {
        self.data_dir.join("accounts").join(user_id)
    }
}

fn open_vault(
    data_dir: &std::path::Path,
    device: &DeviceInfo,
    secrets: &Arc<MemorySecretStore>,
    timings: Timings,
) -> Vault {
    let mut config = VaultConfig::new(
        data_dir.to_owned(),
        device.clone(),
        tokio::runtime::Handle::current(),
    );
    config.timings = timings;
    let store: Arc<dyn SecretStore> = secrets.clone();
    Vault::open(config, store).unwrap()
}

impl Drop for TestVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// A second, independent client session (another device) on the same account.
pub struct RawSession {
    pub client: Client,
    pub token: String,
    pub device: DeviceInfo,
}

pub async fn raw_session(env: &Env, account: &TestAccount) -> RawSession {
    raw_session_with(env, account, None).await
}

pub async fn raw_session_with(
    env: &Env,
    account: &TestAccount,
    factor: Option<TwoFactorToken>,
) -> RawSession {
    let device = device();
    let client = Client::new(env.vw.clone(), device.clone()).unwrap();
    match client
        .login(&account.email, &account.hash, factor.as_ref(), None)
        .await
        .unwrap()
    {
        LoginOutcome::Success(token) => RawSession {
            client,
            token: token.access_token.clone(),
            device,
        },
        other => panic!("raw login failed: {other:?}"),
    }
}

impl RawSession {
    pub async fn api(&self, env: &Env, method: reqwest::Method, path: &str, body: Value) -> Value {
        let response = env
            .http
            .request(method, env.vw.join(path).unwrap())
            .bearer_auth(&self.token)
            .header("device-type", "7")
            .header("bitwarden-client-name", "desktop")
            .header("bitwarden-client-version", "2025.12.0")
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert!(status.is_success(), "{path}: {status} {text}");
        if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap()
        }
    }

    pub async fn ciphers(&self) -> Vec<Cipher> {
        self.client.sync(&self.token).await.unwrap().ciphers
    }

    pub async fn cipher(&self, id: &str) -> Cipher {
        self.ciphers()
            .await
            .into_iter()
            .find(|cipher| cipher.id == id)
            .unwrap_or_else(|| panic!("cipher {id} not on the server"))
    }
}

pub fn decrypt(field: Option<&str>, key: &SymmetricKey) -> String {
    match field {
        Some(text) if !text.is_empty() => text
            .parse::<EncString>()
            .unwrap()
            .decrypt_string(key)
            .unwrap()
            .to_string(),
        _ => String::new(),
    }
}

/// The key a server-side cipher's fields are encrypted with, computed by the harness itself.
pub fn server_cipher_key(cipher: &Cipher, base: &SymmetricKey) -> SymmetricKey {
    match cipher.key.as_deref() {
        Some(wrapped) => {
            let bytes = wrapped.parse::<EncString>().unwrap().decrypt(base).unwrap();
            SymmetricKey::from_bytes(&bytes).unwrap()
        }
        None => SymmetricKey::from_bytes(&base.to_bytes()).unwrap(),
    }
}

pub fn enc(plain: &str, key: &SymmetricKey) -> String {
    EncString::encrypt(plain.as_bytes(), key)
        .unwrap()
        .to_string()
}

pub fn org_key() -> SymmetricKey {
    SymmetricKey::from_bytes(ORG_KEY).unwrap()
}

/// Creates an organization owned by `session`'s user with one collection; returns their ids.
pub async fn create_org(env: &Env, session: &RawSession, billing_email: &str) -> (String, String) {
    let key = org_key();
    let org = session
        .api(
            env,
            reqwest::Method::POST,
            "api/organizations",
            json!({
                "name": "E2E Org",
                "billingEmail": billing_email,
                "collectionName": enc("Shared", &key),
                "key": ORG_KEY_RSA.trim(),
                "planType": 0,
            }),
        )
        .await;
    let org_id = org["id"].as_str().unwrap().to_owned();
    let sync = session.client.sync(&session.token).await.unwrap();
    let collection = sync
        .collections
        .iter()
        .find(|collection| collection.organization_id == org_id)
        .expect("the new organization has its default collection");
    (org_id, collection.id.clone())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub async fn enable_email_two_factor(env: &Env, session: &RawSession, account: &TestAccount) {
    let verification = session
        .api(
            env,
            reqwest::Method::POST,
            "api/two-factor/get-email",
            json!({ "masterPasswordHash": account.hash }),
        )
        .await;
    let token = verification["userVerificationToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = mail_count(env, &account.email).await;
    session
        .api(
            env,
            reqwest::Method::POST,
            "api/two-factor/send-email",
            json!({ "email": account.email, "userVerificationToken": token }),
        )
        .await;
    let code = wait_for_code(env, &account.email, before).await;
    session
        .api(
            env,
            reqwest::Method::PUT,
            "api/two-factor/email",
            json!({ "email": account.email, "token": code, "userVerificationToken": token }),
        )
        .await;
}

/// Returns the base32 secret.
pub async fn enable_authenticator(
    env: &Env,
    session: &RawSession,
    account: &TestAccount,
) -> String {
    let setup = session
        .api(
            env,
            reqwest::Method::POST,
            "api/two-factor/get-authenticator",
            json!({ "masterPasswordHash": account.hash }),
        )
        .await;
    let secret = setup["authenticator"]["key"].as_str().unwrap().to_owned();
    let token = setup["userVerificationToken"].as_str().unwrap().to_owned();
    let code = totp(&secret, unix_now());
    session
        .api(
            env,
            reqwest::Method::PUT,
            "api/two-factor/authenticator",
            json!({
                "key": secret,
                "token": code,
                "masterPasswordHash": account.hash,
                "userVerificationToken": token,
            }),
        )
        .await;
    secret
}

pub fn totp(secret: &str, unix_time: u64) -> String {
    vk_gen::totp::Totp::parse(secret)
        .unwrap()
        .generate(unix_time)
        .code
        .to_string()
}

pub async fn mail_count(env: &Env, to: &str) -> u64 {
    mails(env, to).await["messages_count"].as_u64().unwrap_or(0)
}

async fn mails(env: &Env, to: &str) -> Value {
    let mut url = env.mailpit.join("api/v1/search").unwrap();
    url.query_pairs_mut()
        .append_pair("query", &format!("to:\"{to}\""));
    env.http
        .get(url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Waits for more than `before` mails to `to` and returns the 6-digit code of the newest one.
pub async fn wait_for_code(env: &Env, to: &str, before: u64) -> String {
    let search = eventually(|| async {
        let found = mails(env, to).await;
        (found["messages_count"].as_u64().unwrap_or(0) > before).then_some(found)
    })
    .await;
    let id = search["messages"][0]["ID"].as_str().unwrap();
    let message: Value = env
        .http
        .get(env.mailpit.join(&format!("api/v1/message/{id}")).unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let text = message["Text"].as_str().unwrap();
    text.split(|c: char| !c.is_ascii_digit())
        .find(|word| word.len() == 6)
        .unwrap_or_else(|| panic!("no code in mail: {text}"))
        .to_owned()
}

/// Polls `check` until it yields a value or [`WAIT`] passes.
pub async fn eventually<T, F, Fut>(mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not met within {WAIT:?}"
        );
        tokio::time::sleep(POLL).await;
    }
}

pub async fn wait_until(mut check: impl FnMut() -> bool) {
    eventually(|| {
        let done = check();
        async move { done.then_some(()) }
    })
    .await;
}

pub fn email_factor(code: &str, remember: bool) -> vk_vault::model::TwoFactorAnswer {
    vk_vault::model::TwoFactorAnswer {
        provider: TwoFactorProvider::Email,
        code: code.to_owned(),
        remember,
    }
}

pub fn names(vault: &Vault) -> Vec<String> {
    vault
        .search("", &vk_vault::model::Filter::default())
        .unwrap()
        .iter()
        .map(|item| item.name.to_string())
        .collect()
}

pub mod drafts {
    use vk_vault::model::{CustomField, IdentityData, ItemData, ItemDraft};
    use zeroize::Zeroizing;

    /// RFC 6238 appendix B secret "12345678901234567890" in base32.
    pub const RFC_TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    pub fn base(name: &str, data: ItemData) -> ItemDraft {
        ItemDraft {
            name: name.to_owned(),
            notes: Zeroizing::new(String::new()),
            folder_id: None,
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: false,
            reprompt: false,
            fields: Vec::new(),
            data,
            revision_date: None,
        }
    }

    pub fn login(name: &str, username: &str, password: &str) -> ItemDraft {
        let mut draft = base(
            name,
            ItemData::Login {
                username: username.to_owned(),
                password: Zeroizing::new(password.to_owned()),
                totp: Zeroizing::new(RFC_TOTP_SECRET.to_owned()),
                uris: vec![
                    "https://login.example.com/".to_owned(),
                    "https://alt.example.com".to_owned(),
                ],
            },
        );
        draft.notes = Zeroizing::new(format!("notes for {name}"));
        draft.fields = vec![
            CustomField {
                name: "pin".into(),
                value: Zeroizing::new("4321".into()),
                hidden: true,
                field_type: 1,
                source_index: None,
                withheld: false,
            },
            CustomField {
                name: "plain".into(),
                value: Zeroizing::new("visible".into()),
                hidden: false,
                field_type: 0,
                source_index: None,
                withheld: false,
            },
        ];
        draft
    }

    pub fn note(name: &str) -> ItemDraft {
        let mut draft = base(name, ItemData::SecureNote);
        draft.notes = Zeroizing::new("a secure note body".into());
        draft
    }

    pub fn card(name: &str) -> ItemDraft {
        base(
            name,
            ItemData::Card {
                cardholder_name: "Ada Lovelace".into(),
                brand: "Visa".into(),
                number: Zeroizing::new("4111111111114242".into()),
                exp_month: "12".into(),
                exp_year: "2031".into(),
                code: Zeroizing::new("123".into()),
            },
        )
    }

    pub fn identity(name: &str) -> ItemDraft {
        base(
            name,
            ItemData::Identity(Box::new(IdentityData {
                first_name: "Ada".into(),
                last_name: "Lovelace".into(),
                email: "ada@example.com".into(),
                phone: "+44 20 7946 0000".into(),
                ssn: Zeroizing::new("078-05-1120".into()),
                passport_number: Zeroizing::new("P1234567".into()),
                city: "London".into(),
                ..IdentityData::default()
            })),
        )
    }

    pub const SSH_PRIVATE: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----\n";

    pub fn ssh(name: &str) -> ItemDraft {
        base(
            name,
            ItemData::SshKey {
                private_key: Zeroizing::new(SSH_PRIVATE.into()),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2e e2e@example".into(),
                fingerprint: "SHA256:e2eFingerprintValue".into(),
            },
        )
    }
}

impl RawSession {
    /// Creates a personal login from this (other) device, encrypted the way official clients do.
    pub async fn create_login(&self, account: &TestAccount, name: &str) -> Cipher {
        let item_key = SymmetricKey::generate();
        let request = vk_api::models::CipherRequest {
            r#type: 1,
            name: enc(name, &item_key),
            key: Some(
                EncString::encrypt(&item_key.to_bytes(), &account.user_key)
                    .unwrap()
                    .to_string(),
            ),
            login: Some(vk_api::models::Login {
                username: Some(enc("someone", &item_key)),
                password: Some(enc("from-elsewhere", &item_key)),
                ..vk_api::models::Login::default()
            }),
            ..vk_api::models::CipherRequest::default()
        };
        self.client
            .create_cipher(&self.token, &request, &[])
            .await
            .unwrap()
    }
}
