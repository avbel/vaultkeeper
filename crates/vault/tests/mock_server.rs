//! Vault logic against a wiremock server: login rounds, token refresh, offline mode and its
//! recovery, debounce, sleep and the log-out error collection. Server data is encrypted with
//! vk-crypto directly; the vault decrypts it independently.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use vk_api::{
    DeviceInfo, TwoFactorProvider,
    models::{Cipher, Login, Profile, SshKey, SyncResponse},
};
use vk_crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use vk_vault::{
    BackgroundStatus, Error, LogoutErrors, MemorySecretStore, SecretStore, SecretStoreError,
    Timings, Vault, VaultConfig, VaultService,
    model::{Filter, ItemData, ItemDraft, LoginRequest, LoginStep, SessionState, TwoFactorAnswer},
};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};
use zeroize::Zeroizing;

const USER_ID: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "correct horse battery staple";
/// JWT-shaped tokens whose payload is `{"sub": USER_ID, "exp": 4102444800, "n": 1|2}`; the API
/// client reads `sub` as `encryptedFor` on writes.
const ACCESS_1: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzYmVmMDVkNi05MDcwLTQ4YjQtYjMyMC1hNWQ0MjVlZWM5ZmQiLCJleHAiOjQxMDI0NDQ4MDAsIm4iOjF9.sig1";
const ACCESS_2: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzYmVmMDVkNi05MDcwLTQ4YjQtYjMyMC1hNWQ0MjVlZWM5ZmQiLCJleHAiOjQxMDI0NDQ4MDAsIm4iOjJ9.sig2";
const WAIT: Duration = Duration::from_secs(5);

struct Fake {
    server: MockServer,
    user_key: SymmetricKey,
    protected_key: String,
}

impl Fake {
    async fn start() -> Self {
        let kdf = Kdf::from_wire(0, 5000, None, None).unwrap();
        let master = MasterKey::derive(PASSWORD.as_bytes(), EMAIL, &kdf).unwrap();
        let user_key = SymmetricKey::generate();
        let protected_key = EncString::encrypt(&user_key.to_bytes(), &master.stretch())
            .unwrap()
            .to_string();
        // Not the shared pool: a dropped server must stop answering, and no other test's mocks
        // may answer for it.
        let fake = Self {
            server: MockServer::builder().start().await,
            user_key,
            protected_key,
        };
        fake.mount_login().await;
        fake
    }

    fn url(&self) -> Url {
        Url::parse(&self.server.uri()).unwrap()
    }

    async fn mount_login(&self) {
        Mock::given(method("POST"))
            .and(path("/identity/accounts/prelogin"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })),
            )
            .mount(&self.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(self.token_body(ACCESS_1, "refresh-1")),
            )
            .mount(&self.server)
            .await;
    }

    fn token_body(&self, access: &str, refresh: &str) -> Value {
        json!({
            "access_token": access,
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": refresh,
            "Key": self.protected_key,
        })
    }

    fn login(&self, id: &str, name: &str, password: &str) -> Cipher {
        let item = SymmetricKey::generate();
        let enc = |plain: &str| {
            Some(
                EncString::encrypt(plain.as_bytes(), &item)
                    .unwrap()
                    .to_string(),
            )
        };
        Cipher {
            id: id.into(),
            r#type: 1,
            name: enc(name),
            key: Some(
                EncString::encrypt(&item.to_bytes(), &self.user_key)
                    .unwrap()
                    .to_string(),
            ),
            login: Some(Login {
                username: enc("someone"),
                password: enc(password),
                ..Login::default()
            }),
            edit: true,
            view_password: true,
            revision_date: "2026-11-08T17:00:59.321Z".into(),
            ..Cipher::default()
        }
    }

    fn ssh_key(&self, id: &str, private_key: Option<&str>) -> Cipher {
        let enc = |plain: &str| {
            Some(
                EncString::encrypt(plain.as_bytes(), &self.user_key)
                    .unwrap()
                    .to_string(),
            )
        };
        Cipher {
            id: id.into(),
            r#type: 5,
            name: enc(id),
            ssh_key: Some(SshKey {
                private_key: private_key.and_then(enc),
                public_key: enc("ssh-ed25519 AAAA test"),
                key_fingerprint: enc("SHA256:test"),
                ..SshKey::default()
            }),
            edit: true,
            view_password: true,
            revision_date: "2026-11-08T17:00:59.321Z".into(),
            ..Cipher::default()
        }
    }

    fn sync_body(&self, ciphers: Vec<Cipher>) -> Value {
        serde_json::to_value(SyncResponse {
            profile: Profile {
                id: USER_ID.into(),
                email: EMAIL.into(),
                name: None,
                key: Some(self.protected_key.clone()),
                private_key: None,
                organizations: Vec::new(),
            },
            folders: Vec::new(),
            collections: Vec::new(),
            ciphers,
        })
        .unwrap()
    }

    async fn mount_sync(&self, ciphers: Vec<Cipher>) {
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(self.sync_body(ciphers)))
            .mount(&self.server)
            .await;
    }

    async fn mount_status(&self, http_method: &str, route: &str, status: u16) {
        Mock::given(method(http_method))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status))
            .mount(&self.server)
            .await;
    }

    /// The server's origin answers 503 for everything the vault uses (a proxy in front of a dead
    /// backend), which counts as offline.
    async fn go_down(&self) {
        self.server.reset().await;
        self.mount_status("GET", "/api/sync", 503).await;
        self.mount_status("GET", "/alive", 503).await;
    }

    async fn come_back(&self, ciphers: Vec<Cipher>) {
        self.server.reset().await;
        self.mount_sync(ciphers).await;
        self.mount_status("GET", "/alive", 200).await;
    }

    async fn requests_to(&self, route: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|request| request.url.path() == route)
            .collect()
    }

    fn request(&self) -> LoginRequest {
        LoginRequest {
            server: self.url(),
            email: EMAIL.into(),
            password: Zeroizing::new(PASSWORD.into()),
        }
    }
}

fn timings() -> Timings {
    let mut timings = Timings {
        sync_debounce: Duration::from_millis(100),
        probe_initial: Duration::from_millis(50),
        probe_max: Duration::from_millis(200),
        probe_timeout: Duration::from_secs(2),
        ..Timings::default()
    };
    // wiremock has no hub; keep the failing reconnects rare.
    timings.notifications.backoff_initial = Duration::from_secs(30);
    timings
}

struct Harness {
    vault: Vault,
    secrets: Arc<dyn SecretStore>,
    memory: Option<Arc<MemorySecretStore>>,
    dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn harness_with(timings: Timings, secrets: Option<Arc<dyn SecretStore>>) -> Harness {
    let dir = std::env::temp_dir().join(format!("vk-mock-{}", Uuid::new_v4().simple()));
    let device = DeviceInfo {
        identifier: Uuid::new_v4(),
        name: "test".into(),
        device_type: 7,
    };
    let mut config = VaultConfig::new(dir.clone(), device, tokio::runtime::Handle::current());
    config.timings = timings;
    let memory = Arc::new(MemorySecretStore::new());
    let (secrets, memory) = match secrets {
        Some(custom) => (custom, None),
        None => (memory.clone() as Arc<dyn SecretStore>, Some(memory)),
    };
    let vault = Vault::open(config, Arc::clone(&secrets)).unwrap();
    Harness {
        vault,
        secrets,
        memory,
        dir,
    }
}

fn harness() -> Harness {
    harness_with(timings(), None)
}

async fn logged_in(fake: &Fake, ciphers: Vec<Cipher>) -> Harness {
    fake.mount_sync(ciphers).await;
    let harness = harness();
    let step = harness
        .vault
        .login(fake.request(), None, None)
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
    harness
}

fn names(vault: &Vault) -> Vec<String> {
    vault
        .search("", &Filter::default())
        .unwrap()
        .iter()
        .map(|item| item.name.to_string())
        .collect()
}

async fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not met within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn note_draft(name: &str) -> ItemDraft {
    ItemDraft {
        name: name.into(),
        notes: Zeroizing::new("body".into()),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data: ItemData::SecureNote,
        revision_date: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broken_ssh_item_is_skipped_and_the_other_keys_are_still_served() {
    let fake = Fake::start().await;
    let good = "-----BEGIN OPENSSH PRIVATE KEY-----\ngood\n-----END OPENSSH PRIVATE KEY-----\n";
    let harness = logged_in(
        &fake,
        vec![
            fake.ssh_key("broken", None),
            fake.ssh_key("good", Some(good)),
        ],
    )
    .await;
    let keys = harness.vault.ssh_keys().unwrap();
    let served: Vec<_> = keys.iter().map(|key| &*key.cipher_id.0).collect();
    assert_eq!(served, ["good"]);
    assert_eq!(keys[0].private_key.as_str(), good);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_syncs_and_decrypts_the_vault() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "GitHub", "pw")]).await;
    let vault = &harness.vault;
    assert_eq!(names(vault), ["GitHub"]);
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
    assert_eq!(
        vault.sync_count(),
        0,
        "the login's own sync is not a background sync"
    );
    let stored = harness.memory.as_ref().unwrap();
    assert_eq!(
        stored
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-1"[..])
    );
    let token_request = &fake.requests_to("/identity/connect/token").await[0];
    let form = String::from_utf8_lossy(&token_request.body);
    assert!(
        form.contains("client_id=desktop") && form.contains("scope=api+offline_access"),
        "{form}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_factor_rounds_reuse_the_derived_key_and_store_the_remember_token() {
    let fake = Fake::start().await;
    fake.server.reset().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })),
        )
        .mount(&fake.server)
        .await;
    let mut success = fake.token_body(ACCESS_1, "refresh-1");
    success["TwoFactorToken"] = json!("remember-me");
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=123456"))
        .and(body_string_contains("twoFactorProvider=1"))
        .and(body_string_contains("twoFactorRemember=1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=remember-me"))
        .and(body_string_contains("twoFactorProvider=5"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(fake.token_body(ACCESS_1, "refresh-2")),
        )
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders2": { "1": { "Email": "us***@example.com" }, "0": null }
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/two-factor/send-email-login"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&fake.server)
        .await;
    fake.mount_sync(vec![]).await;

    let harness = harness();
    let vault = &harness.vault;
    assert!(
        matches!(vault.send_email_code().await, Err(Error::LoggedOut)),
        "no login started"
    );
    let step = vault.login(fake.request(), None, None).await.unwrap();
    assert_eq!(
        step,
        LoginStep::TwoFactorRequired(vec![
            TwoFactorProvider::Authenticator,
            TwoFactorProvider::Email
        ])
    );
    vault.send_email_code().await.unwrap();
    let answer = TwoFactorAnswer {
        provider: TwoFactorProvider::Email,
        code: " 123456 ".into(),
        remember: true,
    };
    assert_eq!(
        vault
            .login(fake.request(), Some(answer), None)
            .await
            .unwrap(),
        LoginStep::Done
    );
    assert_eq!(
        fake.requests_to("/identity/accounts/prelogin").await.len(),
        1,
        "one KDF run for both rounds"
    );
    let memory = harness.memory.as_ref().unwrap();
    assert_eq!(
        memory.keys(),
        vec![
            format!("{USER_ID}.refresh_token"),
            format!("{USER_ID}.two_factor_remember")
        ]
    );

    // Next login on this device sends the remembered token instead of asking again.
    vault.begin_add_account();
    assert_eq!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::Done
    );
    assert_eq!(
        memory
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-2"[..])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_or_abandoned_login_keeps_no_typed_password_or_derived_key() {
    let fake = Fake::start().await;
    fake.server.reset().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })),
        )
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken="))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders2": { "1": { "Email": "us***@example.com" } }
        })))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("username=typo%40example.com"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password",
            "ErrorModel": { "Message": "Username or password is incorrect. Try again" }
        })))
        .with_priority(2)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders2": { "1": { "Email": "us***@example.com" } }
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/two-factor/send-email-login"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&fake.server)
        .await;

    let harness = harness();
    let vault = &harness.vault;
    let typo = LoginRequest {
        email: "typo@example.com".into(),
        ..fake.request()
    };
    assert!(vault.login(typo, None, None).await.is_err());
    assert!(
        matches!(vault.send_email_code().await, Err(Error::LoggedOut)),
        "a rejected password leaves no pending login"
    );

    assert!(matches!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::TwoFactorRequired(_)
    ));
    vault.send_email_code().await.unwrap();
    vault.lock();
    assert!(
        matches!(vault.send_email_code().await, Err(Error::LoggedOut)),
        "locking abandons the second round"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn new_device_verification_round() {
    let fake = Fake::start().await;
    fake.server.reset().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })),
        )
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("newDeviceOtp=654321"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fake.token_body(ACCESS_1, "r")))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "New device verification required"
        })))
        .mount(&fake.server)
        .await;
    fake.mount_sync(vec![]).await;

    let harness = harness();
    let vault = &harness.vault;
    assert_eq!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::NewDeviceOtpRequired
    );
    let step = vault
        .login(fake.request(), None, Some("654321".into()))
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_server_switches_to_offline_and_the_probe_recovers_without_the_timer() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "Cached", "pw")]).await;
    let vault = &harness.vault;
    let mut offline = vault.offline_changes();

    fake.go_down().await;
    let error = vault.sync().await.unwrap_err();
    assert!(error.is_offline(), "{error:?}");
    assert!(vault.is_offline());
    assert!(*offline.borrow_and_update());
    assert!(vault.background().offline_probe);
    assert_eq!(names(vault), ["Cached"], "the cached vault stays readable");

    let refused = vault.save(None, note_draft("later")).await.unwrap_err();
    assert!(matches!(refused, Error::Offline), "{refused:?}");
    assert!(refused.is_offline());
    assert!(
        fake.requests_to("/api/ciphers").await.is_empty(),
        "nothing was sent"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(vault.is_offline());
    assert!(
        !fake.requests_to("/alive").await.is_empty(),
        "the probe asks /alive"
    );

    fake.come_back(vec![
        fake.login("c1", "Cached", "pw"),
        fake.login("c2", "Fresh", "pw"),
    ])
    .await;
    wait_until(|| !vault.is_offline()).await;
    wait_until(|| names(vault).contains(&"Fresh".to_owned())).await;
    assert!(!*offline.borrow_and_update());
    wait_until(|| !vault.background().offline_probe).await;
    assert_eq!(vault.sync_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_network_change_probes_at_once() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![]).await;
    let harness = harness_with(
        Timings {
            probe_initial: Duration::from_secs(3600),
            probe_max: Duration::from_secs(3600),
            ..timings()
        },
        None,
    );
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    fake.go_down().await;
    assert!(vault.sync().await.is_err());
    fake.come_back(vec![fake.login("c9", "Back", "pw")]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(vault.is_offline(), "the probe still sleeps");
    assert!(fake.requests_to("/alive").await.is_empty());

    vault.on_network_change();
    wait_until(|| !vault.is_offline()).await;
    assert_eq!(names(vault), ["Back"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_sync_requests_runs_one_sync() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = fake.requests_to("/api/sync").await.len();

    for _ in 0..20 {
        vault.request_sync();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    wait_until(|| vault.sync_count() == 1).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(fake.requests_to("/api/sync").await.len(), before + 1);
    assert_eq!(vault.sync_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_access_token_is_refreshed_once_and_the_call_retried() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&fake.server)
        .await;
    fake.mount_sync(vec![fake.login("c1", "After refresh", "pw")])
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-rotated"
        })))
        .expect(1)
        .mount(&fake.server)
        .await;

    vault.sync().await.unwrap();
    assert_eq!(names(vault), ["After refresh"]);
    let syncs = fake.requests_to("/api/sync").await;
    assert_eq!(syncs.len(), 2);
    assert_eq!(
        syncs[1]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {ACCESS_2}")
    );
    let memory = harness.memory.as_ref().unwrap();
    assert_eq!(
        memory
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-rotated"[..])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_refresh_token_means_logging_in_again() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })))
        .expect(1)
        .mount(&fake.server)
        .await;

    let error = vault.sync().await.unwrap_err();
    assert!(
        matches!(error, Error::Api(vk_api::Error::Unauthorized)),
        "{error:?}"
    );
    assert!(!vault.is_offline());
    assert!(
        harness.memory.as_ref().unwrap().keys().is_empty(),
        "the dead refresh token is gone"
    );
    let again = vault.sync().await.unwrap_err();
    assert!(
        matches!(again, Error::Api(vk_api::Error::Unauthorized)),
        "{again:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sleep_stops_syncing_until_wake() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    assert!(vault.background().sync_worker);
    vault.on_sleep();
    assert_eq!(vault.background(), BackgroundStatus::default());
    let before = fake.requests_to("/api/sync").await.len();
    vault.request_sync();
    vault.sync().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fake.requests_to("/api/sync").await.len(), before);

    vault.on_wake();
    assert!(vault.background().sync_worker && vault.background().websocket);
    wait_until(|| vault.sync_count() == 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_that_finishes_after_lock_is_discarded() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "Before", "pw")]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fake.sync_body(vec![fake.login("c2", "Late", "pw")]))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&fake.server)
        .await;

    let (result, ()) = tokio::join!(vault.sync(), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        vault.lock();
    });
    result.unwrap();
    assert!(matches!(vault.state(), SessionState::Locked { .. }));
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::Locked)
    ));
    fake.server.reset().await;
    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    assert_eq!(
        names(vault),
        ["Before"],
        "the late answer neither unlocked nor reached the cache"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_unlock_and_user_key_unlock_use_only_the_cache() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "Cached", "pw")]).await;
    let vault = &harness.vault;
    let user_key = vault.user_key().unwrap();
    assert_eq!(*user_key, *fake.user_key.to_bytes());
    vault.lock();
    drop(fake);

    assert!(
        vault
            .verify_master_password(Zeroizing::new(PASSWORD.into()))
            .await
            .unwrap()
    );
    assert!(
        !vault
            .verify_master_password(Zeroizing::new("wrong".into()))
            .await
            .unwrap()
    );
    assert!(matches!(
        vault
            .unlock_with_password(Zeroizing::new("wrong".into()))
            .await,
        Err(Error::InvalidPassword)
    ));
    assert!(matches!(
        vault.unlock_with_user_key(Zeroizing::new(vec![1; 7])),
        Err(Error::InvalidPassword)
    ));
    vault.unlock_with_user_key(user_key).unwrap();
    assert_eq!(names(vault), ["Cached"]);
    let error = vault.sync().await.unwrap_err();
    assert!(error.is_offline(), "{error:?}");
}

struct FailingDeletes(MemorySecretStore);

impl SecretStore for FailingDeletes {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        self.0.get(key)
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        self.0.set(key, secret)
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        self.0.delete(key)
    }

    fn delete_all_for(&self, _prefix: &str) -> Result<usize, SecretStoreError> {
        Err(SecretStoreError("keychain locked".into()))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_keeps_wiping_after_a_failed_step_and_reports_it() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![fake.login("c1", "Secret", "pw")])
        .await;
    let harness = harness_with(
        timings(),
        Some(Arc::new(FailingDeletes(MemorySecretStore::new()))),
    );
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    let account_dir = harness.dir.join("accounts").join(USER_ID);
    assert!(account_dir.is_dir());

    let error = vault.logout().await.unwrap_err();
    let Error::Logout(LogoutErrors(collected)) = &error else {
        panic!("expected the collected errors, got {error:?}");
    };
    assert_eq!(collected.len(), 1);
    assert!(collected[0].to_string().contains("keychain locked"));
    assert!(!account_dir.exists(), "later steps still ran");
    assert_eq!(vault.state(), SessionState::LoggedOut);
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::LoggedOut)
    ));
    assert!(
        harness
            .secrets
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edit_from_a_cache_written_before_lossless_ciphers_syncs_first() {
    let fake = Fake::start().await;
    let mut cipher = fake.login("c1", "Passkey site", "pw");
    let passkey_key = SymmetricKey::generate();
    let passkey = json!([{
        "credentialId": EncString::encrypt(b"credential", &passkey_key).unwrap().to_string(),
        "creationDate": "2026-11-08T17:00:59.321Z",
    }]);
    cipher
        .login
        .as_mut()
        .unwrap()
        .extra
        .insert("fido2Credentials".into(), passkey.clone());
    fake.mount_sync(vec![cipher.clone()]).await;
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&cipher))
        .mount(&fake.server)
        .await;
    // Locking drops the access token; the writes after the unlock refresh it.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-1"
        })))
        .mount(&fake.server)
        .await;
    // Only the explicit syncs run, so the count below shows which one the edit caused.
    let mut slow = timings();
    slow.sync_debounce = Duration::from_secs(600);
    let harness = harness_with(slow, None);
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    vault.lock();

    let file = harness
        .dir
        .join("accounts")
        .join(USER_ID)
        .join("vault.json");
    let mut cache: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(cache["ciphers"][0]["login"]["fido2Credentials"], passkey);
    // What an earlier version wrote: no format marker and nothing the models didn't name.
    cache.as_object_mut().unwrap().remove("cacheFormat");
    cache["ciphers"][0]["login"]
        .as_object_mut()
        .unwrap()
        .remove("fido2Credentials");
    std::fs::write(&file, serde_json::to_vec(&cache).unwrap()).unwrap();
    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();

    let syncs = fake.requests_to("/api/sync").await.len();
    let id = vk_vault::model::ItemId("c1".into());
    let mut draft = vault.draft(&id).unwrap();
    draft.name = "Renamed".into();
    vault.save(Some(id.clone()), draft.clone()).await.unwrap();
    assert_eq!(fake.requests_to("/api/sync").await.len(), syncs + 1);
    let put = &fake.requests_to("/api/ciphers/c1").await[0];
    let body: Value = serde_json::from_slice(&put.body).unwrap();
    assert_eq!(
        body["login"]["fido2Credentials"], passkey,
        "the passkey is kept"
    );

    vault.save(Some(id), draft).await.unwrap();
    assert_eq!(
        fake.requests_to("/api/sync").await.len(),
        syncs + 1,
        "a synced vault edits without another sync"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_restores_the_most_recent_account_locked() {
    let fake = Fake::start().await;
    let first = logged_in(&fake, vec![fake.login("c1", "Kept", "pw")]).await;
    let dir = first.dir.clone();
    let device = DeviceInfo {
        identifier: Uuid::new_v4(),
        name: "test".into(),
        device_type: 7,
    };
    let config = VaultConfig::new(
        dir.clone(),
        device.clone(),
        tokio::runtime::Handle::current(),
    );
    let reopened = Vault::open(config, Arc::clone(&first.secrets)).unwrap();
    assert_eq!(
        reopened.state(),
        SessionState::Locked {
            server: fake.url(),
            email: EMAIL.into()
        }
    );
    reopened
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    assert_eq!(names(&reopened), ["Kept"]);
    drop(reopened);

    // An index entry whose account files vanished is skipped instead of failing the start.
    std::fs::remove_dir_all(dir.join("accounts").join(USER_ID)).unwrap();
    let config = VaultConfig::new(dir, device, tokio::runtime::Handle::current());
    let empty = Vault::open(config, Arc::clone(&first.secrets)).unwrap();
    assert_eq!(empty.state(), SessionState::LoggedOut);
    assert_eq!(empty.accounts(), Vec::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_and_logged_out_calls_report_their_state() {
    let harness = harness();
    let vault = &harness.vault;
    assert_eq!(vault.state(), SessionState::LoggedOut);
    let id = vk_vault::model::ItemId("x".into());
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::LoggedOut)
    ));
    assert!(matches!(vault.sync().await, Err(Error::LoggedOut)));
    assert!(matches!(
        vault.save(None, note_draft("n")).await,
        Err(Error::LoggedOut)
    ));
    assert!(matches!(
        vault.unlock_with_password(Zeroizing::new("p".into())).await,
        Err(Error::LoggedOut)
    ));
    assert!(matches!(vault.draft(&id), Err(Error::LoggedOut)));
    assert!(matches!(vault.logout().await, Err(Error::LoggedOut)));
    assert!(vault.ssh_keys().unwrap().is_empty());
    assert_eq!(vault.accounts(), Vec::new());
    vault.lock();
    vault.on_sleep();
    vault.on_wake();
    vault.on_network_change();
    assert_eq!(vault.background(), BackgroundStatus::default());

    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "One", "pw")]).await;
    let vault = &harness.vault;
    let id = vk_vault::model::ItemId("c1".into());
    vault.lock();
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::Locked)
    ));
    assert!(matches!(
        vault.reveal(&id, vk_vault::model::CopyField::Password),
        Err(Error::Locked)
    ));
    assert!(matches!(vault.trash(&id).await, Err(Error::Locked)));
    assert!(matches!(vault.create_folder("f").await, Err(Error::Locked)));
    assert!(matches!(vault.user_key(), Err(Error::Locked)));
    assert!(matches!(vault.folders(), Err(Error::Locked)));
    assert!(vault.ssh_keys().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_reports_the_version_and_needs_no_session() {
    let fake = Fake::start().await;
    fake.mount_status("GET", "/alive", 200).await;
    Mock::given(method("GET"))
        .and(path("/api/version"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#""1.37.5""#))
        .mount(&fake.server)
        .await;
    let harness = harness();
    assert_eq!(harness.vault.state(), SessionState::LoggedOut);

    let probe = harness.vault.probe_server(&fake.url()).await.unwrap();
    assert_eq!(probe.version.as_deref(), Some("1.37.5"));
    assert_eq!(harness.vault.state(), SessionState::LoggedOut);
    assert!(
        !harness.vault.is_offline(),
        "a probe never flips offline mode"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_keeps_a_path_prefix_and_tolerates_a_missing_version() {
    let fake = Fake::start().await;
    fake.mount_status("GET", "/vw/alive", 200).await;
    let harness = harness();
    let prefixed = fake.url().join("vw").unwrap();

    let probe = harness.vault.probe_server(&prefixed).await.unwrap();
    assert_eq!(probe.version, None, "404 on /vw/api/version");
    assert_eq!(fake.requests_to("/vw/api/version").await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_of_a_dead_or_failing_server_is_an_error() {
    let fake = Fake::start().await;
    fake.mount_status("GET", "/alive", 503).await;
    let harness = harness();
    let gateway = harness.vault.probe_server(&fake.url()).await.unwrap_err();
    assert!(gateway.is_offline(), "{gateway:?}");

    let not_vaultwarden = Fake::start().await;
    let error = harness
        .vault
        .probe_server(&not_vaultwarden.url())
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Api(vk_api::Error::Server { status: 404, .. })),
        "{error:?}"
    );
    assert!(!error.is_offline());

    let dead = Url::parse("http://127.0.0.1:9/").unwrap();
    let refused = harness.vault.probe_server(&dead).await.unwrap_err();
    assert!(refused.is_offline(), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_snapshot_does_not_survive_lock_and_unlock() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "GitHub", "pw")]).await;
    let vault = &harness.vault;
    let snapshot = vault.browser_snapshot().unwrap();
    vault.lock();
    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    let page = vk_vault::uri_match::PageUrl::new("https://example.com", "/").unwrap();
    let result = vault.browser_reveal(
        snapshot,
        &vk_vault::model::ItemId("c1".into()),
        &page,
        vk_vault::uri_match::DefaultMatch::Domain,
        true,
        vk_vault::BrowserFields {
            username: true,
            password: true,
        },
    );
    assert!(matches!(result, Err(Error::Conflict)));
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_a_draft_after_a_sync_brought_a_remote_edit_is_a_conflict() {
    let fake = Fake::start().await;
    let original = fake.login("c1", "GitHub", "pw");
    let harness = logged_in(&fake, vec![original.clone()]).await;
    let vault = &harness.vault;
    let id = vk_vault::model::ItemId("c1".into());
    let mut draft = vault.draft(&id).unwrap();
    let browser_snapshot = vault.browser_snapshot().unwrap();
    assert_eq!(
        draft.revision_date.as_deref(),
        Some(original.revision_date.as_str())
    );

    let mut remote = fake.login("c1", "GitHub (phone)", "pw");
    remote.revision_date = "2026-11-08T17:05:00.000Z".into();
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fake.sync_body(vec![remote])))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    vault.sync().await.unwrap();
    assert_eq!(names(vault), ["GitHub (phone)"]);
    let page = vk_vault::uri_match::PageUrl::new("https://example.com", "/").unwrap();
    assert!(matches!(
        vault.browser_reveal(
            browser_snapshot,
            &id,
            &page,
            vk_vault::uri_match::DefaultMatch::Domain,
            true,
            vk_vault::BrowserFields {
                username: true,
                password: true
            }
        ),
        Err(Error::Conflict)
    ));

    draft.name = "GitHub (desktop)".into();
    let refused = vault.save(Some(id.clone()), draft).await.unwrap_err();
    assert!(matches!(refused, Error::Conflict), "{refused:?}");
    assert_eq!(refused.to_string(), vk_vault::CONFLICT_MESSAGE);
    assert!(
        fake.requests_to("/api/ciphers/c1").await.is_empty(),
        "nothing was sent"
    );
    assert_eq!(names(vault), ["GitHub (phone)"]);

    let fresh = vault.draft(&id).unwrap();
    assert_eq!(fresh.name, "GitHub (phone)");
    assert_eq!(
        fresh.revision_date.as_deref(),
        Some("2026-11-08T17:05:00.000Z")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_servers_out_of_date_refusal_is_a_conflict_and_asks_for_a_sync() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "GitHub", "pw")]).await;
    let vault = &harness.vault;
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/c1"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "The client copy of this cipher is out of date. Resync the client and try again.",
            "errorModel": { "message": "The client copy of this cipher is out of date. Resync the client and try again." },
        })))
        .mount(&fake.server)
        .await;
    let syncs = fake.requests_to("/api/sync").await.len();
    let id = vk_vault::model::ItemId("c1".into());
    let mut draft = vault.draft(&id).unwrap();
    draft.name = "Renamed".into();
    let refused = vault.save(Some(id), draft).await.unwrap_err();
    assert!(matches!(refused, Error::Conflict), "{refused:?}");
    let sent = fake.requests_to("/api/ciphers/c1").await;
    let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert_eq!(body["lastKnownRevisionDate"], "2026-11-08T17:00:59.321Z");
    let deadline = tokio::time::Instant::now() + WAIT;
    while fake.requests_to("/api/sync").await.len() == syncs {
        assert!(tokio::time::Instant::now() < deadline, "no sync requested");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_known_account_refuses_a_weaker_kdf_before_sending_the_hash() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    // Same KDF as cached: logging in again is fine.
    assert_eq!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::Done
    );

    // The account was created at Bitwarden's default of 600 000 PBKDF2 iterations; the server now
    // claims 5 000.
    let account = harness
        .dir
        .join("accounts")
        .join(USER_ID)
        .join("account.json");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&account).unwrap()).unwrap();
    record["kdf"]["iterations"] = json!(600_000);
    std::fs::write(&account, serde_json::to_vec(&record).unwrap()).unwrap();
    fake.server.reset().await;
    fake.mount_login().await;

    let error = vault.login(fake.request(), None, None).await.unwrap_err();
    assert!(matches!(error, Error::KdfDowngrade), "{error:?}");
    assert!(fake.requests_to("/identity/connect/token").await.is_empty());
    assert_eq!(
        fake.requests_to("/identity/accounts/prelogin").await.len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_in_flight_during_log_out_does_not_store_its_rotated_token() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-rotated"
                }))
                .set_delay(Duration::from_millis(500)),
        )
        .mount(&fake.server)
        .await;

    let sync = vault.sync();
    let log_out = async {
        let deadline = tokio::time::Instant::now() + WAIT;
        while fake.requests_to("/identity/connect/token").await.is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "no refresh started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        vault.logout().await
    };
    let (_, logged_out) = tokio::join!(sync, log_out);
    logged_out.unwrap();

    assert!(
        harness.memory.as_ref().unwrap().keys().is_empty(),
        "the rotated refresh token outlived the log out"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_attachment_upload_does_not_hold_back_a_sync() {
    let fake = Fake::start().await;
    let item = fake.login("c1", "Item", "pw");
    let harness = logged_in(&fake, vec![item.clone()]).await;
    let vault = &harness.vault;
    // Vaultwarden saves the attachment row before its data arrives, so the sync below sees it.
    let mut with_row = item;
    with_row.attachments = Some(vec![vk_api::models::Attachment {
        id: "att1".into(),
        size: Some("15".into()),
        ..vk_api::models::Attachment::default()
    }]);
    fake.server.reset().await;
    fake.mount_sync(vec![with_row]).await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/v2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachmentId": "att1",
            "url": "/ciphers/c1/attachment/att1",
            "fileUploadType": 0,
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/att1"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&fake.server)
        .await;
    let source = harness.dir.join("report.txt");
    std::fs::write(&source, b"attachment body").unwrap();

    let id = vk_vault::model::ItemId(Arc::from("c1"));
    let upload = vault.upload_attachment(&id, source);
    let sync_meanwhile = async {
        let deadline = tokio::time::Instant::now() + WAIT;
        while fake
            .requests_to("/api/ciphers/c1/attachment/v2")
            .await
            .is_empty()
        {
            assert!(tokio::time::Instant::now() < deadline, "no upload started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::timeout(Duration::from_secs(1), vault.sync()).await
    };
    let (uploaded, synced) = tokio::join!(upload, sync_meanwhile);
    synced.expect("the sync waited for the upload").unwrap();
    assert_eq!(&*uploaded.unwrap().file_name, "report.txt");
    let views = vault.attachments(&id).unwrap();
    assert_eq!(
        views.len(),
        1,
        "the synced row and the upload are one attachment"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_401_from_a_proxy_during_refresh_keeps_the_refresh_token() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    fake.mount_status("POST", "/identity/connect/token", 401)
        .await;

    let error = vault.sync().await.unwrap_err();
    assert!(
        matches!(error, Error::Api(vk_api::Error::Server { status: 401, .. })),
        "{error:?}"
    );
    assert!(
        harness
            .secrets
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .is_some(),
        "only invalid_grant from the identity server deletes the refresh token"
    );
}

/// The ordinary endpoints answer within `read`; a sync or an attachment upload may take far
/// longer and must not be cut off by it.
#[tokio::test(flavor = "multi_thread")]
async fn syncs_and_uploads_outlast_the_read_timeout_of_ordinary_requests() {
    let fake = Fake::start().await;
    let mut timings = timings();
    timings.http.read = Duration::from_millis(300);
    timings.http.request = Duration::from_millis(300);
    let harness = harness_with(timings, None);
    fake.mount_sync(vec![fake.login("c1", "Item", "pw")]).await;
    harness
        .vault
        .login(fake.request(), None, None)
        .await
        .unwrap();
    let vault = &harness.vault;

    fake.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fake.sync_body(vec![fake.login("c1", "Item", "pw")]))
                .set_delay(Duration::from_secs(1)),
        )
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/v2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachmentId": "att1",
            "url": "/ciphers/c1/attachment/att1",
            "fileUploadType": 0,
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/att1"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(1)))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(
                    json!({ "id": "f1", "name": "x", "revisionDate": "2026-11-08T17:00:59.321Z" }),
                )
                .set_delay(Duration::from_secs(1)),
        )
        .mount(&fake.server)
        .await;

    vault.sync().await.unwrap();
    let source = harness.dir.join("slow.bin");
    std::fs::write(&source, b"attachment body").unwrap();
    let id = vk_vault::model::ItemId(Arc::from("c1"));
    vault.upload_attachment(&id, source).await.unwrap();
    // The short limits are in force for everything else.
    let error = vault.create_folder("Slow").await.unwrap_err();
    assert!(error.is_offline(), "{error:?}");
}

/// A keychain whose writes take a second once `slow` is set, like one waiting on an access prompt.
#[derive(Default)]
struct SlowSets {
    memory: MemorySecretStore,
    slow: std::sync::atomic::AtomicBool,
}

impl SecretStore for SlowSets {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        self.memory.get(key)
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        if self.slow.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
        }
        self.memory.set(key, secret)
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        self.memory.delete(key)
    }

    fn delete_all_for(&self, prefix: &str) -> Result<usize, SecretStoreError> {
        self.memory.delete_all_for(prefix)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_keychain_write_during_refresh_does_not_block_state_reads() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![]).await;
    let secrets = Arc::new(SlowSets::default());
    let harness = harness_with(timings(), Some(secrets.clone() as Arc<dyn SecretStore>));
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-rotated"
        })))
        .mount(&fake.server)
        .await;
    secrets
        .slow
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // The keychain write blocks its thread, so the sync runs on its own; on this task's thread
    // the read would only run after it.
    let runtime = tokio::runtime::Handle::current();
    let (waited, state) = tokio::task::block_in_place(|| {
        std::thread::scope(|scope| {
            let sync = scope.spawn(|| runtime.block_on(vault.sync()));
            runtime.block_on(async {
                let deadline = tokio::time::Instant::now() + WAIT;
                while fake.requests_to("/identity/connect/token").await.is_empty() {
                    assert!(tokio::time::Instant::now() < deadline, "no refresh started");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                // The refresh is now inside its one-second keychain write.
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
            let started = std::time::Instant::now();
            let state = vault.state();
            let waited = started.elapsed();
            sync.join().unwrap().unwrap_err();
            (waited, state)
        })
    });

    assert!(
        waited < Duration::from_millis(300),
        "a state read waited {waited:?} for the keychain"
    );
    assert!(matches!(state, SessionState::Unlocked { .. }), "{state:?}");
    assert_eq!(
        secrets
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-rotated"[..])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_the_hub_rejects_is_refreshed_before_reconnecting() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![]).await;
    Mock::given(method("GET"))
        .and(path("/notifications/hub"))
        .and(wiremock::matchers::header(
            "authorization",
            format!("Bearer {ACCESS_1}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(401))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600
        })))
        .mount(&fake.server)
        .await;
    let mut timings = timings();
    timings.notifications.backoff_initial = Duration::from_millis(50);
    timings.notifications.backoff_max = Duration::from_millis(200);
    let harness = harness_with(timings, None);
    harness
        .vault
        .login(fake.request(), None, None)
        .await
        .unwrap();

    let bearer = |request: &Request| {
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let seen: Vec<_> = fake
            .requests_to("/notifications/hub")
            .await
            .iter()
            .filter_map(bearer)
            .collect();
        if seen.contains(&format!("Bearer {ACCESS_2}")) {
            assert_eq!(seen[0], format!("Bearer {ACCESS_1}"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the hub only ever saw {seen:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        fake.requests_to("/identity/connect/token").await.len(),
        2,
        "the password login and one refresh"
    );
}
