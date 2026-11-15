//! Wiremock Vaultwarden stand-in and a `Vault` over a temporary data dir, shared by the vault
//! integration tests. Each test binary compiles this module separately, so the set of helpers it
//! uses differs per binary.

#![allow(dead_code)]
#![allow(clippy::unwrap_used)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use vk_api::{
    DeviceInfo,
    models::{Cipher, Login, Profile, SshKey, SyncResponse},
};
use vk_crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use vk_vault::{
    MemorySecretStore, SecretStore, Timings, Vault, VaultConfig, VaultService,
    model::{Filter, LoginRequest, LoginStep},
};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};
use zeroize::Zeroizing;

pub const USER_ID: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
pub const EMAIL: &str = "user@example.com";
pub const PASSWORD: &str = "correct horse battery staple";
/// JWT-shaped tokens whose payload is `{"sub": USER_ID, "exp": 4102444800, "n": 1|2}`; the API
/// client reads `sub` as `encryptedFor` on writes.
pub const ACCESS_1: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzYmVmMDVkNi05MDcwLTQ4YjQtYjMyMC1hNWQ0MjVlZWM5ZmQiLCJleHAiOjQxMDI0NDQ4MDAsIm4iOjF9.sig1";
pub const ACCESS_2: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzYmVmMDVkNi05MDcwLTQ4YjQtYjMyMC1hNWQ0MjVlZWM5ZmQiLCJleHAiOjQxMDI0NDQ4MDAsIm4iOjJ9.sig2";
pub const WAIT: Duration = Duration::from_secs(5);

pub struct Fake {
    pub server: MockServer,
    pub user_key: SymmetricKey,
    pub protected_key: String,
    pub user_id: String,
}

impl Fake {
    pub async fn start() -> Self {
        Self::start_as(USER_ID).await
    }

    pub async fn start_as(user_id: &str) -> Self {
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
            user_id: user_id.to_owned(),
        };
        fake.mount_login().await;
        fake
    }

    pub fn url(&self) -> Url {
        Url::parse(&self.server.uri()).unwrap()
    }

    pub async fn mount_login(&self) {
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

    pub fn token_body(&self, access: &str, refresh: &str) -> Value {
        json!({
            "access_token": access,
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": refresh,
            "Key": self.protected_key,
        })
    }

    pub fn login(&self, id: &str, name: &str, password: &str) -> Cipher {
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

    pub fn ssh_key(&self, id: &str, private_key: Option<&str>) -> Cipher {
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

    pub fn sync_body(&self, ciphers: Vec<Cipher>) -> Value {
        serde_json::to_value(SyncResponse {
            profile: Profile {
                id: self.user_id.clone(),
                email: EMAIL.into(),
                name: None,
                key: Some(self.protected_key.clone()),
                private_key: None,
                organizations: Vec::new(),
            },
            folders: Vec::new(),
            collections: Vec::new(),
            ciphers,
            sends: Vec::new(),
        })
        .unwrap()
    }

    pub async fn mount_sync(&self, ciphers: Vec<Cipher>) {
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(self.sync_body(ciphers)))
            .mount(&self.server)
            .await;
    }

    pub async fn mount_status(&self, http_method: &str, route: &str, status: u16) {
        Mock::given(method(http_method))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status))
            .mount(&self.server)
            .await;
    }

    /// The server's origin answers 503 for everything the vault uses (a proxy in front of a dead
    /// backend), which counts as offline.
    pub async fn go_down(&self) {
        self.server.reset().await;
        self.mount_status("GET", "/api/sync", 503).await;
        self.mount_status("GET", "/alive", 503).await;
    }

    pub async fn come_back(&self, ciphers: Vec<Cipher>) {
        self.server.reset().await;
        self.mount_sync(ciphers).await;
        self.mount_status("GET", "/alive", 200).await;
    }

    pub async fn requests_to(&self, route: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|request| request.url.path() == route)
            .collect()
    }

    pub fn request(&self) -> LoginRequest {
        LoginRequest {
            server: self.url(),
            email: EMAIL.into(),
            password: Zeroizing::new(PASSWORD.into()),
        }
    }
}

pub fn timings() -> Timings {
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

pub struct Harness {
    pub vault: Vault,
    pub secrets: Arc<dyn SecretStore>,
    pub memory: Option<Arc<MemorySecretStore>>,
    pub dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Like [`harness_with`], but the caller chooses the data dir so a store it builds can share it.
pub fn harness_in(
    dir: PathBuf,
    timings: Timings,
    secrets: Option<Arc<dyn SecretStore>>,
) -> Harness {
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

pub fn harness_with(timings: Timings, secrets: Option<Arc<dyn SecretStore>>) -> Harness {
    let dir = std::env::temp_dir().join(format!("vk-mock-{}", Uuid::new_v4().simple()));
    harness_in(dir, timings, secrets)
}

pub fn harness() -> Harness {
    harness_with(timings(), None)
}

pub async fn logged_in(fake: &Fake, ciphers: Vec<Cipher>) -> Harness {
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

pub fn names(vault: &Vault) -> Vec<String> {
    vault
        .search("", &Filter::default())
        .unwrap()
        .iter()
        .map(|item| item.name.to_string())
        .collect()
}

pub async fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not met within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
