//! The browser save flow against a real `Vault` talking to a wiremock server.

#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unused_async_trait_impl,
    clippy::assert_is_empty
)]

use std::{
    collections::HashSet,
    future::{Ready, ready},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use vaultkeeper::daemon::browser::{
    dedupe::SaveDedupe,
    dispatch::Candidate,
    save::{self, NeverSaveStore, Outcome, SaveError, SaveManager, SaveSettings, Skipped},
};
use vk_api::{
    DeviceInfo,
    models::{Cipher, Login, LoginUri, Profile, SyncResponse},
};
use vk_crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use vk_ipc::{BrowserPrompt, BrowserReply, browser::protocol::SaveKind};
use vk_vault::{
    MemorySecretStore, Timings, Vault, VaultConfig, VaultService,
    model::{CopyField, ItemData, ItemId, LoginRequest},
    uri_match::DefaultMatch,
};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{body_string_contains, method, path, path_regex},
};
use zeroize::Zeroizing;

const USER_ID: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "correct horse battery staple";
const ACCESS: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzYmVmMDVkNi05MDcwLTQ4YjQtYjMyMC1hNWQ0MjVlZWM5ZmQiLCJleHAiOjQxMDI0NDQ4MDAsIm4iOjF9.sig1";

struct Echo;

impl Respond for Echo {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut body: Value = request.body_json().unwrap();
        let last = request.url.path().rsplit('/').next().unwrap().to_owned();
        body["id"] = if last == "ciphers" {
            Uuid::new_v4().to_string().into()
        } else {
            last.into()
        };
        body["revisionDate"] = "2026-11-11T10:00:00.000Z".into();
        body["edit"] = true.into();
        body["viewPassword"] = true.into();
        ResponseTemplate::new(200).set_body_json(body)
    }
}

struct Item {
    id: &'static str,
    username: &'static str,
    password: &'static str,
    uri: &'static str,
    edit: bool,
}

struct Env {
    server: MockServer,
    user_key: SymmetricKey,
    protected_key: String,
    vault: Vault,
    _dir: tempfile::TempDir,
}

impl Env {
    async fn start(items: &[Item]) -> Self {
        let kdf = Kdf::from_wire(0, 5000, None, None).unwrap();
        let master = MasterKey::derive(PASSWORD.as_bytes(), EMAIL, &kdf).unwrap();
        let user_key = SymmetricKey::generate();
        let protected_key = EncString::encrypt(&user_key.to_bytes(), &master.stretch())
            .unwrap()
            .to_string();
        let dir = tempfile::tempdir().unwrap();
        let mut timings = Timings {
            // A background sync would replace the vault with the canned list mid-test.
            sync_debounce: Duration::from_secs(600),
            ..Timings::default()
        };
        timings.notifications.backoff_initial = Duration::from_secs(30);
        let mut config = VaultConfig::new(
            dir.path().to_owned(),
            DeviceInfo {
                identifier: Uuid::new_v4(),
                name: "test".into(),
                device_type: 7,
            },
            tokio::runtime::Handle::current(),
        );
        config.timings = timings;
        let vault = Vault::open(config, Arc::new(MemorySecretStore::new())).unwrap();
        let env = Self {
            server: MockServer::builder().start().await,
            user_key,
            protected_key,
            vault,
            _dir: dir,
        };
        env.mount_login(items).await;
        env.vault
            .login(
                LoginRequest {
                    server: Url::parse(&env.server.uri()).unwrap(),
                    email: EMAIL.into(),
                    password: Zeroizing::new(PASSWORD.into()),
                },
                None,
                None,
            )
            .await
            .unwrap();
        env
    }

    fn enc(key: &SymmetricKey, plain: &str) -> Option<String> {
        Some(
            EncString::encrypt(plain.as_bytes(), key)
                .unwrap()
                .to_string(),
        )
    }

    fn cipher(&self, item: &Item) -> Cipher {
        let key = SymmetricKey::generate();
        Cipher {
            id: item.id.into(),
            r#type: 1,
            name: Self::enc(&key, item.id),
            key: Some(
                EncString::encrypt(&key.to_bytes(), &self.user_key)
                    .unwrap()
                    .to_string(),
            ),
            login: Some(Login {
                username: Self::enc(&key, item.username),
                password: Self::enc(&key, item.password),
                uris: Some(vec![LoginUri {
                    uri: Self::enc(&key, item.uri),
                    ..LoginUri::default()
                }]),
                ..Login::default()
            }),
            edit: item.edit,
            view_password: true,
            revision_date: "2026-11-08T17:00:59.321Z".into(),
            ..Cipher::default()
        }
    }

    async fn mount_login(&self, items: &[Item]) {
        let token = json!({
            "access_token": ACCESS, "expires_in": 3600, "token_type": "Bearer",
            "refresh_token": "refresh-1", "Key": self.protected_key,
        });
        let sync = serde_json::to_value(SyncResponse {
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
            ciphers: items.iter().map(|item| self.cipher(item)).collect(),
            sends: Vec::new(),
        })
        .unwrap();
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
            .respond_with(ResponseTemplate::new(200).set_body_json(&token))
            .mount(&self.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token))
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync))
            .mount(&self.server)
            .await;
    }

    async fn mount_writes(&self, response: impl Respond + 'static) {
        Mock::given(path_regex(r"^/api/ciphers(/[^/]+)?$"))
            .respond_with(response)
            .mount(&self.server)
            .await;
    }

    async fn writes(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| {
                matches!(request.method.as_str(), "POST" | "PUT")
                    && request.url.path().starts_with("/api/ciphers")
            })
            .count()
    }

    fn password_of(&self, id: &str) -> String {
        self.vault
            .reveal(&ItemId(id.into()), CopyField::Password)
            .unwrap()
            .to_string()
    }

    fn login_of(&self, id: &ItemId) -> (String, String, Vec<String>, String) {
        let draft = self.vault.draft(id).unwrap();
        let ItemData::Login {
            username,
            password,
            uris,
            ..
        } = draft.data
        else {
            panic!("not a login");
        };
        (draft.name, username, uris, password.to_string())
    }
}

#[derive(Default)]
struct MemoryNeverSave(Mutex<HashSet<String>>);

impl NeverSaveStore for MemoryNeverSave {
    async fn contains(&self, domain: &str) -> anyhow::Result<bool> {
        Ok(self.0.lock().unwrap().contains(domain))
    }

    async fn add(&self, domain: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().insert(domain.to_owned());
        Ok(())
    }
}

type Log = Arc<Mutex<Vec<BrowserPrompt>>>;

fn answer(
    log: &Log,
    reply: BrowserReply,
) -> impl FnMut(BrowserPrompt) -> Ready<BrowserReply> + Send + use<> {
    let log = Arc::clone(log);
    move |prompt| {
        log.lock().unwrap().push(prompt);
        ready(reply.clone())
    }
}

fn save_reply(target: Option<&str>) -> BrowserReply {
    BrowserReply::Save {
        target: target.map(Arc::from),
    }
}

fn candidate(origin: &str, username: &str, password: &str) -> Candidate {
    Candidate {
        browser: "Firefox".into(),
        origin: origin.into(),
        path: "/login".into(),
        username: username.into(),
        password: Zeroizing::new(password.into()),
        kind: SaveKind::Login,
    }
}

fn settings() -> SaveSettings {
    SaveSettings::new(true, DefaultMatch::Domain)
}

const ALICE: Item = Item {
    id: "a",
    username: "Alice",
    password: "old",
    uri: "https://example.com",
    edit: true,
};

async fn run(
    env: &Env,
    candidate: Candidate,
    dedupe: &mut SaveDedupe,
    never: &MemoryNeverSave,
    prompt: impl FnOnce(BrowserPrompt) -> Ready<BrowserReply> + Send,
) -> Result<Outcome, SaveError> {
    save::handle(&env.vault, candidate, &settings(), never, dedupe, prompt).await
}

#[tokio::test(flavor = "multi_thread")]
async fn equal_password_is_not_offered() {
    let env = Env::start(&[ALICE]).await;
    let log = Log::default();
    let outcome = run(
        &env,
        candidate("https://example.com", "alice", "old"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&log, BrowserReply::Dismissed),
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Skipped(Skipped::NothingToSave));
    assert!(log.lock().unwrap().is_empty());
    assert_eq!(env.writes().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn different_password_updates_the_matching_login() {
    let env = Env::start(&[ALICE]).await;
    env.mount_writes(Echo).await;
    let log = Log::default();
    let outcome = run(
        &env,
        candidate("https://example.com", "alice", "new"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&log, save_reply(Some("a"))),
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Updated(ItemId("a".into())));
    let prompts = log.lock().unwrap();
    let [
        BrowserPrompt::Save {
            host,
            username,
            update_of: Some(item),
            choices,
            ..
        },
    ] = prompts.as_slice()
    else {
        panic!("expected one update prompt: {prompts:?}");
    };
    assert_eq!((host.as_str(), username.as_str()), ("example.com", "alice"));
    assert_eq!(&*item.id, "a");
    assert!(choices.is_empty());
    assert_eq!(env.password_of("a"), "new");
}

#[tokio::test(flavor = "multi_thread")]
async fn new_username_creates_a_login_for_the_origin() {
    let env = Env::start(&[ALICE]).await;
    env.mount_writes(Echo).await;
    let log = Log::default();
    let outcome = run(
        &env,
        candidate("https://www.example.com", "bob", "pw2"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&log, save_reply(None)),
    )
    .await
    .unwrap();
    let Outcome::Created(id) = outcome else {
        panic!("expected a created item: {outcome:?}");
    };
    assert!(matches!(
        log.lock().unwrap().as_slice(),
        [BrowserPrompt::Save {
            update_of: None,
            ..
        }]
    ));
    assert_eq!(
        env.login_of(&id),
        (
            "example.com".to_owned(),
            "bob".to_owned(),
            vec!["https://www.example.com".to_owned()],
            "pw2".to_owned()
        )
    );
    assert_eq!(env.password_of("a"), "old");
}

#[tokio::test(flavor = "multi_thread")]
async fn dismissed_and_timed_out_prompts_write_nothing() {
    let env = Env::start(&[ALICE]).await;
    let log = Log::default();
    let outcome = run(
        &env,
        candidate("https://example.com", "alice", "new"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&log, BrowserReply::Dismissed),
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Dismissed);

    let mut quick = settings();
    quick.prompt_timeout = Duration::from_millis(50);
    let outcome = save::handle(
        &env.vault,
        candidate("https://example.com", "alice", "other"),
        &quick,
        &MemoryNeverSave::default(),
        &mut SaveDedupe::default(),
        |_| std::future::pending::<BrowserReply>(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Dismissed);
    assert_eq!(env.writes().await, 0);
    assert_eq!(env.password_of("a"), "old");
}

#[tokio::test(flavor = "multi_thread")]
async fn never_for_site_silences_the_registrable_domain() {
    let env = Env::start(&[ALICE]).await;
    let (log, never, mut dedupe) = (
        Log::default(),
        MemoryNeverSave::default(),
        SaveDedupe::default(),
    );
    let first = run(
        &env,
        candidate("https://example.com", "alice", "new"),
        &mut dedupe,
        &never,
        answer(&log, BrowserReply::NeverForSite),
    )
    .await
    .unwrap();
    assert_eq!(first, Outcome::NeverSave);
    let later = run(
        &env,
        candidate("https://login.example.com", "carol", "another"),
        &mut dedupe,
        &never,
        answer(&log, BrowserReply::Dismissed),
    )
    .await
    .unwrap();
    assert_eq!(later, Outcome::Skipped(Skipped::NeverSave));
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_candidate_is_ignored() {
    let env = Env::start(&[ALICE]).await;
    let (log, never, mut dedupe) = (
        Log::default(),
        MemoryNeverSave::default(),
        SaveDedupe::default(),
    );
    for expected in [Outcome::Dismissed, Outcome::Skipped(Skipped::Duplicate)] {
        let outcome = run(
            &env,
            candidate("https://example.com", "alice", "new"),
            &mut dedupe,
            &never,
            answer(&log, BrowserReply::Dismissed),
        )
        .await
        .unwrap();
        assert_eq!(outcome, expected);
    }
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn read_only_logins_are_never_update_targets() {
    let env = Env::start(&[Item {
        edit: false,
        ..ALICE
    }])
    .await;
    let log = Log::default();
    let outcome = run(
        &env,
        candidate("https://example.com", "alice", "new"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&log, save_reply(Some("a"))),
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Skipped(Skipped::NothingToSave));
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_and_insecure_pages_stop_before_any_prompt() {
    let env = Env::start(&[ALICE]).await;
    let log = Log::default();
    let mut off = settings();
    off.prompts_enabled = false;
    let disabled = save::handle(
        &env.vault,
        candidate("https://example.com", "alice", "new"),
        &off,
        &MemoryNeverSave::default(),
        &mut SaveDedupe::default(),
        answer(&log, BrowserReply::Dismissed),
    )
    .await
    .unwrap();
    assert_eq!(disabled, Outcome::Skipped(Skipped::Disabled));
    let insecure = run(
        &env,
        candidate("http://example.com", "alice", "new"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&log, BrowserReply::Dismissed),
    )
    .await
    .unwrap();
    assert_eq!(insecure, Outcome::Skipped(Skipped::InvalidPage));
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_candidates_wait_for_the_unlock() {
    let env = Env::start(&[ALICE]).await;
    env.mount_writes(Echo).await;
    let (log, never, mut manager) = (
        Log::default(),
        MemoryNeverSave::default(),
        SaveManager::default(),
    );
    env.vault.lock();
    let queued = manager
        .submit(
            &env.vault,
            candidate("https://example.com", "alice", "new"),
            &settings(),
            &never,
            answer(&log, BrowserReply::Dismissed),
        )
        .await
        .unwrap();
    assert_eq!(queued, Outcome::Queued);
    assert!(manager.next_expiry().is_some());
    assert!(log.lock().unwrap().is_empty());

    env.vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    let results = manager
        .on_unlocked(
            &env.vault,
            &settings(),
            &never,
            answer(&log, save_reply(Some("a"))),
        )
        .await;
    assert!(matches!(
        results.as_slice(),
        [Ok(Outcome::Updated(id))] if &*id.0 == "a"
    ));
    assert_eq!(env.password_of("a"), "new");
    assert!(manager.next_expiry().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_wipes_queued_candidates_and_the_queue_is_bounded() {
    let env = Env::start(&[ALICE]).await;
    let (log, never, mut manager) = (
        Log::default(),
        MemoryNeverSave::default(),
        SaveManager::default(),
    );
    env.vault.lock();
    let mut outcomes = Vec::new();
    for n in 0..4 {
        outcomes.push(
            manager
                .submit(
                    &env.vault,
                    candidate("https://example.com", "alice", &format!("pw{n}")),
                    &settings(),
                    &never,
                    answer(&log, BrowserReply::Dismissed),
                )
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        outcomes,
        [
            Outcome::Queued,
            Outcome::Queued,
            Outcome::Queued,
            Outcome::Skipped(Skipped::QueueFull)
        ]
    );
    manager.clear();
    env.vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    let results = manager
        .on_unlocked(
            &env.vault,
            &settings(),
            &never,
            answer(&log, BrowserReply::Dismissed),
        )
        .await;
    assert!(results.is_empty());
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_change_during_the_prompt_drops_the_save() {
    let env = Env::start(&[ALICE]).await;
    env.mount_writes(Echo).await;
    let outcome = run(
        &env,
        candidate("https://example.com", "alice", "new"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        |_| {
            env.vault.lock();
            ready(save_reply(Some("a")))
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Skipped(Skipped::Stale));
    assert_eq!(env.writes().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_target_the_prompt_did_not_offer_is_refused() {
    let env = Env::start(&[ALICE]).await;
    env.mount_writes(Echo).await;
    for reply in [save_reply(Some("elsewhere")), save_reply(None)] {
        let outcome = run(
            &env,
            candidate("https://example.com", "alice", &format!("n{reply:?}")),
            &mut SaveDedupe::default(),
            &MemoryNeverSave::default(),
            answer(&Log::default(), reply),
        )
        .await
        .unwrap();
        assert_eq!(outcome, Outcome::Skipped(Skipped::Stale));
    }
    assert_eq!(env.writes().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_without_username_offers_the_choices() {
    let other = Item {
        id: "b",
        username: "bob",
        ..ALICE
    };
    let env = Env::start(&[ALICE, other]).await;
    env.mount_writes(Echo).await;
    let log = Log::default();
    let mut change = candidate("https://example.com", "", "new");
    change.kind = SaveKind::Change;
    let outcome = run(
        &env,
        change,
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&log, save_reply(Some("b"))),
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Updated(ItemId("b".into())));
    assert!(matches!(
        log.lock().unwrap().as_slice(),
        [BrowserPrompt::Save { update_of: None, choices, .. }] if choices.len() == 2
    ));
    assert_eq!(env.password_of("b"), "new");
    assert_eq!(env.password_of("a"), "old");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_write_is_reported_once_and_never_retried() {
    let env = Env::start(&[ALICE]).await;
    env.mount_writes(ResponseTemplate::new(400)).await;
    let result = run(
        &env,
        candidate("https://example.com", "alice", "new"),
        &mut SaveDedupe::default(),
        &MemoryNeverSave::default(),
        answer(&Log::default(), save_reply(Some("a"))),
    )
    .await;
    assert!(matches!(result, Err(SaveError::Write(reason)) if !reason.is_empty()));
    assert_eq!(env.writes().await, 1);
    assert_eq!(env.password_of("a"), "old");
}
