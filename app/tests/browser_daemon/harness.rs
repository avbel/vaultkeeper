//! A real `Daemon` on a wiremock Vaultwarden, with the test process playing the `--ui` process
//! (answers `BrowserPrompt`s) and the browser host (frames on `browser.sock`).

use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    sync::oneshot,
};
use url::Url;
use uuid::Uuid;
use vaultkeeper::{
    daemon::{Daemon, DaemonConfig, Peers, browser::ids, target::FrontmostApp},
    os::{
        ClipboardKeeper, DaemonBiometrics,
        layout::{BROWSER_PAIRINGS_FILE, BROWSER_SOCKET, SETTINGS_FILE},
        settings_file::SettingsFile,
    },
    settings::Settings,
    ui_process::answer,
};
use vk_api::models::{Cipher, Login, LoginUri, Profile, SyncResponse};
use vk_crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use vk_ipc::{
    BrowserPrompt, BrowserReply, ClipboardHost, EventStream, RemoteVault, TouchIdBackend,
    TouchIdFailure, TypingTarget, UiCommand, UiEvent,
};
use vk_vault::{
    MemorySecretStore, Timings, VaultService,
    model::{CopyField, ItemId, LoginRequest},
};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{body_string_contains, method, path, path_regex},
};
use zeroize::Zeroizing;

// Generous: the machine may be compiling something else.
pub const WAIT: Duration = Duration::from_secs(15);
pub const QUIET: Duration = Duration::from_millis(600);
pub const EMAIL: &str = "user@example.com";
pub const PASSWORD: &str = "correct horse battery staple";
const USER_ID: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
const ACCESS: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIzYmVmMDVkNi05MDcwLTQ4YjQtYjMyMC1hNWQ0MjVlZWM5ZmQiLCJleHAiOjQxMDI0NDQ4MDAsIm4iOjF9.sig1";
const DOMAIN: &[u8] = b"vaultkeeper-browser-v1\0";

/// Runs one test on its own runtime, after the process environment is set: `set_var` must not
/// race a runtime thread that reads the environment.
pub fn run<F: Future<Output = ()>>(test: F) {
    init_env();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

/// The browser activity log would otherwise land in the real `~/Library/Logs/vaultkeeper`.
fn init_env() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let logs = std::env::temp_dir().join("vk-browser-daemon-test-logs");
        // SAFETY: the first thing every test does, before any runtime thread exists; other test
        // threads are parked on this `OnceLock` or have not reached an environment read yet.
        unsafe { std::env::set_var("VAULTKEEPER_TEST_DATA_DIR", logs) };
    });
}

pub async fn eventually(mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not reached in time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Under /tmp: macOS caps socket paths at 104 bytes and `$TMPDIR` is long.
pub struct DataDir(PathBuf);

impl DataDir {
    pub fn new() -> Self {
        let dir = PathBuf::from(format!(
            "/tmp/vk-bd-{}",
            &Uuid::new_v4().simple().to_string()[..10]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn socket(&self) -> PathBuf {
        self.0.join(BROWSER_SOCKET)
    }

    pub fn pairings(&self) -> PathBuf {
        self.0.join(BROWSER_PAIRINGS_FILE)
    }

    /// Where the daemon keeps the browsers' manifests under `vw-it`.
    pub fn app_support(&self) -> PathBuf {
        self.0.join("app-support")
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn write_settings(dir: &DataDir, settings: &Settings) {
    SettingsFile::write(&dir.path().join(SETTINGS_FILE), settings).unwrap();
}

/// The single-match shortcut is off here so the picker tests keep their prompts; one test turns
/// it on.
pub fn integration_on() -> Settings {
    Settings {
        browser_integration: true,
        browser_fill_single: false,
        ..Settings::default()
    }
}

#[derive(Default)]
pub struct FakeClipboard {
    content: Mutex<Option<String>>,
}

impl FakeClipboard {
    pub fn content(&self) -> Option<String> {
        self.content.lock().unwrap().clone()
    }
}

impl ClipboardHost for FakeClipboard {
    fn copy(&self, text: &str, _clear_after: Option<Duration>) -> Result<(), String> {
        *self.content.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }

    fn clear_if_ours(&self) {
        *self.content.lock().unwrap() = None;
    }
}

impl ClipboardKeeper for FakeClipboard {
    fn recheck(&self) {}
}

/// Touch ID that answers as scripted and counts its checks; nothing is enrolled.
pub struct ScriptedTouchId {
    pub available: std::sync::atomic::AtomicBool,
    pub present: std::sync::atomic::AtomicBool,
    pub checks: std::sync::atomic::AtomicUsize,
}

impl Default for ScriptedTouchId {
    fn default() -> Self {
        Self {
            available: true.into(),
            present: true.into(),
            checks: 0.into(),
        }
    }
}

impl TouchIdBackend for ScriptedTouchId {
    fn enroll(&self, _account_id: &str, _user_key: &[u8]) -> Result<(), TouchIdFailure> {
        Err(TouchIdFailure::Unavailable)
    }

    fn unlock(&self, _account_id: &str) -> Result<Zeroizing<Vec<u8>>, TouchIdFailure> {
        Err(TouchIdFailure::Unavailable)
    }
}

impl DaemonBiometrics for ScriptedTouchId {
    fn authenticate(&self, _reason: &str) -> Result<(), TouchIdFailure> {
        use std::sync::atomic::Ordering;
        self.checks.fetch_add(1, Ordering::SeqCst);
        if self.present.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(TouchIdFailure::Cancelled)
        }
    }

    fn is_available(&self) -> bool {
        self.available.load(std::sync::atomic::Ordering::SeqCst)
    }
}

struct NothingInFront;

impl FrontmostApp for NothingInFront {
    fn frontmost(&self) -> Option<TypingTarget> {
        None
    }
}

pub struct Item {
    pub id: &'static str,
    pub username: &'static str,
    pub password: &'static str,
    pub uri: &'static str,
}

pub const ALICE: &str = "gh-alice";
pub const BOB: &str = "gh-bob";
pub const BANK: &str = "bank";

/// Two logins on github.com's registrable domain and one on an unrelated site.
pub fn items() -> Vec<Item> {
    vec![
        Item {
            id: ALICE,
            username: "alice",
            password: "alice-pw",
            uri: "https://github.com/login",
        },
        Item {
            id: BOB,
            username: "bob",
            password: "bob-pw",
            uri: "https://gist.github.com/",
        },
        Item {
            id: BANK,
            username: "carol",
            password: "carol-pw",
            uri: "https://bank.example.org/",
        },
    ]
}

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

pub struct Fake {
    pub server: MockServer,
    user_key: SymmetricKey,
    protected_key: String,
}

impl Fake {
    async fn start(items: &[Item]) -> Self {
        let kdf = Kdf::from_wire(0, 5000, None, None).unwrap();
        let master = MasterKey::derive(PASSWORD.as_bytes(), EMAIL, &kdf).unwrap();
        let user_key = SymmetricKey::generate();
        let protected_key = EncString::encrypt(&user_key.to_bytes(), &master.stretch())
            .unwrap()
            .to_string();
        let fake = Self {
            server: MockServer::builder().start().await,
            user_key,
            protected_key,
        };
        fake.mount(items).await;
        fake
    }

    fn url(&self) -> Url {
        Url::parse(&self.server.uri()).unwrap()
    }

    /// Decrypts an EncString of a cipher body the daemon wrote, under that cipher's item key.
    pub fn decrypt(&self, cipher: &Value, field: &Value) -> String {
        let wrapped: EncString = cipher["key"].as_str().unwrap().parse().unwrap();
        let key = SymmetricKey::from_bytes(&wrapped.decrypt(&self.user_key).unwrap()).unwrap();
        let field: EncString = field.as_str().unwrap().parse().unwrap();
        String::from_utf8(field.decrypt(&key).unwrap().to_vec()).unwrap()
    }

    #[allow(clippy::unnecessary_wraps)]
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
            edit: true,
            view_password: true,
            revision_date: "2026-11-08T17:00:59.321Z".into(),
            ..Cipher::default()
        }
    }

    async fn mount(&self, items: &[Item]) {
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
        for grant in ["grant_type=password", "grant_type=refresh_token"] {
            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .and(body_string_contains(grant))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token))
                .mount(&self.server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync))
            .mount(&self.server)
            .await;
        Mock::given(path_regex(r"^/api/ciphers(/[^/]+)?$"))
            .respond_with(Echo)
            .mount(&self.server)
            .await;
    }

    /// The bodies of the cipher creates and updates the daemon sent.
    pub async fn written(&self) -> Vec<Value> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| {
                matches!(request.method.as_str(), "POST" | "PUT")
                    && request.url.path().starts_with("/api/ciphers")
            })
            .map(|request| request.body_json().unwrap())
            .collect()
    }

    pub async fn writes(&self) -> usize {
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
}

/// A prompt the daemon sent to the UI; dropping it counts as dismissed.
pub struct Asked {
    pub prompt: BrowserPrompt,
    reply: oneshot::Sender<BrowserReply>,
}

impl Asked {
    pub fn answer(self, reply: BrowserReply) {
        let _ = self.reply.send(reply);
    }

    pub fn fill_with(self, item: &str, confirmed_other_site: bool) {
        self.answer(BrowserReply::Fill {
            item_id: item.into(),
            confirmed_other_site,
        });
    }
}

pub struct Ui {
    pub remote: RemoteVault,
    events: EventStream,
    pub commands: Vec<UiCommand>,
}

impl Ui {
    fn take(&mut self, event: UiEvent) -> Option<Asked> {
        if let Some(notice) = answer(&event) {
            let _ = self.remote.notify(notice);
        }
        match event {
            UiEvent::BrowserPrompt(event) => Some(Asked {
                prompt: event.prompt,
                reply: event.reply,
            }),
            UiEvent::Command { command, .. } => {
                self.commands.push(command);
                None
            }
            _ => None,
        }
    }

    /// The next browser prompt, skipping other events.
    pub async fn prompt(&mut self) -> Asked {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let event = tokio::time::timeout_at(deadline, self.events.next())
                .await
                .expect("a browser prompt in time")
                .expect("the daemon is still there");
            if let Some(asked) = self.take(event) {
                return asked;
            }
        }
    }

    /// Panics when a browser prompt shows up within `QUIET`.
    pub async fn no_prompt(&mut self) {
        let deadline = tokio::time::Instant::now() + QUIET;
        while let Ok(Some(event)) = tokio::time::timeout_at(deadline, self.events.next()).await {
            if let Some(asked) = self.take(event) {
                panic!("unexpected prompt: {:?}", asked.prompt);
            }
        }
    }

    /// Waits for a command the daemon sent, skipping the others.
    pub async fn command(&mut self, wanted: impl Fn(&UiCommand) -> bool) -> UiCommand {
        if let Some(found) = self.commands.iter().position(&wanted) {
            return self.commands.remove(found);
        }
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let event = tokio::time::timeout_at(deadline, self.events.next())
                .await
                .expect("the command in time")
                .expect("the daemon is still there");
            if let Some(asked) = self.take(event) {
                panic!("unexpected prompt: {:?}", asked.prompt);
            }
            if let Some(found) = self.commands.iter().position(&wanted) {
                return self.commands.remove(found);
            }
        }
    }
}

pub struct Rig {
    pub daemon: Arc<Daemon>,
    pub dir: DataDir,
    pub fake: Fake,
    pub clipboard: Arc<FakeClipboard>,
    pub touch_id: Arc<ScriptedTouchId>,
    pub ui: Ui,
}

impl Rig {
    /// Integration on, the standard items, logged in and unlocked, the UI connected.
    pub async fn start() -> Self {
        Self::start_with(&integration_on(), &items()).await
    }

    pub async fn start_with(settings: &Settings, items: &[Item]) -> Self {
        let dir = DataDir::new();
        write_settings(&dir, settings);
        let clipboard = Arc::new(FakeClipboard::default());
        let mut timings = Timings {
            // A background sync would replace the vault with the canned list mid-test.
            sync_debounce: Duration::from_secs(600),
            ..Timings::default()
        };
        timings.notifications.backoff_initial = Duration::from_secs(30);
        let mut config =
            DaemonConfig::new(dir.path().to_owned(), Arc::new(MemorySecretStore::new()));
        config.peers = Peers::AnyOfThisUser;
        config.clipboard = Arc::clone(&clipboard) as Arc<dyn ClipboardKeeper>;
        config.frontmost = Arc::new(NothingInFront);
        let touch_id = Arc::new(ScriptedTouchId::default());
        config.touch_id = Arc::clone(&touch_id) as Arc<dyn DaemonBiometrics>;
        config.timings = timings;
        let daemon = Daemon::start(config).await.unwrap();
        let (remote, events) =
            RemoteVault::connect(dir.path().join(vaultkeeper::os::layout::UI_SOCKET))
                .await
                .unwrap();
        let fake = Fake::start(items).await;
        daemon
            .vault()
            .login(
                LoginRequest {
                    server: fake.url(),
                    email: EMAIL.into(),
                    password: Zeroizing::new(PASSWORD.into()),
                },
                None,
                None,
            )
            .await
            .unwrap();
        if settings.browser_integration {
            let socket = dir.socket();
            eventually(|| socket.exists()).await;
        }
        Self {
            daemon,
            dir,
            fake,
            clipboard,
            touch_id,
            ui: Ui {
                remote,
                events,
                commands: Vec::new(),
            },
        }
    }

    pub fn password_of(&self, id: &str) -> String {
        self.daemon
            .vault()
            .reveal(&ItemId(id.into()), CopyField::Password)
            .unwrap()
            .to_string()
    }

    pub async fn unlock(&self) {
        self.daemon
            .vault()
            .unlock_with_password(Zeroizing::new(PASSWORD.into()))
            .await
            .unwrap();
    }

    /// A browser host with `extension`'s caller connected to `browser.sock`.
    pub async fn connect(&self, extension: &Extension) -> Host {
        Host::connect(&self.dir.socket(), extension).await
    }

    /// Connects and authenticates; a key the daemon does not know is approved in the UI.
    pub async fn open(&mut self, extension: &Extension) -> Host {
        let mut host = self.connect(extension).await;
        let hello = host.hello(extension).await;
        assert_eq!(hello["ok"], true, "{hello}");
        let known = hello["result"]["known"].as_bool().unwrap();
        let id = host.prove(extension, &hello).await;
        if !known {
            self.ui.prompt().await.answer(BrowserReply::PairApproved);
        }
        let proved = host.response(id).await;
        assert_eq!(proved["ok"], true, "{proved}");
        host
    }

    pub async fn shutdown(self) {
        self.daemon.shutdown().await;
    }
}

/// The browser extension's key and the identity the host reports for it.
pub struct Extension {
    key: SigningKey,
    pub caller: String,
    /// "chromium" or "firefox".
    pub kind: &'static str,
    /// What the host reports as its verified parent.
    pub parent: &'static str,
}

impl Extension {
    pub fn chrome(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes((&[seed; 32]).into()).unwrap(),
            caller: format!("chrome-extension://{}/", ids::CHROME_EXTENSION_ID),
            kind: "chromium",
            parent: "chrome",
        }
    }

    pub fn firefox(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes((&[seed; 32]).into()).unwrap(),
            caller: ids::FIREFOX_EXTENSION_ID.to_owned(),
            kind: "firefox",
            parent: "firefox",
        }
    }

    fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public_key())
    }

    /// SHA-256 of the 65 key bytes, the first 8 as uppercase hex in four groups (BROWSERS.md 3.3).
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.public_key());
        let hex: Vec<String> = hash[..8].iter().map(|byte| format!("{byte:02X}")).collect();
        hex.chunks(2)
            .map(<[String]>::concat)
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Signs `"vaultkeeper-browser-v1\0" ‖ challenge ‖ caller` as the spec says.
    pub fn sign(&self, challenge_b64: &str, caller: &str) -> String {
        let mut message = DOMAIN.to_vec();
        message.extend(STANDARD.decode(challenge_b64).unwrap());
        message.extend(caller.as_bytes());
        let signature: Signature = self.key.sign(&message);
        STANDARD.encode(signature.to_bytes())
    }

    fn host_hello(&self) -> Value {
        let caller = if self.kind == "chromium" {
            json!({ "kind": "chromium", "origin": self.caller })
        } else {
            json!({ "kind": "firefox", "extension_id": self.caller })
        };
        json!({
            "protocol": 1,
            "caller": caller,
            "parent": { "pid": 4242, "executable": "/Applications/Browser.app/Contents/MacOS/browser", "browser": self.parent },
        })
    }
}

/// One `browser.sock` connection: u32 LE frames of JSON.
pub struct Host {
    stream: UnixStream,
    next_id: u64,
    pub events: Vec<Value>,
}

impl Host {
    pub async fn connect(socket: &Path, extension: &Extension) -> Self {
        let mut host = Self {
            stream: UnixStream::connect(socket).await.unwrap(),
            next_id: 1,
            events: Vec::new(),
        };
        host.send(&extension.host_hello()).await;
        let welcome = host.recv().await.expect("a welcome");
        assert_eq!(welcome, json!({ "ok": true }));
        host
    }

    pub async fn send(&mut self, value: &Value) {
        let body = serde_json::to_vec(value).unwrap();
        let length = u32::try_from(body.len()).unwrap().to_le_bytes();
        self.stream.write_all(&length).await.unwrap();
        self.stream.write_all(&body).await.unwrap();
    }

    /// The next frame; `None` once the daemon closed the connection.
    pub async fn recv(&mut self) -> Option<Value> {
        tokio::time::timeout(WAIT, async {
            let mut length = [0_u8; 4];
            self.stream.read_exact(&mut length).await.ok()?;
            let mut body = vec![0; u32::from_le_bytes(length) as usize];
            self.stream.read_exact(&mut body).await.ok()?;
            Some(serde_json::from_slice(&body).unwrap())
        })
        .await
        .expect("a frame or a close in time")
    }

    /// Sends `body` with the next id and returns that id.
    pub async fn submit(&mut self, mut body: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        body["id"] = id.into();
        self.send(&body).await;
        id
    }

    /// The response to `id`; events that arrive first are kept in `events`.
    pub async fn response(&mut self, id: u64) -> Value {
        loop {
            let frame = self
                .recv()
                .await
                .unwrap_or_else(|| panic!("closed before the answer to request {id}"));
            if frame.get("event").is_some() {
                self.events.push(frame);
                continue;
            }
            assert_eq!(frame["id"], id, "{frame}");
            return frame;
        }
    }

    pub async fn request(&mut self, body: Value) -> Value {
        let id = self.submit(body).await;
        self.response(id).await
    }

    /// Reads until the daemon closes the connection; a response frame is a failure.
    pub async fn assert_closed(&mut self) {
        while let Some(frame) = self.recv().await {
            assert!(frame.get("event").is_some(), "unexpected frame: {frame}");
            self.events.push(frame);
        }
    }

    /// The next pushed event, waiting for one when none arrived yet.
    pub async fn event(&mut self) -> Value {
        if !self.events.is_empty() {
            return self.events.remove(0);
        }
        let frame = self.recv().await.expect("an event before the close");
        assert!(
            frame.get("event").is_some(),
            "expected an event, got {frame}"
        );
        frame
    }

    pub async fn hello(&mut self, extension: &Extension) -> Value {
        self.request(json!({
            "type": "hello", "protocol": 1, "extension_version": "1.0.0",
            "public_key": extension.public_key_b64(),
        }))
        .await
    }

    /// Sends `prove` for the challenge in `hello`'s answer; returns the request id.
    pub async fn prove(&mut self, extension: &Extension, hello: &Value) -> u64 {
        let challenge = hello["result"]["challenge"].as_str().unwrap();
        self.submit(json!({
            "type": "prove", "signature": extension.sign(challenge, &extension.caller),
        }))
        .await
    }

    pub async fn submit_fill(&mut self, origin: &str, choose: bool) -> u64 {
        self.submit(json!({
            "type": "fill", "origin": origin, "path": "/login", "choose": choose,
            "fields": { "username": true, "password": true },
        }))
        .await
    }

    /// A fill the user answers by picking `item` in the picker.
    pub async fn picked_fill(&mut self, ui: &mut Ui, origin: &str, item: &str) -> Value {
        let id = self.submit_fill(origin, false).await;
        ui.prompt().await.fill_with(item, false);
        self.response(id).await
    }

    pub async fn save_candidate(
        &mut self,
        origin: &str,
        username: &str,
        password: &str,
        kind: &str,
    ) -> Value {
        self.request(json!({
            "type": "save_candidate", "origin": origin, "path": "/login",
            "username": username, "password": password, "kind": kind,
        }))
        .await
    }
}

/// The `paired` entries of `browsers.json`; empty when there is no file.
pub fn paired(dir: &DataDir) -> Vec<Value> {
    stored(dir)["paired"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

pub fn stored(dir: &DataDir) -> Value {
    std::fs::read(dir.pairings())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}
