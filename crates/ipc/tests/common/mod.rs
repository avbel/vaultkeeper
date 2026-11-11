//! Shared test fixtures: a fake `VaultService`, a short socket directory and a raw protocol
//! client. Each test binary uses a different subset.
#![allow(dead_code, reason = "each test binary uses a different subset")]
#![allow(
    clippy::unused_async_trait_impl,
    reason = "the fake answers at once, but the trait methods are async"
)]

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::{mpsc, watch};
use url::Url;
use vk_ipc::{
    DaemonEvent, RemoteVault, ServeOptions, ServerHandle, TouchIdBackend, TouchIdFailure,
    frame::{HEADER_LEN, decode, encode},
    protocol::{DaemonMessage, PROTOCOL_VERSION, UiMessage, Welcome},
    serve, serve_with,
};
use vk_vault::{
    Error, Result, TotpCode, TwoFactorProvider, VaultService,
    model::{
        AccountView, AttachmentView, CollectionView, CopyField, CustomField, Filter, FolderView,
        ItemData, ItemDraft, ItemId, ItemKind, ItemSummary, LoginRequest, LoginStep,
        OrganizationView, ServerProbe, SessionState, SshKeyMaterial, TwoFactorAnswer,
    },
};
use zeroize::Zeroizing;

pub const SERVER: &str = "https://vault.example.com/";
pub const EMAIL: &str = "alice@example.com";
pub const OTHER_SERVER: &str = "https://vw.lan:8443/";
pub const OTHER_EMAIL: &str = "bob@example.com";
pub const PASSWORD: &str = "correct horse battery staple";
/// Makes `verify_master_password` take 50 ms, for the concurrency test.
pub const SLOW_PASSWORD: &str = "slow";
/// A draft with this name saves only after [`FakeVault::finish_slow_save`] (or [`SLOW_SAVE_LIMIT`]
/// as a safety net), logged once the save finished. An explicit release keeps tests that need the
/// save still in flight independent of how loaded the machine is.
/// Long enough to outlast a reconnect: each connect runs the code-signature peer check, which
/// under a parallel test run took longer than the 200 ms this used to be.
pub const SLOW_SAVE: &str = "slow save";
const SLOW_SAVE_LIMIT: Duration = Duration::from_secs(30);
pub const USER_KEY: [u8; 64] = [7; 64];
pub const SSH_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n";
const SLOW_CALL: Duration = Duration::from_millis(50);

/// What the fake's `probe_server` reports, as Vaultwarden's `/api/version` would.
pub const PROBE_VERSION: &str = "1.37.5";
/// The fake's `last_sync` while online: 2026-11-08T12:00:00Z.
pub const LAST_SYNC_UNIX: u64 = 1_762_603_200;

/// A real reqwest transport failure: nothing listens on the discard port.
pub async fn transport_failure() -> reqwest::Error {
    reqwest::Client::new()
        .get("http://127.0.0.1:9/")
        .send()
        .await
        .expect_err("nothing listens on port 9")
}

pub fn url(text: &str) -> Url {
    Url::parse(text).expect("valid URL")
}

pub fn locked() -> SessionState {
    SessionState::Locked {
        server: url(SERVER),
        email: EMAIL.to_owned(),
    }
}

pub fn unlocked() -> SessionState {
    SessionState::Unlocked {
        server: url(SERVER),
        email: EMAIL.to_owned(),
    }
}

pub fn accounts() -> Vec<AccountView> {
    vec![
        AccountView {
            id: "user-1".into(),
            server: url(SERVER),
            email: EMAIL.into(),
            active: true,
            logged_in: true,
        },
        AccountView {
            id: "user-2".into(),
            server: url(OTHER_SERVER),
            email: OTHER_EMAIL.into(),
            active: false,
            logged_in: true,
        },
    ]
}

pub fn folders() -> Vec<FolderView> {
    vec![
        FolderView {
            id: "f1".into(),
            name: "Work".into(),
        },
        FolderView {
            id: "f2".into(),
            name: "Personal".into(),
        },
    ]
}

pub fn organizations() -> Vec<OrganizationView> {
    vec![OrganizationView {
        id: "o1".into(),
        name: "Family".into(),
    }]
}

pub fn collections() -> Vec<CollectionView> {
    vec![CollectionView {
        id: "c1".into(),
        organization_id: "o1".into(),
        name: "Shared".into(),
        read_only: true,
    }]
}

pub fn attachment() -> AttachmentView {
    AttachmentView {
        id: "a1".into(),
        file_name: "report.pdf".into(),
        size_bytes: 12_345,
    }
}

/// `item-000` .. `item-{n-1}`; every 10th one is a favorite in folder f1.
pub fn items(count: usize) -> Arc<[ItemSummary]> {
    (0..count)
        .map(|index| ItemSummary {
            id: ItemId(format!("item-{index:03}").into()),
            kind: if index % 7 == 0 {
                ItemKind::Card
            } else {
                ItemKind::Login
            },
            name: format!("Item {index:03}").into(),
            subtitle: format!("user{index}@example.com").into(),
            favorite: index % 10 == 0,
            folder_id: (index % 10 == 0).then(|| "f1".into()),
            organization_id: None,
            primary_uri: Some(format!("https://site{index}.example").into()),
            has_password: true,
            has_totp: index % 3 == 0,
            reprompt: false,
            deleted: false,
            editable: true,
        })
        .collect()
}

pub fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

pub fn draft() -> ItemDraft {
    ItemDraft {
        name: "Bank".to_owned(),
        notes: secret("PIN 1234"),
        folder_id: Some("f1".into()),
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: true,
        reprompt: false,
        fields: vec![CustomField {
            name: "recovery".to_owned(),
            value: secret("alpha-beta-gamma"),
            hidden: true,
            field_type: 1,
            source_index: None,
            withheld: false,
        }],
        data: ItemData::Login {
            username: "alice".to_owned(),
            password: secret("hunter2"),
            totp: secret("JBSWY3DPEHPK3PXP"),
            uris: vec!["https://bank.example".to_owned()],
        },
        revision_date: Some("2026-11-08T17:00:59.321Z".into()),
    }
}

/// In-memory `VaultService` with fixed data. Calls with arguments are logged so tests can check
/// what crossed the socket.
pub struct FakeVault {
    changes: watch::Sender<u64>,
    state: Mutex<SessionState>,
    offline: AtomicBool,
    hang_sync: AtomicBool,
    items: Arc<[ItemSummary]>,
    lowercase_names: Vec<String>,
    log: Mutex<Vec<String>>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    slow_save_gate: tokio::sync::Notify,
}

impl FakeVault {
    pub fn new(state: SessionState, item_count: usize) -> Arc<Self> {
        let items = items(item_count);
        let lowercase_names = items.iter().map(|item| item.name.to_lowercase()).collect();
        Arc::new(Self {
            changes: watch::channel(0).0,
            state: Mutex::new(state),
            offline: AtomicBool::new(false),
            hang_sync: AtomicBool::new(false),
            items,
            lowercase_names,
            log: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            slow_save_gate: tokio::sync::Notify::new(),
        })
    }

    /// Lets a pending (or the next) [`SLOW_SAVE`] save complete.
    pub fn finish_slow_save(&self) {
        self.slow_save_gate.notify_one();
    }

    pub fn log(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    pub fn set_state(&self, state: SessionState) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
        self.bump();
    }

    pub fn set_offline(&self, offline: bool) {
        self.offline.store(offline, Ordering::SeqCst);
        self.bump();
    }

    /// Makes `sync` never finish, to have a call in flight when the daemon goes away.
    pub fn hang_sync(&self) {
        self.hang_sync.store(true, Ordering::SeqCst);
    }

    pub fn revision(&self) -> u64 {
        *self.changes.borrow()
    }

    fn bump(&self) {
        self.changes.send_modify(|revision| *revision += 1);
    }

    fn record(&self, entry: String) {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry);
    }

    fn set_state_quietly(&self, state: SessionState) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
    }

    fn require_unlocked(&self) -> Result<()> {
        match self.state() {
            SessionState::Unlocked { .. } => Ok(()),
            SessionState::Locked { .. } => Err(Error::Locked),
            SessionState::LoggedOut => Err(Error::LoggedOut),
        }
    }

    async fn slow_call(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(SLOW_CALL).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl VaultService for FakeVault {
    fn state(&self) -> SessionState {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
        let answer = two_factor.as_ref().map_or_else(
            || "none".to_owned(),
            |answer| {
                format!(
                    "{}:{}:{}",
                    answer.provider.id(),
                    answer.code,
                    answer.remember
                )
            },
        );
        self.record(format!(
            "login {} {} {} 2fa={answer} otp={}",
            request.server,
            request.email,
            request.password.as_str(),
            new_device_otp.as_deref().unwrap_or("none"),
        ));
        match (two_factor, new_device_otp) {
            (None, None) => Ok(LoginStep::TwoFactorRequired(vec![
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::Email,
            ])),
            (Some(_), None) => Ok(LoginStep::NewDeviceOtpRequired),
            (_, Some(_)) => {
                self.set_state(unlocked());
                Ok(LoginStep::Done)
            }
        }
    }

    async fn send_email_code(&self) -> Result<()> {
        self.record("send_email_code".to_owned());
        Ok(())
    }

    async fn unlock_with_password(&self, password: Zeroizing<String>) -> Result<()> {
        self.record(format!("unlock_with_password {}", password.as_str()));
        if password.as_str() != PASSWORD {
            return Err(Error::InvalidPassword);
        }
        self.set_state(unlocked());
        Ok(())
    }

    fn unlock_with_user_key(&self, user_key: Zeroizing<Vec<u8>>) -> Result<()> {
        self.record(format!("unlock_with_user_key {} bytes", user_key.len()));
        if user_key.as_slice() != USER_KEY {
            return Err(Error::InvalidPassword);
        }
        self.set_state(unlocked());
        Ok(())
    }

    fn user_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.require_unlocked()?;
        Ok(Zeroizing::new(USER_KEY.to_vec()))
    }

    async fn verify_master_password(&self, password: Zeroizing<String>) -> Result<bool> {
        if password.as_str() == SLOW_PASSWORD {
            self.slow_call().await;
            return Ok(true);
        }
        Ok(password.as_str() == PASSWORD)
    }

    fn lock(&self) {
        self.record("lock".to_owned());
        self.set_state(locked());
    }

    async fn logout(&self) -> Result<()> {
        self.record("logout".to_owned());
        self.set_state(SessionState::LoggedOut);
        Ok(())
    }

    fn accounts(&self) -> Vec<AccountView> {
        accounts()
    }

    fn switch_account(&self, account_id: &str) -> Result<()> {
        self.record(format!("switch_account {account_id}"));
        if account_id != "user-2" {
            return Err(Error::NotFound);
        }
        self.set_state(SessionState::Locked {
            server: url(OTHER_SERVER),
            email: OTHER_EMAIL.to_owned(),
        });
        Ok(())
    }

    fn begin_add_account(&self) {
        self.record("begin_add_account".to_owned());
        // No bump: the daemon still has to refresh the UI's cache for this call.
        self.set_state_quietly(SessionState::LoggedOut);
    }

    async fn sync(&self) -> Result<()> {
        if self.hang_sync.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.record("sync".to_owned());
        if self.offline.load(Ordering::SeqCst) {
            return Err(Error::Api(vk_api::Error::Http(transport_failure().await)));
        }
        Ok(())
    }

    fn is_offline(&self) -> bool {
        self.offline.load(Ordering::SeqCst)
    }

    fn last_sync(&self) -> Option<std::time::SystemTime> {
        (!self.offline.load(Ordering::SeqCst))
            .then(|| std::time::UNIX_EPOCH + Duration::from_secs(LAST_SYNC_UNIX))
    }

    async fn probe_server(&self, server: &Url) -> Result<ServerProbe> {
        self.record(format!("probe_server {server}"));
        if self.offline.load(Ordering::SeqCst) {
            return Err(Error::Api(vk_api::Error::Http(transport_failure().await)));
        }
        Ok(ServerProbe {
            version: Some(PROBE_VERSION.to_owned()),
        })
    }

    fn search(&self, query: &str, filter: &Filter) -> Result<Arc<[ItemSummary]>> {
        self.require_unlocked()?;
        let query = query.to_lowercase();
        Ok(self
            .items
            .iter()
            .zip(&self.lowercase_names)
            .filter(|(item, name)| {
                name.contains(&query) && (!filter.favorites_only || item.favorite)
            })
            .map(|(item, _)| item.clone())
            .collect())
    }

    fn folders(&self) -> Result<Vec<FolderView>> {
        self.require_unlocked()?;
        Ok(folders())
    }

    fn organizations(&self) -> Result<Vec<OrganizationView>> {
        self.require_unlocked()?;
        Ok(organizations())
    }

    fn collections(&self) -> Result<Vec<CollectionView>> {
        self.require_unlocked()?;
        Ok(collections())
    }

    fn reveal(&self, id: &ItemId, field: CopyField) -> Result<Zeroizing<String>> {
        self.require_unlocked()?;
        if id.0.as_ref() == "missing" {
            return Err(Error::NotFound);
        }
        Ok(Zeroizing::new(format!("{}/{field:?}", id.0)))
    }

    fn totp(&self, id: &ItemId, unix_time: u64) -> Result<TotpCode> {
        self.require_unlocked()?;
        if id.0.as_ref() == "bad-totp" {
            return Err(Error::Gen(vk_gen::Error::InvalidTotp(
                "secret is not valid base32",
            )));
        }
        let elapsed = u32::try_from(unix_time % 30).expect("below 30");
        Ok(TotpCode {
            code: secret("287082"),
            period: 30,
            remaining: 30 - elapsed,
        })
    }

    fn draft(&self, id: &ItemId) -> Result<ItemDraft> {
        self.require_unlocked()?;
        self.record(format!("draft {}", id.0));
        Ok(draft())
    }

    async fn save(&self, id: Option<ItemId>, draft: ItemDraft) -> Result<ItemId> {
        if draft.name == SLOW_SAVE {
            let _ = tokio::time::timeout(SLOW_SAVE_LIMIT, self.slow_save_gate.notified()).await;
        }
        let password = match &draft.data {
            ItemData::Login { password, .. } => password.as_str().to_owned(),
            _ => String::new(),
        };
        let target = id.as_ref().map_or("new", |id| id.0.as_ref());
        self.record(format!(
            "save {target} {} {password} fields={}",
            draft.name,
            draft.fields.len()
        ));
        self.bump();
        Ok(id.unwrap_or_else(|| ItemId("item-new".into())))
    }

    fn attachments(&self, id: &ItemId) -> Result<Vec<AttachmentView>> {
        self.record(format!("attachments {}", id.0));
        Ok(vec![attachment()])
    }

    async fn download_attachment(
        &self,
        id: &ItemId,
        attachment_id: &str,
        dest: PathBuf,
    ) -> Result<()> {
        self.record(format!(
            "download {} {attachment_id} {}",
            id.0,
            dest.display()
        ));
        Ok(())
    }

    async fn upload_attachment(&self, id: &ItemId, source: PathBuf) -> Result<AttachmentView> {
        self.record(format!("upload {} {}", id.0, source.display()));
        let file_name = source
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(AttachmentView {
            id: "a2".into(),
            file_name: file_name.into(),
            size_bytes: 42,
        })
    }

    async fn delete_attachment(&self, id: &ItemId, attachment_id: &str) -> Result<()> {
        self.record(format!("delete_attachment {} {attachment_id}", id.0));
        Ok(())
    }

    async fn assign_collections(
        &self,
        id: &ItemId,
        organization_id: &str,
        collection_ids: Vec<Arc<str>>,
    ) -> Result<()> {
        self.record(format!(
            "assign_collections {} {organization_id} {}",
            id.0,
            collection_ids.join(",")
        ));
        Ok(())
    }

    async fn trash(&self, id: &ItemId) -> Result<()> {
        self.record(format!("trash {}", id.0));
        Ok(())
    }

    async fn restore(&self, id: &ItemId) -> Result<()> {
        self.record(format!("restore {}", id.0));
        Ok(())
    }

    async fn delete_permanently(&self, id: &ItemId) -> Result<()> {
        self.record(format!("delete_permanently {}", id.0));
        Err(Error::ReadOnly)
    }

    async fn create_folder(&self, name: &str) -> Result<FolderView> {
        self.record(format!("create_folder {name}"));
        Ok(FolderView {
            id: "f3".into(),
            name: name.into(),
        })
    }

    async fn rename_folder(&self, id: &str, name: &str) -> Result<()> {
        self.record(format!("rename_folder {id} {name}"));
        Ok(())
    }

    async fn delete_folder(&self, id: &str) -> Result<()> {
        self.record(format!("delete_folder {id}"));
        Ok(())
    }

    fn ssh_keys(&self) -> Result<Vec<SshKeyMaterial>> {
        self.require_unlocked()?;
        Ok(vec![SshKeyMaterial {
            cipher_id: ItemId("k1".into()),
            name: "deploy".to_owned(),
            private_key: secret(SSH_PEM),
        }])
    }
}

/// A fresh directory under /tmp: macOS caps socket paths at 104 bytes and `$TMPDIR` is long.
/// Stands in for the Secure Enclave: keeps the sealed key in memory; `refuse` makes the next
/// unlocks fail like a cancelled prompt would.
#[derive(Default)]
pub struct FakeTouchId {
    sealed: Mutex<Option<(String, Vec<u8>)>>,
    refusal: Mutex<Option<TouchIdFailure>>,
    unlocks: Mutex<Vec<String>>,
}

impl FakeTouchId {
    pub fn sealed(&self) -> Option<(String, Vec<u8>)> {
        self.sealed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn refuse(&self, failure: Option<TouchIdFailure>) {
        *self.refusal.lock().unwrap_or_else(PoisonError::into_inner) = failure;
    }

    pub fn unlocks(&self) -> Vec<String> {
        self.unlocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl TouchIdBackend for FakeTouchId {
    fn enroll(&self, account_id: &str, user_key: &[u8]) -> std::result::Result<(), TouchIdFailure> {
        *self.sealed.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((account_id.to_owned(), user_key.to_vec()));
        Ok(())
    }

    fn unlock(&self, account_id: &str) -> std::result::Result<Zeroizing<Vec<u8>>, TouchIdFailure> {
        self.unlocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(account_id.to_owned());
        if let Some(failure) = self
            .refusal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Err(failure);
        }
        match self.sealed() {
            Some((sealed_for, key)) if sealed_for == account_id => Ok(Zeroizing::new(key)),
            _ => Err(TouchIdFailure::Unavailable),
        }
    }
}

pub struct SocketDir(PathBuf);

impl SocketDir {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("/tmp/vkipc-{}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn socket(&self) -> PathBuf {
        self.0.join("ui.sock")
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct Daemon {
    pub fake: Arc<FakeVault>,
    pub server: Option<ServerHandle>,
    pub events: mpsc::Sender<DaemonEvent>,
    pub dir: SocketDir,
}

impl Daemon {
    pub async fn start(fake: Arc<FakeVault>) -> Self {
        let dir = SocketDir::new();
        let (events, source) = mpsc::channel(16);
        let server = serve(dir.socket(), Arc::clone(&fake), source)
            .await
            .expect("serve");
        Self {
            fake,
            server: Some(server),
            events,
            dir,
        }
    }

    pub async fn start_with(fake: Arc<FakeVault>, options: ServeOptions) -> Self {
        let dir = SocketDir::new();
        let (events, source) = mpsc::channel(16);
        let server = serve_with(dir.socket(), Arc::clone(&fake), source, options)
            .await
            .expect("serve");
        Self {
            fake,
            server: Some(server),
            events,
            dir,
        }
    }

    pub fn socket(&self) -> PathBuf {
        self.dir.socket()
    }

    pub async fn connect(&self) -> (RemoteVault, vk_ipc::EventStream) {
        RemoteVault::connect(self.socket()).await.expect("connect")
    }
}

/// Speaks the wire protocol by hand, with blocking std I/O.
pub struct RawClient {
    stream: std::os::unix::net::UnixStream,
}

impl RawClient {
    pub fn connect(path: &Path) -> Self {
        let stream = std::os::unix::net::UnixStream::connect(path).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        Self { stream }
    }

    pub fn send(&mut self, message: &UiMessage) {
        let frame = encode(message).expect("encode");
        self.stream.write_all(&frame).expect("write");
    }

    pub fn write_raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes)
    }

    /// `None` once the daemon closed the connection.
    pub fn recv(&mut self) -> Option<DaemonMessage> {
        let mut header = [0; HEADER_LEN];
        if self.stream.read_exact(&mut header).is_err() {
            return None;
        }
        let len = usize::try_from(u32::from_le_bytes(header)).expect("fits");
        let mut body = vec![0; len];
        self.stream.read_exact(&mut body).expect("body");
        Some(decode(&body).expect("decode"))
    }

    pub fn hello(&mut self) -> Welcome {
        self.send(&UiMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        });
        match self.recv() {
            Some(DaemonMessage::Welcome(welcome)) => *welcome,
            _ => panic!("expected a welcome"),
        }
    }
}
