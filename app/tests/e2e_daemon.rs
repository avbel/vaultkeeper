//! A real `bw-lite --daemon` process against the e2e Vaultwarden (scripts/e2e.sh), driven by a
//! `RemoteVault` client that plays the UI and approves SSH requests on its own.
//!
//! The daemon keeps the real HOME (the login keychain shows a dialog under a fake one) but gets
//! its own data dir and keychain item prefix through the `vw-it` test overrides.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
// `ram_profile` reports its measurements on stderr.
#![allow(clippy::print_stderr)]

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bw_lite::{
    os::settings_file::SettingsFile,
    settings::{LockTimeout, Settings, SshApproval},
};
use bwl_crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use bwl_ipc::{EventStream, RemoteVault, SshDecision, UiEvent};
use bwl_vault::{
    VaultService,
    model::{
        CopyField, Filter, ItemData, ItemDraft, ItemKind, LoginRequest, LoginStep, SessionState,
    },
};
use serde_json::json;
use tokio::process::{Child, Command};
use url::Url;
use zeroize::Zeroizing;

const RSA_PRIVATE_DER: &[u8] = include_bytes!("../../crates/vault/tests/fixtures/rsa_private.der");
const RSA_PUBLIC_B64: &str = include_str!("../../crates/vault/tests/fixtures/rsa_public.b64");
const WAIT: Duration = Duration::from_secs(20);

fn server() -> Url {
    let url = std::env::var("VW_URL")
        .expect("VW_URL must point at the e2e Vaultwarden (run scripts/e2e.sh)");
    Url::parse(&url).expect("VW_URL is a URL")
}

struct Account {
    email: String,
    password: String,
}

/// Registers through the API with the client's own crypto, like the bwl-vault scenarios.
async fn register(server: &Url) -> Account {
    let email = format!("app-e2e-{}@example.com", uuid::Uuid::new_v4().simple());
    let password = format!("pw-{}", uuid::Uuid::new_v4().simple());
    let kdf = Kdf::from_wire(0, 100_000, None, None).unwrap();
    let master = MasterKey::derive(password.as_bytes(), &email, &kdf).unwrap();
    let hash = master.server_hash(password.as_bytes());
    let user_key = SymmetricKey::generate();
    let protected = EncString::encrypt(&user_key.to_bytes(), &master.stretch()).unwrap();
    let private_key = EncString::encrypt(RSA_PRIVATE_DER, &user_key).unwrap();
    let http = reqwest::Client::new();
    let token = http
        .post(
            server
                .join("identity/accounts/register/send-verification-email")
                .unwrap(),
        )
        .json(&json!({ "email": email, "name": "App E2E" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("signups must be allowed")
        .text()
        .await
        .unwrap();
    let response = http
        .post(server.join("identity/accounts/register/finish").unwrap())
        .json(&json!({
            "email": email,
            "masterPasswordHash": hash,
            "key": protected.to_string(),
            "keys": { "encryptedPrivateKey": private_key.to_string(), "publicKey": RSA_PUBLIC_B64.trim() },
            "emailVerificationToken": token.trim().trim_matches('"'),
            "kdf": 0,
            "kdfIterations": 100_000,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "register: {}",
        response.status()
    );
    Account { email, password }
}

/// A short data dir under /tmp (socket paths are capped at 104 bytes) plus a keychain prefix.
struct Sandbox {
    dir: PathBuf,
    keychain_prefix: String,
}

impl Sandbox {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = PathBuf::from(format!("/tmp/bwl-e2e-{}", &id[..12]));
        std::fs::create_dir_all(&dir).unwrap();
        let sandbox = Self {
            keychain_prefix: format!("bw-lite-e2e.{id}."),
            dir,
        };
        assert!(sandbox.agent_socket().as_os_str().len() < 104);
        sandbox
    }

    fn agent_socket(&self) -> PathBuf {
        self.dir.join("ssh-agent.sock")
    }

    fn ui_socket(&self) -> PathBuf {
        self.dir.join("ui.sock")
    }

    fn command(&self, binary: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(binary);
        command
            .args(args)
            .env("BW_LITE_TEST_DATA_DIR", &self.dir)
            .env("BW_LITE_TEST_KEYCHAIN_PREFIX", &self.keychain_prefix)
            .env("BW_LITE_TEST_ANY_PEER", "1")
            .env("RUST_LOG", "info,bwl_ssh=debug")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        command
    }

    /// Headless, and the test process is the UI.
    fn daemon(&self) -> Child {
        self.command(Path::new(env!("CARGO_BIN_EXE_bw-lite")), &["--daemon"])
            .env("BW_LITE_TEST_HEADLESS", "1")
            .env("BW_LITE_TEST_NO_UI", "1")
            .spawn()
            .unwrap()
    }

    async fn connect(&self) -> (RemoteVault, EventStream) {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            match RemoteVault::connect(self.ui_socket()).await {
                Ok(connected) => return connected,
                Err(error) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "daemon not reachable: {error}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Answers every SSH approval with `approve` (ticking "remember" when `remember`) and counts them.
fn auto_approver(
    mut events: EventStream,
    approve: Arc<AtomicBool>,
    remember: bool,
) -> Arc<AtomicUsize> {
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&asked);
    tokio::spawn(async move {
        while let Some(event) = events.next().await {
            if let UiEvent::SshApproval(approval) = event {
                counter.fetch_add(1, Ordering::SeqCst);
                let decision = if approve.load(Ordering::SeqCst) {
                    SshDecision::approve(remember)
                } else {
                    SshDecision::DENY
                };
                let _ = approval.reply.send(decision);
            }
        }
    });
    asked
}

async fn log_in(vault: &impl VaultService, server: &Url, account: &Account) {
    let step = vault
        .login(
            LoginRequest {
                server: server.clone(),
                email: account.email.clone(),
                password: Zeroizing::new(account.password.clone()),
            },
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
}

async fn ssh_add_list(socket: &Path) -> String {
    let output = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .await
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

async fn eventually_listed(socket: &Path, fingerprint: &str) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let listed = ssh_add_list(socket).await;
        if listed.contains(fingerprint) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent lists: {listed}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `ssh-keygen -Y sign` with the agent holding the private half of `public_key`.
async fn sign_with_agent(socket: &Path, dir: &Path, public_key: &str) -> bool {
    let key_file = dir.join("signing.pub");
    let message = dir.join("message.txt");
    std::fs::write(&key_file, format!("{public_key}\n")).unwrap();
    std::fs::write(&message, b"signed by bw-lite e2e\n").unwrap();
    let _ = std::fs::remove_file(dir.join("message.txt.sig"));
    let status = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(&key_file)
        .arg(&message)
        .env("SSH_AUTH_SOCK", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap();
    status.success() && dir.join("message.txt.sig").exists()
}

fn login_draft(name: &str, password: &str) -> ItemDraft {
    ItemDraft {
        name: name.to_owned(),
        notes: Zeroizing::new(String::new()),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data: ItemData::Login {
            username: "octocat".to_owned(),
            password: Zeroizing::new(password.to_owned()),
            totp: Zeroizing::new(String::new()),
            uris: vec!["https://github.com".to_owned()],
        },
    }
}

fn ssh_draft(name: &str) -> (ItemDraft, String, String) {
    let (private_key, public_key, fingerprint) = bwl_ssh::generate_ed25519().unwrap();
    let draft = ItemDraft {
        data: ItemData::SshKey {
            private_key,
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
        },
        ..login_draft(name, "")
    };
    (draft, public_key, fingerprint)
}

async fn terminate(mut daemon: Child) -> std::process::ExitStatus {
    let pid = daemon.id().expect("running").to_string();
    let sent = Command::new("/bin/kill")
        .args(["-TERM", &pid])
        .status()
        .await
        .unwrap();
    assert!(sent.success(), "SIGTERM delivered");
    tokio::time::timeout(WAIT, daemon.wait())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn daemon_login_sync_search_reveal_lock_unlock_ssh_and_logout_wipe() {
    let server = server();
    let account = register(&server).await;
    let sandbox = Sandbox::new();
    let daemon = sandbox.daemon();
    let (vault, events) = sandbox.connect().await;
    let approve = Arc::new(AtomicBool::new(true));
    let approvals = auto_approver(events, Arc::clone(&approve), false);
    assert_eq!(vault.state(), SessionState::LoggedOut);

    let probe = vault.probe_server(&server).await.unwrap();
    assert!(probe.version.is_some(), "Vaultwarden names its release");

    // Login → the daemon's vault is unlocked and synced.
    let step = vault
        .login(
            LoginRequest {
                server: server.clone(),
                email: account.email.clone(),
                password: Zeroizing::new(account.password.clone()),
            },
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
    let user_id = vault.accounts()[0].id.to_string();
    let account_dir = sandbox.dir.join("accounts").join(&user_id);
    assert!(account_dir.is_dir());

    // Writes through the daemon, then a sync from the server.
    let github = vault
        .save(None, login_draft("GitHub e2e", "pw-github-123"))
        .await
        .unwrap();
    let (key_draft, public_key, fingerprint) = ssh_draft("deploy-ed25519");
    vault.save(None, key_draft).await.unwrap();
    vault.sync().await.unwrap();
    assert!(
        vault.last_sync().is_some(),
        "the status line sees the daemon's sync"
    );

    // Search and reveal.
    let found = vault.search("github", &Filter::default()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, github);
    assert_eq!(
        &*vault.reveal(&github, CopyField::Password).unwrap(),
        "pw-github-123"
    );
    let keys = Filter {
        kind: Some(ItemKind::SshKey),
        ..Filter::default()
    };
    assert_eq!(&*vault.search("", &keys).unwrap()[0].subtitle, fingerprint);

    // Lock, then unlock with the master password.
    vault.lock();
    assert!(matches!(vault.state(), SessionState::Locked { .. }));
    assert!(matches!(
        vault.search("github", &Filter::default()),
        Err(bwl_vault::Error::Locked)
    ));
    vault
        .unlock_with_password(Zeroizing::new(account.password.clone()))
        .await
        .unwrap();
    assert_eq!(vault.search("github", &Filter::default()).unwrap().len(), 1);

    // SSH: the agent lists the vault key and signs once the client approves.
    let socket = sandbox.agent_socket();
    eventually_listed(&socket, &fingerprint).await;
    assert!(
        sign_with_agent(&socket, &sandbox.dir, &public_key).await,
        "approved signature"
    );
    assert_eq!(approvals.load(Ordering::SeqCst), 1);
    approve.store(false, Ordering::SeqCst);
    assert!(
        !sign_with_agent(&socket, &sandbox.dir, &public_key).await,
        "denied signature"
    );
    assert_eq!(approvals.load(Ordering::SeqCst), 2);

    // Locking keeps the key loaded, so a sign request still reaches the UI (which unlocks
    // first), but the daemon never lets a locked vault sign, whatever the UI answers.
    vault.lock();
    assert!(ssh_add_list(&socket).await.contains(&fingerprint));
    approve.store(true, Ordering::SeqCst);
    assert!(
        !sign_with_agent(&socket, &sandbox.dir, &public_key).await,
        "no signature while locked"
    );
    assert_eq!(
        approvals.load(Ordering::SeqCst),
        3,
        "the request reached the UI"
    );
    vault
        .unlock_with_password(Zeroizing::new(account.password.clone()))
        .await
        .unwrap();

    // Log out wipes the account.
    vault.logout().await.unwrap();
    assert_eq!(vault.state(), SessionState::LoggedOut);
    assert!(!account_dir.exists(), "accounts/<user_id>/ is gone");
    let refresh = format!("{}{user_id}.refresh_token", sandbox.keychain_prefix);
    assert!(
        bwl_platform::keychain::get(&refresh).unwrap().is_none(),
        "the refresh token left the keychain"
    );
    let deadline = tokio::time::Instant::now() + WAIT;
    while ssh_add_list(&socket).await.contains(&fingerprint) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the agent dropped the key"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(bwl_vault::Error::LoggedOut)
    ));

    // SIGTERM is a graceful quit: both sockets go.
    drop(vault);
    let status = terminate(daemon).await;
    assert!(status.success(), "{status}");
    assert!(!sandbox.ui_socket().exists());
    assert!(!socket.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn remember_until_lock_is_kept_by_the_daemon_and_forgotten_on_lock() {
    let server = server();
    let account = register(&server).await;
    let sandbox = Sandbox::new();
    SettingsFile::write(
        &sandbox.dir.join("settings.json"),
        &Settings {
            ssh_approval: SshApproval::RememberUntilLock,
            ..Settings::default()
        },
    )
    .unwrap();
    let daemon = sandbox.daemon();
    let (vault, events) = sandbox.connect().await;
    let approvals = auto_approver(events, Arc::new(AtomicBool::new(true)), true);
    log_in(&vault, &server, &account).await;
    let (key_draft, public_key, fingerprint) = ssh_draft("remembered-key");
    vault.save(None, key_draft).await.unwrap();
    let socket = sandbox.agent_socket();
    eventually_listed(&socket, &fingerprint).await;

    assert!(sign_with_agent(&socket, &sandbox.dir, &public_key).await);
    assert_eq!(approvals.load(Ordering::SeqCst), 1);
    assert!(sign_with_agent(&socket, &sandbox.dir, &public_key).await);
    assert_eq!(
        approvals.load(Ordering::SeqCst),
        1,
        "the daemon remembered the key, so the UI was not asked again"
    );

    vault.lock();
    vault
        .unlock_with_password(Zeroizing::new(account.password.clone()))
        .await
        .unwrap();
    assert!(sign_with_agent(&socket, &sandbox.dir, &public_key).await);
    assert_eq!(approvals.load(Ordering::SeqCst), 2, "lock forgot it");

    vault.logout().await.unwrap();
    drop(vault);
    terminate(daemon).await;
}

/// The daemon core in-process, so power events can be fed in directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn sleep_and_screen_lock_lock_only_when_the_timeout_says_so() {
    use bw_lite::daemon::{Daemon, DaemonConfig, Peers};
    use bwl_platform::power::PowerEvent;

    let server = server();
    let account = register(&server).await;
    let sandbox = Sandbox::new();
    let settings_file = sandbox.dir.join("settings.json");
    let on_sleep = Settings {
        lock_timeout: LockTimeout::OnSleep,
        ..Settings::default()
    };
    SettingsFile::write(&settings_file, &on_sleep).unwrap();
    let mut config = DaemonConfig::new(
        sandbox.dir.clone(),
        Arc::new(bwl_vault::MemorySecretStore::new()),
    );
    config.peers = Peers::AnyOfThisUser;
    let daemon = Daemon::start(config).await.unwrap();
    let vault = Arc::clone(daemon.vault());
    log_in(vault.as_ref(), &server, &account).await;
    let unlock = || async {
        vault
            .unlock_with_password(Zeroizing::new(account.password.clone()))
            .await
            .unwrap();
    };

    daemon.power_event(PowerEvent::WillSleep);
    assert!(
        matches!(vault.state(), SessionState::Locked { .. }),
        "sleep locks"
    );
    daemon.power_event(PowerEvent::DidWake);
    unlock().await;
    daemon.power_event(PowerEvent::ScreenUnlocked);
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
    daemon.power_event(PowerEvent::ScreenLocked);
    assert!(
        matches!(vault.state(), SessionState::Locked { .. }),
        "screen lock locks"
    );

    // With a 15-minute timeout neither locks; the timer decides.
    SettingsFile::write(
        &settings_file,
        &Settings {
            lock_timeout: LockTimeout::Minutes(15),
            ..Settings::default()
        },
    )
    .unwrap();
    let (client, _events) = sandbox.connect().await;
    client.notify(bwl_ipc::UiNotice::SettingsChanged).unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    while daemon.settings().lock_timeout != LockTimeout::Minutes(15) {
        assert!(tokio::time::Instant::now() < deadline, "settings re-read");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    unlock().await;
    daemon.power_event(PowerEvent::WillSleep);
    daemon.power_event(PowerEvent::ScreenLocked);
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
    daemon.power_event(PowerEvent::DidWake);
    vault.logout().await.unwrap();
    drop(client);
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_launch_forwards_to_the_running_daemon() {
    let sandbox = Sandbox::new();
    let daemon = sandbox.daemon();
    let (_vault, mut events) = sandbox.connect().await;
    let second = sandbox
        .command(Path::new(env!("CARGO_BIN_EXE_bw-lite")), &["--quick"])
        .status()
        .await
        .unwrap();
    assert!(second.success(), "the second instance exits at once");
    let event = tokio::time::timeout(WAIT, events.next()).await.unwrap();
    assert!(
        matches!(
            event,
            Some(UiEvent::Command(bwl_ipc::UiCommand::ShowQuickPanel))
        ),
        "{event:?}"
    );
    terminate(daemon).await;
}

/// `footprint` of `pid` in MiB.
async fn footprint_mib(pid: u32) -> f64 {
    if std::env::var_os("BW_LITE_RAM_VERBOSE").is_some() {
        let detail = Command::new("/usr/bin/heap")
            .args(["-s", &pid.to_string()])
            .output()
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&detail.stdout);
        eprintln!("{}", text.lines().take(45).collect::<Vec<_>>().join("\n"));
    }
    let output = Command::new("/usr/bin/footprint")
        .args(["--noCategories", "-f", "bytes", &pid.to_string()])
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .find(|line| line.contains("Footprint:"))
        .unwrap_or_else(|| {
            panic!(
                "footprint output: {text} {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let bytes: f64 = line
        .split("Footprint:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|number| number.parse().ok())
        .unwrap_or_else(|| panic!("unparsable: {line}"));
    bytes / 1024.0 / 1024.0
}

/// `lsappinfo`'s type for `pid`: "Foreground" with a Dock icon, "UIElement" without.
async fn app_type(pid: u32) -> String {
    let asn = Command::new("/usr/bin/lsappinfo")
        .args(["find", &format!("pid={pid}")])
        .output()
        .await
        .unwrap();
    let asn = String::from_utf8_lossy(&asn.stdout).trim().to_owned();
    let info = Command::new("/usr/bin/lsappinfo")
        .args(["info", "-only", "ApplicationType", &asn])
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&info.stdout).into_owned();
    text.split("type=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_owned()
}

async fn wait_for_child(parent: u32) -> u32 {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(child) = child_of(parent).await {
            return child;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no UI process started"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn child_of(parent: u32) -> Option<u32> {
    let output = Command::new("/usr/bin/pgrep")
        .args(["-P", &parent.to_string()])
        .output()
        .await
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .and_then(|pid| pid.trim().parse().ok())
}

fn seeded_draft(index: usize) -> ItemDraft {
    let mut draft = login_draft(
        &format!("Service {index:03}"),
        &format!("pw-{index:03}-{}", uuid::Uuid::new_v4().simple()),
    );
    if let ItemData::Login {
        username,
        totp,
        uris,
        ..
    } = &mut draft.data
    {
        *username = format!("user{index:03}@example.com");
        *uris = vec![format!("https://service{index:03}.example.com/login")];
        if index.is_multiple_of(10) {
            *totp = Zeroizing::new("JBSWY3DPEHPK3PXP".to_owned());
        }
    }
    if index.is_multiple_of(40) {
        draft.data = ItemData::SecureNote;
        draft.notes = Zeroizing::new(format!("note {index}"));
    }
    draft
}

/// RAM of the release daemon and UI process in the four documented states, with 400 items.
/// `BW_LITE_RAM_BIN` is a release `bw-lite` built with `--features vw-it` (for the test peer).
/// Nothing here can click, so the UI process is SIGTERMed for "after UI exit"; afterwards an SSH
/// prompt nobody answers closes itself (30 s auto-deny), which checks the linger exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "measurement: needs BW_LITE_RAM_BIN and shows the Manager window"]
async fn ram_profile() {
    const ITEMS: usize = 400;
    const SETTLE: Duration = Duration::from_secs(6);
    let binary = PathBuf::from(std::env::var("BW_LITE_RAM_BIN").expect("BW_LITE_RAM_BIN"));
    let server = server();
    let account = register(&server).await;
    let sandbox = Sandbox::new();
    let start = || {
        sandbox
            .command(&binary, &["--daemon"])
            .env("BW_LITE_UI_LINGER_SECS", "5")
            .spawn()
            .unwrap()
    };
    let login = || LoginRequest {
        server: server.clone(),
        email: account.email.clone(),
        password: Zeroizing::new(account.password.clone()),
    };

    let daemon = start();
    let (vault, events) = sandbox.connect().await;
    assert_eq!(
        vault.login(login(), None, None).await.unwrap(),
        LoginStep::Done
    );
    let seeded = std::time::Instant::now();
    for index in 1..ITEMS {
        vault.save(None, seeded_draft(index)).await.unwrap();
    }
    let (key_draft, public_key, _) = ssh_draft("ram-signing-key");
    vault.save(None, key_draft).await.unwrap();
    vault.sync().await.unwrap();
    let count = vault.search("", &Filter::default()).unwrap().len();
    eprintln!("seeded {count} items in {:?}", seeded.elapsed());
    vault.lock();
    drop((vault, events));
    terminate(daemon).await;

    let daemon = start();
    let pid = daemon.id().unwrap();
    let (vault, events) = sandbox.connect().await;
    drop((vault, events));
    tokio::time::sleep(SETTLE).await;
    let tray_locked = footprint_mib(pid).await;

    let (vault, events) = sandbox.connect().await;
    vault
        .unlock_with_password(Zeroizing::new(account.password.clone()))
        .await
        .unwrap();
    vault.sync().await.unwrap();
    assert_eq!(vault.search("", &Filter::default()).unwrap().len(), count);
    drop((vault, events));
    tokio::time::sleep(SETTLE).await;
    let tray_unlocked = footprint_mib(pid).await;

    // A plain second launch asks the daemon for the Manager; it starts the UI process.
    let opened = sandbox.command(&binary, &[]).status().await.unwrap();
    assert!(opened.success());
    let ui = wait_for_child(pid).await;
    tokio::time::sleep(SETTLE).await;
    let manager_daemon = footprint_mib(pid).await;
    let manager_ui = footprint_mib(ui).await;
    let manager_type = app_type(ui).await;

    let killed = Command::new("/bin/kill")
        .args(["-TERM", &ui.to_string()])
        .status()
        .await
        .unwrap();
    assert!(killed.success());
    tokio::time::sleep(SETTLE).await;
    assert_eq!(child_of(pid).await, None, "the UI process is gone");
    let after_ui = footprint_mib(pid).await;

    // An unanswered SSH prompt: the UI starts for it, auto-denies after 30 s, then lingers 5 s.
    let signing = {
        let socket = sandbox.agent_socket();
        let dir = sandbox.dir.clone();
        tokio::spawn(async move { sign_with_agent(&socket, &dir, &public_key).await })
    };
    let prompt_ui = wait_for_child(pid).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let prompt_type = app_type(prompt_ui).await;
    let signed = tokio::time::timeout(Duration::from_secs(60), signing)
        .await
        .unwrap()
        .unwrap();
    let denied_at = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + WAIT;
    while child_of(pid).await == Some(prompt_ui) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the UI process lingered too long"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!(
        "Dock: Manager open = {manager_type}, SSH prompt only = {prompt_type}; \
         unanswered prompt signed = {signed}; UI exited {:?} after the auto-deny",
        denied_at.elapsed()
    );
    assert!(!signed, "an unanswered prompt denies");

    eprintln!("| state | daemon MiB | UI process MiB |");
    eprintln!("|---|---|---|");
    eprintln!("| tray, locked | {tray_locked:.1} | - |");
    eprintln!("| tray, unlocked | {tray_unlocked:.1} | - |");
    eprintln!("| Manager open | {manager_daemon:.1} | {manager_ui:.1} |");
    eprintln!("| after UI exit | {after_ui:.1} | - |");

    let (vault, events) = sandbox.connect().await;
    vault.logout().await.unwrap();
    drop((vault, events));
    terminate(daemon).await;
}
