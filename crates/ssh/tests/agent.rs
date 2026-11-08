//! End-to-end: a real `SshAgent` on a temp socket, driven by the system `ssh-add` and
//! `ssh-keygen`. Fingerprints are the output of `ssh-keygen -lf` for the committed fixtures.

use std::{
    fs,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use bwl_ssh::{
    AgentError, AgentKey, ApprovalKind, ApprovalRequest, ImportError, SshAgent, import_key,
};
use tempfile::TempDir;
use tokio::{
    sync::{mpsc, oneshot},
    task::spawn_blocking,
    time::timeout,
};
use zeroize::Zeroizing;

const COMMAND_LIMIT: Duration = Duration::from_secs(60);
const SHORT_APPROVAL_TIMEOUT: Duration = Duration::from_millis(600);
const PASSPHRASE: &str = "correct horse";

struct FixtureKey {
    file: &'static str,
    fingerprint: &'static str,
}

const ED25519: FixtureKey = FixtureKey {
    file: "ed25519",
    fingerprint: "SHA256:rF76hBWb1V0J5igckCIocsvRL9TfsRHL4dzyBYomAa0",
};
const ED25519_ENC: FixtureKey = FixtureKey {
    file: "ed25519_enc",
    fingerprint: "SHA256:sbDXaF0710r/b2tkG9eZmGV3g5cyvz52D0r4HOwIPW4",
};
const RSA: FixtureKey = FixtureKey {
    file: "rsa",
    fingerprint: "SHA256:DDEvzDILSLX3RqcKRjabBq/ncqjldlJnPha+r6SWMeI",
};
const P256: FixtureKey = FixtureKey {
    file: "ecdsa_p256",
    fingerprint: "SHA256:jdfYG3IiAOeOqqQBvDxLCM7vCPiubTKAj2l9ZL0ZiL4",
};
const P384: FixtureKey = FixtureKey {
    file: "ecdsa_p384",
    fingerprint: "SHA256:rB1OqyWe21WDzoBM0pRFxkhx1PtjZ/ivypsQnR/e1Tw",
};
const P521: FixtureKey = FixtureKey {
    file: "ecdsa_p521",
    fingerprint: "SHA256:k1/80l/NzP7tFj3xC7n5HKSz4v6UjDnfFhPyDscDeOY",
};
const ALL_KEYS: [&FixtureKey; 5] = [&ED25519, &RSA, &P256, &P384, &P521];

impl FixtureKey {
    fn name(&self) -> String {
        format!("{} key", self.file)
    }

    fn cipher_id(&self) -> String {
        format!("cipher-{}", self.file)
    }

    fn pub_path(&self) -> PathBuf {
        fixture_path(&format!("{}.pub", self.file))
    }

    fn agent_key(&self) -> AgentKey {
        let pem = fs::read_to_string(fixture_path(self.file)).expect("fixture");
        let passphrase = (self.file == ED25519_ENC.file).then_some(PASSPHRASE);
        let (private_pem, _, fingerprint) = import_key(&pem, passphrase).expect("fixture imports");
        assert_eq!(fingerprint, self.fingerprint);
        AgentKey {
            cipher_id: self.cipher_id(),
            name: self.name(),
            private_key: private_pem,
        }
    }
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[derive(Clone, Copy)]
enum Verdict {
    Approve,
    Deny,
    DropReply,
    Ignore,
}

#[derive(Default)]
struct UiLog {
    requests: Vec<ApprovalKind>,
    ignored: Vec<oneshot::Sender<bool>>,
}

struct SignInfo {
    cipher_id: Option<String>,
    process_name: Option<String>,
    is_forwarding: bool,
    namespace: Option<String>,
}

impl UiLog {
    fn signs(&self) -> Vec<SignInfo> {
        self.requests
            .iter()
            .filter_map(|kind| match kind {
                ApprovalKind::Sign {
                    cipher_id,
                    process_name,
                    is_forwarding,
                    namespace,
                } => Some(SignInfo {
                    cipher_id: cipher_id.clone(),
                    process_name: process_name.clone(),
                    is_forwarding: *is_forwarding,
                    namespace: namespace.clone(),
                }),
                ApprovalKind::List => None,
            })
            .collect()
    }

    fn list_count(&self) -> usize {
        self.requests
            .iter()
            .filter(|kind| matches!(kind, ApprovalKind::List))
            .count()
    }
}

fn spawn_ui(mut rx: mpsc::Receiver<ApprovalRequest>, verdict: Verdict) -> Arc<Mutex<UiLog>> {
    let log = Arc::new(Mutex::new(UiLog::default()));
    let shared = Arc::clone(&log);
    tokio::spawn(async move {
        while let Some(ApprovalRequest { kind, reply }) = rx.recv().await {
            let mut log = shared.lock().expect("ui log");
            log.requests.push(kind);
            match verdict {
                Verdict::Approve => drop(reply.send(true)),
                Verdict::Deny => drop(reply.send(false)),
                Verdict::DropReply => drop(reply),
                Verdict::Ignore => log.ignored.push(reply),
            }
        }
    });
    log
}

struct Harness {
    dir: TempDir,
    agent: SshAgent,
    ui: Arc<Mutex<UiLog>>,
}

impl Harness {
    fn start(verdict: Verdict) -> Self {
        Self::start_with_timeout(verdict, bwl_ssh::APPROVAL_TIMEOUT)
    }

    fn start_with_timeout(verdict: Verdict, approval_timeout: Duration) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let (tx, rx) = mpsc::channel(8);
        let agent = SshAgent::start_with_approval_timeout(
            dir.path().join("agent.sock"),
            tx,
            approval_timeout,
        )
        .expect("agent starts");
        Self {
            dir,
            agent,
            ui: spawn_ui(rx, verdict),
        }
    }

    fn socket(&self) -> &Path {
        self.agent.socket_path()
    }

    fn load(&self, keys: &[&FixtureKey]) {
        let keys = keys.iter().map(|key| key.agent_key()).collect();
        self.agent.replace_keys(keys).expect("keys load");
    }

    async fn list(&self) -> Output {
        ssh_add_list(self.socket()).await
    }

    async fn sign(&self, key: &FixtureKey, namespace: &str) -> Signing {
        sign_message(self.dir.path(), self.socket(), key, namespace).await
    }

    fn ui(&self) -> MutexGuard<'_, UiLog> {
        self.ui.lock().expect("ui log")
    }
}

async fn sign_message(dir: &Path, socket: &Path, key: &FixtureKey, namespace: &str) -> Signing {
    let message = dir.join(format!("{}.msg", key.file));
    fs::write(&message, "message signed through the bw-lite agent\n").expect("message");
    let mut command = tool("ssh-keygen", socket);
    command
        .args(["-Y", "sign", "-n", namespace, "-f"])
        .arg(key.pub_path())
        .arg(&message);
    let output = run(command).await;
    let mut signature = message.clone().into_os_string();
    signature.push(".sig");
    Signing {
        output,
        signature: signature.into(),
        message,
        namespace: namespace.to_owned(),
    }
}

struct Signing {
    output: Output,
    signature: PathBuf,
    message: PathBuf,
    namespace: String,
}

impl Signing {
    fn succeeded(&self) -> bool {
        self.output.status.success() && self.signature.exists()
    }

    async fn verifies(&self) -> bool {
        let mut command = Command::new("ssh-keygen");
        command
            .args(["-Y", "check-novalidate", "-n", &self.namespace, "-s"])
            .arg(&self.signature)
            .stdin(fs::File::open(&self.message).expect("message"));
        run(command).await.status.success()
    }
}

fn tool(program: &str, socket: &Path) -> Command {
    let mut command = Command::new(program);
    command.env("SSH_AUTH_SOCK", socket).stdin(Stdio::null());
    command
}

async fn run(mut command: Command) -> Output {
    timeout(COMMAND_LIMIT, spawn_blocking(move || command.output()))
        .await
        .expect("command finished in time")
        .expect("blocking task")
        .expect("command ran")
}

async fn ssh_add_list(socket: &Path) -> Output {
    let mut command = tool("ssh-add", socket);
    command.arg("-l");
    run(command).await
}

// Sockets created while another test forks a child leak into that child on macOS (CLOEXEC is
// set after socket creation), so a freshly dropped listener can stay reachable for a moment.
async fn wait_until_nobody_listens(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while UnixStream::connect(socket).is_ok() {
        assert!(Instant::now() < deadline, "the listener never went away");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_add_lists_every_key_type_with_fingerprint_and_name() {
    let harness = Harness::start(Verdict::Approve);
    harness.load(&ALL_KEYS);

    let listing = harness.list().await;

    assert!(listing.status.success(), "{}", text(&listing));
    let listing = text(&listing);
    for key in ALL_KEYS {
        let line = listing
            .lines()
            .find(|line| line.contains(key.fingerprint))
            .unwrap_or_else(|| panic!("{} missing from:\n{listing}", key.file));
        assert!(line.contains(&key.name()), "{line}");
    }
    assert_eq!(listing.lines().count(), ALL_KEYS.len(), "{listing}");
    assert!(
        harness.ui().requests.is_empty(),
        "listing needs no approval once keys are loaded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_signing_succeeds_after_approval_for_every_key_type() {
    let harness = Harness::start(Verdict::Approve);
    harness.load(&ALL_KEYS);

    for key in ALL_KEYS {
        let signing = harness.sign(key, "git").await;

        assert!(
            signing.succeeded(),
            "{}: {}",
            key.file,
            text(&signing.output)
        );
        assert!(
            signing.verifies().await,
            "{}: signature does not verify",
            key.file
        );
    }

    let signs = harness.ui().signs();
    assert_eq!(signs.len(), ALL_KEYS.len());
    for (info, key) in signs.iter().zip(ALL_KEYS) {
        assert_eq!(info.cipher_id.as_deref(), Some(key.cipher_id().as_str()));
        assert_eq!(info.process_name.as_deref(), Some("ssh-keygen"));
        assert_eq!(info.namespace.as_deref(), Some("git"));
        assert!(!info.is_forwarding);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_namespace_is_reported_to_the_ui() {
    let harness = Harness::start(Verdict::Approve);
    harness.load(&[&ED25519]);

    let signing = harness.sign(&ED25519, "file").await;

    assert!(signing.succeeded(), "{}", text(&signing.output));
    let signs = harness.ui().signs();
    assert_eq!(signs.len(), 1);
    assert_eq!(signs[0].namespace.as_deref(), Some("file"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passphrase_protected_import_signs_through_the_agent() {
    let harness = Harness::start(Verdict::Approve);
    harness.load(&[&ED25519_ENC]);

    let signing = harness.sign(&ED25519_ENC, "git").await;

    assert!(signing.succeeded(), "{}", text(&signing.output));
    assert!(signing.verifies().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_signing_fails_and_produces_no_signature() {
    let harness = Harness::start(Verdict::Deny);
    harness.load(&[&ED25519]);

    let signing = harness.sign(&ED25519, "git").await;

    assert!(
        !signing.output.status.success(),
        "{}",
        text(&signing.output)
    );
    assert!(!signing.signature.exists());
    assert!(!harness.ui().signs().is_empty(), "the UI was asked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_reply_sender_denies_signing_without_waiting() {
    let harness = Harness::start(Verdict::DropReply);
    harness.load(&[&ED25519]);
    let started = Instant::now();

    let signing = harness.sign(&ED25519, "git").await;

    assert!(!signing.succeeded());
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "denied early, not at the 30 s timeout"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unanswered_request_is_denied_after_the_timeout() {
    let harness = Harness::start_with_timeout(Verdict::Ignore, SHORT_APPROVAL_TIMEOUT);
    harness.load(&[&ED25519]);
    let started = Instant::now();

    let signing = harness.sign(&ED25519, "git").await;

    assert!(!signing.succeeded(), "{}", text(&signing.output));
    assert!(
        started.elapsed() >= SHORT_APPROVAL_TIMEOUT,
        "denied before the timeout: {:?}",
        started.elapsed()
    );
    let ui = harness.ui();
    assert!(!ui.ignored.is_empty());
    assert!(
        ui.ignored.iter().all(oneshot::Sender::is_closed),
        "the UI sees the request expire"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_approval_channel_denies_signing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    let agent = SshAgent::start(dir.path().join("agent.sock"), tx).expect("agent starts");
    agent
        .replace_keys(vec![ED25519.agent_key()])
        .expect("keys load");

    let signing = sign_message(dir.path(), agent.socket_path(), &ED25519, "git").await;

    assert!(!signing.succeeded(), "{}", text(&signing.output));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_before_the_first_unlock_asks_the_ui() {
    let approved = Harness::start(Verdict::Approve);
    let denied = Harness::start(Verdict::Deny);

    let empty = approved.list().await;
    let refused = denied.list().await;

    assert!(text(&empty).contains("no identities"), "{}", text(&empty));
    assert_eq!(approved.ui().list_count(), 1);
    assert!(
        text(&refused).contains("agent refused operation"),
        "{}",
        text(&refused)
    );
    assert_eq!(denied.ui().list_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_keys_swaps_the_served_set_and_skips_unservable_keys() {
    let harness = Harness::start(Verdict::Approve);
    let garbage = AgentKey {
        cipher_id: "cipher-garbage".to_owned(),
        name: "garbage".to_owned(),
        private_key: Zeroizing::new("not a key".to_owned()),
    };
    let encrypted = AgentKey {
        cipher_id: "cipher-encrypted".to_owned(),
        name: "encrypted".to_owned(),
        private_key: Zeroizing::new(
            fs::read_to_string(fixture_path("ed25519_enc")).expect("fixture"),
        ),
    };

    harness
        .agent
        .replace_keys(vec![garbage, ED25519.agent_key(), encrypted])
        .expect("good keys survive bad ones");
    let first = text(&harness.list().await);
    harness.load(&[&RSA]);
    let second = text(&harness.list().await);
    harness.agent.replace_keys(Vec::new()).expect("empty set");
    let third = harness.list().await;

    assert_eq!(first.lines().count(), 1, "{first}");
    assert!(first.contains(ED25519.fingerprint));
    assert_eq!(second.lines().count(), 1, "{second}");
    assert!(second.contains(RSA.fingerprint) && !second.contains(ED25519.fingerprint));
    assert_eq!(third.status.code(), Some(1), "{}", text(&third));
    assert_eq!(
        harness.ui().list_count(),
        0,
        "an initialized store never asks"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socket_is_private_to_the_user() {
    let harness = Harness::start(Verdict::Approve);

    let mode = fs::metadata(harness.socket())
        .expect("socket")
        .permissions()
        .mode();

    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_removes_the_socket_and_refuses_further_keys() {
    let mut harness = Harness::start(Verdict::Approve);
    harness.load(&[&ED25519]);
    let socket = harness.socket().to_path_buf();

    harness.agent.stop();
    harness.agent.stop();

    assert!(!harness.agent.is_running());
    assert!(!socket.exists());
    assert_eq!(ssh_add_list(&socket).await.status.code(), Some(2));
    let error = harness
        .agent
        .replace_keys(vec![ED25519.agent_key()])
        .expect_err("stopped");
    assert!(matches!(
        error.downcast_ref::<AgentError>(),
        Some(AgentError::NotRunning)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_agent_removes_the_socket() {
    let harness = Harness::start(Verdict::Approve);
    let socket = harness.socket().to_path_buf();
    assert!(socket.exists());

    drop(harness.agent);

    assert!(!socket.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_restarts_on_the_same_path_without_old_keys() {
    let mut harness = Harness::start(Verdict::Approve);
    harness.load(&[&ED25519]);
    let socket = harness.socket().to_path_buf();
    harness.agent.stop();
    let (tx, rx) = mpsc::channel(8);

    let restarted = SshAgent::start(socket.clone(), tx).expect("restart on the same path");
    let _ui = spawn_ui(rx, Verdict::Approve);

    restarted
        .replace_keys(vec![RSA.agent_key()])
        .expect("keys load");
    let listing = text(&ssh_add_list(&socket).await);
    assert!(
        listing.contains(RSA.fingerprint) && !listing.contains(ED25519.fingerprint),
        "{listing}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_socket_file_is_replaced() {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("agent.sock");
    drop(UnixListener::bind(&socket).expect("bind"));
    assert!(socket.exists(), "the dead listener leaves its file behind");
    wait_until_nobody_listens(&socket).await;
    let (tx, rx) = mpsc::channel(8);
    let _ui = spawn_ui(rx, Verdict::Approve);

    let agent = SshAgent::start(socket.clone(), tx).expect("stale socket is replaced");

    agent
        .replace_keys(vec![ED25519.agent_key()])
        .expect("keys load");
    assert!(ssh_add_list(&socket).await.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_agent_is_not_hijacked_by_a_second_start() {
    let harness = Harness::start(Verdict::Approve);
    harness.load(&[&ED25519]);
    let (tx, _rx) = mpsc::channel(1);

    let error = SshAgent::start(harness.socket().to_path_buf(), tx)
        .err()
        .expect("refused");

    assert!(matches!(
        error.downcast_ref::<AgentError>(),
        Some(AgentError::AlreadyRunning(_))
    ));
    let listing = text(&harness.list().await);
    assert!(listing.contains(ED25519.fingerprint), "{listing}");
}

#[test]
fn starting_outside_a_runtime_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("agent.sock");
    let (tx, _rx) = mpsc::channel(1);

    let error = SshAgent::start(socket.clone(), tx)
        .err()
        .expect("no runtime");

    assert!(matches!(
        error.downcast_ref::<AgentError>(),
        Some(AgentError::NoRuntime)
    ));
    assert!(!socket.exists());
}

#[test]
fn agent_runs_when_started_under_a_runtime_enter_guard() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("agent.sock");
    let (tx, rx) = mpsc::channel(8);

    let agent = {
        let _enter = runtime.enter();
        SshAgent::start(socket.clone(), tx).expect("agent starts")
    };
    let _ui = runtime.block_on(async { spawn_ui(rx, Verdict::Approve) });

    agent
        .replace_keys(vec![ED25519.agent_key()])
        .expect("keys load");
    let listing = runtime.block_on(ssh_add_list(&socket));
    assert!(listing.status.success(), "{}", text(&listing));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_keygen_accepts_every_imported_format_and_agrees_on_the_fingerprint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let formats = [
        (
            "ed25519_pkcs8",
            "SHA256:sfDG1iJ6szTs6TIfzFKLBsc6ZruG2ApNpekhnev6am4",
        ),
        ("rsa_traditional", RSA.fingerprint),
        ("rsa_pkcs8", RSA.fingerprint),
        ("ecdsa_p256_pkcs8", P256.fingerprint),
        ("ecdsa_p256_sec1", P256.fingerprint),
        ("ecdsa_p384_pkcs8", P384.fingerprint),
        ("ecdsa_p521", P521.fingerprint),
    ];

    for (file, expected) in formats {
        let input = fs::read_to_string(fixture_path(file)).expect("fixture");
        let (pem, public, fingerprint) = import_key(&input, None).expect(file);
        assert_eq!(fingerprint, expected, "{file}");

        let path = dir.path().join(format!("{file}.pem"));
        fs::write(&path, pem.as_bytes()).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let mut fingerprint_cmd = Command::new("ssh-keygen");
        fingerprint_cmd.arg("-lf").arg(&path).stdin(Stdio::null());
        let mut derive_cmd = Command::new("ssh-keygen");
        derive_cmd
            .arg("-y")
            .arg("-f")
            .arg(&path)
            .stdin(Stdio::null());
        let listed = run(fingerprint_cmd).await;
        let derived = run(derive_cmd).await;

        assert!(
            text(&listed).contains(expected),
            "{file}: {}",
            text(&listed)
        );
        let derived = String::from_utf8_lossy(&derived.stdout).into_owned();
        assert_eq!(
            derived.split_whitespace().take(2).collect::<Vec<_>>(),
            public.split_whitespace().take(2).collect::<Vec<_>>(),
            "{file}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_key_has_the_fingerprint_ssh_keygen_computes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (pem, public, fingerprint) = bwl_ssh::generate_ed25519().expect("generate");
    let path = dir.path().join("generated");
    fs::write(&path, pem.as_bytes()).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    let mut command = Command::new("ssh-keygen");
    command.arg("-lf").arg(&path).stdin(Stdio::null());

    let listed = run(command).await;

    assert!(text(&listed).contains(&fingerprint), "{}", text(&listed));
    assert!(public.starts_with("ssh-ed25519 "));
}

#[test]
fn wrong_passphrase_is_a_typed_error_for_the_ui() {
    let input = fs::read_to_string(fixture_path("ed25519_enc")).expect("fixture");

    let error = import_key(&input, Some("nope")).expect_err("wrong passphrase");

    assert!(matches!(
        error.downcast_ref::<ImportError>(),
        Some(ImportError::WrongPassphrase)
    ));
}
