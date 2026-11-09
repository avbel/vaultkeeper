//! The daemon core in-process (vault + IPC server + SSH agent over a temp data dir and an
//! in-memory secret store), driven by a `RemoteVault` the way the `--ui` process drives it.

#![allow(clippy::unwrap_used)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use bw_lite::{
    daemon::{Daemon, DaemonConfig, Peers, routing::Effect},
    os::{
        ClipboardKeeper,
        layout::{SETTINGS_FILE, SSH_SOCKET, UI_SOCKET},
        settings_file::SettingsFile,
    },
    settings::Settings,
    ui_process::answer,
};
use bwl_ipc::{ClipboardHost, EventStream, RemoteVault, UiCommand, UiEvent, UiNotice};
use bwl_ssh::{ApprovalKind, ApprovalRequest};
use bwl_vault::{
    MemorySecretStore, VaultService,
    model::{Filter, LoginRequest, SessionState},
};
use tokio::{sync::oneshot, task::JoinHandle};
use url::Url;
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(5);

/// Under /tmp: macOS caps socket paths at 104 bytes and `$TMPDIR` is long.
struct DataDir(PathBuf);

impl DataDir {
    fn new() -> Self {
        let dir = PathBuf::from(format!(
            "/tmp/bwl-app-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_settings(dir: &Path, settings: &Settings) {
    SettingsFile::write(&dir.join(SETTINGS_FILE), settings).unwrap();
}

async fn start(dir: &DataDir) -> Arc<Daemon> {
    start_with_clipboard(dir, Arc::new(FakeClipboard::default())).await
}

async fn start_with_clipboard(dir: &DataDir, clipboard: Arc<FakeClipboard>) -> Arc<Daemon> {
    let mut config = DaemonConfig::new(dir.path().to_owned(), Arc::new(MemorySecretStore::new()));
    config.peers = Peers::AnyOfThisUser;
    config.clipboard = clipboard;
    Daemon::start(config).await.unwrap()
}

/// The daemon's pasteboard, so no test touches the user's real one.
#[derive(Default)]
struct FakeClipboard {
    content: Mutex<Option<(String, Option<Duration>)>>,
}

impl FakeClipboard {
    fn content(&self) -> Option<(String, Option<Duration>)> {
        self.content.lock().unwrap().clone()
    }
}

impl ClipboardHost for FakeClipboard {
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<(), String> {
        *self.content.lock().unwrap() = Some((text.to_owned(), clear_after));
        Ok(())
    }

    fn clear_if_ours(&self) {
        *self.content.lock().unwrap() = None;
    }
}

impl ClipboardKeeper for FakeClipboard {
    fn recheck(&self) {}
}

async fn connect(dir: &DataDir) -> (RemoteVault, EventStream) {
    RemoteVault::connect(dir.path().join(UI_SOCKET))
        .await
        .unwrap()
}

async fn next(events: &mut EventStream) -> UiEvent {
    tokio::time::timeout(WAIT, events.next())
        .await
        .expect("an event in time")
        .expect("the daemon is still there")
}

async fn eventually(mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not reached in time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ui_client_sees_the_daemon_vault_and_unreachable_servers_stay_offline() {
    let dir = DataDir::new();
    let daemon = start(&dir).await;
    let (vault, _events) = connect(&dir).await;
    assert!(daemon.ui_connected());
    assert_eq!(vault.state(), SessionState::LoggedOut);
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(bwl_vault::Error::LoggedOut)
    ));

    // Nothing listens on the discard port: a transport failure inside the daemon's real vault.
    let dead = Url::parse("http://127.0.0.1:9/").unwrap();
    let probe = vault.probe_server(&dead).await.unwrap_err();
    assert!(
        probe.is_offline(),
        "the offline flag survives IPC: {probe:?}"
    );
    let login = vault
        .login(
            LoginRequest {
                server: dead,
                email: "a@example.com".to_owned(),
                password: Zeroizing::new("pw".to_owned()),
            },
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(login.is_offline(), "{login:?}");
    assert_eq!(vault.state(), SessionState::LoggedOut);
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_wait_for_the_ui_and_arrive_in_order() {
    let dir = DataDir::new();
    let daemon = start(&dir).await;
    daemon.apply(Effect::Show(UiCommand::ShowManager));
    daemon.apply(Effect::Show(UiCommand::ToggleQuickPanel));
    assert!(!daemon.ui_connected());

    let (_vault, mut events) = connect(&dir).await;
    assert!(matches!(
        next(&mut events).await,
        UiEvent::Command {
            seq: 1,
            command: UiCommand::ShowManager
        }
    ));
    assert!(matches!(
        next(&mut events).await,
        UiEvent::Command {
            seq: 2,
            command: UiCommand::ToggleQuickPanel
        }
    ));
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_follows_the_saved_setting() {
    let dir = DataDir::new();
    write_settings(
        dir.path(),
        &Settings {
            ssh_agent: false,
            ..Settings::default()
        },
    );
    let daemon = start(&dir).await;
    let socket = dir.path().join(SSH_SOCKET);
    assert!(!daemon.ssh_agent_running());
    assert!(!socket.exists());
    let (vault, _events) = connect(&dir).await;

    write_settings(dir.path(), &Settings::default());
    vault.notify(UiNotice::SettingsChanged).unwrap();
    eventually(|| daemon.ssh_agent_running()).await;
    assert!(socket.exists(), "the agent listens at {}", socket.display());

    write_settings(
        dir.path(),
        &Settings {
            ssh_agent: false,
            ..Settings::default()
        },
    );
    vault.notify(UiNotice::SettingsChanged).unwrap();
    eventually(|| !daemon.ssh_agent_running()).await;
    eventually(|| !socket.exists()).await;
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_logged_out_agent_serves_no_keys() {
    let dir = DataDir::new();
    let daemon = start(&dir).await;
    let socket = dir.path().join(SSH_SOCKET);
    eventually(|| socket.exists()).await;
    let listed = tokio::process::Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(!listed.status.success(), "no identities: {stdout}");
    assert!(!stdout.contains("SHA256:"), "{stdout}");
    assert!(
        stdout.contains("no identities"),
        "an empty list without a prompt, not a refusal: {stdout}"
    );
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_tells_the_ui_and_removes_the_sockets() {
    let dir = DataDir::new();
    let daemon = start(&dir).await;
    let (_vault, mut events) = connect(&dir).await;
    let ui_socket = dir.path().join(UI_SOCKET);
    let agent_socket = dir.path().join(SSH_SOCKET);
    assert!(ui_socket.exists() && agent_socket.exists());
    daemon.shutdown().await;
    let last = tokio::time::timeout(WAIT, events.next()).await.unwrap();
    assert!(
        matches!(last, Some(UiEvent::Shutdown) | None),
        "the UI is told to exit: {last:?}"
    );
    assert!(!ui_socket.exists());
    assert!(!agent_socket.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_device_id_survives_a_restart() {
    let dir = DataDir::new();
    let first = start(&dir).await;
    first.shutdown().await;
    let device = std::fs::read(dir.path().join("device.json")).unwrap();
    let second = start(&dir).await;
    second.shutdown().await;
    assert_eq!(
        std::fs::read(dir.path().join("device.json")).unwrap(),
        device
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_outlives_the_ui_process_that_made_it_and_quit_clears_it() {
    let dir = DataDir::new();
    let clipboard = Arc::new(FakeClipboard::default());
    let daemon = start_with_clipboard(&dir, Arc::clone(&clipboard)).await;
    let (first, events) = connect(&dir).await;
    let thirty = Some(Duration::from_secs(30));
    first.copy_to_clipboard("hunter2", thirty).unwrap();
    assert_eq!(clipboard.content(), Some(("hunter2".to_owned(), thirty)));
    drop((first, events));
    eventually(|| !daemon.ui_connected()).await;
    assert_eq!(
        clipboard.content(),
        Some(("hunter2".to_owned(), thirty)),
        "the daemon keeps the copy and its timer when the UI goes"
    );
    let (second, _events) = connect(&dir).await;
    second.clear_clipboard().unwrap();
    assert_eq!(
        clipboard.content(),
        None,
        "a later UI clears an earlier one's copy"
    );
    second.copy_to_clipboard("kept", None).unwrap();
    daemon.shutdown().await;
    assert_eq!(clipboard.content(), None, "quitting clears our copy");
}

/// A stand-in `--ui` executable that never connects, logging the pid of each start to
/// `<its path>.log`. Each test gets a symlink to one script written once: exec'ing a file that
/// was just written while another test thread forks fails with ETXTBSY.
fn hanging_ui(dir: &DataDir) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    static SCRIPT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let script = SCRIPT.get_or_init(|| {
        let script = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bwl-hanging-ui.sh");
        if !script.exists() {
            std::fs::write(&script, "#!/bin/sh\necho $$ >> \"$0.log\"\nexec sleep 30\n").unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        script
    });
    let link = dir.path().join("hanging-ui");
    std::os::unix::fs::symlink(script, &link).unwrap();
    let log = dir.path().join("hanging-ui.log");
    (link, log)
}

fn starts(log: &Path) -> usize {
    pids(log).len()
}

fn pids(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log).map_or_else(
        |_| Vec::new(),
        |text| text.lines().map(str::to_owned).collect(),
    )
}

fn alive(pid: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", pid])
        .status()
        .unwrap()
        .success()
}

async fn start_with_ui(dir: &DataDir, ui_exe: PathBuf, hang_after: Duration) -> Arc<Daemon> {
    let mut config = DaemonConfig::new(dir.path().to_owned(), Arc::new(MemorySecretStore::new()));
    config.peers = Peers::AnyOfThisUser;
    config.clipboard = Arc::new(FakeClipboard::default());
    config.ui_exe = Some(ui_exe);
    config.ui_hang_after = hang_after;
    Daemon::start(config).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ui_that_never_answers_is_killed_and_replaced() {
    let dir = DataDir::new();
    let (script, log) = hanging_ui(&dir);
    let daemon = start_with_ui(&dir, script, Duration::from_millis(300)).await;
    daemon.apply(Effect::Show(UiCommand::ShowManager));
    eventually(|| starts(&log) >= 2).await;
    let first = pids(&log).remove(0);
    eventually(|| !alive(&first)).await;
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ui_that_answers_from_its_main_loop_is_kept() {
    let dir = DataDir::new();
    let (script, log) = hanging_ui(&dir);
    // Long enough that a loaded machine cannot fail the setup below on its own.
    let hang_after = Duration::from_secs(2);
    let daemon = start_with_ui(&dir, script, hang_after).await;
    // The started process plays dead; the test plays the UI it would have become, so the
    // watchdog's victim would be that process.
    daemon.apply(Effect::Show(UiCommand::ShowManager));
    eventually(|| starts(&log) >= 1).await;
    let (ui, mut events) = connect(&dir).await;
    let shown = next(&mut events).await;
    assert!(matches!(
        shown,
        UiEvent::Command {
            command: UiCommand::ShowManager,
            ..
        }
    ));
    ui.notify(answer(&shown).unwrap()).unwrap();
    // A file panel holds the main loop: the next command waits for the user, not the watchdog.
    ui.notify(UiNotice::Modal(true)).unwrap();
    daemon.apply(Effect::Show(UiCommand::ShowGenerator));
    assert!(matches!(
        next(&mut events).await,
        UiEvent::Command {
            command: UiCommand::ShowGenerator,
            ..
        }
    ));
    tokio::time::sleep(hang_after + Duration::from_millis(700)).await;
    assert_eq!(starts(&log), 1, "nothing replaced");
    assert!(alive(&pids(&log)[0]), "nothing killed");
    assert!(daemon.ui_connected());
    daemon.shutdown().await;
}

/// Plays a healthy `--ui` process: every event is answered as `ui_process` answers it from its
/// main loop, approvals are left to the user (never answered).
fn healthy_ui(ui: RemoteVault, mut events: EventStream) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut prompts = Vec::new();
        while let Some(event) = events.next().await {
            if let Some(answer) = answer(&event) {
                ui.notify(answer).unwrap();
            }
            if let UiEvent::SshApproval(approval) = event {
                prompts.push(approval);
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ssh_request_given_up_before_the_ui_connected_does_not_get_it_killed() {
    let dir = DataDir::new();
    let (script, log) = hanging_ui(&dir);
    let hang_after = Duration::from_secs(2);
    let daemon = start_with_ui(&dir, script, hang_after).await;
    // A sign request while no UI is connected queues a prompt and starts one; the ssh client gives
    // up (Ctrl-C, its timeout) before that UI connects.
    let (reply, agent) = oneshot::channel();
    let request = ApprovalRequest {
        kind: ApprovalKind::Sign {
            cipher_id: Some("cipher".to_owned()),
            process_name: Some("git".to_owned()),
            is_forwarding: false,
            namespace: Some("git".to_owned()),
        },
        reply,
    };
    let asking = tokio::spawn({
        let daemon = Arc::clone(&daemon);
        async move { daemon.approve(request).await }
    });
    eventually(|| starts(&log) >= 1).await;
    drop(agent);
    tokio::time::timeout(WAIT, asking).await.unwrap().unwrap();
    let pid = pids(&log).remove(0);
    let (ui, events) = connect(&dir).await;
    let answering = healthy_ui(ui, events);
    tokio::time::sleep(hang_after + Duration::from_millis(700)).await;
    assert!(alive(&pid), "the dead request alone got the UI killed");
    daemon.apply(Effect::Show(UiCommand::ShowManager));
    tokio::time::sleep(hang_after + Duration::from_millis(700)).await;
    assert!(
        alive(&pid),
        "the command after the dead request got the UI killed"
    );
    assert_eq!(starts(&log), 1, "nothing replaced");
    assert!(daemon.ui_connected());
    daemon.shutdown().await;
    answering.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_lost_with_a_killed_ui_do_not_get_its_replacement_killed() {
    let dir = DataDir::new();
    let (script, log) = hanging_ui(&dir);
    let hang_after = Duration::from_secs(2);
    let daemon = start_with_ui(&dir, script, hang_after).await;
    let sent = tokio::time::Instant::now();
    daemon.apply(Effect::Show(UiCommand::ShowManager));
    eventually(|| starts(&log) >= 1).await;
    // A hung UI: it takes both commands from the daemon but its main loop never gets to them.
    let (ui, mut events) = connect(&dir).await;
    next(&mut events).await;
    tokio::time::sleep_until(sent + hang_after / 2).await;
    daemon.apply(Effect::Show(UiCommand::ShowGenerator));
    next(&mut events).await;
    // Gone before the first command's watcher kills it, so the daemon can start a replacement.
    drop((ui, events));
    eventually(|| starts(&log) >= 2).await;
    let [first, second] = <[String; 2]>::try_from(pids(&log)).unwrap();
    eventually(|| !alive(&first)).await;
    // The second command's watcher fires after the replacement started; that command went with
    // the killed UI, so it must not count against the new one.
    tokio::time::sleep_until(sent + hang_after / 2 + hang_after + Duration::from_millis(700)).await;
    assert!(
        alive(&second),
        "the replacement was killed for its predecessor's command"
    );
    assert_eq!(starts(&log), 2, "no third start");
    daemon.shutdown().await;
}
