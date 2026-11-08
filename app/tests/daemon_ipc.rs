//! The daemon core in-process (vault + IPC server + SSH agent over a temp data dir and an
//! in-memory secret store), driven by a `RemoteVault` the way the `--ui` process drives it.

#![allow(clippy::unwrap_used)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bw_lite::{
    daemon::{Daemon, DaemonConfig, Peers, routing::Effect},
    os::{
        layout::{SETTINGS_FILE, SSH_SOCKET, UI_SOCKET},
        settings_file::SettingsFile,
    },
    settings::{Settings, ThemeChoice},
};
use bwl_ipc::{EventStream, RemoteVault, UiCommand, UiEvent, UiNotice};
use bwl_vault::{
    MemorySecretStore, VaultService,
    model::{Filter, LoginRequest, SessionState},
};
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
    let mut config = DaemonConfig::new(dir.path().to_owned(), Arc::new(MemorySecretStore::new()));
    config.peers = Peers::AnyOfThisUser;
    Daemon::start(config).await.unwrap()
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
        UiEvent::Command(UiCommand::ShowManager)
    ));
    assert!(matches!(
        next(&mut events).await,
        UiEvent::Command(UiCommand::ToggleQuickPanel)
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
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_theme_from_the_tray_is_saved_and_the_ui_reloads() {
    let dir = DataDir::new();
    write_settings(
        dir.path(),
        &Settings {
            hotkey: "Cmd+Alt+K".to_owned(),
            ..Settings::default()
        },
    );
    let daemon = start(&dir).await;
    let (_vault, mut events) = connect(&dir).await;
    let seen = daemon.subscribe_settings();
    daemon.apply(Effect::SetTheme(ThemeChoice::Dark));
    let saved = SettingsFile::read(&dir.path().join(SETTINGS_FILE));
    assert_eq!(saved.theme, ThemeChoice::Dark);
    assert_eq!(saved.hotkey, "Cmd+Alt+K", "other settings are kept");
    assert!(matches!(
        next(&mut events).await,
        UiEvent::Command(UiCommand::ReloadSettings)
    ));
    assert!(
        seen.has_changed().unwrap(),
        "the tray and hotkey watchers hear it"
    );
    assert_eq!(daemon.settings().theme, ThemeChoice::Dark);
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
