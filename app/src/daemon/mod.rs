//! `vaultkeeper --daemon` (also `--tray`, which autostart uses): owns the vault, the IPC server, the
//! SSH agent, the lock timer, power events, the tray and the global hotkey. It runs the Slint
//! event loop on the main thread for the tray alone; windows live in the `--ui` process.

pub mod browser;
mod core;
pub mod device;
mod hotkey;
mod hotkey_pause;
pub mod launcher;
pub mod lock;
pub mod routing;
pub mod secrets;
mod security;
mod site_icons;
pub mod ssh;
pub mod target;
pub(crate) mod tray;
pub mod tray_sync;
pub mod update;

#[cfg(not(windows))]
use std::path::Path;
use std::path::PathBuf;
use std::{sync::Arc, time::Duration};

use anyhow::Context;
use vk_platform::single_instance;

pub use self::core::{Daemon, DaemonConfig, Peers};
use self::routing::Launch;
use crate::run::{Backend, select_backend};

/// Test-only switches, read from the environment only in builds with the `vw-it` feature (the
/// data dir override lives in [`crate::os::layout::data_dir`]).
#[derive(Debug, Default)]
struct TestOverrides {
    /// No tray, no hotkey (no menu bar icon, no clash with a running vaultkeeper).
    headless: bool,
    /// Any process of this user may connect as the UI (the test binary drives the daemon).
    any_peer: bool,
    /// Never start `--ui`: the test process is the UI.
    no_ui: bool,
    /// Namespaces the keychain items so a run never touches real ones.
    keychain_prefix: Option<String>,
}

impl TestOverrides {
    #[cfg(feature = "vw-it")]
    fn from_env() -> Self {
        let set = |name: &str| std::env::var_os(name).is_some_and(|value| value == "1");
        Self {
            headless: set("VAULTKEEPER_TEST_HEADLESS"),
            any_peer: set("VAULTKEEPER_TEST_ANY_PEER"),
            no_ui: set("VAULTKEEPER_TEST_NO_UI"),
            keychain_prefix: std::env::var("VAULTKEEPER_TEST_KEYCHAIN_PREFIX").ok(),
        }
    }

    #[cfg(not(feature = "vw-it"))]
    fn from_env() -> Self {
        Self::default()
    }
}

/// The exit status that asks launchd's `KeepAlive` to start the (updated) app again.
#[cfg(target_os = "macos")]
const RESTART_EXIT: i32 = 75;
/// How long an updated app waits for the old daemon to finish shutting down.
#[cfg(unix)]
const WAIT_FOR_PREVIOUS: Duration = Duration::from_secs(30);

/// Points the login item (tray launches) and, on Linux, the launcher entry at this install.
fn refresh_shell_entries(launch: Launch) {
    if launch == Launch::Tray {
        refresh_login_agent();
    }
    #[cfg(target_os = "linux")]
    write_desktop_entry();
}

/// Keeps the launcher entry pointing at this install; a failure costs only the launcher icon.
#[cfg(target_os = "linux")]
fn write_desktop_entry() {
    use crate::os::desktop_entry;
    let (Some(home), Some(exe)) = (
        vk_platform::desktop_file::data_home(),
        vk_platform::install_kind::current_install_path(),
    ) else {
        return;
    };
    if let Err(error) = desktop_entry::ensure(&home, &exe) {
        tracing::warn!(%error, "cannot write the launcher entry");
    }
}

/// The data dir after its startup check, and the socket dir (the runtime dir on Linux). On Linux
/// the process is then non-dumpable and, when requested, sandboxed.
fn prepare_dirs() -> anyhow::Result<(PathBuf, PathBuf)> {
    let data_dir = crate::os::layout::data_dir().context("create the data directory")?;
    crate::os::startup_check::enforce(&data_dir)?;
    let report =
        crate::os::security_gate::enforce(crate::os::security_gate::Role::Daemon, &data_dir)
            .inspect_err(|refusal| crate::refusal::present(&data_dir, &refusal.to_string()))?;
    crate::app::note_start(&report);
    // Nothing reads the daemon's exe: clients check it through daemon_check instead.
    vk_platform::hardening::harden_after_handshake();
    let socket_dir = crate::os::layout::socket_dir(&data_dir);
    vk_platform::fs::ensure_private_dir(&socket_dir).context("create the socket directory")?;
    #[cfg(target_os = "linux")]
    if vk_platform::sandbox::requested() {
        sandbox(&data_dir, &socket_dir);
    }
    Ok((data_dir, socket_dir))
}

/// The UI the daemon starts later inherits the same rule set.
#[cfg(target_os = "linux")]
fn sandbox(data_dir: &Path, socket_dir: &Path) {
    use vk_platform::desktop_file;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let config_home = desktop_file::config_home().unwrap_or_else(|| home.join(".config"));
    let data_home = desktop_file::data_home().unwrap_or_else(|| home.join(".local/share"));
    let cache_home = desktop_file::cache_home().unwrap_or_else(|| home.join(".cache"));
    let log_dir = crate::os::log_file::log_dir().unwrap_or_else(|| data_dir.join("logs"));
    let install = vk_platform::install_kind::current_install_path().unwrap_or_default();
    // Under Homebrew the whole prefix: `opt/vaultkeeper` resolves to a versioned Cellar directory,
    // and the next upgrade's binary lives in another one. Elsewhere `<prefix>/bin/vaultkeeper`.
    let install_text = install.to_string_lossy();
    let install_prefix = install_text.split_once("/opt/vaultkeeper/").map_or_else(
        || {
            install
                .ancestors()
                .nth(2)
                .unwrap_or(Path::new("/"))
                .to_owned()
        },
        |(prefix, _)| PathBuf::from(prefix),
    );
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let rules = vk_platform::sandbox::rules(&vk_platform::sandbox::Dirs {
        home: &home,
        data_dir,
        socket_dir,
        log_dir: &log_dir,
        install_prefix: &install_prefix,
        runtime_dir: runtime_dir.as_deref(),
        config_home: &config_home,
        data_home: &data_home,
        cache_home: &cache_home,
    });
    match vk_platform::sandbox::restrict(&rules) {
        Ok(status) => tracing::info!(%status, "sandbox"),
        Err(error) => tracing::warn!(%error, "the Landlock sandbox could not be applied"),
    }
}

/// The token a launch carried belongs to the window its command opens.
fn keep_launch_token(token: Option<String>) {
    tracing::debug!(token = token.is_some(), "activation token from a launch");
    #[cfg(target_os = "linux")]
    crate::os::linux::activation::offer(token);
    #[cfg(not(target_os = "linux"))]
    drop(token);
}

/// Taken before any thread starts: it is removed from the environment so children never inherit it.
#[cfg(target_os = "linux")]
fn take_launch_token() -> Option<String> {
    crate::os::linux::activation::take_from_environment()
}

#[cfg(not(target_os = "linux"))]
const fn take_launch_token() -> Option<String> {
    None
}

/// `None` when another instance runs: it was asked to show what `launch` asks for.
fn acquire_instance(
    socket_dir: &std::path::Path,
    launch: Launch,
    token: Option<&str>,
    forward: std::sync::mpsc::Sender<(single_instance::Command, Option<String>)>,
) -> anyhow::Result<Option<single_instance::InstanceGuard>> {
    let acquired = single_instance::acquire_in(
        socket_dir,
        routing::forwarded(launch),
        token,
        move |command, token| {
            let _ = forward.send((command, token));
        },
    );
    match acquired {
        Ok(instance) => Ok(Some(instance)),
        Err(vk_platform::Error::AlreadyRunning) => {
            tracing::info!("vaultkeeper is already running; asked it to show a window");
            Ok(None)
        }
        Err(error) => {
            tracing::error!(%error, "cannot start or reach a Vaultkeeper instance");
            Err(error).context("check for a running Vaultkeeper")
        }
    }
}

pub fn run(launch: Launch, wait_for: Option<i32>) -> anyhow::Result<()> {
    let launch_token = take_launch_token();
    let overrides = TestOverrides::from_env();
    // Windows: step 3b - the restart hand-off waits on the old process handle.
    #[cfg(unix)]
    if let Some(pid) = wait_for
        && !single_instance::wait_for_exit(pid, WAIT_FOR_PREVIOUS)
    {
        tracing::warn!(pid, "the previous vaultkeeper is still running");
    }
    #[cfg(not(unix))]
    let _ = wait_for;
    refresh_shell_entries(launch);
    let (data_dir, socket_dir) = prepare_dirs()?;
    let (forward_tx, forward_rx) = std::sync::mpsc::channel();
    let Some(instance) =
        acquire_instance(&socket_dir, launch, launch_token.as_deref(), forward_tx)?
    else {
        return Ok(());
    };
    keep_launch_token(launch_token);
    // Two workers: vault work is short and I/O bound; more threads only cost memory.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("vaultkeeper-daemon")
        .enable_all()
        .build()
        .context("start the async runtime")?;
    select_backend(Backend::Daemon)?;
    let secrets = secrets::open(&data_dir, overrides.keychain_prefix.as_deref());
    // The Linux clipboard portal task is spawned on the runtime that is current here.
    let _runtime_guard = runtime.enter();
    let mut config = DaemonConfig::new(data_dir, secrets);
    if overrides.any_peer {
        config.peers = Peers::AnyOfThisUser;
    }
    if !overrides.no_ui {
        config.ui_exe = Some(std::env::current_exe().context("locate the vaultkeeper binary")?);
    }
    config.self_update = !overrides.headless;
    config.inherit_ui_channel = config.ui_exe.is_some();
    let daemon = runtime.block_on(Daemon::start(config))?;
    let forwarder = {
        let daemon = Arc::clone(&daemon);
        std::thread::Builder::new()
            .name("vaultkeeper-instance".to_owned())
            .spawn(move || {
                for (command, token) in forward_rx {
                    keep_launch_token(token);
                    routing::dispatch_second_launch(
                        command,
                        || daemon.typing_target(),
                        |effect| daemon.apply(effect),
                        quit_event_loop,
                    );
                }
            })
            .context("start the second-launch listener")?
    };
    let shell = (!overrides.headless)
        .then(|| Shell::install(&daemon))
        .transpose()?;
    let power = watch_power(&daemon);
    let network = watch_network(&daemon);
    let signals = runtime.spawn(quit_on_signal());
    if let Some(effect) = routing::startup(
        launch,
        &vk_vault::VaultService::state(daemon.vault().as_ref()),
        !vk_vault::VaultService::accounts(daemon.vault().as_ref()).is_empty(),
        daemon.settings().ask_unlock_on_start,
        || daemon.typing_target(),
    ) {
        daemon.apply(effect);
    }
    tracing::info!(socket = %daemon.data_dir().display(), "vaultkeeper daemon running");
    let ran = slint::run_event_loop_until_quit().context("run the event loop");
    runtime.block_on(daemon.shutdown());
    signals.abort();
    drop((shell, power, network));
    // Still holding the single-instance lock: a browser host or a Dock click must not become the
    // daemon between this one quitting and the updated one starting.
    if let Some(bundle) = daemon.restart_after_shutdown() {
        #[cfg(windows)]
        if let Err(error) = daemon.run_update_installer(&bundle) {
            tracing::error!(
                error = format!("{error:#}"),
                "the update installer did not start"
            );
        }
        #[cfg(not(windows))]
        relaunch(&bundle);
    }
    drop(instance);
    if forwarder.join().is_err() {
        tracing::error!("second-launch listener panicked");
    }
    runtime.shutdown_timeout(Duration::from_secs(2));
    ran
}

/// Starts the upgraded binary, which waits for this process to exit before taking the instance
/// lock. A user unit's `Restart=` does not apply: this exit is a clean one.
#[cfg(target_os = "linux")]
fn relaunch(exe: &Path) {
    let pid = std::process::id().to_string();
    match std::process::Command::new(exe)
        .args(["--tray", "--wait-for", &pid])
        .spawn()
    {
        Ok(_) => tracing::info!(exe = %exe.display(), "started the upgraded Vaultkeeper"),
        Err(error) => tracing::error!(%error, "cannot start the upgraded Vaultkeeper"),
    }
}

/// Starts the updated app. When launchd started this process as the login agent's job, a non-zero
/// exit makes it start the same path again (`KeepAlive { SuccessfulExit = false }`), so the new
/// daemon stays launchd's job and is restarted after a crash; the exit releases the lock.
/// Otherwise LaunchServices opens a new instance, which waits for this process to exit before
/// taking the single-instance lock.
#[cfg(target_os = "macos")]
fn relaunch(bundle: &Path) {
    if vk_platform::autostart::started_by_login_agent() {
        tracing::info!("exiting for launchd to start the updated app");
        std::process::exit(RESTART_EXIT);
    }
    let pid = std::process::id().to_string();
    let opened = std::process::Command::new("/usr/bin/open")
        .args(["-n", "-g"])
        .arg(bundle)
        .args(["--args", "--tray", "--wait-for", &pid])
        .status();
    match opened {
        Ok(status) if status.success() => {
            tracing::info!("started the updated app");
            return;
        }
        Ok(status) => tracing::error!(%status, "LaunchServices did not start the updated app"),
        Err(error) => tracing::error!(%error, "LaunchServices did not start the updated app"),
    }
    // Without LaunchServices the app is not registered as launched, but it runs.
    if let Err(error) = std::process::Command::new(bundle.join("Contents/MacOS/vaultkeeper"))
        .args(["--tray", "--wait-for", &pid])
        .spawn()
    {
        tracing::error!(%error, "cannot start the updated app");
    }
}

/// Gives a login agent written by an older version the restart-after-crash setting.
fn refresh_login_agent() {
    match vk_platform::autostart::refresh() {
        Ok(true) => tracing::info!("login item updated to restart after a crash"),
        Ok(false) => {}
        Err(error) => tracing::warn!(%error, "cannot check the login item"),
    }
}

/// The main-thread parts: tray icon and global hotkey.
struct Shell {
    _tray: tray::Handle,
    _hotkey: Option<std::rc::Rc<hotkey::Hotkey>>,
}

impl Shell {
    fn install(daemon: &Arc<Daemon>) -> anyhow::Result<Self> {
        let tray = tray::install(daemon).context("create the tray icon")?;
        let hotkey = match hotkey::Hotkey::new(daemon) {
            Ok(hotkey) => {
                let hotkey = std::rc::Rc::new(hotkey);
                daemon.report_hotkeys(hotkey_pause::apply(
                    &*hotkey,
                    &daemon.settings(),
                    daemon.hotkeys_paused(),
                ));
                follow_hotkey_setting(daemon, &hotkey)?;
                Some(hotkey)
            }
            Err(error) => {
                tracing::warn!(%error, "no global hotkey");
                None
            }
        };
        Ok(Self {
            _tray: tray,
            _hotkey: hotkey,
        })
    }
}

/// Rebinds on every settings re-read and pause change; while paused nothing is bound.
fn follow_hotkey_setting(
    daemon: &Arc<Daemon>,
    hotkey: &std::rc::Rc<hotkey::Hotkey>,
) -> anyhow::Result<()> {
    let mut settings = daemon.subscribe_settings();
    let mut paused = daemon.subscribe_hotkey_pause();
    let weak = std::rc::Rc::downgrade(hotkey);
    let daemon = Arc::clone(daemon);
    slint::spawn_local(async move {
        loop {
            tokio::select! {
                changed = settings.changed() => if changed.is_err() { break },
                changed = paused.changed() => if changed.is_err() { break },
            }
            let Some(hotkey) = weak.upgrade() else {
                break;
            };
            let fresh = settings.borrow_and_update().clone();
            let pause = *paused.borrow_and_update();
            daemon.report_hotkeys(hotkey_pause::apply(&*hotkey, &fresh, pause));
        }
    })?;
    Ok(())
}

/// Sleep, wake and screen lock; delivered on the main run loop, handled on a small thread.
fn watch_power(daemon: &Arc<Daemon>) -> Option<vk_platform::power::PowerWatcher> {
    let (events_tx, events) = std::sync::mpsc::channel();
    let watcher = match vk_platform::power::subscribe(events_tx) {
        Ok(watcher) => watcher,
        Err(error) => {
            tracing::warn!(%error, "no sleep/wake events; lock on sleep is off");
            return None;
        }
    };
    let daemon = Arc::clone(daemon);
    let spawned = std::thread::Builder::new()
        .name("vaultkeeper-power".to_owned())
        .spawn(move || {
            for event in events {
                tracing::debug!(?event, "power event");
                daemon.power_event(event);
                // Only Windows reports this to the daemon while it can still shut down cleanly.
                #[cfg(windows)]
                if event == vk_platform::power::PowerEvent::SessionEnding {
                    quit_event_loop();
                }
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "cannot watch power events");
    }
    Some(watcher)
}

/// Network path changes, on a small thread: an offline vault probes the server as soon as a
/// network is usable again instead of waiting for its next retry.
fn watch_network(daemon: &Arc<Daemon>) -> Option<vk_platform::network::NetworkWatcher> {
    let (events_tx, events) = std::sync::mpsc::channel();
    let watcher = match vk_platform::network::subscribe(events_tx) {
        Ok(watcher) => watcher,
        Err(error) => {
            tracing::warn!(%error, "no network change events");
            return None;
        }
    };
    let daemon = Arc::clone(daemon);
    let spawned = std::thread::Builder::new()
        .name("vaultkeeper-network".to_owned())
        .spawn(move || {
            for event in events {
                tracing::debug!(?event, "network event");
                daemon.network_event(event);
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "cannot watch network changes");
    }
    Some(watcher)
}

/// SIGTERM (logout, `launchctl`, `kill`) and SIGINT quit like the tray's Quit.
#[cfg(unix)]
async fn quit_on_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut interrupt)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        tracing::warn!("cannot listen for SIGTERM/SIGINT");
        return;
    };
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM: quitting"),
        _ = interrupt.recv() => tracing::info!("SIGINT: quitting"),
    }
    quit_event_loop();
}

fn quit_event_loop() {
    let quit = slint::invoke_from_event_loop(|| {
        if let Err(error) = slint::quit_event_loop() {
            tracing::error!(%error, "cannot quit the event loop");
        }
    });
    if let Err(error) = quit {
        tracing::error!(%error, "cannot reach the event loop to quit");
    }
}

/// Closing the console, logging off and shutting down arrive as console control events.
#[cfg(windows)]
async fn quit_on_signal() {
    use windows_sys::{
        Win32::System::Console::{
            CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT, SetConsoleCtrlHandler,
        },
        core::BOOL,
    };

    // How long the system waits for a handler before terminating the process anyway is 5 s for
    // CTRL_CLOSE and shorter at shutdown; the handler must not return before the quit has run,
    // because returning lets the system kill the process.
    const GRACE: Duration = Duration::from_secs(4);

    unsafe extern "system" fn handler(event: u32) -> BOOL {
        match event {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => {
                tracing::info!(event, "console interrupt: quitting");
                quit_event_loop();
                1
            }
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                tracing::info!(event, "console is going away: quitting");
                quit_event_loop();
                std::thread::sleep(GRACE);
                1
            }
            _ => 0,
        }
    }

    // SAFETY: `handler` is a `'static` function with the signature the API expects, and it only
    // calls thread-safe code.
    if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "cannot listen for console events");
    }
    std::future::pending::<()>().await;
}

#[cfg(not(any(unix, windows)))]
async fn quit_on_signal() {
    std::future::pending::<()>().await;
}
