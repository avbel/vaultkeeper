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
mod site_icons;
pub mod ssh;
pub mod target;
mod tray;
pub mod tray_sync;

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

pub fn run(launch: Launch) -> anyhow::Result<()> {
    let overrides = TestOverrides::from_env();
    if launch == Launch::Tray {
        refresh_login_agent();
    }
    let data_dir = crate::os::layout::data_dir().context("create the data directory")?;
    let (forward_tx, forward_rx) = std::sync::mpsc::channel();
    let instance = match single_instance::acquire_in(&data_dir, routing::forwarded(launch), {
        move |command| {
            let _ = forward_tx.send(command);
        }
    }) {
        Ok(instance) => instance,
        Err(vk_platform::Error::AlreadyRunning) => {
            tracing::info!("vaultkeeper is already running; asked it to show a window");
            return Ok(());
        }
        Err(error) => return Err(error).context("check for a running Vaultkeeper"),
    };
    // Two workers: vault work is short and I/O bound; more threads only cost memory.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("vaultkeeper-daemon")
        .enable_all()
        .build()
        .context("start the async runtime")?;
    select_backend(Backend::Daemon)?;
    let mut config = DaemonConfig::new(
        data_dir,
        Arc::new(match overrides.keychain_prefix.clone() {
            Some(prefix) => secrets::KeychainStore::with_prefix(prefix),
            None => secrets::KeychainStore::new(),
        }),
    );
    if overrides.any_peer {
        config.peers = Peers::AnyOfThisUser;
    }
    if !overrides.no_ui {
        config.ui_exe = Some(std::env::current_exe().context("locate the vaultkeeper binary")?);
    }
    let daemon = runtime.block_on(Daemon::start(config))?;
    let forwarder = {
        let daemon = Arc::clone(&daemon);
        std::thread::Builder::new()
            .name("vaultkeeper-instance".to_owned())
            .spawn(move || {
                for command in forward_rx {
                    daemon.apply(routing::second_launch(command));
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
        daemon.settings().ask_unlock_on_start,
    ) {
        daemon.apply(effect);
    }
    tracing::info!(socket = %daemon.data_dir().display(), "vaultkeeper daemon running");
    let ran = slint::run_event_loop_until_quit().context("run the event loop");
    runtime.block_on(daemon.shutdown());
    signals.abort();
    drop((shell, power, network));
    drop(instance);
    if forwarder.join().is_err() {
        tracing::error!("second-launch listener panicked");
    }
    runtime.shutdown_timeout(Duration::from_secs(2));
    ran
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
    _tray: crate::ui::TrayIcon,
    _hotkey: Option<std::rc::Rc<hotkey::Hotkey>>,
}

impl Shell {
    fn install(daemon: &Arc<Daemon>) -> anyhow::Result<Self> {
        let tray = tray::install(daemon).context("create the tray icon")?;
        let hotkey = match hotkey::Hotkey::new(daemon) {
            Ok(hotkey) => {
                let hotkey = std::rc::Rc::new(hotkey);
                hotkey_pause::apply(&*hotkey, &daemon.settings(), daemon.hotkeys_paused());
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
            hotkey_pause::apply(&*hotkey, &fresh, pause);
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
    let quit = slint::invoke_from_event_loop(|| {
        if let Err(error) = slint::quit_event_loop() {
            tracing::error!(%error, "cannot quit the event loop");
        }
    });
    if let Err(error) = quit {
        tracing::error!(%error, "cannot reach the event loop to quit");
    }
}
