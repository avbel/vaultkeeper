//! `bw-lite --ui`: the windows. Started by the daemon on demand, it proxies `VaultService` to the
//! daemon over `ui.sock`, shows what the daemon asks for, and exits 120 s after its last window
//! closed, at once when the daemon goes away. Copies go to the daemon, which clears them.

pub mod bridge;
pub mod linger;

use std::{
    rc::{Rc, Weak},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use bwl_ipc::{EventStream, IpcError, RemoteVault, UiEvent, UiNotice};
use tokio::sync::mpsc;

use self::{
    bridge::{Bridged, bridge},
    linger::{Linger, decide, linger_from_env},
};
use crate::{
    app::{App, UiCommand},
    hooks::Hooks,
    os::{Notifier, layout::UI_SOCKET},
    run::{Backend, UiOptions, run_ui, select_backend},
};

/// Activity notices reset the daemon's lock timer, which counts in minutes.
const ACTIVITY_EVERY: Duration = Duration::from_secs(30);

pub fn run(first_unlock: bool) -> anyhow::Result<()> {
    let data_dir = crate::os::layout::data_dir().context("locate the data directory")?;
    // One worker: this process only waits on the daemon.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("bw-lite-ui")
        .enable_all()
        .build()
        .context("start the async runtime")?;
    let (remote, events) = match runtime.block_on(RemoteVault::connect(data_dir.join(UI_SOCKET))) {
        Ok(connected) => connected,
        Err(IpcError::Busy) => {
            tracing::info!("another UI process is connected to the daemon");
            return Ok(());
        }
        Err(error) => return Err(error).context("connect to the bw-lite daemon"),
    };
    let remote = Arc::new(remote);
    let notify = notifier(&remote);
    select_backend(Backend::Ui {
        on_input: activity_reporter(Arc::clone(&notify)),
    })?;
    let hooks = Hooks::system(&data_dir, &notify, &remote);
    let linger = Rc::new(LingerTimer {
        timer: slint::Timer::default(),
        linger: linger_from_env(std::env::var("BW_LITE_UI_LINGER_SECS").ok().as_deref()),
    });
    let (commands, received) = mpsc::unbounded_channel();
    let forwarder = runtime.spawn(forward_events(events, commands, Arc::clone(&notify)));
    let on_closed = Rc::clone(&linger);
    let ran = run_ui(
        Arc::clone(&remote),
        hooks,
        runtime.handle().clone(),
        Some(received),
        UiOptions {
            host_tray: false,
            tray_only: true,
            initial: None,
            ui_process: true,
            first_unlock,
        },
        move |app| on_closed.start(app),
    );
    forwarder.abort();
    drop(linger);
    drop(remote);
    runtime.shutdown_timeout(Duration::from_secs(1));
    ran
}

fn notifier(remote: &Arc<RemoteVault>) -> Notifier {
    let remote = Arc::clone(remote);
    Arc::new(move |notice| {
        if let Err(error) = remote.notify(notice) {
            tracing::debug!(%error, ?notice, "notice not sent");
        }
    })
}

/// At most one activity notice per [`ACTIVITY_EVERY`], however fast the user types.
fn activity_reporter(notify: Notifier) -> Box<dyn FnMut()> {
    let mut last: Option<Instant> = None;
    Box::new(move || {
        if last.is_none_or(|sent| sent.elapsed() >= ACTIVITY_EVERY) {
            last = Some(Instant::now());
            notify(UiNotice::Activity);
        }
    })
}

async fn forward_events(
    mut events: EventStream,
    commands: mpsc::UnboundedSender<UiCommand>,
    notify: Notifier,
) {
    let mut received = 0_u64;
    while let Some(event) = events.next().await {
        if matches!(event, UiEvent::Command(_) | UiEvent::SshApproval(_)) {
            received += 1;
            report_alive(&notify, received);
        }
        match bridge(event) {
            Bridged::Command(command) => {
                if commands.send(command).is_err() {
                    break;
                }
            }
            Bridged::Ignore => {}
            Bridged::Quit => break,
        }
    }
    tracing::info!("the daemon went away; exiting");
    let quit = slint::invoke_from_event_loop(|| {
        if let Err(error) = slint::quit_event_loop() {
            tracing::error!(%error, "cannot quit the event loop");
        }
    });
    if let Err(error) = quit {
        tracing::error!(%error, "cannot reach the event loop to quit");
    }
}

/// Answers from the main loop, so a UI whose main thread hangs stays silent and the daemon's
/// watchdog restarts it; this task alone would keep reading the socket.
fn report_alive(notify: &Notifier, received: u64) {
    let notify = Arc::clone(notify);
    if let Err(error) = slint::invoke_from_event_loop(move || notify(UiNotice::Alive(received))) {
        tracing::debug!(%error, "event loop gone; no answer to the daemon");
    }
}

/// One restartable timer: each "last window closed" restarts the full linger.
struct LingerTimer {
    timer: slint::Timer,
    linger: Duration,
}

impl LingerTimer {
    fn start(&self, app: &Weak<App<RemoteVault>>) {
        let app = Weak::clone(app);
        self.timer
            .start(slint::TimerMode::SingleShot, self.linger, move || {
                linger_ended(&app);
            });
    }
}

fn linger_ended(app: &Weak<App<RemoteVault>>) {
    let windows = app.upgrade().map_or(0, |app| app.open_window_count());
    match decide(windows) {
        Linger::Stay => {}
        Linger::ExitNow => {
            tracing::info!("no window for the linger period; exiting");
            if let Err(error) = slint::quit_event_loop() {
                tracing::error!(%error, "cannot quit the event loop");
            }
        }
    }
}
