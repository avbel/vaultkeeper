//! The Linux shortcut backend: the desktop's GlobalShortcuts portal binds the Quick Panel and
//! Generator shortcuts and tells the daemon when one fires. The desktop owns the binding (the user
//! may change it in its own settings), so the saved accelerator is only the preferred trigger.
//! Without the portal Settings shows the compositor lines to paste instead.

use std::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use ashpd::{
    Error as PortalError,
    desktop::{
        Session,
        global_shortcuts::{
            BindShortcutsOptions, ConfigureShortcutsOptions, GlobalShortcuts, ListShortcutsOptions,
            NewShortcut, Shortcut,
        },
    },
};
use futures_util::{Stream, StreamExt as _};
use tokio::{sync::mpsc, task::JoinHandle};
use vk_ipc::HotkeyMode;

use super::portal_plan::{self, desired, needs_bind, shortcut_id};
use crate::{
    daemon::{
        Daemon,
        core::HotkeyBindings,
        hotkey_pause::HotkeyBinder,
        routing::{self, HotkeySlot},
    },
    os::linux::{hotkey_status, portal},
};

/// A portal call that answers on its own: the portal is stuck when it takes longer.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Binding may wait on a dialog the user has to answer (GNOME asks once per shortcut).
const BIND_TIMEOUT: Duration = Duration::from_secs(180);
/// Before another attempt after the portal was unreachable or its session ended.
const RECONNECT_DELAY: Duration = Duration::from_secs(15);
const ACTIVATION_TOKEN_KEY: &str = "activation_token";

type Wanted = Vec<(HotkeySlot, String)>;

/// Shown by the desktop in its own shortcut settings.
const fn description(slot: HotkeySlot) -> &'static str {
    match slot {
        HotkeySlot::QuickPanel => "Open the Vaultkeeper Quick Panel",
        HotkeySlot::Generator => "Open the Vaultkeeper password generator",
    }
}

enum Control {
    Wanted(Wanted),
    Configure,
}

static CONTROL: OnceLock<mpsc::UnboundedSender<Control>> = OnceLock::new();
static PENDING_TOKEN: Mutex<Option<(Instant, String)>> = Mutex::new(None);
/// A token that has waited longer was not meant for the UI that starts now.
const TOKEN_LIFETIME: Duration = Duration::from_secs(10);

/// The `Hotkey` the daemon shell holds: `bind` only records what is wanted, and a task on the
/// daemon's runtime talks to the portal.
pub struct Hotkey {
    wanted: RefCell<Wanted>,
    control: mpsc::UnboundedSender<Control>,
    task: JoinHandle<()>,
}

impl Hotkey {
    #[allow(
        clippy::unnecessary_wraps,
        reason = "same seam as the global-hotkey backend"
    )]
    pub fn new(daemon: &Arc<Daemon>) -> anyhow::Result<Self> {
        let (control, requests) = mpsc::unbounded_channel();
        let _ = CONTROL.set(control.clone());
        let task = daemon
            .runtime_handle()
            .spawn(run(Arc::clone(daemon), requests));
        Ok(Self {
            wanted: RefCell::new(Vec::new()),
            control,
            task,
        })
    }
}

impl HotkeyBinder for Hotkey {
    fn bind(&self, slot: HotkeySlot, accelerator: &str) -> anyhow::Result<()> {
        let mut wanted = self.wanted.borrow_mut();
        wanted.retain(|(bound, _)| *bound != slot);
        wanted.push((slot, accelerator.trim().to_owned()));
        self.control
            .send(Control::Wanted(wanted.clone()))
            .map_err(|_| anyhow::anyhow!("the shortcut task has stopped"))
    }
}

impl Drop for Hotkey {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Opens the desktop's shortcut settings for the shortcuts bound through the portal.
pub fn configure_system_shortcuts() {
    if let Some(control) = CONTROL.get() {
        let _ = control.send(Control::Configure);
    }
}

/// The activation token the last shortcut press carried, handed to the UI process that press
/// starts as `XDG_ACTIVATION_TOKEN`. A token works once, so it is taken, not copied.
pub fn take_activation_token() -> Option<String> {
    let pending = PENDING_TOKEN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    pending
        .filter(|(stored, _)| stored.elapsed() < TOKEN_LIFETIME)
        .map(|(_, token)| token)
}

fn store_activation_token(token: Option<String>) {
    *PENDING_TOKEN.lock().unwrap_or_else(PoisonError::into_inner) =
        token.map(|token| (Instant::now(), token));
}

type Activations = Pin<Box<dyn Stream<Item = (String, Option<String>)> + Send>>;

/// A live session and what it has bound so far.
struct Live {
    link: Link,
    activations: Activations,
    bound: Wanted,
}

/// What the calls need; kept apart from the activation stream, which is not `Sync`.
struct Link {
    portal: GlobalShortcuts,
    session: Session<GlobalShortcuts>,
}

enum Backend {
    /// Not contacted yet, or waiting to try again.
    Idle,
    Live(Box<Live>),
    /// The desktop has no GlobalShortcuts portal; trying again cannot help.
    Missing,
}

async fn run(daemon: Arc<Daemon>, mut requests: mpsc::UnboundedReceiver<Control>) {
    let mut wanted = Wanted::new();
    let mut backend = Backend::Idle;
    let mut retry = false;
    loop {
        let activation = async {
            match &mut backend {
                Backend::Live(live) => live.activations.next().await,
                Backend::Idle | Backend::Missing => std::future::pending().await,
            }
        };
        let reconnect = async {
            if retry {
                tokio::time::sleep(RECONNECT_DELAY).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            request = requests.recv() => match request {
                Some(Control::Wanted(fresh)) => wanted = fresh,
                Some(Control::Configure) => {
                    let link = match &backend {
                        Backend::Live(live) => Some(&live.link),
                        Backend::Idle | Backend::Missing => None,
                    };
                    configure(link).await;
                    continue;
                }
                None => break,
            },
            pressed = activation => {
                if let Some((id, token)) = pressed {
                    press(&daemon, &wanted, &id, token);
                } else {
                    tracing::warn!("the GlobalShortcuts Activated stream ended; the global shortcuts are off until the portal is back");
                    close(&mut backend).await;
                    hotkey_status::set(Err("the portal's shortcut session ended".to_owned()));
                    retry = true;
                }
                continue;
            }
            () = reconnect => {}
        }
        retry = sync(&daemon, &wanted, &mut backend).await;
    }
    close(&mut backend).await;
}

/// `true` when the portal could not be reached this time and another attempt is due.
async fn sync(daemon: &Arc<Daemon>, wanted: &Wanted, backend: &mut Backend) -> bool {
    let desired = desired(wanted);
    if desired.is_empty() || matches!(backend, Backend::Missing) {
        return false;
    }
    if matches!(backend, Backend::Idle) {
        match connect().await {
            Ok(live) => *backend = Backend::Live(Box::new(live)),
            Err(PortalError::PortalNotFound(interface)) => {
                tracing::info!(%interface, "no GlobalShortcuts portal; shortcuts are bound in the compositor");
                *backend = Backend::Missing;
                hotkey_status::set(Err("this desktop has no GlobalShortcuts portal".to_owned()));
                daemon.report_hotkey_bindings(bindings(
                    HotkeyMode::Manual,
                    String::new(),
                    String::new(),
                ));
                return false;
            }
            Err(error) => {
                tracing::warn!(%error, "cannot reach the GlobalShortcuts portal");
                hotkey_status::set(Err(error.to_string()));
                return true;
            }
        }
    }
    let Backend::Live(live) = backend else {
        return false;
    };
    if !needs_bind(&live.bound, &desired) {
        return false;
    }
    match bind(&live.link, &desired).await {
        Ok(listed) => {
            live.bound = desired;
            hotkey_status::set(Ok(()));
            report(daemon, &listed);
        }
        Err(error) => {
            tracing::warn!(%error, "the GlobalShortcuts portal refused the shortcuts");
            hotkey_status::set(Err(error.to_string()));
        }
    }
    false
}

#[allow(
    clippy::default_trait_access,
    reason = "ashpd does not export the session options type"
)]
async fn connect() -> Result<Live, PortalError> {
    portal::ensure_registered().await;
    let portal = within(CALL_TIMEOUT, GlobalShortcuts::new()).await?;
    let session = within(CALL_TIMEOUT, portal.create_session(Default::default())).await?;
    let activations = within(CALL_TIMEOUT, portal.receive_activated()).await?;
    let activations: Activations = Box::pin(activations.map(|activated| {
        let token = activated
            .options()
            .get(ACTIVATION_TOKEN_KEY)
            .and_then(|value| <&str>::try_from(value).ok())
            .map(str::to_owned);
        (activated.shortcut_id().to_owned(), token)
    }));
    Ok(Live {
        link: Link { portal, session },
        activations,
        bound: Wanted::new(),
    })
}

/// Binds every desired shortcut and returns what the desktop lists afterwards.
async fn bind(link: &Link, desired: &Wanted) -> Result<Vec<Shortcut>, PortalError> {
    let shortcuts: Vec<NewShortcut> = desired
        .iter()
        .map(|(slot, trigger)| {
            NewShortcut::new(shortcut_id(*slot), description(*slot))
                .preferred_trigger(trigger.as_str())
        })
        .collect();
    let request = within(
        BIND_TIMEOUT,
        link.portal.bind_shortcuts(
            &link.session,
            &shortcuts,
            None,
            BindShortcutsOptions::default(),
        ),
    )
    .await?;
    let bound = request.response()?;
    let listed = within(
        CALL_TIMEOUT,
        link.portal
            .list_shortcuts(&link.session, ListShortcutsOptions::default()),
    )
    .await
    .and_then(|request| request.response());
    Ok(listed.map_or_else(
        |_| bound.shortcuts().to_vec(),
        |list| list.shortcuts().to_vec(),
    ))
}

fn report(daemon: &Arc<Daemon>, shortcuts: &[Shortcut]) {
    let (quick_panel, generator) = portal_plan::trigger_descriptions(
        shortcuts
            .iter()
            .map(|shortcut| (shortcut.id(), shortcut.trigger_description())),
    );
    daemon.report_hotkey_bindings(bindings(HotkeyMode::Portal, quick_panel, generator));
}

fn bindings(mode: HotkeyMode, quick_panel: String, generator: String) -> HotkeyBindings {
    HotkeyBindings {
        mode,
        quick_panel,
        generator,
    }
}

/// A press of a shortcut that is no longer wanted (paused for a recorder, or cleared) is dropped:
/// the portal cannot unbind, so it still delivers it.
fn press(daemon: &Arc<Daemon>, wanted: &Wanted, id: &str, token: Option<String>) {
    let Some(slot) = portal_plan::slot_for_id(id) else {
        return;
    };
    let active = wanted
        .iter()
        .any(|(wanted, accelerator)| *wanted == slot && !accelerator.is_empty());
    if !active {
        return;
    }
    tracing::debug!(?slot, token = token.is_some(), "global shortcut pressed");
    store_activation_token(token);
    let daemon = Arc::clone(daemon);
    // `typing_target` may wait on another thread, so the press is applied off the portal task.
    tokio::task::spawn_blocking(move || {
        daemon.apply(routing::hotkey(slot, || daemon.typing_target()));
    });
}

async fn configure(link: Option<&Link>) {
    let Some(link) = link else {
        tracing::info!("no shortcut session to configure");
        return;
    };
    let configured = within(
        CALL_TIMEOUT,
        link.portal
            .configure_shortcuts(&link.session, None, ConfigureShortcutsOptions::default()),
    )
    .await;
    if let Err(error) = configured {
        tracing::warn!(%error, "the desktop did not open its shortcut settings");
    }
}

async fn close(backend: &mut Backend) {
    if let Backend::Live(live) = std::mem::replace(backend, Backend::Idle) {
        let _ = within(CALL_TIMEOUT, live.link.session.close()).await;
    }
}

/// Maps a timeout to the portal error type the callers already handle.
async fn within<T>(
    limit: Duration,
    call: impl Future<Output = Result<T, PortalError>>,
) -> Result<T, PortalError> {
    tokio::time::timeout(limit, call)
        .await
        .unwrap_or_else(|_| Err(PortalError::IO(std::io::ErrorKind::TimedOut.into())))
}
