//! The Linux shortcut backend: the desktop's GlobalShortcuts portal binds the Quick Panel and
//! Generator shortcuts and tells the daemon when one fires. The desktop owns the binding (the user
//! may change it in its own settings), so the saved accelerator is only the preferred trigger.
//! Without the portal Settings shows the compositor lines to paste instead.

use std::{
    cell::RefCell,
    future::Future,
    sync::{Arc, OnceLock},
    time::Duration,
};

use ashpd::{
    Error as PortalError,
    desktop::{
        Session,
        global_shortcuts::{
            BindShortcutsOptions, ConfigureShortcutsOptions, GlobalShortcuts, ListShortcutsOptions,
            NewShortcut,
        },
    },
    zbus,
};
use futures_util::{Stream, StreamExt as _};
use tokio::{sync::mpsc, task::JoinHandle};
use vk_ipc::HotkeyMode;

use super::portal_plan::{self, Plan, desired, plan, shortcut_id};
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
/// Before another attempt after the portal was unreachable or its session ended.
const RECONNECT_DELAY: Duration = Duration::from_secs(15);
/// After a portal restart a hardened process is refused until it restarts too; asking again
/// cannot change that, so the retries stop after this many refusals in a row.
const REFUSALS_BEFORE_GIVING_UP: u8 = 3;
/// A burst of binds (one per slot) is folded into one portal call.
const COALESCE: Duration = Duration::from_millis(50);
const ACTIVATION_TOKEN_KEY: &str = "activation_token";
const WAITING_FOR_DIALOG: &str = "waiting for you to confirm the shortcuts in the desktop's dialog";
const PORTAL_BUS_NAME: &str = "org.freedesktop.portal.Desktop";

type Wanted = Vec<(HotkeySlot, String)>;

/// Shown by the desktop in its own shortcut settings.
const fn description(slot: HotkeySlot) -> &'static str {
    match slot {
        HotkeySlot::QuickPanel => "Open the Vaultkeeper Quick Panel",
        HotkeySlot::Generator => "Open the Vaultkeeper password generator",
    }
}

enum Control {
    /// The saved accelerators and whether a recorder has paused them, sampled together so the
    /// session never sees an unpaused state with still-empty slots.
    Wanted(Wanted, bool),
    Configure,
}

static CONTROL: OnceLock<mpsc::UnboundedSender<Control>> = OnceLock::new();

/// The `Hotkey` the daemon shell holds: `bind` only records what is wanted, and a task on the
/// daemon's runtime talks to the portal.
pub struct Hotkey {
    daemon: Arc<Daemon>,
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
            daemon: Arc::clone(daemon),
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
            .send(Control::Wanted(
                wanted.clone(),
                self.daemon.hotkeys_paused(),
            ))
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

/// `(shortcut id, the desktop's description of its trigger)`.
type Listed = Vec<(String, String)>;

enum Event {
    Activated(String, Option<String>),
    Changed(Listed),
    /// The desktop closed the session, the portal restarted, or the bus went away: nothing will
    /// be delivered on this session any more.
    Closed,
}

/// Stops the signal watchers of a session when it is dropped.
struct Watchers(Vec<JoinHandle<()>>);

impl Drop for Watchers {
    fn drop(&mut self) {
        for watcher in &self.0 {
            watcher.abort();
        }
    }
}

/// A live session and what it has bound so far.
struct Live {
    link: Link,
    events: mpsc::UnboundedReceiver<Event>,
    bound: Wanted,
    _watchers: Watchers,
}

/// What the calls need.
struct Link {
    portal: GlobalShortcuts,
    session: Arc<Session<GlobalShortcuts>>,
}

enum Bound {
    Done(Result<Listed, PortalError>),
    SessionEnded,
    ControlsClosed,
}

fn absorb(request: Control, wanted: &mut Wanted, paused: &mut bool, configure_pending: &mut bool) {
    match request {
        Control::Wanted(fresh, now_paused) => {
            *wanted = fresh;
            *paused = now_paused;
        }
        Control::Configure => *configure_pending = true,
    }
}

enum Backend {
    /// Not contacted yet, or waiting to try again.
    Idle,
    Live(Box<Live>),
    /// The desktop has no GlobalShortcuts portal; trying again cannot help.
    Missing,
    /// The portal keeps refusing this process; only a restart of Vaultkeeper helps.
    Refused,
}

struct Task {
    daemon: Arc<Daemon>,
    wanted: Wanted,
    /// A Settings recorder is waiting for a key: nothing is bound or dropped meanwhile.
    paused: bool,
    backend: Backend,
    /// The portal could not be reached or its session ended; another attempt is due.
    retry: bool,
    /// "Change in system settings…" was clicked while no session could take it yet.
    configure_pending: bool,
    refusals: u8,
    /// Wanted shortcuts changed while a bind waited on the desktop's dialog.
    resync: bool,
}

async fn run(daemon: Arc<Daemon>, mut requests: mpsc::UnboundedReceiver<Control>) {
    let mut task = Task {
        daemon,
        wanted: Wanted::new(),
        paused: false,
        backend: Backend::Idle,
        retry: false,
        configure_pending: false,
        refusals: 0,
        resync: false,
    };
    loop {
        let event = async {
            match &mut task.backend {
                Backend::Live(live) => live.events.recv().await,
                Backend::Idle | Backend::Missing | Backend::Refused => std::future::pending().await,
            }
        };
        let reconnect = async {
            if task.retry {
                tokio::time::sleep(RECONNECT_DELAY).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            request = requests.recv() => {
                let Some(first) = request else { break };
                task.on_request(first, &mut requests).await;
            }
            event = event => {
                if !task.on_event(event, &mut requests).await {
                    // A session that ended is retried by the timer or a new request, never at
                    // once: a desktop that keeps closing it must not be hammered with dialogs.
                    continue;
                }
            }
            () = reconnect => {}
        }
        task.flush_configure().await;
        task.retry = task.sync(&mut requests).await;
        while std::mem::take(&mut task.resync) {
            task.retry = task.sync(&mut requests).await;
        }
    }
    close(&mut task.backend).await;
}

impl Task {
    /// Folds every queued request in; a "Change in system settings…" among them is kept.
    fn drain(&mut self, requests: &mut mpsc::UnboundedReceiver<Control>) {
        while let Ok(request) = requests.try_recv() {
            self.take(request);
        }
    }

    fn take(&mut self, request: Control) {
        absorb(
            request,
            &mut self.wanted,
            &mut self.paused,
            &mut self.configure_pending,
        );
    }

    /// Opens the desktop's dialog once a session exists; until then the click waits.
    async fn flush_configure(&mut self) {
        if !self.configure_pending {
            return;
        }
        let Backend::Live(live) = &self.backend else {
            tracing::info!("no shortcut session to configure yet");
            return;
        };
        self.configure_pending = false;
        configure(&live.link).await;
    }
}

impl Task {
    async fn on_request(
        &mut self,
        first: Control,
        requests: &mut mpsc::UnboundedReceiver<Control>,
    ) {
        let wanted_changed = matches!(first, Control::Wanted(..));
        self.take(first);
        if wanted_changed {
            tokio::time::sleep(COALESCE).await;
        }
        self.drain(requests);
    }

    /// `false` when the session ended and the portal must not be contacted again straight away.
    async fn on_event(
        &mut self,
        event: Option<Event>,
        requests: &mut mpsc::UnboundedReceiver<Control>,
    ) -> bool {
        match event {
            Some(Event::Activated(id, token)) => {
                self.drain(requests);
                press(&self.daemon, &self.wanted, self.paused, &id, token);
                true
            }
            Some(Event::Changed(listed)) => {
                report(&self.daemon, &listed);
                true
            }
            Some(Event::Closed) | None => {
                tracing::warn!(
                    "the GlobalShortcuts session ended; the global shortcuts are off until the portal is back"
                );
                close(&mut self.backend).await;
                hotkey_status::set(Err("the portal's shortcut session ended".to_owned()));
                self.retry = true;
                false
            }
        }
    }

    /// Brings the portal in line with the wanted shortcuts. `true` when the portal could not be
    /// reached this time and another attempt is due.
    async fn sync(&mut self, requests: &mut mpsc::UnboundedReceiver<Control>) -> bool {
        if matches!(self.backend, Backend::Missing | Backend::Refused) {
            return false;
        }
        let desired = desired(&self.wanted);
        if let Backend::Live(live) = &self.backend {
            match plan(&live.bound, &desired, self.paused) {
                Plan::Nothing => return false,
                Plan::Bind => {}
                Plan::Rebuild => {
                    // A session that may still be alive must not get a twin: try again later.
                    if !close(&mut self.backend).await {
                        return true;
                    }
                }
            }
        }
        if desired.is_empty() {
            return false;
        }
        if matches!(self.backend, Backend::Idle) && !self.connect_backend().await {
            return !matches!(self.backend, Backend::Missing | Backend::Refused);
        }
        match self.bind_waiting(&desired, requests).await {
            Bound::Done(Ok(listed)) => {
                if let Backend::Live(live) = &mut self.backend {
                    live.bound = desired;
                }
                hotkey_status::set(Ok(()));
                report(&self.daemon, &listed);
            }
            Bound::Done(Err(error)) => {
                tracing::warn!(%error, "the GlobalShortcuts portal refused the shortcuts");
                hotkey_status::set(Err(error.to_string()));
                report(&self.daemon, &Listed::new());
            }
            Bound::SessionEnded => {
                self.on_event(Some(Event::Closed), requests).await;
                report(&self.daemon, &Listed::new());
                // GNOME keeps the dialog of a closed session on screen, so a timed retry would
                // stack another one; only a user action (Configure, a changed shortcut) rebinds.
                return false;
            }
            Bound::ControlsClosed => {}
        }
        false
    }

    /// The desktop may keep the bind open for as long as its dialog is unanswered, so Settings
    /// is told it is pending, and "Change in system settings…" and a lost session still get
    /// through meanwhile. Nothing is abandoned and re-asked: GNOME keeps the old dialog open
    /// (neither `Request.Close` nor closing the session dismisses it), so another bind would
    /// only stack a second one.
    async fn bind_waiting(
        &mut self,
        desired: &Wanted,
        requests: &mut mpsc::UnboundedReceiver<Control>,
    ) -> Bound {
        let Task {
            daemon,
            wanted,
            paused,
            backend,
            configure_pending,
            resync,
            ..
        } = self;
        let Backend::Live(live) = backend else {
            return Bound::Done(Err(PortalError::NoResponse));
        };
        let Live {
            link,
            events,
            bound,
            ..
        } = &mut **live;
        if bound.is_empty() {
            daemon.report_hotkey_bindings(bindings(
                HotkeyMode::PortalPending,
                String::new(),
                String::new(),
            ));
            hotkey_status::set(Err(WAITING_FOR_DIALOG.to_owned()));
        }
        let call = bind(link, desired);
        tokio::pin!(call);
        loop {
            tokio::select! {
                result = &mut call => return Bound::Done(result),
                request = requests.recv() => match request {
                    Some(Control::Configure) => configure(link).await,
                    Some(other) => {
                        absorb(other, wanted, paused, configure_pending);
                        *resync = true;
                    }
                    None => return Bound::ControlsClosed,
                },
                event = events.recv() => match event {
                    Some(Event::Activated(id, token)) => press(daemon, wanted, *paused, &id, token),
                    Some(Event::Changed(listed)) => {
                        // An empty list during the wait would flip "waiting" to "not assigned"
                        // while the dialog is still open.
                        if !(bound.is_empty() && listed.is_empty()) {
                            report(daemon, &listed);
                        }
                    }
                    Some(Event::Closed) | None => return Bound::SessionEnded,
                },
            }
        }
    }

    /// `false` when there is no session; `Missing` then says whether a retry could help.
    async fn connect_backend(&mut self) -> bool {
        match connect().await {
            Ok(live) => {
                self.backend = Backend::Live(Box::new(live));
                self.refusals = 0;
                true
            }
            Err(PortalError::PortalNotFound(interface)) => {
                tracing::info!(%interface, "no GlobalShortcuts portal; shortcuts are bound in the compositor");
                self.backend = Backend::Missing;
                hotkey_status::set(Err("this desktop has no GlobalShortcuts portal".to_owned()));
                self.daemon.report_hotkey_bindings(bindings(
                    HotkeyMode::Manual,
                    String::new(),
                    String::new(),
                ));
                false
            }
            Err(error) => {
                if matches!(
                    &error,
                    PortalError::Portal(ashpd::PortalError::NotAllowed(_))
                ) {
                    self.refusals = self.refusals.saturating_add(1);
                    if self.refusals >= REFUSALS_BEFORE_GIVING_UP {
                        self.daemon.report_hotkey_bindings(bindings(
                            HotkeyMode::Manual,
                            String::new(),
                            String::new(),
                        ));
                        tracing::warn!(%error, "the portal keeps refusing this process; restart Vaultkeeper to get global shortcuts back");
                        self.backend = Backend::Refused;
                        hotkey_status::set(Err(
                            "the portal refuses this app; restart Vaultkeeper".to_owned()
                        ));
                        return false;
                    }
                }
                if !matches!(
                    &error,
                    PortalError::Portal(ashpd::PortalError::NotAllowed(_))
                ) {
                    self.refusals = 0;
                }
                tracing::warn!(%error, "cannot reach the GlobalShortcuts portal");
                hotkey_status::set(Err(error.to_string()));
                false
            }
        }
    }
}

#[allow(
    clippy::default_trait_access,
    reason = "ashpd does not export the session options type"
)]
async fn connect() -> Result<Live, PortalError> {
    if tokio::time::timeout(CALL_TIMEOUT, portal::ensure_registered())
        .await
        .is_err()
    {
        tracing::warn!("registering with the portal timed out");
    }
    let portal = within(CALL_TIMEOUT, GlobalShortcuts::new()).await?;
    let session = within(CALL_TIMEOUT, portal.create_session(Default::default())).await?;
    let session = Arc::new(session);
    let activated = within(CALL_TIMEOUT, portal.receive_activated()).await?;
    let changed = within(CALL_TIMEOUT, portal.receive_shortcuts_changed()).await?;
    let (events_tx, events) = mpsc::unbounded_channel();
    let watchers = Watchers(vec![
        forward(activated, events_tx.clone(), |activated| {
            let token = activated
                .options()
                .get(ACTIVATION_TOKEN_KEY)
                .and_then(|value| <&str>::try_from(value).ok())
                .map(str::to_owned);
            Event::Activated(activated.shortcut_id().to_owned(), token)
        }),
        forward(changed, events_tx.clone(), |changed| {
            Event::Changed(listed(changed.shortcuts().iter()))
        }),
        tokio::spawn(watch_session_closed(
            Arc::clone(&session),
            events_tx.clone(),
        )),
        tokio::spawn(watch_portal_owner(events_tx)),
    ]);
    Ok(Live {
        link: Link { portal, session },
        events,
        bound: Wanted::new(),
        _watchers: watchers,
    })
}

fn listed<'a>(
    shortcuts: impl Iterator<Item = &'a ashpd::desktop::global_shortcuts::Shortcut>,
) -> Listed {
    shortcuts
        .map(|shortcut| {
            (
                shortcut.id().to_owned(),
                shortcut.trigger_description().to_owned(),
            )
        })
        .collect()
}

/// Sends every item as an event; a stream that ends means the bus connection is gone.
fn forward<S>(
    mut stream: S,
    events: mpsc::UnboundedSender<Event>,
    into_event: impl Fn(S::Item) -> Event + Send + 'static,
) -> JoinHandle<()>
where
    S: Stream + Send + Unpin + 'static,
    S::Item: Send,
{
    tokio::spawn(async move {
        while let Some(item) = stream.next().await {
            if events.send(into_event(item)).is_err() {
                return;
            }
        }
        let _ = events.send(Event::Closed);
    })
}

/// `Session.Closed`: the desktop ended the session on its own.
async fn watch_session_closed(
    session: Arc<Session<GlobalShortcuts>>,
    events: mpsc::UnboundedSender<Event>,
) {
    let mut closed = match session.receive_closed().await {
        Ok(closed) => Box::pin(closed),
        Err(error) => {
            tracing::warn!(%error, "cannot watch the shortcut session for closing");
            return;
        }
    };
    if closed.next().await.is_some() {
        let _ = events.send(Event::Closed);
    }
}

/// A restarted portal has lost every session without a signal.
async fn watch_portal_owner(events: mpsc::UnboundedSender<Event>) {
    let watched = async {
        let connection = zbus::Connection::session().await?;
        let dbus = zbus::fdo::DBusProxy::new(&connection).await?;
        let mut changes = dbus
            .receive_name_owner_changed_with_args(&[(0, PORTAL_BUS_NAME)])
            .await?;
        while changes.next().await.is_some() {
            if events.send(Event::Closed).is_err() {
                break;
            }
        }
        Ok::<(), zbus::Error>(())
    };
    if let Err(error) = watched.await {
        tracing::warn!(%error, "cannot watch the portal for restarts");
    }
}

/// Binds every desired shortcut and returns what the desktop lists afterwards.
async fn bind(link: &Link, desired: &Wanted) -> Result<Listed, PortalError> {
    let shortcuts: Vec<NewShortcut> = desired
        .iter()
        .map(|(slot, trigger)| {
            NewShortcut::new(shortcut_id(*slot), description(*slot))
                .preferred_trigger(trigger.as_str())
        })
        .collect();
    let request = link
        .portal
        .bind_shortcuts(
            &link.session,
            &shortcuts,
            None,
            BindShortcutsOptions::default(),
        )
        .await?;
    let bound = request.response()?;
    let relisted = within(
        CALL_TIMEOUT,
        link.portal
            .list_shortcuts(&link.session, ListShortcutsOptions::default()),
    )
    .await
    .and_then(|request| request.response());
    Ok(relisted.map_or_else(
        |_| listed(bound.shortcuts().iter()),
        |list| listed(list.shortcuts().iter()),
    ))
}

fn report(daemon: &Arc<Daemon>, shortcuts: &Listed) {
    let (quick_panel, generator) = portal_plan::trigger_descriptions(
        shortcuts
            .iter()
            .map(|(id, trigger)| (id.as_str(), trigger.as_str())),
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

/// Presses of a shortcut that is paused for a recorder, or has no trigger the portal was given,
/// are dropped.
fn press(daemon: &Arc<Daemon>, wanted: &Wanted, paused: bool, id: &str, token: Option<String>) {
    let Some(slot) = portal_plan::slot_for_id(id) else {
        return;
    };
    if !portal_plan::is_active(wanted, slot, paused || daemon.hotkeys_paused()) {
        return;
    }
    tracing::debug!(?slot, token = token.is_some(), "global shortcut pressed");
    crate::os::linux::activation::offer(token);
    let daemon = Arc::clone(daemon);
    // `typing_target` may wait on another thread, so the press is applied off the portal task.
    tokio::task::spawn_blocking(move || {
        daemon.apply(routing::hotkey(slot, || daemon.typing_target()));
    });
}

async fn configure(link: &Link) {
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

/// `false` when the portal did not answer `Close` in time, so the session may still be alive; any
/// other answer (including "no such session") means it is gone.
async fn close(backend: &mut Backend) -> bool {
    let Backend::Live(live) = std::mem::replace(backend, Backend::Idle) else {
        return true;
    };
    let closed = within(CALL_TIMEOUT, live.link.session.close()).await;
    !matches!(closed, Err(PortalError::IO(error)) if error.kind() == std::io::ErrorKind::TimedOut)
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
