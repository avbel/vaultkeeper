//! Linux half of [`super::subscribe`]: logind on the system bus (sleep, shutdown, this session's
//! lock) and the KDE/GNOME screensaver on the session bus, read on one thread.
//!
//! The thread drives zbus through `zbus::block_on`, which owns a private tokio runtime, so the
//! caller needs no runtime of its own. Chain C14: docs/solutions/linux-ideas.md.

use std::{
    collections::HashMap,
    future::poll_fn,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
        mpsc::{Sender, channel},
    },
    task::{Poll, Waker},
    thread::{self, JoinHandle},
    time::Duration,
};

use tracing::{debug, warn};
use zbus::{
    Connection, MatchRule, Message, MessageStream, OwnedFd, OwnedObjectPath, OwnedVariant, Variant,
    export::futures_core::Stream, message::Type,
};

use super::{
    PowerEvent,
    signal::{self, BusSignal, Tracker},
};

const SLEEP_GRACE: Duration = Duration::from_millis(300);
const LOGIND_NAME: &str = "org.freedesktop.login1";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

#[derive(Default)]
struct Stop {
    requested: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Stop {
    fn is_requested(&self, waker: &Waker) -> bool {
        *self.waker.lock().unwrap_or_else(PoisonError::into_inner) = Some(waker.clone());
        self.requested.load(Ordering::Acquire)
    }

    fn request(&self) {
        self.requested.store(true, Ordering::Release);
        if let Some(waker) = self
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            waker.wake();
        }
    }
}

/// Dropping stops the watcher thread and joins it.
pub(super) struct Subscription {
    stop: Arc<Stop>,
    thread: Option<JoinHandle<()>>,
}

impl Subscription {
    pub(super) fn new(tx: Sender<PowerEvent>) -> io::Result<Self> {
        let stop = Arc::new(Stop::default());
        let (ready_tx, ready_rx) = channel();
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("vaultkeeper-power-bus".to_owned())
            .spawn(move || zbus::block_on(run(tx, &thread_stop, &ready_tx)))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                stop,
                thread: Some(thread),
            }),
            Ok(Err(reason)) => {
                let _ = thread.join();
                Err(io::Error::other(reason))
            }
            Err(_) => Err(io::Error::other(
                "power watcher thread ended during startup",
            )),
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.stop.request();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn run(tx: Sender<PowerEvent>, stop: &Stop, ready: &Sender<Result<(), String>>) {
    let (mut streams, system) = open_streams().await;
    if streams.is_empty() {
        let _ = ready.send(Err(
            "neither the system nor the session bus is reachable".to_owned()
        ));
        return;
    }
    let _ = ready.send(Ok(()));
    let mut tracker = Tracker::default();
    let mut inhibitor = take_inhibitor(system.as_ref()).await;
    while let Some(message) = next_message(&mut streams, stop).await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "power watcher: bus message error");
                continue;
            }
        };
        let signal = signal_of(&message);
        let Some(event) = signal.and_then(|signal| tracker.apply(signal)) else {
            continue;
        };
        if tx.send(event).is_err() {
            return;
        }
        match signal {
            Some(BusSignal::PrepareForSleep(true)) => {
                // The event API has no acknowledgement, so the consumer only gets this grace
                // period to lock before logind may suspend.
                thread::sleep(SLEEP_GRACE);
                inhibitor = None;
            }
            Some(BusSignal::PrepareForSleep(false)) if inhibitor.is_none() => {
                inhibitor = take_inhibitor(system.as_ref()).await;
            }
            _ => {}
        }
    }
}

/// A logind delay inhibitor holds the suspend back (up to `InhibitDelayMaxSec`) until the fd is
/// closed, so the vault can lock first. Without it the watcher still works, only racing suspend.
async fn take_inhibitor(system: Option<&Connection>) -> Option<OwnedFd> {
    let connection = system?;
    let reply = connection
        .call_method(
            Some(LOGIND_NAME),
            LOGIND_PATH,
            Some(signal::LOGIND_MANAGER),
            "Inhibit",
            &(
                "sleep",
                "Vaultkeeper",
                "Lock the vault before sleep",
                "delay",
            ),
        )
        .await
        .inspect_err(|error| warn!(%error, "no sleep inhibitor; locking may race suspend"))
        .ok()?;
    reply.body().deserialize::<OwnedFd>().ok()
}

async fn open_streams() -> (Vec<MessageStream>, Option<Connection>) {
    let mut streams = Vec::new();
    let system = match Connection::system().await {
        Ok(connection) => {
            streams.extend(logind_streams(&connection).await);
            Some(connection)
        }
        Err(error) => {
            warn!(%error, "no system bus; sleep and logind lock events are off");
            None
        }
    };
    match Connection::session().await {
        Ok(connection) => streams.extend(screensaver_streams(&connection).await),
        Err(error) => warn!(%error, "no session bus; screensaver lock events are off"),
    }
    (streams, system)
}

async fn logind_streams(connection: &Connection) -> Vec<MessageStream> {
    let mut streams = Vec::new();
    let manager = signal_rule(
        Some(LOGIND_NAME),
        Some(LOGIND_PATH),
        Some(signal::LOGIND_MANAGER),
    );
    streams.extend(stream_for(connection, manager).await);
    match session_path(connection).await {
        Ok(path) => {
            let session = signal_rule(Some(LOGIND_NAME), Some(path.as_str()), None);
            streams.extend(stream_for(connection, session).await);
        }
        Err(error) => warn!(%error, "logind session not found; lock signals from it are off"),
    }
    streams
}

async fn screensaver_streams(connection: &Connection) -> Vec<MessageStream> {
    let mut streams = Vec::new();
    for interface in [signal::KDE_SCREENSAVER, signal::GNOME_SCREENSAVER] {
        streams.extend(stream_for(connection, signal_rule(None, None, Some(interface))).await);
    }
    streams
}

fn signal_rule(
    sender: Option<&str>,
    path: Option<&str>,
    interface: Option<&str>,
) -> zbus::Result<MatchRule<'static>> {
    let mut builder = MatchRule::builder().msg_type(Type::Signal);
    if let Some(sender) = sender {
        builder = builder.sender(sender.to_owned());
    }
    if let Some(path) = path {
        builder = builder.path(path.to_owned());
    }
    if let Some(interface) = interface {
        builder = builder.interface(interface.to_owned());
    }
    builder.build()
}

async fn stream_for(
    connection: &Connection,
    rule: zbus::Result<MatchRule<'static>>,
) -> Option<MessageStream> {
    let stream = match rule {
        Ok(rule) => MessageStream::for_match_rule(rule, connection, None).await,
        Err(error) => Err(error),
    };
    stream
        .inspect_err(|error| warn!(%error, "power watcher: match rule rejected"))
        .ok()
}

/// "auto" is logind's own name for the caller's session; an explicit id is the fallback when the
/// bus peer credentials do not resolve one.
async fn session_path(connection: &Connection) -> zbus::Result<OwnedObjectPath> {
    let id = std::env::var("XDG_SESSION_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "auto".to_owned());
    let reply = connection
        .call_method(
            Some(LOGIND_NAME),
            LOGIND_PATH,
            Some(signal::LOGIND_MANAGER),
            "GetSession",
            &(id.as_str(),),
        )
        .await?;
    reply.body().deserialize()
}

async fn next_message(
    streams: &mut Vec<MessageStream>,
    stop: &Stop,
) -> Option<zbus::Result<Message>> {
    poll_fn(|cx| {
        if stop.is_requested(cx.waker()) {
            return Poll::Ready(None);
        }
        let mut index = 0;
        while index < streams.len() {
            match Pin::new(&mut streams[index]).poll_next(cx) {
                Poll::Ready(Some(message)) => return Poll::Ready(Some(message)),
                Poll::Ready(None) => {
                    debug!("power watcher: a bus stream ended");
                    drop(streams.swap_remove(index));
                }
                Poll::Pending => index += 1,
            }
        }
        if streams.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    })
    .await
}

fn signal_of(message: &Message) -> Option<BusSignal> {
    let header = message.header();
    let interface = header.interface()?.as_str();
    let member = header.member()?.as_str();
    if interface == PROPERTIES && member == "PropertiesChanged" {
        return locked_hint(message);
    }
    let flag = message.body().deserialize::<bool>().ok();
    signal::classify(interface, member, flag)
}

fn locked_hint(message: &Message) -> Option<BusSignal> {
    let (interface, changed, _invalidated): (String, HashMap<String, OwnedVariant>, Vec<String>) =
        message.body().deserialize().ok()?;
    if interface != signal::LOGIND_SESSION {
        return None;
    }
    match &**changed.get("LockedHint")? {
        Variant::Bool(locked) => Some(BusSignal::LockedHint(*locked)),
        _ => None,
    }
}
