//! Linux half of [`super::subscribe`]: NetworkManager's `StateChanged` signal and the `State` and
//! `PrimaryConnection` property changes on the system bus, read on one thread.
//!
//! The thread drives zbus through `zbus::block_on`, which runs on one tokio runtime shared by the
//! whole process, so the caller needs no runtime of its own. Without NetworkManager nothing is sent and the caller's
//! periodic probe is the only trigger; the match rule names the service, so a NetworkManager that
//! starts later is picked up.

use std::{
    collections::HashMap,
    future::poll_fn,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender, channel},
    },
    task::{Poll, Waker},
    thread::{self, JoinHandle},
    time::Duration,
};

use tracing::warn;
use zbus::{
    Connection, MatchRule, Message, MessageStream, OwnedVariant, Variant,
    export::futures_core::Stream, message::Type,
};

use super::{
    NetworkEvent,
    nm::{self, NM_NAME, NM_PATH, PROPERTIES},
};

const METHOD_TIMEOUT: Duration = Duration::from_secs(3);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

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

    fn is_requested_now(&self) -> bool {
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
    finished: Receiver<()>,
}

impl Subscription {
    pub(super) fn new(tx: Sender<NetworkEvent>) -> io::Result<Self> {
        let stop = Arc::new(Stop::default());
        let (ready_tx, ready_rx) = channel();
        let (finished_tx, finished) = channel();
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("vaultkeeper-network-bus".to_owned())
            .spawn(move || {
                zbus::block_on(run(tx, &thread_stop, &ready_tx));
                let _ = finished_tx.send(());
            })?;
        match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                stop,
                thread: Some(thread),
                finished,
            }),
            Ok(Err(reason)) => {
                let _ = thread.join();
                Err(io::Error::other(reason))
            }
            Err(RecvTimeoutError::Timeout) => {
                // Connecting and authenticating are not covered by the method timeout. The thread
                // is left to end by itself once the stop flag reaches it.
                stop.request();
                Err(io::Error::other(
                    "the bus did not answer in time; the network watcher is off",
                ))
            }
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::other(
                "network watcher thread ended during startup",
            )),
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.stop.request();
        if let Some(thread) = self.thread.take() {
            // A wedged bus call must not hold up the daemon's shutdown.
            if let Err(RecvTimeoutError::Timeout) = self.finished.recv_timeout(JOIN_TIMEOUT) {
                warn!("the network watcher thread did not stop in time; leaving it behind");
            } else {
                let _ = thread.join();
            }
        }
    }
}

async fn run(tx: Sender<NetworkEvent>, stop: &Stop, ready: &Sender<Result<(), String>>) {
    let mut stream = match open_stream().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!("system bus: {error}")));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    while let Some(message) = next_message(&mut stream, stop).await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "network watcher: bus message error");
                continue;
            }
        };
        if let Some(event) = event_of(&message)
            && tx.send(event).is_err()
        {
            return;
        }
    }
    if !stop.is_requested_now() {
        warn!("network watcher: the system bus stream ended; network change events stopped");
    }
}

/// Bounds every method call so a stalled bus cannot hang startup or the shutdown join.
async fn open_stream() -> zbus::Result<MessageStream> {
    let connection: Connection = zbus::connection::Builder::system()
        .method_timeout(METHOD_TIMEOUT)
        .build()
        .await?;
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(NM_NAME)
        .path(NM_PATH)
        .build()?;
    MessageStream::for_match_rule(rule, &connection, None).await
}

async fn next_message(stream: &mut MessageStream, stop: &Stop) -> Option<zbus::Result<Message>> {
    poll_fn(|cx| {
        if stop.is_requested(cx.waker()) {
            return Poll::Ready(None);
        }
        Pin::new(&mut *stream).poll_next(cx)
    })
    .await
}

fn event_of(message: &Message) -> Option<NetworkEvent> {
    let header = message.header();
    let interface = header.interface()?.as_str();
    let member = header.member()?.as_str();
    match (interface, member) {
        (NM_NAME, "StateChanged") => nm::event_for_state(message.body().deserialize().ok()?),
        (PROPERTIES, "PropertiesChanged") => changed_event(message),
        _ => None,
    }
}

fn changed_event(message: &Message) -> Option<NetworkEvent> {
    let (interface, changed, _invalidated): (String, HashMap<String, OwnedVariant>, Vec<String>) =
        message.body().deserialize().ok()?;
    if interface != NM_NAME {
        return None;
    }
    // `State` is skipped: `StateChanged` already reports every change, and reading it here too
    // delivered each one twice.
    match &**changed.get("PrimaryConnection")? {
        Variant::ObjectPath(path) => Some(nm::event_for_primary(path.as_str())),
        _ => None,
    }
}
