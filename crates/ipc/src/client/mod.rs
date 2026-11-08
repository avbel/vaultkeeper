//! UI side: [`RemoteVault`] proxies `VaultService` to the daemon.
//!
//! The socket belongs to a dedicated `bwl-ipc` thread running its own current-thread runtime,
//! so callers need no particular runtime and a blocked caller never stalls the I/O.
//! - State, accounts, offline flag, folders, organizations and collections are served from a
//!   cache that the daemon refreshes before every `Changed` and before answering any
//!   state-changing call, so they never block.
//! - The other sync methods (search, reveal, totp, draft, unlock with the Touch ID key, lock,
//!   ...) are blocking round-trips: the calling thread waits on a channel while the I/O thread
//!   does the exchange. See the crate docs for the measured latency.
//! - Async methods await a oneshot; they must run inside a Tokio runtime with timers enabled
//!   (the per-call timeout uses `tokio::time`).

mod events;
mod io;
mod service;

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc, Mutex, PoisonError, RwLock, RwLockReadGuard,
        atomic::{AtomicU64, Ordering},
        mpsc as std_mpsc,
    },
};

use bwl_vault::model::{AccountView, CollectionView, FolderView, OrganizationView, SessionState};
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::Zeroizing;

pub use events::{EventStream, SshApproval, UiEvent};

use crate::{
    ConvertError, IpcError,
    dto::WireError,
    frame::encode,
    protocol::{Call, Reply, Snapshot, UiMessage, UiNotice},
};

/// `VaultService` backed by the daemon. Dropping it closes the connection and joins the I/O
/// thread.
pub struct RemoteVault {
    shared: Arc<Shared>,
    changes: watch::Receiver<u64>,
    _io: io::IoThread,
}

impl RemoteVault {
    /// Connects, says `Hello` and waits for the daemon's welcome (at most 5 s). Fails with
    /// [`IpcError::Busy`] when another UI process is connected and with
    /// [`IpcError::VersionMismatch`] when the daemon runs a different build.
    pub async fn connect(path: impl AsRef<Path>) -> Result<(Self, EventStream), IpcError> {
        // A unix-socket connect completes or fails at once; it does not wait on the peer.
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        stream.set_nonblocking(true)?;
        let (ready_tx, ready_rx) = oneshot::channel();
        // Unbounded: the reader must never wait on the UI (that would stall every response), and
        // events arrive at human pace.
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let io = io::IoThread::spawn(stream, events_tx, ready_tx)?;
        let (shared, changes) = ready_rx.await.map_err(|_| IpcError::Disconnected)??;
        Ok((
            Self {
                shared,
                changes,
                _io: io,
            },
            EventStream::new(events_rx),
        ))
    }

    fn cache(&self) -> RwLockReadGuard<'_, Cache> {
        self.shared
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends a notice without waiting; fails only when the daemon connection is gone.
    pub fn notify(&self, notice: UiNotice) -> Result<(), IpcError> {
        let frame = encode(&UiMessage::Notice(notice))?;
        self.shared
            .outbox
            .send(frame)
            .map_err(|_| IpcError::Disconnected)
    }

    async fn call(&self, call: Call) -> bwl_vault::Result<Reply> {
        let timeout = call.timeout();
        let (tx, rx) = oneshot::channel();
        let _pending = self.shared.begin(call, Waiter::Async(tx))?;
        let outcome = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(IpcError::Disconnected),
            Err(_) => Err(IpcError::Timeout(timeout)),
        };
        settle(outcome)
    }

    fn call_blocking(&self, call: Call) -> bwl_vault::Result<Reply> {
        let timeout = call.timeout();
        let (tx, rx) = std_mpsc::sync_channel(1);
        let _pending = self.shared.begin(call, Waiter::Blocking(tx))?;
        let outcome = match rx.recv_timeout(timeout) {
            Ok(outcome) => outcome,
            Err(std_mpsc::RecvTimeoutError::Timeout) => Err(IpcError::Timeout(timeout)),
            Err(std_mpsc::RecvTimeoutError::Disconnected) => Err(IpcError::Disconnected),
        };
        settle(outcome)
    }
}

type Outcome = Result<Result<Reply, WireError>, IpcError>;
type Frame = Zeroizing<Vec<u8>>;

fn settle(outcome: Outcome) -> bwl_vault::Result<Reply> {
    match outcome {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
    }
}

enum Waiter {
    Async(oneshot::Sender<Outcome>),
    Blocking(std_mpsc::SyncSender<Outcome>),
}

impl Waiter {
    fn wake(self, outcome: Outcome) {
        // A waiter that gave up (timeout, dropped future) is simply gone.
        match self {
            Self::Async(tx) => {
                let _ = tx.send(outcome);
            }
            Self::Blocking(tx) => {
                let _ = tx.try_send(outcome);
            }
        }
    }
}

/// State shared between `RemoteVault` (callers) and the I/O thread.
struct Shared {
    next_id: AtomicU64,
    calls: Mutex<Calls>,
    outbox: mpsc::UnboundedSender<Frame>,
    cache: RwLock<Cache>,
}

#[derive(Default)]
struct Calls {
    pending: HashMap<u64, Waiter>,
    closed: bool,
}

impl Shared {
    fn new(outbox: mpsc::UnboundedSender<Frame>, cache: Cache) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            calls: Mutex::new(Calls::default()),
            outbox,
            cache: RwLock::new(cache),
        }
    }

    fn calls(&self) -> std::sync::MutexGuard<'_, Calls> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers the waiter and queues the request; the guard forgets the call when dropped.
    fn begin(&self, call: Call, waiter: Waiter) -> Result<PendingCall<'_>, IpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = encode(&UiMessage::Request { id, call })?;
        {
            let mut calls = self.calls();
            if calls.closed {
                return Err(IpcError::Disconnected);
            }
            calls.pending.insert(id, waiter);
        }
        let pending = PendingCall { shared: self, id };
        self.outbox
            .send(frame)
            .map_err(|_| IpcError::Disconnected)?;
        Ok(pending)
    }

    fn complete(&self, id: u64, result: Result<Reply, WireError>) {
        let waiter = self.calls().pending.remove(&id);
        if let Some(waiter) = waiter {
            waiter.wake(Ok(result));
        } else {
            tracing::debug!(id, "response for a call nobody waits for");
        }
    }

    /// Fails every pending call and refuses new ones.
    fn close(&self) {
        let pending = {
            let mut calls = self.calls();
            calls.closed = true;
            std::mem::take(&mut calls.pending)
        };
        for waiter in pending.into_values() {
            waiter.wake(Err(IpcError::Disconnected));
        }
    }

    fn write_cache(&self) -> std::sync::RwLockWriteGuard<'_, Cache> {
        self.cache.write().unwrap_or_else(PoisonError::into_inner)
    }
}

#[must_use]
struct PendingCall<'a> {
    shared: &'a Shared,
    id: u64,
}

impl Drop for PendingCall<'_> {
    fn drop(&mut self) {
        self.shared.calls().pending.remove(&self.id);
    }
}

/// The client's copy of [`Snapshot`], in model types.
struct Cache {
    state: SessionState,
    accounts: Vec<AccountView>,
    is_offline: bool,
    last_sync: Option<std::time::SystemTime>,
    folders: Result<Vec<FolderView>, WireError>,
    organizations: Result<Vec<OrganizationView>, WireError>,
    collections: Result<Vec<CollectionView>, WireError>,
}

impl TryFrom<Snapshot> for Cache {
    type Error = ConvertError;

    fn try_from(snapshot: Snapshot) -> Result<Self, ConvertError> {
        Ok(Self {
            state: snapshot.state.try_into()?,
            accounts: snapshot
                .accounts
                .into_iter()
                .map(AccountView::try_from)
                .collect::<Result<_, _>>()?,
            is_offline: snapshot.is_offline,
            last_sync: snapshot
                .last_sync
                .map(|unix| std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix)),
            folders: model_list(snapshot.folders),
            organizations: model_list(snapshot.organizations),
            collections: model_list(snapshot.collections),
        })
    }
}

fn model_list<D, T: From<D>>(list: Result<Vec<D>, WireError>) -> Result<Vec<T>, WireError> {
    list.map(|items| items.into_iter().map(T::from).collect())
}
