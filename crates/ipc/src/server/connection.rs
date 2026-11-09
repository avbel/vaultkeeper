//! One accepted socket: peer check, handshake, then the request/event session.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tokio::{
    io::AsyncWriteExt,
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
};
use vk_vault::VaultService;
use zeroize::Zeroizing;

use super::{Backends, DaemonEvent, Shared, TaskGuard, dispatch::dispatch, log_join, stopped};
use crate::{
    IpcError,
    dto::WireError,
    frame::{decode, encode, read_frame},
    peer,
    protocol::{
        DaemonMessage, Event, PROTOCOL_VERSION, Refusal, Snapshot, SshDecision, UiMessage,
        UiNotice, Welcome,
    },
};

/// Frames queued for the writer; producers wait when the UI reads slowly.
const OUTBOX_CAPACITY: usize = 32;
/// How long the writer may take to flush the last frames (such as `Shutdown`) when closing.
const FLUSH_GRACE: Duration = Duration::from_secs(1);

type Frame = Zeroizing<Vec<u8>>;

pub(super) async fn handle<S: VaultService>(
    stream: UnixStream,
    shared: Arc<Shared<S>>,
    stop: watch::Receiver<bool>,
) {
    let peer = match peer::credentials(&stream) {
        Ok(peer) => peer,
        Err(error) => {
            tracing::warn!(%error, "cannot identify the IPC peer; closing");
            return;
        }
    };
    if peer.uid != shared.uid || !shared.verifier.verify(&peer) {
        tracing::warn!(
            uid = peer.uid,
            pid = peer.pid,
            executable = %peer.executable.display(),
            "refused an IPC peer"
        );
        return;
    }
    match accept(stream, &shared, stop).await {
        Ok(()) => tracing::debug!(pid = peer.pid, "UI process disconnected"),
        Err(error) => tracing::info!(%error, pid = peer.pid, "IPC connection ended"),
    }
}

async fn accept<S: VaultService>(
    stream: UnixStream,
    shared: &Shared<S>,
    stop: watch::Receiver<bool>,
) -> Result<(), IpcError> {
    let (mut read, mut write) = stream.into_split();
    let theirs = tokio::time::timeout(shared.handshake_timeout, read_hello(&mut read))
        .await
        .map_err(|_| IpcError::Protocol("no Hello within the handshake timeout"))??;
    if theirs != PROTOCOL_VERSION {
        refuse(
            &mut write,
            Refusal::VersionMismatch {
                daemon: PROTOCOL_VERSION,
            },
        )
        .await;
        return Err(IpcError::VersionMismatch {
            ours: PROTOCOL_VERSION,
            theirs,
        });
    }
    let Ok(slot) = Arc::clone(&shared.slot).try_acquire_owned() else {
        refuse(&mut write, Refusal::Busy).await;
        return Err(IpcError::Busy);
    };
    serve_session(read, write, shared, slot, stop).await
}

async fn read_hello(read: &mut OwnedReadHalf) -> Result<u32, IpcError> {
    let body = read_frame(read).await?.ok_or(IpcError::Disconnected)?;
    match decode(&body)? {
        UiMessage::Hello { protocol_version } => Ok(protocol_version),
        _ => Err(IpcError::Protocol("the first message must be Hello")),
    }
}

async fn refuse(write: &mut OwnedWriteHalf, refusal: Refusal) {
    let sent = match encode(&DaemonMessage::Refused(refusal)) {
        Ok(frame) => write.write_all(&frame).await.map_err(IpcError::from),
        Err(error) => Err(error),
    };
    if let Err(error) = sent {
        tracing::debug!(%error, "could not send the refusal");
    }
    let _ = write.shutdown().await;
}

enum Ended {
    Stopped,
    Reader(Result<(), IpcError>),
    Writer(Result<(), IpcError>),
}

async fn serve_session<S: VaultService>(
    read: OwnedReadHalf,
    write: OwnedWriteHalf,
    shared: &Shared<S>,
    slot: OwnedSemaphorePermit,
    mut stop: watch::Receiver<bool>,
) -> Result<(), IpcError> {
    let (outbox, frames) = mpsc::channel(OUTBOX_CAPACITY);
    let mut writer = TaskGuard(tokio::spawn(write_frames(write, frames)));
    // Subscribed before the welcome is built, so no change between the two goes unnoticed.
    let changes = shared.service.changes();
    let publisher = Arc::new(Publisher::new(Arc::clone(&shared.service), outbox));
    publisher.welcome().await?;
    let approvals = Arc::new(Approvals::default());
    let forward_changes = TaskGuard(tokio::spawn(forward_changes(
        Arc::clone(&publisher),
        changes,
    )));
    let forward_events = TaskGuard(tokio::spawn(forward_events(
        Arc::clone(&shared.events),
        Arc::clone(&publisher),
        Arc::clone(&approvals),
    )));
    let calls = Arc::new(Mutex::new(JoinSet::new()));
    let requests = Requests {
        service: Arc::clone(&shared.service),
        publisher: Arc::clone(&publisher),
        approvals,
        limit: Arc::new(Semaphore::new(shared.max_concurrent_calls)),
        calls: Arc::clone(&calls),
        notices: shared.notices.clone(),
        backends: shared.backends.clone(),
    };
    let mut reader = TaskGuard(tokio::spawn(read_requests(read, requests)));
    let ended = tokio::select! {
        biased;
        () = stopped(&mut stop) => Ended::Stopped,
        joined = &mut reader.0 => Ended::Reader(flatten(joined)),
        joined = &mut writer.0 => Ended::Writer(flatten(joined)),
    };
    if matches!(ended, Ended::Stopped) {
        let _ = publisher.send_event(Event::Shutdown).await;
    }
    drop((reader, forward_changes, forward_events, publisher));
    let result = match ended {
        Ended::Stopped => {
            // The writer ends once every outbox sender is gone, after flushing `Shutdown`.
            let _ = tokio::time::timeout(FLUSH_GRACE, &mut writer.0).await;
            Ok(())
        }
        Ended::Reader(result) | Ended::Writer(result) => result,
    };
    drop(writer);
    // The next UI process may connect while the calls of this one finish.
    drop(slot);
    // Waits for room rather than dropping it like the UI's own notices: nothing else would
    // undo what the UI turned on.
    if let Some(notices) = &shared.notices
        && notices.send(UiNotice::Disconnected).await.is_err()
    {
        tracing::debug!("nobody reads UI notices");
    }
    finish_calls(&calls).await;
    result
}

/// Calls already started run to the end even though nobody reads their answers: cancelling
/// one at an arbitrary await could leave a save or a log out half done. They are still owned
/// by this connection, so dropping the `ServerHandle` aborts them.
async fn finish_calls(calls: &Mutex<JoinSet<()>>) {
    let mut calls = std::mem::take(&mut *lock_calls(calls));
    while let Some(joined) = calls.join_next().await {
        log_join("IPC call", joined);
    }
}

fn flatten(joined: Result<Result<(), IpcError>, tokio::task::JoinError>) -> Result<(), IpcError> {
    joined.unwrap_or_else(|error| Err(IpcError::Io(std::io::Error::other(error))))
}

async fn write_frames(
    mut write: OwnedWriteHalf,
    mut frames: mpsc::Receiver<Frame>,
) -> Result<(), IpcError> {
    while let Some(frame) = frames.recv().await {
        write.write_all(&frame).await?;
    }
    write.shutdown().await?;
    Ok(())
}

struct Requests<S> {
    service: Arc<S>,
    publisher: Arc<Publisher<S>>,
    approvals: Arc<Approvals>,
    limit: Arc<Semaphore>,
    /// Shared with the session so the calls outlive this reader.
    calls: Arc<Mutex<JoinSet<()>>>,
    notices: Option<mpsc::Sender<UiNotice>>,
    backends: Backends,
}

async fn read_requests<S: VaultService>(
    mut read: OwnedReadHalf,
    requests: Requests<S>,
) -> Result<(), IpcError> {
    while let Some(body) = read_frame(&mut read).await? {
        match decode(&body)? {
            UiMessage::Request { id, call } => {
                // Waiting here stops reading, which pushes back on a client that floods us.
                let permit = Arc::clone(&requests.limit)
                    .acquire_owned()
                    .await
                    .map_err(|_| IpcError::Protocol("call limiter closed"))?;
                let call = answer(
                    Arc::clone(&requests.service),
                    requests.backends.clone(),
                    Arc::clone(&requests.publisher),
                    id,
                    call,
                    permit,
                );
                lock_calls(&requests.calls).spawn(call);
            }
            UiMessage::SshApprovalReply {
                request_id,
                approved,
                remember,
            } => requests
                .approvals
                .resolve(request_id, SshDecision { approved, remember }),
            UiMessage::Notice(notice) => {
                // Notices are hints (a settings reload, activity); dropping one under load is fine.
                if let Some(notices) = &requests.notices
                    && notices.try_send(notice).is_err()
                {
                    tracing::debug!(?notice, "UI notice dropped");
                }
            }
            UiMessage::Hello { .. } => return Err(IpcError::Protocol("Hello after the handshake")),
        }
        let mut calls = lock_calls(&requests.calls);
        while let Some(joined) = calls.try_join_next() {
            log_join("IPC call", joined);
        }
    }
    Ok(())
}

fn lock_calls(calls: &Mutex<JoinSet<()>>) -> std::sync::MutexGuard<'_, JoinSet<()>> {
    calls.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn answer<S: VaultService>(
    service: Arc<S>,
    backends: Backends,
    publisher: Arc<Publisher<S>>,
    id: u64,
    call: crate::protocol::Call,
    _permit: OwnedSemaphorePermit,
) {
    let refresh = call.changes_state();
    let result = dispatch(&service, backends, call).await;
    if let Err(error) = &result {
        tracing::debug!(id, ?error, "IPC call failed");
    }
    // The cache refresh goes out first, so the UI never sees the answer with stale state.
    if publisher.publish(refresh).await.is_err() {
        return;
    }
    let frame = encode(&DaemonMessage::Response { id, result }).or_else(|error| {
        tracing::warn!(%error, id, "cannot encode an IPC response");
        encode(&DaemonMessage::Response {
            id,
            result: Err(WireError::internal(error.to_string())),
        })
    });
    match frame {
        Ok(frame) => {
            let _ = publisher.outbox.send(frame).await;
        }
        Err(error) => tracing::error!(%error, id, "cannot encode an IPC error response"),
    }
}

async fn forward_changes<S: VaultService>(
    publisher: Arc<Publisher<S>>,
    mut changes: watch::Receiver<u64>,
) {
    while changes.changed().await.is_ok() {
        if publisher.publish(false).await.is_err() {
            break;
        }
    }
}

async fn forward_events<S: VaultService>(
    source: Arc<AsyncMutex<mpsc::Receiver<DaemonEvent>>>,
    publisher: Arc<Publisher<S>>,
    approvals: Arc<Approvals>,
) {
    let mut source = source.lock_owned().await;
    while let Some(event) = source.recv().await {
        let event = match event {
            DaemonEvent::Command { seq, command } => Event::Command { seq, command },
            DaemonEvent::Shutdown => Event::Shutdown,
            // The agent gave up while no UI was connected. Dropping the event silently would
            // leave the UI's acknowledgements short of `seq`, and the daemon would take the
            // healthy UI for a hung one.
            DaemonEvent::SshApproval { seq, reply, .. } if reply.is_closed() => Event::Skipped(seq),
            DaemonEvent::SshApproval { seq, prompt, reply } => Event::SshApproval {
                seq,
                request_id: approvals.register(reply),
                prompt,
            },
        };
        if publisher.send_event(event).await.is_err() {
            break;
        }
    }
}

#[derive(Default)]
struct Approvals {
    inner: Mutex<ApprovalTable>,
}

#[derive(Default)]
struct ApprovalTable {
    next_id: u64,
    pending: HashMap<u64, oneshot::Sender<SshDecision>>,
}

impl Approvals {
    fn register(&self, reply: oneshot::Sender<SshDecision>) -> u64 {
        let mut table = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        table.pending.retain(|_, reply| !reply.is_closed());
        table.next_id += 1;
        let id = table.next_id;
        table.pending.insert(id, reply);
        id
    }

    fn resolve(&self, id: u64, decision: SshDecision) {
        let reply = self
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .remove(&id);
        if let Some(reply) = reply {
            let _ = reply.send(decision);
        }
    }
}

/// Sends cache snapshots and change notifications in order. The lock is held across the sends so
/// a snapshot can never be overtaken by an older one.
struct Publisher<S> {
    service: Arc<S>,
    revision: watch::Receiver<u64>,
    outbox: mpsc::Sender<Frame>,
    last: AsyncMutex<Published>,
}

#[derive(Default, Clone, Copy)]
struct Published {
    revision: u64,
    offline: bool,
}

impl<S: VaultService> Publisher<S> {
    fn new(service: Arc<S>, outbox: mpsc::Sender<Frame>) -> Self {
        Self {
            revision: service.changes(),
            service,
            outbox,
            last: AsyncMutex::new(Published::default()),
        }
    }

    async fn welcome(&self) -> Result<(), IpcError> {
        let mut last = self.last.lock().await;
        let revision = *self.revision.borrow();
        let snapshot = snapshot(self.service.as_ref());
        let offline = snapshot.is_offline;
        let welcome = Welcome {
            protocol_version: PROTOCOL_VERSION,
            revision,
            snapshot,
        };
        self.send(&DaemonMessage::Welcome(Box::new(welcome)))
            .await?;
        *last = Published { revision, offline };
        Ok(())
    }

    /// Sends a snapshot (then `OfflineChanged` / `Changed` when those moved) if the change
    /// counter moved since the last one, or always when `force` is set.
    async fn publish(&self, force: bool) -> Result<(), IpcError> {
        let mut last = self.last.lock().await;
        let revision = *self.revision.borrow();
        if !force && revision == last.revision {
            return Ok(());
        }
        let snapshot = snapshot(self.service.as_ref());
        let offline = snapshot.is_offline;
        self.send_event(Event::Snapshot(Box::new(snapshot))).await?;
        if offline != last.offline {
            self.send_event(Event::OfflineChanged(offline)).await?;
        }
        if revision != last.revision {
            self.send_event(Event::Changed(revision)).await?;
        }
        *last = Published { revision, offline };
        Ok(())
    }

    async fn send_event(&self, event: Event) -> Result<(), IpcError> {
        self.send(&DaemonMessage::Event(event)).await
    }

    async fn send(&self, message: &DaemonMessage) -> Result<(), IpcError> {
        let frame = encode(message)?;
        self.outbox
            .send(frame)
            .await
            .map_err(|_| IpcError::Disconnected)
    }
}

fn snapshot<S: VaultService>(service: &S) -> Snapshot {
    Snapshot {
        state: service.state().into(),
        accounts: service.accounts().into_iter().map(Into::into).collect(),
        is_offline: service.is_offline(),
        last_sync: service.last_sync().and_then(|time| {
            time.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|elapsed| elapsed.as_secs())
        }),
        folders: wire_list(service.folders()),
        organizations: wire_list(service.organizations()),
        collections: wire_list(service.collections()),
    }
}

fn wire_list<T, D: From<T>>(list: vk_vault::Result<Vec<T>>) -> Result<Vec<D>, WireError> {
    list.map(|items| items.into_iter().map(D::from).collect())
        .map_err(|error| WireError::from(&error))
}
