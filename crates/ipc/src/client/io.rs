//! The client's I/O thread: handshake, then one reader and one writer over the socket.

use std::{sync::Arc, thread, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
};

use super::{Cache, Frame, Shared, SshApproval, UiEvent};
use crate::{
    IpcError,
    frame::{decode, encode, read_frame},
    protocol::{DaemonMessage, Event, PROTOCOL_VERSION, Refusal, UiMessage, Welcome},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

type Ready = oneshot::Sender<Result<(Arc<Shared>, watch::Receiver<u64>), IpcError>>;

/// Owns the thread; dropping it stops the session and joins the thread.
pub(super) struct IoThread {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl IoThread {
    pub(super) fn spawn(
        stream: std::os::unix::net::UnixStream,
        events: mpsc::UnboundedSender<UiEvent>,
        ready: Ready,
    ) -> std::io::Result<Self> {
        let (stop, stopped) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("bwl-ipc".to_owned())
            .spawn(move || run(stream, events, ready, stopped))?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for IoThread {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("the IPC client thread panicked");
        }
    }
}

fn run(
    stream: std::os::unix::net::UnixStream,
    events: mpsc::UnboundedSender<UiEvent>,
    ready: Ready,
    mut stopped: oneshot::Receiver<()>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(error.into()));
            return;
        }
    };
    runtime.block_on(async move {
        let connected = tokio::select! {
            connected = connect(stream) => connected,
            _ = &mut stopped => return,
        };
        let (read, write, shared, changes) = match connected {
            Ok(connected) => connected,
            Err(error) => {
                let _ = ready.send(Err(error));
                return;
            }
        };
        if ready
            .send(Ok((Arc::clone(&shared), changes.subscribe())))
            .is_err()
        {
            return;
        }
        let outcome = session(read, write, &shared, &changes, &events, stopped).await;
        if let Err(error) = outcome {
            tracing::info!(%error, "IPC connection to the daemon ended");
        }
        shared.close();
    });
}

type Connected = (OwnedReadHalf, OutboxWriter, Arc<Shared>, watch::Sender<u64>);

struct OutboxWriter {
    write: OwnedWriteHalf,
    outbox: mpsc::UnboundedReceiver<Frame>,
}

async fn connect(stream: std::os::unix::net::UnixStream) -> Result<Connected, IpcError> {
    let stream = UnixStream::from_std(stream)?;
    let (mut read, mut write) = stream.into_split();
    let welcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut read, &mut write))
        .await
        .map_err(|_| IpcError::Timeout(HANDSHAKE_TIMEOUT))??;
    let cache = Cache::try_from(welcome.snapshot)?;
    // Unbounded: sync callers must not block on a full queue, and each caller has at most one
    // request in flight, so the callers bound it themselves.
    let (outbox_tx, outbox) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared::new(outbox_tx, cache));
    let (changes, _) = watch::channel(welcome.revision);
    Ok((read, OutboxWriter { write, outbox }, shared, changes))
}

async fn handshake(
    read: &mut OwnedReadHalf,
    write: &mut OwnedWriteHalf,
) -> Result<Welcome, IpcError> {
    let hello = encode(&UiMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
    })?;
    write.write_all(&hello).await.map_err(hung_up)?;
    let body = read_frame(read)
        .await
        .map_err(|error| match error {
            IpcError::Io(io) => hung_up(io),
            other => other,
        })?
        .ok_or(IpcError::Disconnected)?;
    match decode(&body)? {
        DaemonMessage::Welcome(welcome) if welcome.protocol_version == PROTOCOL_VERSION => {
            Ok(*welcome)
        }
        DaemonMessage::Welcome(welcome) => Err(IpcError::VersionMismatch {
            ours: PROTOCOL_VERSION,
            theirs: welcome.protocol_version,
        }),
        DaemonMessage::Refused(Refusal::VersionMismatch { daemon }) => {
            Err(IpcError::VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: daemon,
            })
        }
        DaemonMessage::Refused(Refusal::Busy) => Err(IpcError::Busy),
        DaemonMessage::Response { .. } | DaemonMessage::Event(_) => Err(IpcError::Protocol(
            "the daemon did not start with a welcome",
        )),
    }
}

/// A daemon that refuses a peer just closes the socket; depending on timing the client sees
/// EOF, a reset or a broken pipe, which all mean the same here.
fn hung_up(error: std::io::Error) -> IpcError {
    match error.kind() {
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::NotConnected => IpcError::Disconnected,
        _ => IpcError::Io(error),
    }
}

/// Runs until the daemon goes away, a frame is malformed, or `RemoteVault` is dropped. The
/// reader never waits on the writer or the UI, so responses keep flowing whatever the UI does.
async fn session(
    read: OwnedReadHalf,
    writer: OutboxWriter,
    shared: &Shared,
    changes: &watch::Sender<u64>,
    events: &mpsc::UnboundedSender<UiEvent>,
    stopped: oneshot::Receiver<()>,
) -> Result<(), IpcError> {
    tokio::select! {
        _ = stopped => Ok(()),
        result = read_messages(read, shared, changes, events) => result,
        result = write_frames(writer) => result,
    }
}

async fn write_frames(mut writer: OutboxWriter) -> Result<(), IpcError> {
    while let Some(frame) = writer.outbox.recv().await {
        writer.write.write_all(&frame).await?;
    }
    Ok(())
}

async fn read_messages(
    mut read: OwnedReadHalf,
    shared: &Shared,
    changes: &watch::Sender<u64>,
    events: &mpsc::UnboundedSender<UiEvent>,
) -> Result<(), IpcError> {
    let mut approvals = JoinSet::new();
    while let Some(body) = read_frame(&mut read).await? {
        match decode(&body)? {
            DaemonMessage::Response { id, result } => shared.complete(id, result),
            DaemonMessage::Event(event) => {
                on_event(event, shared, changes, events, &mut approvals)?;
            }
            DaemonMessage::Welcome(_) | DaemonMessage::Refused(_) => {
                return Err(IpcError::Protocol("handshake message after the handshake"));
            }
        }
        while approvals.try_join_next().is_some() {}
    }
    Err(IpcError::Disconnected)
}

fn on_event(
    event: Event,
    shared: &Shared,
    changes: &watch::Sender<u64>,
    events: &mpsc::UnboundedSender<UiEvent>,
    approvals: &mut JoinSet<()>,
) -> Result<(), IpcError> {
    // Sends fail only when the UI dropped its EventStream; calls keep working without it.
    match event {
        Event::Snapshot(snapshot) => *shared.write_cache() = Cache::try_from(*snapshot)?,
        Event::Changed(revision) => {
            changes.send_if_modified(|current| {
                let moved = *current != revision;
                *current = revision;
                moved
            });
        }
        Event::OfflineChanged(offline) => {
            shared.write_cache().is_offline = offline;
            let _ = events.send(UiEvent::OfflineChanged(offline));
        }
        Event::Command(command) => {
            let _ = events.send(UiEvent::Command(command));
        }
        Event::SshApproval { request_id, prompt } => {
            let (reply, decision) = oneshot::channel();
            approvals.spawn(send_decision(shared.outbox.clone(), request_id, decision));
            let _ = events.send(UiEvent::SshApproval(SshApproval {
                request_id,
                prompt,
                reply,
            }));
        }
        Event::Shutdown => {
            let _ = events.send(UiEvent::Shutdown);
        }
    }
    Ok(())
}

/// A dropped `reply` sender counts as deny, as with the SSH agent's own approval channel.
async fn send_decision(
    outbox: mpsc::UnboundedSender<Frame>,
    request_id: u64,
    decision: oneshot::Receiver<bool>,
) {
    let approved = decision.await.unwrap_or(false);
    match encode(&UiMessage::SshApprovalReply {
        request_id,
        approved,
    }) {
        Ok(frame) => {
            let _ = outbox.send(frame);
        }
        Err(error) => tracing::error!(%error, "cannot encode an SSH approval reply"),
    }
}
