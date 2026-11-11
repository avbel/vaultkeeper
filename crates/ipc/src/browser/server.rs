use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use zeroize::Zeroizing;

use super::{
    BROWSER_MAX_FRAME,
    protocol::{HostHello, PROTOCOL_VERSION, Refusal},
};
use crate::{IpcError, PeerVerifier, frame::read_frame_with_limit, peer, server};

pub struct BrowserConnection {
    pub id: u64,
    pub hello: HostHello,
    pub incoming: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    pub outgoing: mpsc::Sender<Zeroizing<Vec<u8>>>,
}

pub struct BrowserServeOptions {
    pub verifier: Arc<dyn PeerVerifier>,
    pub require_verified_parent: bool,
    pub max_connections: usize,
}

#[must_use = "dropping the handle stops the browser server"]
pub struct BrowserServerHandle {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl Drop for BrowserServerHandle {
    fn drop(&mut self) {
        self.task.abort();
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %self.path.display(), "cannot remove browser socket");
        }
    }
}

impl BrowserServerHandle {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Binds a private browser socket and starts its accept loop.
///
/// Cancel-safe: all setup happens before the returned future first yields.
pub async fn serve_browser(
    path: PathBuf,
    options: BrowserServeOptions,
    connections: mpsc::Sender<BrowserConnection>,
) -> Result<BrowserServerHandle, IpcError> {
    server::prepare_directory(&path)?;
    server::remove_stale_socket(&path)?;
    let listener = server::bind(&path)?;
    let task = tokio::spawn(accept_loop(listener, options, connections));
    Ok(BrowserServerHandle { path, task })
}

// Cancel-safe: dropping the loop aborts its owned connection tasks.
async fn accept_loop(
    listener: UnixListener,
    options: BrowserServeOptions,
    connections: mpsc::Sender<BrowserConnection>,
) {
    let options = Arc::new(options);
    let slots = Arc::new(Semaphore::new(options.max_connections));
    let ids = Arc::new(AtomicU64::new(1));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            () = connections.closed() => break,
            Some(result) = tasks.join_next() => {
                if let Err(error) = result && error.is_panic() {
                    tracing::error!(%error, "browser connection task panicked");
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    // Bound pending handshakes as well as established sessions.
                    if tasks.len() >= options.max_connections.saturating_add(16) { continue; }
                    tasks.spawn(handle(stream, Arc::clone(&options), Arc::clone(&slots), Arc::clone(&ids), connections.clone()));
                }
                Err(error) => {
                    tracing::warn!(%error, "browser accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

// Not cancel-safe mid-frame; cancellation always drops the socket.
async fn handle(
    mut stream: UnixStream,
    options: Arc<BrowserServeOptions>,
    slots: Arc<Semaphore>,
    ids: Arc<AtomicU64>,
    connections: mpsc::Sender<BrowserConnection>,
) {
    let Ok(peer) = peer::credentials(&stream) else {
        return;
    };
    if peer.uid != peer::own_uid() || !options.verifier.verify(&peer) {
        return;
    }
    let Ok(Ok(Some(body))) = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame_with_limit(&mut stream, BROWSER_MAX_FRAME),
    )
    .await
    else {
        return;
    };
    let Ok(hello) = serde_json::from_slice::<HostHello>(&body) else {
        return;
    };
    let refusal = if hello.protocol != PROTOCOL_VERSION {
        Some(Refusal::Version)
    } else if options.require_verified_parent && hello.parent.browser.is_none() {
        Some(Refusal::UnverifiedParent)
    } else {
        None
    };
    if let Some(reason) = refusal {
        let _ = write_json(
            &mut stream,
            &serde_json::json!({"ok": false, "reason": reason}),
        )
        .await;
        return;
    }
    let Ok(_permit) = slots.try_acquire_owned() else {
        let _ = write_json(
            &mut stream,
            &serde_json::json!({"ok": false, "reason": "busy"}),
        )
        .await;
        return;
    };
    if write_json(&mut stream, &serde_json::json!({"ok": true}))
        .await
        .is_err()
    {
        return;
    }
    let (incoming_tx, incoming) = mpsc::channel(16);
    let (outgoing, mut outgoing_rx) = mpsc::channel::<Zeroizing<Vec<u8>>>(16);
    let connection = BrowserConnection {
        id: ids.fetch_add(1, Ordering::Relaxed),
        hello,
        incoming,
        outgoing,
    };
    if connections.send(connection).await.is_err() {
        return;
    }
    let (mut read, mut write) = stream.into_split();
    let reader = async {
        while let Ok(Some(body)) = read_frame_with_limit(&mut read, BROWSER_MAX_FRAME).await {
            if incoming_tx.send(body).await.is_err() {
                break;
            }
        }
    };
    let writer = async {
        while let Some(body) = outgoing_rx.recv().await {
            if write_body(&mut write, &body).await.is_err() {
                break;
            }
        }
    };
    tokio::select! { () = reader => {}, () = writer => {} }
}

// Not cancel-safe: a partially written frame requires closing the socket.
async fn write_body<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > BROWSER_MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "browser frame too large",
        ));
    }
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "browser frame too large"))?;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(body).await
}

// Not cancel-safe: a partially written frame requires closing the socket.
async fn write_json<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &serde_json::Value,
) -> io::Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(value)?);
    write_body(writer, &body).await
}
