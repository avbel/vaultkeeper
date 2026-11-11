//! Listener lifecycle and cancellation ownership for browser sessions.

use std::{future::Future, path::PathBuf, sync::Arc};

use anyhow::{Context, ensure};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};
use vk_ipc::{
    SameExecutable,
    browser::{BrowserConnection, BrowserServeOptions, BrowserServerHandle, serve_browser},
};

use super::pairing::PairingStore;

pub struct BrowserControl {
    _server: BrowserServerHandle,
    connections: mpsc::Receiver<BrowserConnection>,
    store: Arc<Mutex<PairingStore>>,
}

impl BrowserControl {
    /// Bind only after the runtime and store checks succeed. Dropping this value closes the
    /// listener and transport tasks; the owner must also cancel its session tasks.
    pub async fn start(socket: PathBuf, store_path: PathBuf) -> anyhow::Result<Self> {
        ensure!(
            runtime_allowed(),
            "browser integration requires a hardened runtime"
        );
        let store = PairingStore::load(&store_path).context("load browser pairings")?;
        let verifier = SameExecutable::current().context("identify browser host executable")?;
        let (sender, connections) = mpsc::channel(4);
        let server = serve_browser(
            socket,
            BrowserServeOptions {
                verifier: Arc::new(verifier),
                require_verified_parent: !dev_browser_enabled(),
                max_connections: 4,
            },
            sender,
        )
        .await
        .context("start browser listener")?;
        Ok(Self {
            _server: server,
            connections,
            store: Arc::new(Mutex::new(store)),
        })
    }

    #[must_use]
    pub fn store(&self) -> Arc<Mutex<PairingStore>> {
        Arc::clone(&self.store)
    }

    /// Own all session tasks so cancelling this future closes the listener and aborts every session.
    pub async fn run<F, Fut>(mut self, handler: F)
    where
        F: Fn(BrowserConnection, Arc<Mutex<PairingStore>>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                connection = self.connections.recv() => match connection {
                    Some(connection) if sessions.len() < 4 => { sessions.spawn(handler(connection, Arc::clone(&self.store))); }
                    Some(_) => tracing::warn!("browser session capacity reached"),
                    None => break,
                },
                Some(result) = sessions.join_next() => {
                    if let Err(error) = result && error.is_panic() {
                        tracing::error!(%error, "browser session panicked");
                    }
                }
            }
        }
    }
}

#[cfg(all(test, feature = "vw-it"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_control_aborts_accepted_sessions() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct OnDrop(Arc<AtomicBool>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dir = tempfile::tempdir().expect("temporary directory");
        let socket = dir.path().join("browser.sock");
        let control = BrowserControl::start(socket.clone(), dir.path().join("browsers.json"))
            .await
            .expect("start");
        let dropped = Arc::new(AtomicBool::new(false));
        let (started_tx, mut started_rx) = mpsc::channel(1);
        let signal = Arc::clone(&dropped);
        let task = tokio::spawn(control.run(move |_connection, _store| {
            let guard = OnDrop(Arc::clone(&signal));
            let started = started_tx.clone();
            async move {
                let _guard = guard;
                started.send(()).await.expect("started");
                std::future::pending::<()>().await;
            }
        }));
        let mut peer = tokio::net::UnixStream::connect(&socket)
            .await
            .expect("connect");
        let hello = br#"{"protocol":1,"caller":{"kind":"firefox","extension_id":"test"},"parent":{"pid":1,"executable":"test","browser":"firefox"}}"#;
        peer.write_all(&(hello.len() as u32).to_le_bytes())
            .await
            .expect("header");
        peer.write_all(hello).await.expect("hello");
        let length = peer.read_u32_le().await.expect("welcome header");
        let mut welcome = vec![0; length as usize];
        peer.read_exact(&mut welcome).await.expect("welcome");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&welcome).expect("json")["ok"],
            true
        );
        started_rx.recv().await.expect("session started");
        task.abort();
        let _ = task.await;
        // JoinSet aborts children when dropped; await their cancellation on the runtime.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session stopped");
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn listener_starts_and_stops_and_corrupt_store_fails_closed() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let socket = dir.path().join("browser.sock");
        let store = dir.path().join("browsers.json");
        let control = BrowserControl::start(socket.clone(), store.clone())
            .await
            .expect("start");
        assert!(socket.exists());
        drop(control);
        assert!(!socket.exists());
        std::fs::write(&store, b"not json").expect("corrupt store");
        assert!(BrowserControl::start(socket.clone(), store).await.is_err());
        assert!(!socket.exists());
    }
}

fn runtime_allowed() -> bool {
    crate::browser_status::start_blocker().is_none()
}

fn dev_browser_enabled() -> bool {
    cfg!(debug_assertions)
        && std::env::var_os("VAULTKEEPER_DEV_BROWSER").as_deref() == Some(std::ffi::OsStr::new("1"))
}
