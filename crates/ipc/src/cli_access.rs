//! The terminal commands talk to the tray through a separate, read-only TLS endpoint.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vk_vault::model::{CliLoginField, CliLoginKey};
use zeroize::Zeroizing;

use crate::{IpcError, PeerVerifier, SameExecutable, frame, peer, server};

const SERVER_NAME: &str = "vaultkeeper-cli.local";
const DEADLINE: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 16;
const MAX_CERTIFICATE: usize = 4096;
const MAX_REQUEST: usize = 4096;

#[derive(Serialize, Deserialize)]
pub enum Request {
    ListKeys,
    GetFields {
        key: String,
    },
    GetValue {
        key: String,
        field: String,
        allow_private: bool,
    },
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Keys(Vec<CliLoginKey>),
    Fields(Vec<CliLoginField>),
    Value(Zeroizing<String>),
    Locked,
    LoggedOut,
    Unavailable,
    NotFound,
    NoSuchField,
    PrivateField,
}

#[must_use = "dropping the handle stops the CLI socket"]
pub struct Listener {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "cannot remove the CLI socket");
        }
    }
}

/// Must run inside the daemon's Tokio runtime. `changes` invalidates pending vault responses.
pub fn serve(
    path: PathBuf,
    changes: watch::Receiver<u64>,
    handle: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> Result<Listener, IpcError> {
    let verifier = SameExecutable::current()?;
    let identity = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
        .map_err(io::Error::other)?;
    let certificate = identity.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
    let mut tls = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key.into())
    .map_err(io::Error::other)?;
    tls.send_tls13_tickets = 0;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    server::prepare_directory(&path)?;
    server::remove_stale_socket(&path)?;
    let socket = server::bind(&path)?;
    let task = tokio::spawn(accept(
        socket,
        verifier,
        acceptor,
        certificate,
        changes,
        Arc::new(handle),
    ));
    Ok(Listener { path, task })
}

async fn accept(
    socket: UnixListener,
    verifier: SameExecutable,
    acceptor: TlsAcceptor,
    certificate: CertificateDer<'static>,
    changes: watch::Receiver<u64>,
    handle: Arc<impl Fn(Request) -> Response + Send + Sync + 'static>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            Some(_) = connections.join_next() => {}
            accepted = socket.accept() => match accepted {
                Ok((stream, _)) if connections.len() < MAX_CONNECTIONS => {
                    let verifier = verifier.clone();
                    let acceptor = acceptor.clone();
                    let certificate = certificate.clone();
                    let changes = changes.clone();
                    let handle = Arc::clone(&handle);
                    connections.spawn(async move {
                        let _ = timeout(
                            DEADLINE,
                            respond(stream, &verifier, acceptor, &certificate, changes, &*handle),
                        ).await;
                    });
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "CLI socket accept failed");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

fn verify(stream: &UnixStream, verifier: &SameExecutable) -> Result<(), IpcError> {
    let peer = peer::credentials(stream)?;
    if peer.uid != peer::own_uid() || !verifier.verify(&peer) {
        return Err(
            io::Error::new(io::ErrorKind::PermissionDenied, "untrusted CLI socket peer").into(),
        );
    }
    Ok(())
}

async fn respond(
    mut stream: UnixStream,
    verifier: &SameExecutable,
    acceptor: TlsAcceptor,
    certificate: &[u8],
    mut changes: watch::Receiver<u64>,
    handle: &impl Fn(Request) -> Response,
) -> Result<(), IpcError> {
    verify(&stream, verifier)?;
    // Only the public certificate crosses the kernel-authenticated socket before TLS.
    let size = u32::try_from(certificate.len()).map_err(io::Error::other)?;
    stream.write_u32_le(size).await?;
    stream.write_all(certificate).await?;
    let mut tls = acceptor.accept(stream).await?;
    let body = frame::read_frame_with_limit(&mut tls, MAX_REQUEST)
        .await?
        .ok_or(IpcError::Disconnected)?;
    let request = frame::decode(&body)?;
    changes.borrow_and_update();
    let response = handle(request);
    let is_vault_data = matches!(
        response,
        Response::Keys(_) | Response::Fields(_) | Response::Value(_)
    );
    let encoded = frame::encode(&response)?;
    drop(response);
    let write = async {
        tls.write_all(&encoded).await?;
        tls.flush().await
    };
    tokio::select! {
        biased;
        _ = changes.changed(), if is_vault_data => {}
        result = write => result?,
    }
    Ok(())
}

pub async fn call(path: &Path, request: &Request) -> Result<Response, IpcError> {
    timeout(DEADLINE, exchange(path, request))
        .await
        .map_err(|_| IpcError::Timeout(DEADLINE))?
}

async fn exchange(path: &Path, request: &Request) -> Result<Response, IpcError> {
    let mut stream = UnixStream::connect(path).await?;
    verify(&stream, &SameExecutable::current()?)?;
    let certificate = frame::read_frame_with_limit(&mut stream, MAX_CERTIFICATE)
        .await?
        .ok_or(IpcError::Disconnected)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.as_slice()))
        .map_err(io::Error::other)?;
    let tls = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = ServerName::try_from(SERVER_NAME).map_err(io::Error::other)?;
    let mut tls = TlsConnector::from(Arc::new(tls))
        .connect(name, stream)
        .await?;
    tls.write_all(&frame::encode(request)?).await?;
    tls.flush().await?;
    let body = frame::read_frame(&mut tls)
        .await?
        .ok_or(IpcError::Disconnected)?;
    frame::decode(&body)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            Self(PathBuf::from(format!("/tmp/vk-cli-{}", std::process::id())))
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn requires_tls_and_cancels_a_response_on_vault_change() {
        let dir = TestDir::new();
        let path = dir.0.join("cli.sock");
        let (publish, changes) = watch::channel(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let listener = serve(path.clone(), changes, move |request| {
            handled.fetch_add(1, Ordering::Relaxed);
            match request {
                Request::ListKeys => Response::Keys(vec![CliLoginKey {
                    key: Arc::from("key"),
                    title: Arc::from("Test login"),
                }]),
                Request::GetFields { .. } => Response::Fields(Vec::new()),
                Request::GetValue { key, .. } => {
                    if key == "revoked" {
                        publish.send_replace(1);
                    }
                    Response::Value(Zeroizing::new("test-password".to_owned()))
                }
            }
        })
        .expect("listen");

        let mut plaintext = UnixStream::connect(&path).await.expect("connect");
        assert!(
            frame::read_frame_with_limit(&mut plaintext, MAX_CERTIFICATE)
                .await
                .expect("certificate")
                .is_some()
        );
        plaintext
            .write_all(&frame::encode(&Request::ListKeys).expect("encode"))
            .await
            .expect("write");
        plaintext.shutdown().await.expect("close");
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        let Response::Keys(keys) = call(&path, &Request::ListKeys).await.expect("TLS list") else {
            panic!("expected keys");
        };
        assert_eq!(&*keys[0].key, "key");
        assert_eq!(&*keys[0].title, "Test login");
        let request = |key: &str| Request::GetValue {
            key: key.to_owned(),
            field: "password".to_owned(),
            allow_private: true,
        };
        let Response::Value(value) = call(&path, &request("key")).await.expect("TLS value") else {
            panic!("expected credentials");
        };
        assert_eq!(value.as_str(), "test-password");
        assert!(call(&path, &request("revoked")).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        drop(listener);
        assert!(!path.exists());
    }
}
