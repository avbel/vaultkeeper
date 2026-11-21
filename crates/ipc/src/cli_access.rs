//! The terminal commands talk to the tray through a separate, read-only TLS endpoint.

use std::{fs, io, sync::Arc, time::Duration};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vk_vault::model::{CliLoginField, CliLoginKey};
use zeroize::Zeroizing;

#[cfg(unix)]
use crate::peer;
use crate::{
    IpcError, PeerCredentials, PeerVerifier, SameExecutable, frame, server,
    transport::{self, Endpoint, Listener as TransportListener, Stream},
};

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
    endpoint: Endpoint,
    task: JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(path) = self.endpoint.as_path()
            && let Err(error) = fs::remove_file(path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "cannot remove the CLI socket");
        }
    }
}

/// Must run inside the daemon's Tokio runtime. `changes` invalidates pending vault responses.
pub fn serve(
    endpoint: impl Into<Endpoint>,
    changes: watch::Receiver<u64>,
    handle: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> Result<Listener, IpcError> {
    let endpoint = endpoint.into();
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
    server::prepare_endpoint(&endpoint)?;
    let socket = server::bind_endpoint(&endpoint)?;
    let task = tokio::spawn(accept(
        socket,
        verifier,
        acceptor,
        certificate,
        changes,
        Arc::new(handle),
    ));
    Ok(Listener { endpoint, task })
}

async fn accept(
    socket: TransportListener,
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
                Ok((stream, peer)) if connections.len() < MAX_CONNECTIONS => {
                    let verifier = verifier.clone();
                    let acceptor = acceptor.clone();
                    let certificate = certificate.clone();
                    let changes = changes.clone();
                    let handle = Arc::clone(&handle);
                    connections.spawn(async move {
                        let _ = timeout(
                            DEADLINE,
                            respond(stream, peer, &verifier, acceptor, &certificate, changes, &*handle),
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

fn verify(peer: &PeerCredentials, verifier: &SameExecutable) -> Result<(), IpcError> {
    #[cfg(unix)]
    if peer.uid != peer::own_uid() {
        return Err(
            io::Error::new(io::ErrorKind::PermissionDenied, "untrusted CLI socket peer").into(),
        );
    }
    if !verifier.verify(peer) {
        return Err(
            io::Error::new(io::ErrorKind::PermissionDenied, "untrusted CLI socket peer").into(),
        );
    }
    Ok(())
}

async fn respond(
    mut stream: Stream,
    peer: PeerCredentials,
    verifier: &SameExecutable,
    acceptor: TlsAcceptor,
    certificate: &[u8],
    mut changes: watch::Receiver<u64>,
    handle: &impl Fn(Request) -> Response,
) -> Result<(), IpcError> {
    verify(&peer, verifier)?;
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

/// The daemon is non-dumpable on Linux, so its executable cannot be read there: the socket and
/// the peer's cgroup are checked instead (`daemon_check`).
#[cfg(target_os = "linux")]
async fn connect_verified(endpoint: &Endpoint) -> Result<Stream, IpcError> {
    if let Some(path) = endpoint.as_path() {
        crate::daemon_check::check_socket(path)?;
    }
    let stream = transport::connect(endpoint).await?;
    let binding = crate::daemon_check::check_peer(stream.as_unix())?;
    tracing::debug!(?binding, "CLI daemon check passed");
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_verified(endpoint: &Endpoint) -> Result<Stream, IpcError> {
    let stream = transport::connect(endpoint).await?;
    verify(&stream.peer_credentials()?, &SameExecutable::current()?)?;
    Ok(stream)
}

pub async fn call(endpoint: impl Into<Endpoint>, request: &Request) -> Result<Response, IpcError> {
    let endpoint = endpoint.into();
    timeout(DEADLINE, exchange(&endpoint, request))
        .await
        .map_err(|_| IpcError::Timeout(DEADLINE))?
}

async fn exchange(endpoint: &Endpoint, request: &Request) -> Result<Response, IpcError> {
    let mut stream = connect_verified(endpoint).await?;
    let certificate = frame::read_frame_with_limit(&mut stream, MAX_CERTIFICATE)
        .await?
        .ok_or(IpcError::Disconnected)?;
    // The daemon sends its certificate only after it verified us by our exe.
    #[cfg(target_os = "linux")]
    vk_linux::probes::drop_dumpable();
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

#[cfg(all(test, unix))]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use tokio::net::UnixStream;

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
