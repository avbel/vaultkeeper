//! The named-pipe transport, exercised where only Windows can run it: the pool and its DACL, the
//! server check on connect, and the peer check on accept.

#![cfg(windows)]

use std::{
    io,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::ServerOptions,
};
use vk_ipc::{
    PeerVerifier, SameExecutable,
    transport::{Endpoint, Listener, connect},
};

/// A hang in accept or connect must surface as a failure with a message, not as a stuck CI job.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

async fn accept_and_connect(
    listener: &Listener,
    endpoint: &Endpoint,
) -> (
    (vk_ipc::transport::Stream, vk_ipc::PeerCredentials),
    vk_ipc::transport::Stream,
) {
    let (accepted, connected) = tokio::join!(
        tokio::time::timeout(STEP_TIMEOUT, listener.accept()),
        tokio::time::timeout(STEP_TIMEOUT, connect(endpoint)),
    );
    (
        accepted
            .expect("accept timed out after 10 s")
            .expect("accept"),
        connected
            .expect("connect timed out after 10 s")
            .expect("connect"),
    )
}

/// A pipe name unique to this test run, so parallel tests and re-runs never share one.
fn unique_name(tag: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\vk-ipc-{}-{tag}-{n}", std::process::id())
}

#[tokio::test]
async fn round_trip_through_bind_and_connect() {
    let endpoint = Endpoint::pipe(unique_name("roundtrip"));
    let listener = Listener::bind(&endpoint).expect("bind");
    let ((mut server, peer), mut client) = accept_and_connect(&listener, &endpoint).await;

    assert_eq!(
        peer.pid,
        i32::try_from(std::process::id()).expect("pid fits")
    );

    client.write_all(b"ping").await.expect("client write");
    let mut received = [0_u8; 4];
    server.read_exact(&mut received).await.expect("server read");
    assert_eq!(&received, b"ping");

    server.write_all(b"pong").await.expect("server write");
    let mut received = [0_u8; 4];
    client.read_exact(&mut received).await.expect("client read");
    assert_eq!(&received, b"pong");
}

#[tokio::test]
async fn a_name_can_be_bound_again_after_shutdown() {
    let endpoint = Endpoint::pipe(unique_name("rebind"));
    let first = Listener::bind(&endpoint).expect("bind");
    let ((server, _peer), client) = accept_and_connect(&first, &endpoint).await;
    drop(client);
    drop(server);
    first.shutdown().await;

    let second = Listener::bind(&endpoint).expect("rebind after shutdown");
    let _ = accept_and_connect(&second, &endpoint).await;
}

#[tokio::test]
async fn a_second_bind_of_the_same_name_fails() {
    let endpoint = Endpoint::pipe(unique_name("squat"));
    let _listener = Listener::bind(&endpoint).expect("bind");
    let Err(error) = Listener::bind(&endpoint) else {
        panic!("the name is taken");
    };
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn the_dacl_denies_a_plain_extra_instance() {
    let endpoint = Endpoint::pipe(unique_name("dacl"));
    let _listener = Listener::bind(&endpoint).expect("bind");
    let name = endpoint.as_pipe().expect("pipe name");
    // No first-instance flag: the failure proves the DACL, not just the flag, refuses a new one.
    let error = ServerOptions::new()
        .create(name)
        .expect_err("the DACL denies it");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn five_clients_recycle_a_pool_of_four() {
    let endpoint = Endpoint::pipe(unique_name("recycle"));
    let listener = Listener::bind(&endpoint).expect("bind");
    for iteration in 0..5 {
        let ((mut server, _peer), mut client) = accept_and_connect(&listener, &endpoint).await;
        client
            .write_all(&[0x01])
            .await
            .unwrap_or_else(|error| panic!("iteration {iteration}: client write: {error}"));
        let mut received = [0_u8; 1];
        server
            .read_exact(&mut received)
            .await
            .unwrap_or_else(|error| panic!("iteration {iteration}: server read: {error}"));
        assert_eq!(received, [0x01], "iteration {iteration}");
        // The reply is still unread when the server drops; recycling must not discard it.
        server
            .write_all(&[0x02])
            .await
            .unwrap_or_else(|error| panic!("iteration {iteration}: server reply: {error}"));
        drop(server);
        client
            .read_exact(&mut received)
            .await
            .unwrap_or_else(|error| panic!("iteration {iteration}: client read reply: {error}"));
        assert_eq!(received, [0x02], "iteration {iteration}");
    }
}

#[tokio::test]
async fn our_own_client_passes_the_identity_check() {
    let endpoint = Endpoint::pipe(unique_name("identity"));
    let listener = Listener::bind(&endpoint).expect("bind");
    let ((_server, peer), _client) = accept_and_connect(&listener, &endpoint).await;
    assert!(SameExecutable::current().expect("verifier").verify(&peer));
}

#[tokio::test]
async fn a_verifier_for_another_executable_rejects_our_peer() {
    let endpoint = Endpoint::pipe(unique_name("foreign"));
    let listener = Listener::bind(&endpoint).expect("bind");
    let ((_server, peer), _client) = accept_and_connect(&listener, &endpoint).await;
    // A verifier pinned to another binary never admits our own peer.
    let foreign = SameExecutable::new(Path::new(r"C:\Windows\explorer.exe")).expect("verifier");
    assert!(!foreign.verify(&peer));
}

#[tokio::test]
async fn the_ui_pipe_serves_its_server_end_to_the_adopted_client() {
    let mut pipe = vk_ipc::transport::UiPipe::create().expect("create");
    assert!(pipe.client_handle().is_some());
    // This process is both ends here, so the parent-pid check of `adopt_ui_pipe` is not exercised;
    // the daemon-side pid check already ran inside `create`.
    pipe.close_client();
    drop(pipe.into_stream());
}
