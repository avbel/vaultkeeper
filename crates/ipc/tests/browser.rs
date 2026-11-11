mod common;

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::mpsc,
};
use vk_ipc::{
    PeerCredentials,
    browser::{BROWSER_MAX_FRAME, BrowserServeOptions, serve_browser},
};
use zeroize::Zeroizing;

async fn send(stream: &mut UnixStream, body: &[u8]) {
    stream
        .write_all(&(u32::try_from(body.len()).expect("test frame length fits")).to_le_bytes())
        .await
        .expect("browser test operation");
    stream
        .write_all(body)
        .await
        .expect("browser test operation");
}

async fn recv(stream: &mut UnixStream) -> serde_json::Value {
    let len = stream.read_u32_le().await.expect("browser test operation") as usize;
    let mut body = vec![0; len];
    stream
        .read_exact(&mut body)
        .await
        .expect("browser test operation");
    serde_json::from_slice(&body).expect("browser test operation")
}

#[tokio::test]
async fn browser_socket_handshake_limits_and_relay() {
    let dir = common::SocketDir::new();
    let path = dir.path().join("browser.sock");
    let (tx, mut rx) = mpsc::channel(8);
    let server = serve_browser(
        path.clone(),
        BrowserServeOptions {
            verifier: Arc::new(|_: &PeerCredentials| true),
            require_verified_parent: true,
            max_connections: 4,
        },
        tx,
    )
    .await
    .expect("browser test operation");
    let hello = |protocol, browser: serde_json::Value| {
        serde_json::to_vec(&serde_json::json!({
            "protocol": protocol, "caller": {"kind": "firefox", "extension_id": "test"},
            "parent": {"pid": 1, "executable": "browser", "browser": browser}
        }))
        .expect("browser test operation")
    };
    let mut wrong = UnixStream::connect(&path)
        .await
        .expect("browser test operation");
    send(&mut wrong, &hello(2, serde_json::json!("firefox"))).await;
    assert_eq!(recv(&mut wrong).await["reason"], "version");
    let mut unverified = UnixStream::connect(&path)
        .await
        .expect("browser test operation");
    send(&mut unverified, &hello(1, serde_json::Value::Null)).await;
    assert_eq!(recv(&mut unverified).await["reason"], "unverified_parent");
    let mut clients = Vec::new();
    let mut sessions = Vec::new();
    for _ in 0..4 {
        let mut client = UnixStream::connect(&path)
            .await
            .expect("browser test operation");
        send(&mut client, &hello(1, serde_json::json!("firefox"))).await;
        assert_eq!(recv(&mut client).await["ok"], true);
        sessions.push(rx.recv().await.expect("browser test operation"));
        clients.push(client);
    }
    let mut fifth = UnixStream::connect(&path)
        .await
        .expect("browser test operation");
    send(&mut fifth, &hello(1, serde_json::json!("firefox"))).await;
    assert_eq!(recv(&mut fifth).await["reason"], "busy");
    send(&mut clients[0], br#"{"type":"status","id":1}"#).await;
    assert_eq!(
        sessions[0]
            .incoming
            .recv()
            .await
            .expect("browser test operation")
            .as_slice(),
        br#"{"type":"status","id":1}"#
    );
    sessions[0]
        .outgoing
        .send(Zeroizing::new(br#"{"id":1,"ok":true}"#.to_vec()))
        .await
        .expect("browser test operation");
    assert_eq!(recv(&mut clients[0]).await["id"], 1);
    clients[0]
        .write_all(&(u32::try_from(BROWSER_MAX_FRAME + 1).expect("frame limit fits")).to_le_bytes())
        .await
        .expect("browser test operation");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), sessions[0].incoming.recv())
            .await
            .expect("browser test operation")
            .is_none()
    );
    drop(clients.pop());
    assert!(
        tokio::time::timeout(Duration::from_secs(2), sessions[3].incoming.recv())
            .await
            .expect("browser test operation")
            .is_none()
    );
    drop(server);
    assert!(!path.exists());
}
