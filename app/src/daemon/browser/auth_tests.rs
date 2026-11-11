use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use tokio::sync::{Mutex, mpsc};
use vk_ipc::{
    BrowserReply,
    browser::{
        BrowserConnection,
        protocol::{Caller, HostHello, KnownBrowser, ParentInfo, State, Theme},
    },
};
use zeroize::Zeroizing;

use super::{auth::authenticate, pairing::PairingStore};

#[tokio::test]
async fn disconnect_withdraws_pairing_prompt() {
    let dir = tempfile::tempdir().expect("directory");
    let store = Arc::new(Mutex::new(
        PairingStore::load(&dir.path().join("browsers.json")).expect("store"),
    ));
    let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
    let (tx, incoming) = mpsc::channel(4);
    let (outgoing, mut rx) = mpsc::channel(4);
    let connection = BrowserConnection {
        id: 1,
        hello: HostHello {
            protocol: 1,
            caller: Caller::Firefox {
                extension_id: "extension".into(),
            },
            parent: ParentInfo {
                pid: 1,
                executable: "test".into(),
                browser: Some(KnownBrowser::Firefox),
            },
        },
        incoming,
        outgoing,
    };
    let (prompted, ready) = tokio::sync::oneshot::channel();
    let (approve, answer) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(authenticate(
        connection,
        Arc::clone(&store),
        move |_| async move {
            let _ = prompted.send(());
            answer.await.unwrap_or(BrowserReply::Dismissed)
        },
        || (State::Locked, Theme::Dark),
    ));
    let hello = serde_json::json!({"type":"hello","id":1,"protocol":1,"extension_version":"1","public_key":STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes())});
    tx.send(Zeroizing::new(serde_json::to_vec(&hello).expect("hello")))
        .await
        .expect("send");
    let reply: serde_json::Value =
        serde_json::from_slice(&rx.recv().await.expect("challenge")).expect("json");
    let challenge = STANDARD
        .decode(reply["result"]["challenge"].as_str().expect("challenge"))
        .expect("base64");
    let mut message = b"vaultkeeper-browser-v1\0".to_vec();
    message.extend_from_slice(&challenge);
    message.extend_from_slice(b"extension");
    let signature: Signature = key.sign(&message);
    let proof = serde_json::json!({"type":"prove","id":2,"signature":STANDARD.encode(signature.to_bytes())});
    tx.send(Zeroizing::new(serde_json::to_vec(&proof).expect("proof")))
        .await
        .expect("send");
    ready.await.expect("prompt started");
    drop(rx);
    assert!(task.await.expect("task").is_none());
    assert!(approve.send(BrowserReply::PairApproved).is_err());
    assert!(store.lock().await.paired.is_empty());
}

#[tokio::test]
async fn invalid_signature_never_prompts_or_persists() {
    let dir = tempfile::tempdir().expect("directory");
    let store = Arc::new(Mutex::new(
        PairingStore::load(&dir.path().join("browsers.json")).expect("store"),
    ));
    let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
    let (tx, incoming) = mpsc::channel(4);
    let (outgoing, mut rx) = mpsc::channel(4);
    let connection = BrowserConnection {
        id: 1,
        hello: HostHello {
            protocol: 1,
            caller: Caller::Firefox {
                extension_id: "extension".into(),
            },
            parent: ParentInfo {
                pid: 1,
                executable: "test".into(),
                browser: Some(KnownBrowser::Firefox),
            },
        },
        incoming,
        outgoing,
    };
    let task = tokio::spawn(authenticate(
        connection,
        Arc::clone(&store),
        |_| async { panic!("invalid signature prompted") },
        || (State::Locked, Theme::Dark),
    ));
    let hello = serde_json::json!({"type":"hello","id":1,"protocol":1,"extension_version":"1","public_key":STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes())});
    tx.send(Zeroizing::new(serde_json::to_vec(&hello).expect("hello")))
        .await
        .expect("send");
    rx.recv().await.expect("challenge");
    let proof = serde_json::json!({"type":"prove","id":2,"signature":"invalid"});
    tx.send(Zeroizing::new(serde_json::to_vec(&proof).expect("proof")))
        .await
        .expect("send");
    let reply: serde_json::Value =
        serde_json::from_slice(&rx.recv().await.expect("response")).expect("json");
    assert_eq!(reply["error"], "denied");
    assert!(task.await.expect("task").is_none());
    assert!(store.lock().await.paired.is_empty());
    assert!(!dir.path().join("browsers.json").exists());
}

#[tokio::test]
async fn authenticates_new_then_known_key() {
    let dir = tempfile::tempdir().expect("directory");
    let store = Arc::new(Mutex::new(
        PairingStore::load(&dir.path().join("browsers.json")).expect("store"),
    ));
    let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
    let public_key = STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes());
    let prompted = Arc::new(AtomicUsize::new(0));
    for known in [false, true] {
        let (tx, incoming) = mpsc::channel(4);
        let (outgoing, mut rx) = mpsc::channel(4);
        let connection = BrowserConnection {
            id: 1,
            hello: HostHello {
                protocol: 1,
                caller: Caller::Firefox {
                    extension_id: "extension".into(),
                },
                parent: ParentInfo {
                    pid: 1,
                    executable: "test".into(),
                    browser: Some(KnownBrowser::Firefox),
                },
            },
            incoming,
            outgoing,
        };
        let count = Arc::clone(&prompted);
        let task = tokio::spawn(authenticate(
            connection,
            Arc::clone(&store),
            move |_| async move {
                count.fetch_add(1, Ordering::SeqCst);
                BrowserReply::PairApproved
            },
            || (State::Unlocked, Theme::Dark),
        ));
        let hello = serde_json::json!({"type":"hello","id":1,"protocol":1,"extension_version":"1","public_key":public_key});
        tx.send(Zeroizing::new(serde_json::to_vec(&hello).expect("hello")))
            .await
            .expect("send");
        let reply: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.expect("challenge")).expect("json");
        assert_eq!(reply["result"]["known"], known);
        let challenge = STANDARD
            .decode(reply["result"]["challenge"].as_str().expect("challenge"))
            .expect("base64");
        let mut message = b"vaultkeeper-browser-v1\0".to_vec();
        message.extend_from_slice(&challenge);
        message.extend_from_slice(b"extension");
        let signature: Signature = key.sign(&message);
        let proof = serde_json::json!({"type":"prove","id":2,"signature":STANDARD.encode(signature.to_bytes())});
        tx.send(Zeroizing::new(serde_json::to_vec(&proof).expect("proof")))
            .await
            .expect("send");
        let reply: serde_json::Value =
            serde_json::from_slice(&rx.recv().await.expect("proof reply")).expect("json");
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["result"]["state"], "unlocked");
        assert!(task.await.expect("task").is_some());
    }
    assert_eq!(prompted.load(Ordering::SeqCst), 1);
    assert_eq!(
        PairingStore::load(&dir.path().join("browsers.json"))
            .expect("reload")
            .paired
            .len(),
        1
    );
}
