use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use tokio::sync::{mpsc, oneshot, watch};
use vk_ipc::{
    BrowserPrompt, BrowserReply,
    browser::{
        BrowserConnection,
        protocol::{AppView, ErrorCode, FillResult, State, Theme},
    },
};
use zeroize::Zeroizing;

use super::{
    dispatch::{BrowserHost, Candidate, FillFlow, serve},
    fill::{FillRequest, Filled},
    pairing::PairingStore,
};

struct StubHost {
    enabled: AtomicBool,
    replies: Mutex<Vec<BrowserReply>>,
    unlocked: Mutex<Vec<oneshot::Sender<()>>>,
    activity: AtomicUsize,
    locked: AtomicBool,
    hold_unlock: AtomicBool,
    release_unlock: tokio::sync::Notify,
    epoch: AtomicUsize,
    records: Mutex<Vec<String>>,
    limits: Arc<Mutex<super::limits::Limits>>,
    changes: watch::Receiver<u64>,
}

impl StubHost {
    fn new() -> (Arc<Self>, watch::Sender<u64>) {
        let (changes, changes_rx) = watch::channel(0);
        let host = Arc::new(Self {
            enabled: AtomicBool::new(true),
            replies: Mutex::new(Vec::new()),
            unlocked: Mutex::new(Vec::new()),
            activity: AtomicUsize::new(0),
            locked: AtomicBool::new(false),
            hold_unlock: AtomicBool::new(false),
            release_unlock: tokio::sync::Notify::new(),
            epoch: AtomicUsize::new(0),
            records: Mutex::new(Vec::new()),
            limits: Arc::new(Mutex::new(super::limits::Limits::new(
                std::time::Instant::now(),
            ))),
            changes: changes_rx,
        });
        (host, changes)
    }

    fn reply(&self, reply: BrowserReply) {
        self.replies.lock().expect("replies").push(reply);
    }
}

impl BrowserHost for StubHost {
    fn prompt(&self, _prompt: BrowserPrompt) -> impl Future<Output = BrowserReply> + Send {
        let reply = self
            .replies
            .lock()
            .expect("replies")
            .pop()
            .unwrap_or(BrowserReply::Dismissed);
        std::future::ready(reply)
    }
    fn presence(&self, _reason: &str) -> impl Future<Output = bool> + Send {
        std::future::ready(true)
    }
    fn unlock(&self) -> impl Future<Output = ()> + Send {
        if let Some(done) = self.unlocked.lock().expect("waiters").pop() {
            let _ = done.send(());
        }
        self.locked.store(false, Ordering::SeqCst);
        let hold = self.hold_unlock.load(Ordering::SeqCst);
        async move {
            if hold {
                self.release_unlock.notified().await;
            }
        }
    }
    fn return_to(&self) -> impl Future<Output = Option<vk_ipc::TypingTarget>> + Send {
        std::future::ready(None)
    }
    fn status(&self) -> (State, Theme) {
        if self.locked.load(Ordering::SeqCst) {
            (State::Locked, Theme::Dark)
        } else {
            (State::Unlocked, Theme::Dark)
        }
    }
    fn limits(&self, _key: &[u8; 65]) -> Arc<Mutex<super::limits::Limits>> {
        Arc::clone(&self.limits)
    }
    fn approvals_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst) as u64
    }
    fn filled(&self, record: super::dispatch::FillRecord) {
        self.records
            .lock()
            .expect("records")
            .push(format!("{}@{}", record.item.0, record.host));
    }
    fn default_match(&self) -> vk_vault::uri_match::DefaultMatch {
        vk_vault::uri_match::DefaultMatch::Domain
    }
    fn browser_fill_single(&self) -> bool {
        false
    }
    fn browser_touch_id(&self) -> bool {
        false
    }
    fn enabled(&self, _browser: vk_ipc::browser::protocol::KnownBrowser) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }
    fn candidate(&self, _candidate: Candidate) {}
    fn open_app(&self, _view: AppView) {}
    fn note_activity(&self) {
        self.activity.fetch_add(1, Ordering::SeqCst);
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.clone()
    }
}

/// Fills wait for the test to hand back an answer, so tests control in-flight state and results.
struct GatedFills {
    gate: mpsc::Sender<oneshot::Sender<Result<Filled, ErrorCode>>>,
    seen: Mutex<Vec<Option<vk_vault::model::ItemId>>>,
}

impl GatedFills {
    fn new(gate: mpsc::Sender<oneshot::Sender<Result<Filled, ErrorCode>>>) -> Self {
        Self {
            gate,
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl FillFlow for GatedFills {
    async fn run<P, PFut, T, TFut, A, AFut>(
        &self,
        request: FillRequest,
        _prompt: P,
        _presence: T,
        _authorized: A,
    ) -> Result<Filled, ErrorCode>
    where
        P: FnOnce(BrowserPrompt) -> PFut + Send,
        PFut: Future<Output = BrowserReply> + Send,
        T: FnOnce() -> TFut + Send,
        TFut: Future<Output = bool> + Send,
        A: FnOnce() -> AFut + Send,
        AFut: Future<Output = bool> + Send,
    {
        self.seen.lock().expect("seen").push(request.remembered);
        let (done, answer) = oneshot::channel();
        self.gate.send(done).await.expect("gate open");
        answer.await.unwrap_or(Err(ErrorCode::Cancelled))
    }
}

type Channel = (
    BrowserConnection,
    mpsc::Sender<Zeroizing<Vec<u8>>>,
    mpsc::Receiver<Zeroizing<Vec<u8>>>,
);

fn connection() -> Channel {
    let (incoming_tx, incoming) = mpsc::channel(4);
    let (outgoing, outgoing_rx) = mpsc::channel(4);
    let hello = vk_ipc::browser::protocol::HostHello {
        protocol: 1,
        caller: vk_ipc::browser::protocol::Caller::Firefox {
            extension_id: "extension".into(),
        },
        parent: vk_ipc::browser::protocol::ParentInfo {
            pid: 1,
            executable: "test".into(),
            browser: Some(vk_ipc::browser::protocol::KnownBrowser::Firefox),
        },
    };
    (
        BrowserConnection {
            id: 1,
            hello,
            incoming,
            outgoing,
        },
        incoming_tx,
        outgoing_rx,
    )
}

async fn next(outgoing: &mut mpsc::Receiver<Zeroizing<Vec<u8>>>) -> serde_json::Value {
    next_response(outgoing).await
}

/// Skips pushed `Event` frames so tests observe request responses only.
async fn next_response(outgoing: &mut mpsc::Receiver<Zeroizing<Vec<u8>>>) -> serde_json::Value {
    loop {
        let body = tokio::time::timeout(Duration::from_secs(5), outgoing.recv())
            .await
            .expect("response")
            .expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        if value.get("event").is_none() {
            return value;
        }
    }
}

fn fill_request(id: u64, origin: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({
            "type":"fill","id":id,"origin":origin,"path":"/","choose":false,
            "fields":{"username":true,"password":true}
        }))
        .expect("fill"),
    )
}

fn store() -> (
    Arc<tokio::sync::Mutex<PairingStore>>,
    SigningKey,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("directory");
    let mut pairing = PairingStore::load(&dir.path().join("browsers.json")).expect("store");
    let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
    let encoded = STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes());
    let bytes = super::pairing::public_key(&encoded).expect("public key");
    pairing
        .approve(
            &bytes,
            vk_ipc::browser::protocol::KnownBrowser::Firefox,
            "extension",
            1,
        )
        .expect("approve");
    (Arc::new(tokio::sync::Mutex::new(pairing)), key, dir)
}

/// Completes hello/prove with the pre-paired key so dispatch requests reach the session loop.
async fn authenticate(
    incoming_tx: &mpsc::Sender<Zeroizing<Vec<u8>>>,
    outgoing_rx: &mut mpsc::Receiver<Zeroizing<Vec<u8>>>,
    key: &SigningKey,
) {
    let encoded = STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes());
    let hello = serde_json::json!({"type":"hello","id":1,"protocol":1,"extension_version":"test","public_key":encoded});
    incoming_tx
        .send(Zeroizing::new(serde_json::to_vec(&hello).expect("hello")))
        .await
        .expect("send hello");
    let reply = next(outgoing_rx).await;
    assert_eq!(reply["ok"], true, "hello: {reply}");
    let challenge = STANDARD
        .decode(reply["result"]["challenge"].as_str().expect("challenge"))
        .expect("base64");
    let mut message = b"vaultkeeper-browser-v1\0".to_vec();
    message.extend_from_slice(&challenge);
    message.extend_from_slice(b"extension");
    let signature: Signature = key.sign(&message);
    let proof = serde_json::json!({"type":"prove","id":2,"signature":STANDARD.encode(signature.to_bytes())});
    incoming_tx
        .send(Zeroizing::new(serde_json::to_vec(&proof).expect("prove")))
        .await
        .expect("send prove");
    let reply = next(outgoing_rx).await;
    assert_eq!(reply["ok"], true, "prove: {reply}");
}

#[tokio::test]
async fn answers_status_and_rejects_reauthentication() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    let status = Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({"type":"status","id":5})).expect("status"),
    );
    incoming_tx.send(status).await.expect("send");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["id"], 5);
    assert_eq!(reply["result"]["state"], "unlocked");
    let hello = Zeroizing::new(serde_json::to_vec(&serde_json::json!({"type":"hello","id":6,"protocol":1,"extension_version":"1","public_key":"x"})).expect("hello"));
    incoming_tx.send(hello).await.expect("send");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["error"], "unpaired");
    drop(incoming_tx);
    task.await.expect("serve ends with the transport");
}

#[tokio::test]
async fn second_fill_while_in_flight_is_busy_and_disconnect_cancels_the_first() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, mut gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    incoming_tx
        .send(fill_request(1, "https://example.com"))
        .await
        .expect("send");
    let done = tokio::time::timeout(Duration::from_secs(5), gate_rx.recv())
        .await
        .expect("fill started")
        .expect("gate");
    incoming_tx
        .send(fill_request(2, "https://example.com"))
        .await
        .expect("send");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["id"], 2);
    assert_eq!(reply["error"], "busy");
    drop(incoming_tx);
    drop(outgoing_rx);
    drop(done);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn disabled_answers_denied_and_enabled_save_candidates_are_acked() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();

    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    host.enabled.store(false, Ordering::SeqCst);
    incoming_tx
        .send(fill_request(1, "https://example.com"))
        .await
        .expect("send");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["error"], "denied");
    host.enabled.store(true, Ordering::SeqCst);
    let save = Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({
            "type":"save_candidate","id":3,"origin":"https://example.com","path":"/",
            "username":"user","password":"secret","kind":"login"
        }))
        .expect("save"),
    );
    incoming_tx.send(save).await.expect("send");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["result"], serde_json::json!({}));
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn fill_result_reaches_the_extension_and_counts_activity() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    host.reply(BrowserReply::Fill {
        item_id: "item".into(),
        confirmed_other_site: false,
    });
    let (gate_tx, mut gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    incoming_tx
        .send(fill_request(1, "https://example.com"))
        .await
        .expect("send");
    let done = tokio::time::timeout(Duration::from_secs(5), gate_rx.recv())
        .await
        .expect("fill started")
        .expect("gate");
    let result = Ok(Filled::bare(FillResult {
        username: Some(Zeroizing::new("user".into())),
        password: Some(Zeroizing::new("secret".into())),
    }));
    assert!(done.send(result).is_ok(), "answer");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["id"], 1);
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["result"]["username"], "user");
    assert_eq!(host.activity.load(Ordering::SeqCst), 1);
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn unlock_reaches_the_host_before_the_state_reply() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (unlocked, waiter) = oneshot::channel();
    host.unlocked.lock().expect("waiters").push(unlocked);
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    let unlock = Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({"type":"unlock","id":7})).expect("unlock"),
    );
    incoming_tx.send(unlock).await.expect("send");
    tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("unlock reached the host")
        .expect("signalled");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["result"]["state"], "unlocked");
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn cancelled_fills_trigger_the_cooldown_after_three() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, mut gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    for id in 1..=3 {
        host.reply(BrowserReply::Dismissed);
        incoming_tx
            .send(fill_request(id, "https://example.com"))
            .await
            .expect("send");
        let done = tokio::time::timeout(Duration::from_secs(5), gate_rx.recv())
            .await
            .expect("fill started")
            .expect("gate");
        drop(done);
        let reply = next(&mut outgoing_rx).await;
        assert_eq!(reply["error"], "cancelled", "fill {id}");
    }
    incoming_tx
        .send(fill_request(4, "https://example.com"))
        .await
        .expect("send");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["error"], "rate_limited");
    drop(incoming_tx);
    task.await.expect("serve ends");
}

/// The shape a `GatedFills` answer takes.
#[allow(clippy::unnecessary_wraps)]
fn filled(remember: bool) -> Result<Filled, ErrorCode> {
    Ok(Filled {
        remember,
        ..Filled::bare(FillResult {
            username: Some(Zeroizing::new("user".into())),
            password: Some(Zeroizing::new("secret".into())),
        })
    })
}

#[tokio::test]
async fn approval_is_remembered_per_origin_until_the_epoch_moves() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, mut gate_rx) = mpsc::channel(1);
    let fills = Arc::new(GatedFills::new(gate_tx));
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::clone(&fills),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    for (id, origin, answer) in [
        (1, "https://example.com", filled(true)),
        (2, "https://example.com", filled(false)),
        (3, "https://other.test", filled(false)),
    ] {
        incoming_tx
            .send(fill_request(id, origin))
            .await
            .expect("send");
        let done = gate_rx.recv().await.expect("fill started");
        assert!(done.send(answer).is_ok());
        assert_eq!(next(&mut outgoing_rx).await["ok"], true);
    }
    host.epoch.fetch_add(1, Ordering::SeqCst);
    incoming_tx
        .send(fill_request(4, "https://example.com"))
        .await
        .expect("send");
    let done = gate_rx.recv().await.expect("fill started");
    assert!(done.send(filled(false)).is_ok());
    assert_eq!(next(&mut outgoing_rx).await["ok"], true);
    let seen = fills.seen.lock().expect("seen").clone();
    let id = |item: &str| Some(vk_vault::model::ItemId(item.into()));
    assert_eq!(seen, vec![None, id("item"), None, None]);
    assert_eq!(host.records.lock().expect("records").len(), 4);
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn lock_during_a_fill_does_not_remember_its_approval() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, mut gate_rx) = mpsc::channel(1);
    let fills = Arc::new(GatedFills::new(gate_tx));
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::clone(&fills),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    incoming_tx
        .send(fill_request(1, "https://example.com"))
        .await
        .expect("send");
    let done = gate_rx.recv().await.expect("fill started");
    host.epoch.fetch_add(1, Ordering::SeqCst);
    assert!(done.send(filled(true)).is_ok());
    assert_eq!(next(&mut outgoing_rx).await["ok"], true);
    incoming_tx
        .send(fill_request(2, "https://example.com"))
        .await
        .expect("send");
    let done = gate_rx.recv().await.expect("fill started");
    assert!(done.send(filled(false)).is_ok());
    assert_eq!(next(&mut outgoing_rx).await["ok"], true);
    assert_eq!(fills.seen.lock().expect("seen").clone(), vec![None, None]);
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn locked_vault_shows_the_lock_screen_before_the_fill_runs() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    host.locked.store(true, Ordering::SeqCst);
    let (unlocked, waiter) = oneshot::channel();
    host.unlocked.lock().expect("waiters").push(unlocked);
    let pairing = store();
    let (gate_tx, mut gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    incoming_tx
        .send(fill_request(1, "https://example.com"))
        .await
        .expect("send");
    tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("lock screen requested")
        .expect("signalled");
    let done = gate_rx.recv().await.expect("fill ran after unlock");
    assert!(done.send(filled(false)).is_ok());
    assert_eq!(next(&mut outgoing_rx).await["ok"], true);
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn revoked_pairing_closes_the_connection() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        Arc::clone(&pairing.0),
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    pairing.0.lock().await.paired.clear();
    incoming_tx
        .send(fill_request(1, "https://example.com"))
        .await
        .expect("send");
    assert_eq!(next(&mut outgoing_rx).await["error"], "denied");
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("serve ended")
        .expect("no panic");
}

#[tokio::test]
async fn state_event_is_pushed_only_when_state_or_theme_changed() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    changes.send_modify(|value| *value += 1);
    host.locked.store(true, Ordering::SeqCst);
    changes.send_modify(|value| *value += 1);
    let event = tokio::time::timeout(Duration::from_secs(5), outgoing_rx.recv())
        .await
        .expect("event")
        .expect("body");
    let event: serde_json::Value = serde_json::from_slice(&event).expect("json");
    assert_eq!(event["event"], "state");
    assert_eq!(event["state"], "locked");
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn cooldown_survives_a_reconnect_and_ignores_origin_spelling() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    for round in 0..2 {
        let (connection, incoming_tx, mut outgoing_rx) = connection();
        let (gate_tx, mut gate_rx) = mpsc::channel(1);
        let task = tokio::spawn(serve(
            connection,
            Arc::clone(&pairing.0),
            Arc::new(GatedFills::new(gate_tx)),
            Arc::clone(&host),
        ));
        authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
        if round == 0 {
            for id in 1..=3 {
                incoming_tx
                    .send(fill_request(id, "https://example.com"))
                    .await
                    .expect("send");
                drop(gate_rx.recv().await.expect("fill started"));
                assert_eq!(next(&mut outgoing_rx).await["error"], "cancelled");
            }
        } else {
            incoming_tx
                .send(fill_request(9, "HTTPS://Example.com:443"))
                .await
                .expect("send");
            assert_eq!(next(&mut outgoing_rx).await["error"], "rate_limited");
        }
        drop(incoming_tx);
        task.await.expect("serve ends");
    }
}

#[tokio::test]
async fn unknown_request_type_gets_an_error_reply() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    incoming_tx
        .send(Zeroizing::new(br#"{"id":9,"type":"nope"}"#.to_vec()))
        .await
        .expect("send");
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["id"], 9);
    assert_eq!(reply["error"], "unknown_type");
    drop(incoming_tx);
    task.await.expect("serve ends");
}

struct PanickingFills;

impl FillFlow for PanickingFills {
    async fn run<P, PFut, T, TFut, A, AFut>(
        &self,
        _request: FillRequest,
        _prompt: P,
        _presence: T,
        _authorized: A,
    ) -> Result<Filled, ErrorCode>
    where
        P: FnOnce(BrowserPrompt) -> PFut + Send,
        PFut: Future<Output = BrowserReply> + Send,
        T: FnOnce() -> TFut + Send,
        TFut: Future<Output = bool> + Send,
        A: FnOnce() -> AFut + Send,
        AFut: Future<Output = bool> + Send,
    {
        panic!("fill flow bug");
    }
}

#[tokio::test]
async fn a_panicking_fill_is_answered_and_does_not_block_the_next_one() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(PanickingFills),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    for id in 1..=2 {
        incoming_tx
            .send(fill_request(id, &format!("https://site{id}.test")))
            .await
            .expect("send");
        let reply = next(&mut outgoing_rx).await;
        assert_eq!(reply["id"], id);
        assert_eq!(reply["error"], "internal");
    }
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn open_app_and_unlock_share_a_small_budget() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    for id in 1..=7 {
        incoming_tx
            .send(Zeroizing::new(
                serde_json::to_vec(
                    &serde_json::json!({"type":"open_app","id":id,"view":"manager"}),
                )
                .expect("open"),
            ))
            .await
            .expect("send");
        let reply = next(&mut outgoing_rx).await;
        if id <= 6 {
            assert_eq!(reply["ok"], true, "open {id}");
        } else {
            assert_eq!(reply["error"], "rate_limited");
        }
    }
    drop(incoming_tx);
    task.await.expect("serve ends");
}

#[tokio::test]
async fn a_browser_toggled_off_is_not_served() {
    let (connection, _incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    host.enabled.store(false, Ordering::SeqCst);
    let pairing = store();
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    tokio::time::timeout(
        Duration::from_secs(5),
        serve(
            connection,
            pairing.0,
            Arc::new(GatedFills::new(gate_tx)),
            host,
        ),
    )
    .await
    .expect("serve returns at once");
    assert!(outgoing_rx.recv().await.is_none());
}

#[tokio::test]
async fn a_pending_unlock_does_not_block_other_requests() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    host.hold_unlock.store(true, Ordering::SeqCst);
    let pairing = store();
    let (gate_tx, _gate_rx) = mpsc::channel(1);
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(GatedFills::new(gate_tx)),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    let request =
        |value: serde_json::Value| Zeroizing::new(serde_json::to_vec(&value).expect("json"));
    incoming_tx
        .send(request(serde_json::json!({"type":"unlock","id":7})))
        .await
        .expect("send");
    incoming_tx
        .send(request(serde_json::json!({"type":"status","id":8})))
        .await
        .expect("send");
    // The status answer must not wait for the user to finish unlocking.
    assert_eq!(next(&mut outgoing_rx).await["id"], 8);
    host.release_unlock.notify_one();
    let reply = next(&mut outgoing_rx).await;
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["result"]["state"], "unlocked");
    drop(incoming_tx);
    task.await.expect("serve ends");
}

/// Asks the prompt like the real fill does and cancels unless the user picked something.
struct PromptingFills;

impl FillFlow for PromptingFills {
    async fn run<P, PFut, T, TFut, A, AFut>(
        &self,
        _request: FillRequest,
        prompt: P,
        _presence: T,
        _authorized: A,
    ) -> Result<Filled, ErrorCode>
    where
        P: FnOnce(BrowserPrompt) -> PFut + Send,
        PFut: Future<Output = BrowserReply> + Send,
        T: FnOnce() -> TFut + Send,
        TFut: Future<Output = bool> + Send,
        A: FnOnce() -> AFut + Send,
        AFut: Future<Output = bool> + Send,
    {
        let asked = prompt(BrowserPrompt::Pair {
            browser: "Firefox".into(),
            fingerprint: "x".into(),
        })
        .await;
        match asked {
            BrowserReply::Fill { .. } => Ok(filled_login(false)),
            _ => Err(ErrorCode::Cancelled),
        }
    }
}

fn filled_login(remember: bool) -> Filled {
    Filled {
        remember,
        ..Filled::bare(FillResult {
            username: Some(Zeroizing::new("user".into())),
            password: Some(Zeroizing::new("secret".into())),
        })
    }
}

#[tokio::test]
async fn a_picker_the_user_walked_away_from_does_not_count_toward_the_cooldown() {
    let (connection, incoming_tx, mut outgoing_rx) = connection();
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let task = tokio::spawn(serve(
        connection,
        pairing.0,
        Arc::new(PromptingFills),
        Arc::clone(&host),
    ));
    authenticate(&incoming_tx, &mut outgoing_rx, &pairing.1).await;
    for id in 1..=4 {
        host.reply(BrowserReply::Abandoned);
        incoming_tx
            .send(fill_request(id, "https://example.com"))
            .await
            .expect("send");
        let reply = next(&mut outgoing_rx).await;
        assert_eq!(
            reply["error"], "cancelled",
            "fill {id} is cancelled, not rate limited"
        );
    }
    // Three real dismissals still trigger it.
    for id in 5..=7 {
        host.reply(BrowserReply::Dismissed);
        incoming_tx
            .send(fill_request(id, "https://example.com"))
            .await
            .expect("send");
        assert_eq!(next(&mut outgoing_rx).await["error"], "cancelled");
    }
    incoming_tx
        .send(fill_request(8, "https://example.com"))
        .await
        .expect("send");
    assert_eq!(next(&mut outgoing_rx).await["error"], "rate_limited");
    drop(incoming_tx);
    task.await.expect("serve ends");
}
