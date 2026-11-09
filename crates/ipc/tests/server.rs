//! Connection lifecycle, events, peer checks and failure handling between `serve` and
//! `RemoteVault`.

mod common;

use std::{
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bwl_ipc::{
    DaemonEvent, IpcError, PROTOCOL_VERSION, PeerCredentials, RemoteVault, ServeOptions,
    SshApprovalKind, SshDecision, SshPrompt, TypingTarget, UiCommand, UiEvent, UiNotice,
    dto::{SessionStateDto, WireError},
    frame::{HEADER_LEN, MAX_FRAME_LEN, encode},
    ipc_error,
    protocol::{DaemonMessage, Event, Refusal, Snapshot, UiMessage, Welcome},
    serve,
};
use bwl_vault::{VaultService, model::CopyField, model::ItemId};
use common::{
    Daemon, FakeVault, RawClient, SLOW_PASSWORD, SLOW_SAVE, SocketDir, draft, locked, secret,
    unlocked,
};
use tokio::sync::{mpsc, oneshot};

const EVENT_WAIT: Duration = Duration::from_secs(5);

async fn next_event(events: &mut bwl_ipc::EventStream) -> Option<UiEvent> {
    tokio::time::timeout(EVENT_WAIT, events.next())
        .await
        .expect("event within 5 s")
}

fn prompt() -> SshPrompt {
    SshPrompt {
        kind: SshApprovalKind::Sign,
        process: "git".to_owned(),
        pid: Some(4242),
        key_name: "deploy".to_owned(),
        fingerprint: "SHA256:abc".to_owned(),
        purpose: Some("git commit signing".to_owned()),
        return_to: Some(TypingTarget {
            pid: 377,
            name: "Terminal".to_owned(),
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_queued_before_the_ui_connects_are_delivered_in_order() {
    let daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let safari = TypingTarget {
        pid: 812,
        name: "Safari".to_owned(),
    };
    for (seq, command) in [
        (
            1,
            UiCommand::ShowQuickPanel {
                target: Some(safari.clone()),
            },
        ),
        (2, UiCommand::ShowUnlock),
    ] {
        daemon
            .events
            .send(DaemonEvent::Command { seq, command })
            .await
            .expect("queue");
    }
    let (_vault, mut events) = daemon.connect().await;
    assert!(matches!(
        next_event(&mut events).await,
        Some(UiEvent::Command {
            seq: 1,
            command: UiCommand::ShowQuickPanel { target: Some(ref target) }
        }) if *target == safari
    ));
    assert!(matches!(
        next_event(&mut events).await,
        Some(UiEvent::Command {
            seq: 2,
            command: UiCommand::ShowUnlock
        })
    ));
    for (seq, command) in [
        (3, UiCommand::ShowManager),
        (4, UiCommand::ShowLogin),
        (5, UiCommand::ShowSettings),
        (6, UiCommand::ShowGenerator),
        (
            7,
            UiCommand::ToggleQuickPanel {
                target: Some(safari.clone()),
            },
        ),
        (8, UiCommand::ToggleQuickPanel { target: None }),
    ] {
        daemon
            .events
            .send(DaemonEvent::Command {
                seq,
                command: command.clone(),
            })
            .await
            .expect("send");
        let event = next_event(&mut events).await;
        match &event {
            Some(UiEvent::Command {
                command: received, ..
            }) => {
                assert_eq!(*received, command);
                assert_eq!(
                    event.as_ref().and_then(UiEvent::seq),
                    Some(seq),
                    "the daemon's number reaches the UI"
                );
            }
            other => panic!("expected {command:?}, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_approvals_reach_the_ui_and_its_answer_reaches_the_agent() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    // Expired before any UI showed up: must be skipped, not shown, but its number still reaches
    // the UI so the daemon's count of answered events does not fall behind.
    let (stale_reply, stale) = oneshot::channel();
    drop(stale);
    daemon
        .events
        .send(DaemonEvent::SshApproval {
            seq: 1,
            prompt: prompt(),
            reply: stale_reply,
        })
        .await
        .expect("queue");
    let (_vault, mut events) = daemon.connect().await;
    let skipped = next_event(&mut events).await;
    assert!(
        matches!(skipped, Some(UiEvent::Skipped(1))),
        "no prompt for the expired request: {skipped:?}"
    );

    let (reply, approved) = oneshot::channel();
    daemon
        .events
        .send(DaemonEvent::SshApproval {
            seq: 2,
            prompt: prompt(),
            reply,
        })
        .await
        .expect("send");
    let Some(UiEvent::SshApproval(request)) = next_event(&mut events).await else {
        panic!("expected an approval request");
    };
    assert_eq!(request.prompt, prompt());
    assert_eq!(request.seq, 2);
    request
        .reply
        .send(SshDecision::approve(true))
        .expect("reply");
    assert_eq!(
        tokio::time::timeout(EVENT_WAIT, approved)
            .await
            .expect("in time"),
        Ok(SshDecision {
            approved: true,
            remember: true
        }),
        "the answer and the remember choice both reach the daemon"
    );

    let (reply, denied) = oneshot::channel();
    let list_prompt = SshPrompt {
        kind: SshApprovalKind::List,
        pid: None,
        purpose: None,
        ..prompt()
    };
    daemon
        .events
        .send(DaemonEvent::SshApproval {
            seq: 3,
            prompt: list_prompt.clone(),
            reply,
        })
        .await
        .expect("send");
    let Some(UiEvent::SshApproval(request)) = next_event(&mut events).await else {
        panic!("expected an approval request");
    };
    assert_eq!(request.prompt, list_prompt);
    drop(request);
    assert_eq!(
        tokio::time::timeout(EVENT_WAIT, denied)
            .await
            .expect("in time"),
        Ok(SshDecision::DENY),
        "dropping the reply denies"
    );
}

/// Blocking: the raw client reads with std I/O.
fn next_approval_id(raw: &mut RawClient) -> u64 {
    loop {
        match raw.recv() {
            Some(DaemonMessage::Event(Event::SshApproval { request_id, .. })) => return request_id,
            Some(_) => {}
            None => panic!("the daemon closed the connection"),
        }
    }
}

fn reply_to(raw: &mut RawClient, request_id: u64, approved: bool) {
    raw.send(&UiMessage::SshApprovalReply {
        request_id,
        approved,
        remember: false,
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_or_repeated_reply_never_answers_another_request() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    let socket = daemon.socket();
    let mut raw = tokio::task::spawn_blocking(move || {
        let mut raw = RawClient::connect(&socket);
        raw.hello();
        raw
    })
    .await
    .expect("connect");

    let (reply, first) = oneshot::channel();
    daemon
        .events
        .send(DaemonEvent::SshApproval {
            seq: 1,
            prompt: prompt(),
            reply,
        })
        .await
        .expect("send");
    let (first_id, raw_back) = tokio::task::spawn_blocking(move || {
        let id = next_approval_id(&mut raw);
        reply_to(&mut raw, id, false);
        (id, raw)
    })
    .await
    .expect("first");
    raw = raw_back;
    assert_eq!(
        tokio::time::timeout(EVENT_WAIT, first)
            .await
            .expect("in time"),
        Ok(SshDecision::DENY)
    );

    let (reply, mut second) = oneshot::channel();
    daemon
        .events
        .send(DaemonEvent::SshApproval {
            seq: 2,
            prompt: prompt(),
            reply,
        })
        .await
        .expect("send");
    let (second_id, raw_back) = tokio::task::spawn_blocking(move || {
        let id = next_approval_id(&mut raw);
        // A late approve for the answered request, and one for an id never issued.
        reply_to(&mut raw, first_id, true);
        reply_to(&mut raw, id + 100, true);
        (id, raw)
    })
    .await
    .expect("second");
    raw = raw_back;
    assert_ne!(first_id, second_id, "every request gets its own id");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        second.try_recv(),
        Err(oneshot::error::TryRecvError::Empty),
        "stale replies did not answer the pending request"
    );
    tokio::task::spawn_blocking(move || reply_to(&mut raw, second_id, false))
        .await
        .expect("answer");
    assert_eq!(
        tokio::time::timeout(EVENT_WAIT, second)
            .await
            .expect("in time"),
        Ok(SshDecision::DENY),
        "only its own reply decides it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_approval_is_denied_when_the_ui_disconnects() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    let (vault, mut events) = daemon.connect().await;
    let (reply, decision) = oneshot::channel();
    daemon
        .events
        .send(DaemonEvent::SshApproval {
            seq: 1,
            prompt: prompt(),
            reply,
        })
        .await
        .expect("send");
    let Some(UiEvent::SshApproval(request)) = next_event(&mut events).await else {
        panic!("expected an approval request");
    };
    drop(vault);
    let decision = tokio::time::timeout(EVENT_WAIT, decision)
        .await
        .expect("in time");
    assert!(
        decision.is_err() || decision == Ok(SshDecision::DENY),
        "a vanished UI never approves: {decision:?}"
    );
    drop(request);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_flip_is_announced_and_cached_and_changes_tick() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    let (vault, mut events) = daemon.connect().await;
    let mut changes = vault.changes();
    assert!(!vault.is_offline());
    daemon.fake.set_offline(true);
    assert!(matches!(
        next_event(&mut events).await,
        Some(UiEvent::OfflineChanged(true))
    ));
    assert!(vault.is_offline());
    tokio::time::timeout(EVENT_WAIT, changes.changed())
        .await
        .expect("in time")
        .expect("changed");
    assert_eq!(*changes.borrow(), daemon.fake.revision());
    daemon.fake.set_offline(false);
    assert!(matches!(
        next_event(&mut events).await,
        Some(UiEvent::OfflineChanged(false))
    ));
    assert!(!vault.is_offline());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_shutdown_event_is_forwarded() {
    let daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let (_vault, mut events) = daemon.connect().await;
    daemon
        .events
        .send(DaemonEvent::Shutdown)
        .await
        .expect("send");
    assert!(matches!(
        next_event(&mut events).await,
        Some(UiEvent::Shutdown)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_shutdown_tells_the_ui_then_ends_the_stream_and_removes_the_socket() {
    let mut daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let (vault, mut events) = daemon.connect().await;
    let server = daemon.server.take().expect("server");
    tokio::time::timeout(EVENT_WAIT, server.shutdown())
        .await
        .expect("shutdown in time");
    assert!(matches!(
        next_event(&mut events).await,
        Some(UiEvent::Shutdown)
    ));
    assert!(next_event(&mut events).await.is_none(), "stream ends");
    assert!(!daemon.socket().exists());
    let error = vault.sync().await.expect_err("daemon gone");
    assert!(matches!(ipc_error(&error), Some(IpcError::Disconnected)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_client_is_refused_until_the_first_leaves() {
    let daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let (first, _first_events) = daemon.connect().await;
    let refused = RemoteVault::connect(daemon.socket()).await;
    assert!(
        matches!(refused, Err(IpcError::Busy)),
        "{:?}",
        refused.err()
    );
    assert_eq!(first.state(), locked(), "the first client is unaffected");
    drop(first);
    let deadline = Instant::now() + EVENT_WAIT;
    loop {
        match RemoteVault::connect(daemon.socket()).await {
            Ok((third, _events)) => {
                assert_eq!(third.state(), locked());
                break;
            }
            Err(IpcError::Busy) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("reconnect failed: {error}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifier_sees_our_credentials_and_its_refusal_closes_the_socket() {
    let seen = Arc::new(Mutex::new(Vec::<PeerCredentials>::new()));
    let record = Arc::clone(&seen);
    let options = ServeOptions::with_verifier(move |peer: &PeerCredentials| {
        record.lock().expect("lock").push(peer.clone());
        false
    });
    let daemon = Daemon::start_with(FakeVault::new(unlocked(), 0), options).await;
    let refused = RemoteVault::connect(daemon.socket()).await;
    let error = refused.err().expect("refused");
    assert!(
        matches!(error, IpcError::Disconnected),
        "the daemon hangs up without a word: {error:?}"
    );
    let seen = seen.lock().expect("lock").clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].pid,
        i32::try_from(std::process::id()).expect("pid fits")
    );
    assert_eq!(
        seen[0].executable,
        std::env::current_exe()
            .expect("exe")
            .canonicalize()
            .expect("canonical")
    );
    assert_eq!(daemon.fake.log(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_verifier_accepts_the_same_executable() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    let (vault, _events) = daemon.connect().await;
    assert_eq!(vault.state(), unlocked());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_closes_the_connection_and_frees_the_slot() {
    let daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let mut raw = RawClient::connect(&daemon.socket());
    raw.hello();
    let too_long = u32::try_from(MAX_FRAME_LEN + 1).expect("fits");
    raw.write_raw(&too_long.to_le_bytes()).expect("header");
    loop {
        match raw.recv() {
            None => break,
            Some(DaemonMessage::Event(_)) => {}
            Some(_) => panic!("no answer to an oversized frame"),
        }
    }
    let deadline = Instant::now() + EVENT_WAIT;
    loop {
        match RemoteVault::connect(daemon.socket()).await {
            Ok(_) => break,
            Err(IpcError::Busy) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("reconnect failed: {error}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_body_closes_the_connection() {
    let daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let mut raw = RawClient::connect(&daemon.socket());
    raw.hello();
    raw.write_raw(&[1, 0, 0, 0, 0xff]).expect("write");
    while let Some(message) = raw.recv() {
        assert!(matches!(message, DaemonMessage::Event(_)));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_refuses_another_protocol_version() {
    let daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let mut raw = RawClient::connect(&daemon.socket());
    raw.send(&UiMessage::Hello {
        protocol_version: PROTOCOL_VERSION + 1,
    });
    let Some(DaemonMessage::Refused(refusal)) = raw.recv() else {
        panic!("expected a refusal");
    };
    assert_eq!(
        refusal,
        Refusal::VersionMismatch {
            daemon: PROTOCOL_VERSION
        }
    );
    assert!(raw.recv().is_none(), "the daemon hangs up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_peer_is_dropped_after_the_handshake_timeout() {
    let options = ServeOptions {
        handshake_timeout: Duration::from_millis(100),
        ..ServeOptions::new().expect("options")
    };
    let daemon = Daemon::start_with(FakeVault::new(locked(), 0), options).await;
    let mut raw = RawClient::connect(&daemon.socket());
    assert!(raw.recv().is_none(), "closed without a Hello");
    let (vault, _events) = daemon.connect().await;
    assert_eq!(vault.state(), locked());
}

/// A hand-written daemon: answers `Hello` with `reply`, then reads until the client leaves.
fn fake_daemon(dir: &SocketDir, reply: &DaemonMessage) -> std::thread::JoinHandle<()> {
    std::fs::create_dir_all(dir.path()).expect("dir");
    let listener = std::os::unix::net::UnixListener::bind(dir.socket()).expect("bind");
    let frame = encode(reply).expect("encode");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut header = [0; HEADER_LEN];
        stream.read_exact(&mut header).expect("hello header");
        let mut body = vec![0; usize::try_from(u32::from_le_bytes(header)).expect("fits")];
        stream.read_exact(&mut body).expect("hello body");
        stream.write_all(&frame).expect("reply");
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink);
    })
}

fn logged_out_snapshot() -> Snapshot {
    Snapshot {
        state: SessionStateDto::LoggedOut,
        accounts: Vec::new(),
        is_offline: false,
        last_sync: None,
        folders: Err(WireError::LoggedOut),
        organizations: Err(WireError::LoggedOut),
        collections: Err(WireError::LoggedOut),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_rejects_a_daemon_speaking_another_version() {
    let dir = SocketDir::new();
    let daemon = fake_daemon(
        &dir,
        &DaemonMessage::Welcome(Box::new(Welcome {
            protocol_version: PROTOCOL_VERSION + 1,
            revision: 0,
            snapshot: logged_out_snapshot(),
        })),
    );
    let error = RemoteVault::connect(dir.socket())
        .await
        .err()
        .expect("refused");
    assert!(
        matches!(error, IpcError::VersionMismatch { ours, theirs }
            if ours == PROTOCOL_VERSION && theirs == PROTOCOL_VERSION + 1),
        "{error:?}"
    );
    daemon.join().expect("fake daemon");
}

#[tokio::test(start_paused = true)]
async fn call_times_out_when_the_daemon_never_answers() {
    let dir = SocketDir::new();
    let daemon = fake_daemon(
        &dir,
        &DaemonMessage::Welcome(Box::new(Welcome {
            protocol_version: PROTOCOL_VERSION,
            revision: 0,
            snapshot: logged_out_snapshot(),
        })),
    );
    let (vault, _events) = RemoteVault::connect(dir.socket()).await.expect("connect");
    let error = vault.sync().await.expect_err("no answer");
    assert!(
        matches!(ipc_error(&error), Some(IpcError::Timeout(after)) if *after == Duration::from_secs(600)),
        "{error:?}"
    );
    let error = vault.logout().await.expect_err("no answer");
    assert!(
        matches!(ipc_error(&error), Some(IpcError::Timeout(after)) if *after == Duration::from_secs(30)),
        "{error:?}"
    );
    drop(vault);
    daemon.join().expect("fake daemon");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_daemon_fails_pending_calls_and_ends_the_stream() {
    let mut daemon = Daemon::start(FakeVault::new(unlocked(), 5)).await;
    daemon.fake.hang_sync();
    let (vault, mut events) = daemon.connect().await;
    let vault = Arc::new(vault);
    let mut changes = vault.changes();
    let pending = tokio::spawn({
        let vault = Arc::clone(&vault);
        async move { vault.sync().await }
    });
    // Let the request reach the daemon before it goes away.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(daemon.server.take());

    let error = tokio::time::timeout(EVENT_WAIT, pending)
        .await
        .expect("fails promptly")
        .expect("task")
        .expect_err("daemon gone");
    assert!(
        matches!(ipc_error(&error), Some(IpcError::Disconnected)),
        "{error:?}"
    );
    assert!(next_event(&mut events).await.is_none(), "stream ends");
    let started = Instant::now();
    let later = vault.reveal(&ItemId("item-001".into()), CopyField::Password);
    assert!(matches!(
        later.as_ref().map_err(ipc_error),
        Err(Some(IpcError::Disconnected))
    ));
    assert!(started.elapsed() < Duration::from_secs(1), "fails fast");
    assert!(changes.changed().await.is_err(), "changes watch closes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calls_in_flight_finish_after_the_ui_leaves_and_a_new_ui_can_connect_meanwhile() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    let (vault, _events) = daemon.connect().await;
    let mut slow = draft();
    slow.name = SLOW_SAVE.to_owned();
    let abandoned = tokio::time::timeout(
        Duration::from_millis(50),
        vault.save(Some(ItemId("i1".into())), slow),
    )
    .await;
    assert!(abandoned.is_err(), "the save is still running");
    drop(vault);

    let deadline = Instant::now() + EVENT_WAIT;
    let next = loop {
        match RemoteVault::connect(daemon.socket()).await {
            Ok((next, _events)) => break next,
            Err(IpcError::Busy) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("reconnect failed: {error}"),
        }
    };
    assert_eq!(
        daemon.fake.log(),
        Vec::<String>::new(),
        "the new UI got in before the old save finished"
    );
    let finished = format!("save i1 {SLOW_SAVE} hunter2 fields=1");
    let deadline = Instant::now() + EVENT_WAIT;
    while !daemon.fake.log().contains(&finished) {
        assert!(
            Instant::now() < deadline,
            "the abandoned save never finished"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(next.state(), unlocked());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundred_parallel_calls_complete_with_bounded_concurrency() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 50)).await;
    let (vault, _events) = daemon.connect().await;
    let vault = Arc::new(vault);
    let started = Instant::now();
    let mut slow = tokio::task::JoinSet::new();
    for _ in 0..60 {
        let vault = Arc::clone(&vault);
        slow.spawn(async move { vault.verify_master_password(secret(SLOW_PASSWORD)).await });
    }
    let blocking: Vec<_> = (0..40)
        .map(|index| {
            let vault = Arc::clone(&vault);
            std::thread::spawn(move || {
                let id = format!("item-{index:03}");
                let secret = vault
                    .reveal(&ItemId(id.as_str().into()), CopyField::Password)
                    .expect("reveal");
                assert_eq!(secret.as_str(), format!("{id}/Password"));
            })
        })
        .collect();
    while let Some(result) = slow.join_next().await {
        assert!(result.expect("task").expect("call"));
    }
    for thread in blocking {
        thread.join().expect("blocking caller");
    }
    // 60 calls of 50 ms take 3 s one by one and about 0.4 s eight at a time.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(daemon.fake.max_in_flight(), 8, "concurrency is capped at 8");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socket_is_0600_and_an_existing_directory_is_tightened_to_0700() {
    let dir = SocketDir::new();
    std::fs::create_dir_all(dir.path()).expect("dir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let (_events, source) = mpsc::channel(1);
    let server = serve(dir.socket(), FakeVault::new(locked(), 0), source)
        .await
        .expect("serve");
    let mode = |path: &std::path::Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(dir.path()), 0o700);
    assert_eq!(mode(&dir.socket()), 0o600);
    assert_eq!(server.path(), dir.socket());
    drop(server);
    assert!(
        !dir.socket().exists(),
        "dropping the handle removes the socket"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_socket_is_replaced_but_a_live_daemon_or_a_plain_file_is_not() {
    let dir = SocketDir::new();
    std::fs::create_dir_all(dir.path()).expect("dir");
    drop(std::os::unix::net::UnixListener::bind(dir.socket()).expect("bind"));
    assert!(
        dir.socket().exists(),
        "a dead listener leaves its socket file"
    );
    let (_events, source) = mpsc::channel(1);
    let server = serve(dir.socket(), FakeVault::new(locked(), 0), source)
        .await
        .expect("replaces the stale socket");

    let (_events, source) = mpsc::channel(1);
    let second = serve(dir.socket(), FakeVault::new(locked(), 0), source).await;
    assert!(
        matches!(&second, Err(IpcError::Io(io)) if io.kind() == std::io::ErrorKind::AddrInUse),
        "{:?}",
        second.err()
    );
    drop(server);

    std::fs::write(dir.socket(), b"not a socket").expect("file");
    let (_events, source) = mpsc::channel(1);
    let refused = serve(dir.socket(), FakeVault::new(locked(), 0), source).await;
    assert!(
        matches!(&refused, Err(IpcError::Io(io)) if io.kind() == std::io::ErrorKind::AlreadyExists),
        "{:?}",
        refused.err()
    );
    assert_eq!(std::fs::read(dir.socket()).expect("kept"), b"not a socket");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notices_from_the_ui_reach_the_daemon_channel() {
    let (notices, mut received) = mpsc::channel(4);
    let options = ServeOptions::new().expect("options").with_notices(notices);
    let daemon = Daemon::start_with(FakeVault::new(unlocked(), 0), options).await;
    let (vault, _events) = daemon.connect().await;
    vault
        .notify(UiNotice::SettingsChanged)
        .expect("notify settings");
    vault.notify(UiNotice::Activity).expect("notify activity");
    let first = tokio::time::timeout(EVENT_WAIT, received.recv()).await;
    let second = tokio::time::timeout(EVENT_WAIT, received.recv()).await;
    assert_eq!(first.expect("in time"), Some(UiNotice::SettingsChanged));
    assert_eq!(second.expect("in time"), Some(UiNotice::Activity));
    assert!(
        daemon.fake.log().is_empty(),
        "notices are not vault calls: {:?}",
        daemon.fake.log()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_end_of_a_ui_session_is_queued_as_a_notice() {
    let (notices, mut received) = mpsc::channel(4);
    let options = ServeOptions::new().expect("options").with_notices(notices);
    let daemon = Daemon::start_with(FakeVault::new(unlocked(), 0), options).await;
    let (vault, events) = daemon.connect().await;
    vault
        .notify(UiNotice::ShortcutRecording(true))
        .expect("notify recording");
    let first = tokio::time::timeout(EVENT_WAIT, received.recv()).await;
    assert_eq!(
        first.expect("in time"),
        Some(UiNotice::ShortcutRecording(true))
    );
    drop((vault, events));
    let ended = tokio::time::timeout(EVENT_WAIT, received.recv()).await;
    assert_eq!(ended.expect("in time"), Some(UiNotice::Disconnected));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notices_without_a_daemon_channel_are_ignored() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    let (vault, _events) = daemon.connect().await;
    vault.notify(UiNotice::Activity).expect("notify");
    assert_eq!(
        vault
            .search("", &bwl_vault::model::Filter::default())
            .map(|items| items.len())
            .ok(),
        Some(0)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_handle_reports_whether_a_ui_is_connected() {
    let daemon = Daemon::start(FakeVault::new(locked(), 0)).await;
    let server = daemon.server.as_ref().expect("server");
    assert!(!server.is_ui_connected());
    let (vault, events) = daemon.connect().await;
    assert!(server.is_ui_connected());
    drop((vault, events));
    let deadline = Instant::now() + EVENT_WAIT;
    while server.is_ui_connected() {
        assert!(
            Instant::now() < deadline,
            "the slot is released after a disconnect"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let notify_after_close = RemoteVault::connect(daemon.socket()).await;
    assert!(notify_after_close.is_ok(), "the next UI may connect");
}
