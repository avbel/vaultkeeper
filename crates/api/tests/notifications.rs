#![allow(clippy::unwrap_used)]

mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bwl_api::notifications::{
    ListenError, ListenOptions, Notification, ReconnectOptions, listen, listen_with,
    run_with_reconnect,
};
use common::hub::{self, Hub, Socket, close_message, complete_handshake, drain, frame, invocation};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::tungstenite::Message;
use url::Url;
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(5);

fn quick() -> ListenOptions {
    ListenOptions {
        ping_interval: Duration::from_millis(40),
        stale_after: Duration::from_millis(250),
        handshake_timeout: Duration::from_millis(500),
        own_device_id: None,
    }
}

type Outcome = Result<(), ListenError>;

fn start(
    base: Url,
    token: &str,
    options: ListenOptions,
) -> (mpsc::Receiver<Notification>, JoinHandle<Outcome>) {
    let (tx, rx) = mpsc::channel(32);
    let token = token.to_owned();
    let task = tokio::spawn(async move { listen_with(&base, &token, &tx, &options).await });
    (rx, task)
}

async fn next(rx: &mut mpsc::Receiver<Notification>) -> Notification {
    timeout(WAIT, rx.recv())
        .await
        .expect("no notification in time")
        .expect("channel closed")
}

async fn finished(task: JoinHandle<Outcome>) -> Outcome {
    timeout(WAIT, task)
        .await
        .expect("listen did not finish")
        .unwrap()
}

async fn serve_updates(mut socket: Socket, frames: Vec<Vec<u8>>) {
    complete_handshake(&mut socket).await;
    for data in frames {
        socket.send(Message::binary(data)).await.unwrap();
    }
    drain(&mut socket).await;
}

#[tokio::test]
async fn connects_to_the_hub_path_with_the_token_and_forwards_a_cipher_update() {
    let hub =
        hub::spawn(|_, socket| serve_updates(socket, vec![invocation(0, "cipher-1", Some("web"))]))
            .await;
    let (mut rx, task) = start(hub.base(), "a b+c/d=", quick());

    assert_eq!(next(&mut rx).await, Notification::Connected);
    assert_eq!(
        next(&mut rx).await,
        Notification::CipherChanged {
            id: "cipher-1".into()
        }
    );

    let accepted = hub.accepted();
    assert_eq!(accepted.len(), 1);
    assert_eq!(
        accepted[0].uri, "/notifications/hub",
        "the token must not appear in the URL"
    );
    assert_eq!(accepted[0].bearer(), Some("a b+c/d="));
    task.abort();
}

#[tokio::test]
async fn server_url_with_a_path_prefix_is_kept() {
    let hub = hub::spawn(|_, socket| serve_updates(socket, vec![])).await;
    let base = Url::parse(&format!("http://{}/vw", hub.addr)).unwrap();
    let (mut rx, task) = start(base, "t", quick());

    assert_eq!(next(&mut rx).await, Notification::Connected);

    assert_eq!(hub.accepted()[0].uri, "/vw/notifications/hub");
    task.abort();
}

#[tokio::test]
async fn a_token_that_cannot_be_a_header_value_is_rejected_without_connecting() {
    let hub = hub::spawn(|_, socket| serve_updates(socket, vec![])).await;
    let (_rx, task) = start(hub.base(), "bad\ntoken", quick());

    let outcome = finished(task).await;

    assert!(
        matches!(outcome, Err(ListenError::Unauthorized)),
        "{outcome:?}"
    );
    assert!(hub.accepted().is_empty());
}

#[tokio::test]
async fn public_listen_uses_default_timings_and_reports_connected() {
    let hub = hub::spawn(|_, socket| serve_updates(socket, vec![])).await;
    let (tx, mut rx) = mpsc::channel(4);
    let base = hub.base();
    let task = tokio::spawn(async move { listen(&base, "t", tx).await });

    assert_eq!(next(&mut rx).await, Notification::Connected);
    drop(rx);
    assert!(finished(task).await.is_ok());
}

#[tokio::test]
async fn every_update_type_maps_to_its_notification() {
    let kinds: [u8; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 100];
    let frames: Vec<Vec<u8>> = kinds
        .iter()
        .map(|kind| invocation(*kind, "x", None))
        .collect();
    let hub = hub::spawn(move |_, socket| serve_updates(socket, frames.clone())).await;
    let (mut rx, task) = start(hub.base(), "t", quick());

    assert_eq!(next(&mut rx).await, Notification::Connected);
    let mut seen = Vec::new();
    for _ in kinds {
        seen.push(next(&mut rx).await);
    }

    let id = || "x".to_owned();
    assert_eq!(
        seen,
        vec![
            Notification::CipherChanged { id: id() },
            Notification::CipherChanged { id: id() },
            Notification::CipherDeleted { id: id() },
            Notification::FolderDeleted { id: id() },
            Notification::VaultChanged,
            Notification::VaultChanged,
            Notification::VaultChanged,
            Notification::FolderChanged { id: id() },
            Notification::FolderChanged { id: id() },
            Notification::CipherDeleted { id: id() },
            Notification::VaultChanged,
            Notification::LogOut,
            Notification::Other(12),
            Notification::Other(15),
            Notification::Other(100),
        ]
    );
    task.abort();
}

#[tokio::test]
async fn several_messages_in_one_frame_are_delivered_in_order() {
    let mut combined = invocation(0, "first", None);
    combined.extend(frame(&[0x91, 0x06]));
    combined.extend(invocation(8, "second", None));
    let hub = hub::spawn(move |_, socket| serve_updates(socket, vec![combined.clone()])).await;
    let (mut rx, task) = start(hub.base(), "t", quick());

    assert_eq!(next(&mut rx).await, Notification::Connected);
    assert_eq!(
        next(&mut rx).await,
        Notification::CipherChanged { id: "first".into() }
    );
    assert_eq!(
        next(&mut rx).await,
        Notification::FolderChanged {
            id: "second".into()
        }
    );
    task.abort();
}

#[tokio::test]
async fn notifications_caused_by_this_device_are_dropped_except_log_out() {
    let frames = vec![
        invocation(0, "mine", Some("device-1")),
        invocation(0, "theirs", Some("device-2")),
        invocation(11, "ignored-id", Some("device-1")),
    ];
    let hub = hub::spawn(move |_, socket| serve_updates(socket, frames.clone())).await;
    let options = ListenOptions {
        own_device_id: Some("device-1".into()),
        ..quick()
    };
    let (mut rx, task) = start(hub.base(), "t", options);

    assert_eq!(next(&mut rx).await, Notification::Connected);
    assert_eq!(
        next(&mut rx).await,
        Notification::CipherChanged {
            id: "theirs".into()
        }
    );
    assert_eq!(next(&mut rx).await, Notification::LogOut);
    task.abort();
}

#[tokio::test]
async fn refused_handshake_is_reported() {
    let hub = hub::spawn(|_, mut socket| async move {
        let _ = socket.next().await;
        socket
            .send(Message::binary(
                b"{\"error\":\"unsupported protocol\"}\x1e".to_vec(),
            ))
            .await
            .unwrap();
        drain(&mut socket).await;
    })
    .await;
    let (_rx, task) = start(hub.base(), "t", quick());

    match finished(task).await {
        Err(ListenError::Handshake(message)) => {
            assert!(message.contains("unsupported protocol"), "{message}");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn silent_server_trips_the_handshake_timeout() {
    let hub = hub::spawn(|_, mut socket| async move { drain(&mut socket).await }).await;
    let started = Instant::now();
    let (_rx, task) = start(
        hub.base(),
        "t",
        ListenOptions {
            handshake_timeout: Duration::from_millis(150),
            ..quick()
        },
    );

    let outcome = finished(task).await;

    assert!(
        matches!(outcome, Err(ListenError::HandshakeTimeout(_))),
        "{outcome:?}"
    );
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn upgrade_rejections_map_to_unauthorized_and_status() {
    for (status, expected_unauthorized) in [(401_u16, true), (404, false)] {
        let hub = hub::spawn_rejecting(move |_, _| Some(status), |_, _| async {}).await;
        let (_rx, task) = start(hub.base(), "t", quick());

        match finished(task).await {
            Err(ListenError::Unauthorized) if expected_unauthorized => {}
            Err(ListenError::Status(code)) if !expected_unauthorized => assert_eq!(code, status),
            other => panic!("status {status}: unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn non_http_base_urls_are_refused_without_connecting() {
    let (tx, _rx) = mpsc::channel(1);
    let base = Url::parse("ftp://example.com/").unwrap();

    let outcome = listen_with(&base, "t", &tx, &quick()).await;

    assert!(matches!(outcome, Err(ListenError::UnsupportedScheme(scheme)) if scheme == "ftp"));
}

#[tokio::test]
async fn websocket_close_frame_ends_the_listener_with_closed() {
    let hub = hub::spawn(|_, mut socket| async move {
        complete_handshake(&mut socket).await;
        socket.close(None).await.unwrap();
        drain(&mut socket).await;
    })
    .await;
    let (mut rx, task) = start(hub.base(), "t", quick());

    assert_eq!(next(&mut rx).await, Notification::Connected);

    let outcome = finished(task).await;
    assert!(matches!(outcome, Err(ListenError::Closed)), "{outcome:?}");
}

#[tokio::test]
async fn dropped_tcp_connection_is_an_error_not_a_clean_end() {
    let hub = hub::spawn(|_, mut socket| async move {
        complete_handshake(&mut socket).await;
    })
    .await;
    let (_rx, task) = start(hub.base(), "t", quick());

    let outcome = finished(task).await;

    assert!(
        matches!(
            outcome,
            Err(ListenError::WebSocket(_) | ListenError::Closed)
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn signalr_close_message_ends_the_listener_with_its_error_text() {
    let frames = vec![close_message("server shutting down")];
    let hub = hub::spawn(move |_, socket| serve_updates(socket, frames.clone())).await;
    let (_rx, task) = start(hub.base(), "t", quick());

    match finished(task).await {
        Err(ListenError::ServerClose(Some(message))) => assert_eq!(message, "server shutting down"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn malformed_frame_is_a_protocol_error() {
    let hub = hub::spawn(|_, socket| serve_updates(socket, vec![vec![0x7f, 0x01]])).await;
    let (_rx, task) = start(hub.base(), "t", quick());

    let outcome = finished(task).await;

    assert!(
        matches!(outcome, Err(ListenError::Protocol(_))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_server_that_goes_silent_is_detected_as_stale_within_the_window() {
    let hub = hub::spawn(|_, mut socket| async move {
        complete_handshake(&mut socket).await;
        sleep(Duration::from_secs(30)).await;
    })
    .await;
    let (mut rx, task) = start(hub.base(), "t", quick());
    assert_eq!(next(&mut rx).await, Notification::Connected);
    let connected = Instant::now();

    let outcome = finished(task).await;

    let elapsed = connected.elapsed();
    assert!(
        matches!(outcome, Err(ListenError::Stale(window)) if window == quick().stale_after),
        "{outcome:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(240),
        "stale after only {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "stale detection took {elapsed:?}"
    );
}

#[tokio::test]
async fn server_pings_are_answered_and_keep_the_connection_alive() {
    let (report, reply) = oneshot::channel();
    let report = Arc::new(std::sync::Mutex::new(Some(report)));
    let hub = hub::spawn(move |_, mut socket| {
        let report = Arc::clone(&report);
        async move {
            complete_handshake(&mut socket).await;
            let payload = vec![0x02, 0x91, 0x06];
            let mut pongs = Vec::new();
            for _ in 0..12 {
                socket
                    .send(Message::Ping(payload.clone().into()))
                    .await
                    .unwrap();
                let deadline = sleep(Duration::from_millis(60));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        message = socket.next() => match message {
                            Some(Ok(Message::Pong(data))) => pongs.push(data.to_vec()),
                            Some(Ok(_)) => {}
                            _ => return,
                        },
                        () = &mut deadline => break,
                    }
                }
            }
            if let Some(report) = report.lock().unwrap().take() {
                let _ = report.send(pongs);
            }
            socket.close(None).await.unwrap();
            drain(&mut socket).await;
        }
    })
    .await;
    let options = ListenOptions {
        ping_interval: Duration::from_secs(10),
        ..quick()
    };
    let (mut rx, task) = start(hub.base(), "t", options);
    assert_eq!(next(&mut rx).await, Notification::Connected);

    let outcome = finished(task).await;

    assert!(
        matches!(outcome, Err(ListenError::Closed)),
        "stayed alive for ~720ms > stale_after, got {outcome:?}"
    );
    let pongs = reply.await.unwrap();
    let echoed = pongs
        .iter()
        .filter(|data| data.as_slice() == [0x02, 0x91, 0x06])
        .count();
    assert!(
        echoed >= 10,
        "only {echoed} of 12 server pings were answered: {pongs:?}"
    );
}

#[tokio::test]
async fn client_sends_signalr_and_websocket_pings_at_the_configured_interval() {
    let (report, reply) = oneshot::channel();
    let report = Arc::new(std::sync::Mutex::new(Some(report)));
    let hub = hub::spawn(move |_, mut socket| {
        let report = Arc::clone(&report);
        async move {
            complete_handshake(&mut socket).await;
            let started = Instant::now();
            let (mut signalr, mut websocket) = (Vec::new(), Vec::new());
            while started.elapsed() < Duration::from_millis(330) {
                let Ok(Some(Ok(message))) = timeout(Duration::from_millis(50), socket.next()).await
                else {
                    continue;
                };
                match message {
                    Message::Binary(data) if data.as_ref() == [0x02, 0x91, 0x06] => {
                        signalr.push(started.elapsed());
                    }
                    Message::Ping(_) => websocket.push(started.elapsed()),
                    _ => {}
                }
            }
            if let Some(report) = report.lock().unwrap().take() {
                let _ = report.send((signalr, websocket));
            }
            drain(&mut socket).await;
        }
    })
    .await;
    let options = ListenOptions {
        ping_interval: Duration::from_millis(80),
        stale_after: Duration::from_secs(5),
        ..quick()
    };
    let (mut rx, task) = start(hub.base(), "t", options);
    assert_eq!(next(&mut rx).await, Notification::Connected);

    let (signalr, websocket) = timeout(WAIT, reply).await.unwrap().unwrap();
    task.abort();

    for (name, times) in [("signalr", &signalr), ("websocket", &websocket)] {
        assert!((3..=5).contains(&times.len()), "{name} pings at {times:?}");
        assert!(
            times[0] >= Duration::from_millis(60),
            "{name} ping came too early: {times:?}"
        );
    }
}

#[tokio::test]
async fn dropping_the_receiver_ends_the_listener_cleanly() {
    let frames: Vec<Vec<u8>> = (0..50)
        .map(|n| invocation(0, &format!("c{n}"), None))
        .collect();
    let hub = hub::spawn(move |_, socket| serve_updates(socket, frames.clone())).await;
    let (mut rx, task) = start(hub.base(), "t", quick());
    assert_eq!(next(&mut rx).await, Notification::Connected);

    drop(rx);

    assert!(finished(task).await.is_ok());
}

#[tokio::test]
async fn dropping_the_listener_future_closes_the_socket() {
    let (closed_tx, closed_rx) = oneshot::channel();
    let closed_tx = Arc::new(std::sync::Mutex::new(Some(closed_tx)));
    let hub = hub::spawn(move |_, mut socket| {
        let closed_tx = Arc::clone(&closed_tx);
        async move {
            complete_handshake(&mut socket).await;
            drain(&mut socket).await;
            if let Some(tx) = closed_tx.lock().unwrap().take() {
                let _ = tx.send(Instant::now());
            }
        }
    })
    .await;
    let (tx, mut rx) = mpsc::channel(8);
    let base = hub.base();
    let options = ListenOptions {
        stale_after: Duration::from_secs(30),
        ping_interval: Duration::from_secs(10),
        ..quick()
    };

    let dropped = Instant::now();
    let outcome = timeout(
        Duration::from_millis(300),
        listen_with(&base, "t", &tx, &options),
    )
    .await;

    assert!(outcome.is_err(), "listener should still have been running");
    assert_eq!(rx.recv().await, Some(Notification::Connected));
    let closed_at = timeout(WAIT, closed_rx)
        .await
        .expect("server never saw the close")
        .unwrap();
    assert!(closed_at.duration_since(dropped) < Duration::from_secs(2));
}

type Token = std::future::Ready<Option<Zeroizing<String>>>;

fn provider(
    tokens: &'static [&'static str],
) -> (
    impl FnMut(Option<Zeroizing<String>>) -> Token,
    Arc<AtomicUsize>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let next_token = move |_rejected| {
        let index = counter.fetch_add(1, Ordering::SeqCst);
        let token = tokens
            .get(index)
            .or(tokens.last())
            .map(|t| Zeroizing::new((*t).to_owned()));
        std::future::ready(token)
    };
    (next_token, calls)
}

fn reconnect_options(initial_ms: u64, max_ms: u64, healthy_ms: u64) -> ReconnectOptions {
    ReconnectOptions {
        listen: quick(),
        backoff_initial: Duration::from_millis(initial_ms),
        backoff_max: Duration::from_millis(max_ms),
        healthy_after: Duration::from_millis(healthy_ms),
    }
}

async fn closing_hub() -> Hub {
    hub::spawn(|_, mut socket| async move {
        complete_handshake(&mut socket).await;
        socket.close(None).await.unwrap();
        drain(&mut socket).await;
    })
    .await
}

#[tokio::test]
async fn reconnects_with_doubling_backoff_and_announces_every_connection() {
    let hub = closing_hub().await;
    let (token, calls) = provider(&["t1", "t2", "t3", "t4", "t5"]);
    let (tx, mut rx) = mpsc::channel(16);
    let base = hub.base();
    let options = reconnect_options(60, 200, 10_000);
    let runner = tokio::spawn(async move { run_with_reconnect(&base, token, tx, &options).await });

    for _ in 0..5 {
        assert_eq!(next(&mut rx).await, Notification::Connected);
    }
    runner.abort();

    let accepted = hub.accepted();
    let tokens: Vec<String> = accepted
        .iter()
        .take(5)
        .map(|a| a.bearer().unwrap().to_owned())
        .collect();
    assert_eq!(
        tokens,
        ["t1", "t2", "t3", "t4", "t5"],
        "each attempt asks the provider for a token"
    );
    assert!(calls.load(Ordering::SeqCst) >= 5);
    let gaps: Vec<Duration> = accepted
        .windows(2)
        .take(4)
        .map(|pair| pair[1].at - pair[0].at)
        .collect();
    for (gap, minimum) in gaps.iter().zip([60, 120, 200, 200]) {
        assert!(
            *gap >= Duration::from_millis(minimum - 5),
            "gaps {gaps:?} vs backoff 60,120,200,200"
        );
    }
}

#[tokio::test]
async fn backoff_resets_after_a_connection_that_stayed_healthy() {
    let hub = hub::spawn(|index, mut socket| async move {
        complete_handshake(&mut socket).await;
        if index == 2 {
            sleep(Duration::from_millis(250)).await;
        }
        socket.close(None).await.unwrap();
        drain(&mut socket).await;
    })
    .await;
    let (token, _) = provider(&["t"]);
    let (tx, mut rx) = mpsc::channel(16);
    let base = hub.base();
    let options = reconnect_options(100, 800, 150);
    let runner = tokio::spawn(async move { run_with_reconnect(&base, token, tx, &options).await });

    for _ in 0..4 {
        assert_eq!(next(&mut rx).await, Notification::Connected);
    }
    runner.abort();

    let accepted = hub.accepted();
    let gap = |from: usize| accepted[from + 1].at - accepted[from].at;
    assert!(
        gap(0) >= Duration::from_millis(95),
        "first retry waits the initial backoff: {:?}",
        gap(0)
    );
    assert!(
        gap(1) >= Duration::from_millis(195),
        "second retry doubles: {:?}",
        gap(1)
    );
    // Connection 2 lived 250 ms; without the reset the next wait would be 400 ms (total 650 ms).
    assert!(
        gap(2) < Duration::from_millis(550),
        "backoff was not reset: {:?}",
        gap(2)
    );
}

#[tokio::test]
async fn an_expired_token_is_replaced_by_asking_the_provider_again() {
    let hub = hub::spawn_rejecting(
        |_, request| (request.bearer() == Some("expired")).then_some(401),
        |_, socket| serve_updates(socket, vec![]),
    )
    .await;
    let (token, calls) = provider(&["expired", "fresh"]);
    let (tx, mut rx) = mpsc::channel(4);
    let base = hub.base();
    let options = reconnect_options(20, 100, 10_000);
    let runner = tokio::spawn(async move { run_with_reconnect(&base, token, tx, &options).await });

    assert_eq!(next(&mut rx).await, Notification::Connected);
    runner.abort();

    let tokens: Vec<String> = hub
        .accepted()
        .iter()
        .map(|a| a.bearer().unwrap().to_owned())
        .collect();
    assert_eq!(tokens, ["expired", "fresh"]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_provider_learns_which_token_the_hub_rejected() {
    let hub = hub::spawn_rejecting(
        |index, _| (index == 0).then_some(401),
        |index, mut socket| async move {
            if index == 1 {
                // Ends this connection, so the next attempt follows a plain failure.
                complete_handshake(&mut socket).await;
                socket.close(None).await.unwrap();
                drain(&mut socket).await;
            } else {
                serve_updates(socket, vec![]).await;
            }
        },
    )
    .await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let token = move |rejected: Option<Zeroizing<String>>| {
        let mut seen = record.lock().unwrap();
        seen.push(rejected.map(|token| token.to_string()));
        std::future::ready(Some(Zeroizing::new(format!("t{}", seen.len()))))
    };
    let (tx, mut rx) = mpsc::channel(4);
    let base = hub.base();
    let options = reconnect_options(20, 100, 10_000);
    let runner = tokio::spawn(async move { run_with_reconnect(&base, token, tx, &options).await });

    assert_eq!(next(&mut rx).await, Notification::Connected);
    assert_eq!(next(&mut rx).await, Notification::Connected);
    runner.abort();

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen[..3],
        [None, Some("t1".to_owned()), None],
        "only the 401 hands the rejected token back"
    );
}

#[tokio::test]
async fn provider_returning_none_stops_the_loop_without_connecting() {
    let hub = closing_hub().await;
    let (tx, _rx) = mpsc::channel(4);
    let base = hub.base();
    let options = reconnect_options(10, 50, 1000);

    timeout(
        WAIT,
        run_with_reconnect(&base, |_| std::future::ready(None), tx, &options),
    )
    .await
    .expect("loop should end when logged out");

    assert!(hub.accepted().is_empty());
}

#[tokio::test]
async fn dropping_the_receiver_stops_the_reconnect_loop() {
    let hub = hub::spawn(|_, socket| serve_updates(socket, vec![])).await;
    let (token, _) = provider(&["t"]);
    let (tx, mut rx) = mpsc::channel(4);
    let base = hub.base();
    let options = reconnect_options(10, 50, 1000);
    let runner = tokio::spawn(async move { run_with_reconnect(&base, token, tx, &options).await });
    assert_eq!(next(&mut rx).await, Notification::Connected);

    drop(rx);

    timeout(WAIT, runner)
        .await
        .expect("loop should end without a receiver")
        .unwrap();
}

#[tokio::test]
async fn dropping_the_reconnect_future_during_backoff_stops_all_retries() {
    let hub = closing_hub().await;
    let (token, _) = provider(&["t"]);
    let (tx, mut rx) = mpsc::channel(16);
    let base = hub.base();
    let options = reconnect_options(100, 400, 10_000);
    let mut run = Box::pin(run_with_reconnect(&base, token, tx, &options));

    tokio::select! {
        () = &mut run => panic!("loop ended on its own"),
        event = rx.recv() => assert_eq!(event, Some(Notification::Connected)),
    }
    // The first connection has closed by now and the loop is asleep in its 100 ms backoff.
    sleep(Duration::from_millis(20)).await;
    drop(run);
    let attempts = hub.accepted().len();
    sleep(Duration::from_millis(500)).await;

    assert_eq!(
        hub.accepted().len(),
        attempts,
        "no attempt may follow the drop"
    );
}

/// Building the rustls client config panics when no single crypto provider is selectable, so a
/// TLS attempt that merely fails (the peer is not a TLS server) proves the `wss` path is wired.
#[tokio::test]
async fn https_base_attempts_a_tls_handshake_instead_of_panicking() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    let (tx, _rx) = mpsc::channel(1);
    let base = Url::parse(&format!("https://{address}/")).unwrap();

    let outcome = listen_with(&base, "t", &tx, &quick()).await;

    assert!(
        matches!(
            outcome,
            Err(ListenError::WebSocket(_) | ListenError::HandshakeTimeout(_))
        ),
        "{outcome:?}"
    );
}
