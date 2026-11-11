//! Authenticate one browser connection before dispatching vault requests.

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tokio::sync::Mutex;
use vk_ipc::{
    BrowserPrompt, BrowserReply,
    browser::{
        BrowserConnection,
        protocol::{Caller, ErrorCode, KnownBrowser, Request, State, Theme},
    },
};
use zeroize::Zeroizing;

use super::{
    pairing::{PairingStore, fingerprint},
    request,
    session::{PairingSession, Proof},
};

/// Returns the authenticated connection, its public key and the state the proof reply carried,
/// so the caller can tell the extension about any change after that. Closing/cancelling this future drops the
/// pending UI prompt and connection, so neither can later authorize a different session.
pub async fn authenticate<F, Fut, S>(
    mut connection: BrowserConnection,
    store: Arc<Mutex<PairingStore>>,
    prompt: F,
    status: S,
) -> Option<(BrowserConnection, [u8; 65], (State, Theme))>
where
    F: FnOnce(BrowserPrompt) -> Fut,
    Fut: Future<Output = BrowserReply>,
    S: Fn() -> (State, Theme),
{
    let (caller, inferred_browser) = match &connection.hello.caller {
        Caller::Chromium { origin } => (origin.clone(), KnownBrowser::Chrome),
        Caller::Firefox { extension_id } => (extension_id.clone(), KnownBrowser::Firefox),
    };
    let browser = connection.hello.parent.browser.unwrap_or(inferred_browser);
    if browser != inferred_browser {
        return None;
    }
    let name = match browser {
        KnownBrowser::Chrome => "Google Chrome",
        KnownBrowser::Firefox => "Firefox",
    };
    let mut pairing = PairingSession::new(caller.clone());
    let (hello_id, protocol, public_key) =
        match tokio::time::timeout(Duration::from_secs(60), next(&mut connection))
            .await
            .ok()??
        {
            Request::Hello {
                id,
                protocol,
                public_key,
                ..
            } => (id, protocol, public_key),
            request => {
                failure(&connection, id(&request), ErrorCode::Unpaired).await;
                return None;
            }
        };
    let challenge = pairing.hello(protocol, &public_key, &*store.lock().await);
    let challenge = match challenge {
        Ok(challenge) => challenge,
        Err(code) => {
            failure(&connection, hello_id, code).await;
            return None;
        }
    };
    if !success(
        &connection,
        hello_id,
        json!({"challenge":challenge.challenge,"known":challenge.known}),
    )
    .await
    {
        return None;
    }
    let (prove_id, signature) =
        match tokio::time::timeout(Duration::from_secs(60), next(&mut connection))
            .await
            .ok()??
        {
            Request::Prove { id, signature } => (id, signature),
            request => {
                failure(&connection, id(&request), ErrorCode::Unpaired).await;
                return None;
            }
        };
    let proof = pairing.prove(&signature, &*store.lock().await);
    match proof {
        Ok(Proof::Paired) => {}
        Ok(Proof::ApprovalRequired { fingerprint }) => {
            let result = tokio::select! {
                () = connection.outgoing.closed() => return None,
                result = tokio::time::timeout(Duration::from_secs(60), prompt(BrowserPrompt::Pair { browser: name.into(), fingerprint })) => result,
            };
            if !matches!(result, Ok(BrowserReply::PairApproved)) {
                failure(&connection, prove_id, ErrorCode::Denied).await;
                return None;
            }
            let key = *pairing.pending_key()?;
            let persisted = persist_approval(&connection, store, key, browser, caller).await;
            if pairing.finish_pairing(persisted).is_err() {
                failure(&connection, prove_id, ErrorCode::Denied).await;
                return None;
            }
        }
        Err(code) => {
            failure(&connection, prove_id, code).await;
            return None;
        }
    }
    let key = *pairing.paired_key()?;
    let sent = status();
    let (state, theme) = sent;
    if !success(
        &connection,
        prove_id,
        json!({"state":state,"theme":theme,"fingerprint":fingerprint(&key)}),
    )
    .await
    {
        return None;
    }
    Some((connection, key, sent))
}

async fn persist_approval(
    connection: &BrowserConnection,
    store: Arc<Mutex<PairingStore>>,
    key: [u8; 65],
    browser: KnownBrowser,
    caller: String,
) -> bool {
    let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let mut locked_store = tokio::select! {
        () = connection.outgoing.closed() => return false,
        guard = store.lock_owned() => guard,
    };
    if connection.outgoing.is_closed() {
        return false;
    }
    tokio::task::spawn_blocking(move || {
        locked_store.approve(&key, browser, &caller, elapsed.as_secs())
    })
    .await
    .is_ok_and(|result| result.is_ok())
}

async fn next(connection: &mut BrowserConnection) -> Option<Request> {
    loop {
        let body = connection.incoming.recv().await?;
        match request::decode(&body) {
            Ok(request) => return Some(request),
            Err((Some(id), code)) => failure(connection, id, code).await,
            Err((None, _)) => return None,
        }
    }
}

fn id(request: &Request) -> u64 {
    match request {
        Request::Hello { id, .. }
        | Request::Prove { id, .. }
        | Request::Status { id }
        | Request::Fill { id, .. }
        | Request::SaveCandidate { id, .. }
        | Request::Unlock { id }
        | Request::OpenApp { id, .. } => *id,
    }
}

async fn success(connection: &BrowserConnection, id: u64, result: Value) -> bool {
    send(connection, json!({"id":id,"ok":true,"result":result})).await
}
async fn failure(connection: &BrowserConnection, id: u64, code: ErrorCode) {
    let _ = send(connection, json!({"id":id,"ok":false,"error":code})).await;
}
async fn send(connection: &BrowserConnection, value: Value) -> bool {
    let Ok(bytes) = serde_json::to_vec(&value) else {
        return false;
    };
    connection
        .outgoing
        .send(Zeroizing::new(bytes))
        .await
        .is_ok()
}
