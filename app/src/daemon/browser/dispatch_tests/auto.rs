//! A page-load fill must come out as the quiet `no_auto` unless every condition holds, and never
//! reach the picker, the unlock screen or the presence check.

use super::*;

type Pairing = (
    Arc<tokio::sync::Mutex<PairingStore>>,
    SigningKey,
    tempfile::TempDir,
);

fn auto_request(id: u64, origin: &str, choose: bool) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({
            "type":"fill","id":id,"origin":origin,"path":"/","choose":choose,"auto":true,
            "fields":{"username":true,"password":true}
        }))
        .expect("fill"),
    )
}

impl Session {
    async fn auto(&mut self, id: u64, origin: &str) -> serde_json::Value {
        self.incoming
            .send(auto_request(id, origin, false))
            .await
            .expect("send");
        next_response(&mut self.outgoing).await
    }

    /// An auto fill that must be refused before any flow starts.
    async fn quiet(&mut self, id: u64, origin: &str) {
        let reply = self.auto(id, origin).await;
        assert_eq!(reply["id"], id);
        assert_eq!(reply["error"], "no_auto", "{reply}");
        assert_eq!(self.fills.auto_requests.load(Ordering::SeqCst), 0);
    }

    /// Lets the flow run and answers it.
    async fn auto_answered(
        &mut self,
        id: u64,
        answer: Result<Filled, ErrorCode>,
    ) -> serde_json::Value {
        self.incoming
            .send(auto_request(id, "https://example.com", false))
            .await
            .expect("send");
        let done = self.gate.recv().await.expect("fill started");
        assert!(done.send(answer).is_ok());
        next_response(&mut self.outgoing).await
    }
}

fn nothing_shown(host: &StubHost) {
    assert_eq!(host.prompts.load(Ordering::SeqCst), 0, "no picker");
    assert_eq!(
        host.presences.load(Ordering::SeqCst),
        0,
        "no presence check"
    );
    assert_eq!(host.unlocks.load(Ordering::SeqCst), 0, "no unlock screen");
}

/// A session whose user picked `item` for example.com, with the setting on.
async fn remembered(host: &Arc<StubHost>, pairing: &Pairing) -> Session {
    host.autofill.store(true, Ordering::SeqCst);
    let mut session = Session::open(host, &pairing.0, &pairing.1).await;
    session.fill(1, "https://example.com", filled(true)).await;
    session
}

#[tokio::test]
async fn the_remembered_login_is_released_on_load_without_counting_as_activity() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    let activity = host.activity.load(Ordering::SeqCst);
    let answer = Ok(Filled {
        via: Via::Auto,
        ..Filled::bare(FillResult {
            username: Some(Zeroizing::new("user".into())),
            password: Some(Zeroizing::new("secret".into())),
        })
    });
    let reply = session.auto_answered(2, answer).await;
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["result"]["password"], "secret");
    assert_eq!(session.fills.auto_requests.load(Ordering::SeqCst), 1);
    assert_eq!(session.seen(), vec![None, Some(item_id("item"))]);
    assert_eq!(host.records.lock().expect("records").len(), 2);
    assert_eq!(
        host.activity.load(Ordering::SeqCst),
        activity,
        "a page load does not keep the vault from locking"
    );
    nothing_shown(&host);
    session.close().await;
}

#[tokio::test]
async fn the_setting_off_refuses_quietly() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    host.autofill.store(false, Ordering::SeqCst);
    session.quiet(2, "https://example.com").await;
    nothing_shown(&host);
    session.close().await;
}

#[tokio::test]
async fn a_locked_vault_is_not_unlocked_for_it() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    host.locked.store(true, Ordering::SeqCst);
    session.quiet(2, "https://example.com").await;
    nothing_shown(&host);
    session.close().await;
}

#[tokio::test]
async fn a_site_without_a_remembered_login_gets_nothing() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    session.quiet(2, "https://other.test").await;
    nothing_shown(&host);
    session.close().await;
}

#[tokio::test]
async fn touch_id_on_means_no_auto_fill_and_no_biometric_prompt() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    host.touch_id.store(true, Ordering::SeqCst);
    session.quiet(2, "https://example.com").await;
    nothing_shown(&host);
    session.close().await;
}

#[tokio::test]
async fn an_http_page_gets_nothing_even_with_a_remembered_login() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    session.fill(2, "http://localhost:3000", filled(true)).await;
    session.quiet(3, "http://localhost:3000").await;
    nothing_shown(&host);
    session.close().await;
}

#[tokio::test]
async fn at_most_three_a_minute_per_origin() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    for id in 2..=4 {
        let reply = session.auto_answered(id, filled(false)).await;
        assert_eq!(reply["ok"], true, "{reply}");
    }
    let before = session.fills.auto_requests.load(Ordering::SeqCst);
    let reply = session.auto(5, "https://example.com").await;
    assert_eq!(reply["error"], "no_auto");
    assert_eq!(session.fills.auto_requests.load(Ordering::SeqCst), before);
    nothing_shown(&host);
    session.close().await;
}

#[tokio::test]
async fn a_failed_flow_is_quiet_and_starts_no_cooldown_for_user_fills() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    for id in 2..=4 {
        let reply = session.auto_answered(id, Err(ErrorCode::Cancelled)).await;
        assert_eq!(reply["error"], "no_auto", "{reply}");
    }
    session
        .incoming
        .send(fill_request(5, "https://example.com"))
        .await
        .expect("send");
    let done = session.gate.recv().await.expect("a user fill still runs");
    drop(done);
    session.close().await;
}

#[tokio::test]
async fn a_picker_in_flight_and_a_contradictory_request_are_not_auto_filled() {
    let (host, _changes) = StubHost::new();
    let pairing = store();
    let mut session = remembered(&host, &pairing).await;
    session
        .incoming
        .send(auto_request(2, "https://example.com", true))
        .await
        .expect("send");
    let reply = next_response(&mut session.outgoing).await;
    assert_eq!(reply["error"], "bad_request");
    session
        .incoming
        .send(fill_request(3, "https://example.com"))
        .await
        .expect("send");
    let done = session.gate.recv().await.expect("fill started");
    session.quiet(4, "https://example.com").await;
    drop(done);
    session.close().await;
}
