//! Request dispatch for one authenticated browser connection.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::{
    sync::{Mutex, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use vk_ipc::{
    BrowserPrompt, BrowserReply, TypingTarget,
    browser::{
        BrowserConnection,
        protocol::{
            AppView, Caller, ErrorCode, Event, FillFields, KnownBrowser, Request, SaveKind, State,
            Theme,
        },
    },
};
use vk_vault::{Vault, model::ItemId, uri_match::DefaultMatch};
use zeroize::Zeroizing;

use super::{
    auth::authenticate,
    fill::{self, FillRequest, Filled, Via},
    limits::Limits,
    pairing::PairingStore,
    request,
};

const UNLOCK_WAIT: Duration = Duration::from_secs(120);
const MAX_REMEMBERED: usize = 32;
const MAX_UNLOCKS: usize = 2;

/// The fill flow behind the dispatch seam. The real implementation binds the vault snapshot;
/// tests substitute a stub to exercise queueing, cancellation and limits without a vault.
pub trait FillFlow: Send + Sync {
    fn run<P, PFut, T, TFut, A, AFut>(
        &self,
        request: FillRequest,
        prompt: P,
        presence: T,
        authorized: A,
    ) -> impl Future<Output = Result<Filled, ErrorCode>> + Send
    where
        P: FnOnce(BrowserPrompt) -> PFut + Send,
        PFut: Future<Output = BrowserReply> + Send,
        T: FnOnce() -> TFut + Send,
        TFut: Future<Output = bool> + Send,
        A: FnOnce() -> AFut + Send,
        AFut: Future<Output = bool> + Send;
}

pub struct RealFills {
    pub vault: Arc<Vault>,
}

impl FillFlow for RealFills {
    fn run<P, PFut, T, TFut, A, AFut>(
        &self,
        request: FillRequest,
        prompt: P,
        presence: T,
        authorized: A,
    ) -> impl Future<Output = Result<Filled, ErrorCode>> + Send
    where
        P: FnOnce(BrowserPrompt) -> PFut + Send,
        PFut: Future<Output = BrowserReply> + Send,
        T: FnOnce() -> TFut + Send,
        TFut: Future<Output = bool> + Send,
        A: FnOnce() -> AFut + Send,
        AFut: Future<Output = bool> + Send,
    {
        fill::fill(&self.vault, request, prompt, presence, authorized)
    }
}

/// What the activity log and the TOTP copy need to know about a finished fill; no secrets.
pub struct FillRecord {
    pub browser: String,
    pub host: String,
    pub item: ItemId,
    pub via: Via,
    pub has_totp: bool,
    /// This site's address when the login was saved for another site.
    pub unsaved_address: Option<String>,
}

/// What the connection may ask of the daemon. Implemented by the daemon; tests use a stub.
pub trait BrowserHost: Send + Sync {
    fn prompt(&self, prompt: BrowserPrompt) -> impl Future<Output = BrowserReply> + Send;
    /// Asks for Touch ID for this one fill; `false` refuses.
    fn presence(&self, reason: &str) -> impl Future<Output = bool> + Send;
    /// Shows the unlock UI and resolves when the vault is no longer locked.
    fn unlock(&self) -> impl Future<Output = ()> + Send;
    /// The app in front now, read before any window of ours comes up.
    fn return_to(&self) -> impl Future<Output = Option<TypingTarget>> + Send;
    fn status(&self) -> (State, Theme);
    /// Rate-limit state of one paired key. Shared by its connections so a reconnect does not
    /// reset the buckets or the cancellation cooldown.
    fn limits(&self, key: &[u8; 65]) -> Arc<std::sync::Mutex<Limits>>;
    fn default_match(&self) -> DefaultMatch;
    fn browser_touch_id(&self) -> bool;
    fn browser_fill_single(&self) -> bool;
    /// Integration and the per-request permission must still hold right now.
    fn enabled(&self, browser: KnownBrowser) -> bool;
    /// Changes whenever remembered approvals must be forgotten: lock, logout, account switch,
    /// sleep or screen lock.
    fn approvals_epoch(&self) -> u64;
    /// Hands a validated candidate to the daemon's bounded, account-bound queue.
    fn candidate(&self, candidate: Candidate);
    fn filled(&self, record: FillRecord);
    fn open_app(&self, view: AppView);
    fn note_activity(&self);
    /// Fires on vault state changes and when the pairing store was reloaded.
    fn changes(&self) -> watch::Receiver<u64>;
}

pub struct Candidate {
    pub browser: String,
    pub origin: String,
    pub path: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub kind: SaveKind,
}

struct Completion {
    id: u64,
    origin: String,
    epoch: u64,
    answer: Result<Filled, ErrorCode>,
    /// The user walked away (the picker lost focus): not a cancel for the cooldown.
    abandoned: bool,
}

struct InFlight {
    id: u64,
    /// Held for its Drop: dropping it cancels the fill, dropping the prompt, which the UI
    /// counts as dismissed.
    _cancel: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// Approvals the user gave on this connection, valid only within one approvals epoch.
struct Remembered {
    epoch: u64,
    items: HashMap<String, ItemId>,
}

impl Remembered {
    fn sync(&mut self, epoch: u64) {
        if self.epoch != epoch {
            self.items.clear();
            self.epoch = epoch;
        }
    }

    fn get(&mut self, epoch: u64, origin: &str) -> Option<ItemId> {
        self.sync(epoch);
        self.items.get(origin).cloned()
    }

    fn insert(&mut self, epoch: u64, origin: String, item: ItemId) {
        self.sync(epoch);
        if self.items.len() >= MAX_REMEMBERED && !self.items.contains_key(&origin) {
            self.items.clear();
        }
        self.items.insert(origin, item);
    }
}

struct Closed;

struct Dispatcher<H, F> {
    outgoing: mpsc::Sender<Zeroizing<Vec<u8>>>,
    store: Arc<Mutex<PairingStore>>,
    key: [u8; 65],
    caller: String,
    browser: &'static str,
    kind: KnownBrowser,
    fills: Arc<F>,
    host: Arc<H>,
    limits: Arc<std::sync::Mutex<Limits>>,
    remembered: Remembered,
    inflight: Option<InFlight>,
    /// `unlock` waits for the user, so it runs beside the request loop; dropping the set on
    /// disconnect cancels the waits.
    unlocks: JoinSet<u64>,
    completions: mpsc::Sender<Completion>,
    last_status: (State, Theme),
}

/// Runs until the transport closes, proof fails, the pairing is revoked, or the task is
/// cancelled; cancelling aborts any fill in flight, which drops its UI prompt and counts as
/// dismissed.
pub async fn serve<H: BrowserHost + 'static, F: FillFlow + 'static>(
    connection: BrowserConnection,
    store: Arc<Mutex<PairingStore>>,
    fills: Arc<F>,
    host: Arc<H>,
) {
    if !host.enabled(caller_kind(&connection)) {
        return;
    }
    let Some((connection, key, sent)) = authenticate(
        connection,
        Arc::clone(&store),
        |prompt| host.prompt(prompt),
        || host.status(),
    )
    .await
    else {
        return;
    };
    let BrowserConnection {
        hello,
        mut incoming,
        outgoing,
        ..
    } = connection;
    let (caller, browser_kind) = match hello.caller {
        Caller::Chromium { origin } => (origin, KnownBrowser::Chrome),
        Caller::Firefox { extension_id } => (extension_id, KnownBrowser::Firefox),
    };
    let browser = browser_name(browser_kind);
    let (completions, mut completed) = mpsc::channel(1);
    let mut changes = host.changes();
    // The current state goes out with the prove reply; only later changes push events.
    changes.borrow_and_update();
    let mut dispatcher = Dispatcher {
        outgoing,
        store,
        key,
        caller,
        browser,
        kind: browser_kind,
        fills,
        limits: host.limits(&key),
        remembered: Remembered {
            epoch: host.approvals_epoch(),
            items: HashMap::new(),
        },
        inflight: None,
        unlocks: JoinSet::new(),
        completions,
        last_status: sent,
        host,
    };
    // A change between the proof reply and the subscription must not be lost.
    if dispatcher.changed().await.is_err() {
        return;
    }
    loop {
        let step = tokio::select! {
            body = incoming.recv() => match body {
                Some(body) => dispatcher.request(&body).await,
                None => return,
            },
            Some(done) = completed.recv() => dispatcher.complete(done).await,
            () = fill_ended(&mut dispatcher.inflight) => dispatcher.fill_lost(&mut completed).await,
            Some(unlocked) = dispatcher.unlocks.join_next() => match unlocked {
                Ok(id) => dispatcher.answer_state(id).await,
                Err(_) => Ok(()),
            },
            moved = changes.changed() => match moved {
                Ok(()) => dispatcher.changed().await,
                Err(_) => return,
            },
        };
        if step.is_err() {
            return;
        }
    }
}

impl<H: BrowserHost + 'static, F: FillFlow + 'static> Dispatcher<H, F> {
    async fn request(&mut self, body: &[u8]) -> Result<(), Closed> {
        let request = match request::decode(body) {
            Ok(request) => request,
            Err((Some(id), code)) => return self.respond::<()>(id, Err(code)).await,
            Err((None, _)) => return Err(Closed),
        };
        let id = id_of(&request);
        if !self.paired().await {
            let _ = self.respond::<()>(id, Err(ErrorCode::Denied)).await;
            return Err(Closed);
        }
        if !self.host.enabled(self.kind) {
            return self.respond::<()>(id, Err(ErrorCode::Denied)).await;
        }
        match request {
            Request::Status { .. } => self.answer_state(id).await,
            Request::Fill {
                origin,
                path,
                choose,
                fields,
                ..
            } => self.fill(id, origin, path, choose, fields).await,
            Request::SaveCandidate { .. } => self.save(id, &request).await,
            Request::Unlock { .. } | Request::OpenApp { .. }
                if !self.limit(|limits| limits.open_app(Instant::now())) =>
            {
                self.respond::<()>(id, Err(ErrorCode::RateLimited)).await
            }
            Request::Unlock { .. } => {
                if self.unlocks.len() >= MAX_UNLOCKS {
                    return self.respond::<()>(id, Err(ErrorCode::Busy)).await;
                }
                let host = Arc::clone(&self.host);
                self.unlocks.spawn(async move {
                    let _ = tokio::time::timeout(UNLOCK_WAIT, host.unlock()).await;
                    id
                });
                Ok(())
            }
            Request::OpenApp { view, .. } => {
                self.host.open_app(view);
                self.respond(id, Ok(serde_json::json!({}))).await
            }
            Request::Hello { .. } | Request::Prove { .. } => {
                self.respond::<()>(id, Err(ErrorCode::Unpaired)).await
            }
        }
    }

    fn limit<T>(&self, check: impl FnOnce(&mut Limits) -> T) -> T {
        let mut limits = self
            .limits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        check(&mut limits)
    }

    /// The pairing may have been removed in Settings since this connection proved its key.
    async fn paired(&self) -> bool {
        self.store.lock().await.contains(&self.key, &self.caller)
    }

    async fn fill(
        &mut self,
        id: u64,
        origin: String,
        path: String,
        choose: bool,
        fields: FillFields,
    ) -> Result<(), Closed> {
        if self.inflight.is_some() {
            return self.respond::<()>(id, Err(ErrorCode::Busy)).await;
        }
        let key = canonical_origin(&origin);
        if !self.limit(|limits| limits.fill(&key, Instant::now())) {
            return self.respond::<()>(id, Err(ErrorCode::RateLimited)).await;
        }
        let epoch = self.host.approvals_epoch();
        let remembered = self.remembered.get(epoch, &key);
        let task = FillTask {
            id,
            key,
            origin,
            path,
            choose,
            fields,
            epoch,
            remembered,
            browser: self.browser,
            kind: self.kind,
            completions: self.completions.clone(),
        };
        self.inflight = Some(spawn_fill(&self.fills, &self.host, task));
        Ok(())
    }

    /// Validates and acknowledges a save candidate; the daemon's queue owns it from here.
    async fn save(&mut self, id: u64, request: &Request) -> Result<(), Closed> {
        if request::validate(request).is_err() {
            return self.respond::<()>(id, Err(ErrorCode::BadRequest)).await;
        }
        if !self.limit(|limits| limits.save(Instant::now())) {
            return self.respond::<()>(id, Err(ErrorCode::RateLimited)).await;
        }
        let Request::SaveCandidate {
            origin,
            path,
            username,
            password,
            kind,
            ..
        } = request
        else {
            return self.respond::<()>(id, Err(ErrorCode::BadRequest)).await;
        };
        self.respond(id, Ok(serde_json::json!({}))).await?;
        self.host.candidate(Candidate {
            browser: self.browser.to_owned(),
            origin: origin.clone(),
            path: path.clone(),
            username: username.clone(),
            password: password.clone(),
            kind: kind.clone(),
        });
        Ok(())
    }

    /// The task ended: its completion, if any, is already queued; otherwise it died without
    /// one and the request would wait for the extension's timeout.
    async fn fill_lost(
        &mut self,
        completed: &mut mpsc::Receiver<Completion>,
    ) -> Result<(), Closed> {
        let Some(inflight) = self.inflight.take() else {
            return Ok(());
        };
        if let Ok(done) = completed.try_recv() {
            self.inflight = Some(inflight);
            return self.complete(done).await;
        }
        tracing::error!("browser fill task ended without an answer");
        self.respond::<()>(inflight.id, Err(ErrorCode::Internal))
            .await
    }

    /// Delivers a finished fill: cancellation counting, memory, activity, then the response.
    async fn complete(&mut self, done: Completion) -> Result<(), Closed> {
        if let Some(inflight) = self.inflight.take_if(|inflight| inflight.id == done.id) {
            inflight.task.abort();
        }
        let Completion {
            id,
            origin,
            epoch,
            answer,
            abandoned,
        } = done;
        let answer = match answer {
            Ok(filled) => {
                self.finished(&origin, epoch, &filled);
                Ok(filled.result)
            }
            Err(code) => {
                if matches!(code, ErrorCode::Cancelled | ErrorCode::Timeout) && !abandoned {
                    self.limit(|limits| limits.cancelled(&origin, Instant::now()));
                }
                Err(code)
            }
        };
        self.respond(id, answer).await
    }

    fn finished(&mut self, origin: &str, epoch: u64, filled: &Filled) {
        // A lock during the fill ends the approval it came from.
        if filled.remember && self.host.approvals_epoch() == epoch {
            self.remembered
                .insert(epoch, origin.to_owned(), filled.item.clone());
        }
        self.host.note_activity();
        self.host.filled(FillRecord {
            browser: self.browser.to_owned(),
            host: filled.host.clone(),
            item: filled.item.clone(),
            via: filled.via,
            unsaved_address: filled.unsaved_address.clone(),
            has_totp: filled.has_totp,
        });
    }

    /// Pushes the state only when it differs from what the extension was last told.
    async fn changed(&mut self) -> Result<(), Closed> {
        if !self.paired().await {
            return Err(Closed);
        }
        let status = self.host.status();
        if status == self.last_status {
            return Ok(());
        }
        self.last_status = status;
        let (state, theme) = status;
        let event = serde_json::to_vec(&Event::State { state, theme }).map_err(|_| Closed)?;
        self.outgoing
            .send(Zeroizing::new(event))
            .await
            .map_err(|_| Closed)
    }

    async fn answer_state(&mut self, id: u64) -> Result<(), Closed> {
        let (state, theme) = self.host.status();
        self.last_status = (state, theme);
        self.respond(id, Ok(serde_json::json!({"state": state, "theme": theme})))
            .await
    }

    /// Serialises straight into a wiped buffer sized for the largest frame, so a password never
    /// sits in an intermediate tree or a reallocated, unwiped prefix.
    async fn respond<T: Serialize>(
        &self,
        id: u64,
        result: Result<T, ErrorCode>,
    ) -> Result<(), Closed> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(RESPONSE_CAPACITY));
        match result {
            Ok(result) => serde_json::to_writer(
                &mut *bytes,
                &Success {
                    id,
                    ok: true,
                    result,
                },
            ),
            Err(error) => serde_json::to_writer(
                &mut *bytes,
                &Failure {
                    id,
                    ok: false,
                    error,
                },
            ),
        }
        .map_err(|_| Closed)?;
        self.outgoing.send(bytes).await.map_err(|_| Closed)
    }
}

#[derive(Serialize)]
struct Success<T> {
    id: u64,
    ok: bool,
    result: T,
}

#[derive(Serialize)]
struct Failure {
    id: u64,
    ok: bool,
    error: ErrorCode,
}

/// The most a response can take; the extension never gets a longer frame.
const RESPONSE_CAPACITY: usize = vk_ipc::browser::BROWSER_MAX_FRAME;

/// Scheme, lower-case ASCII host and non-default port, so `HTTPS://Example.com:443` and
/// `https://example.com` share one cooldown and one remembered approval.
fn canonical_origin(origin: &str) -> String {
    url::Url::parse(origin).map_or_else(
        |_| origin.to_owned(),
        |url| url.origin().ascii_serialization(),
    )
}

/// Resolves when the fill task has ended, normally or by panic.
async fn fill_ended(inflight: &mut Option<InFlight>) {
    match inflight.as_mut() {
        Some(inflight) => {
            let _ = (&mut inflight.task).await;
        }
        None => std::future::pending().await,
    }
}

struct FillTask {
    id: u64,
    /// The origin as the vault and the limiters see it; `origin` is what the extension sent.
    key: String,
    origin: String,
    path: String,
    choose: bool,
    fields: FillFields,
    epoch: u64,
    remembered: Option<ItemId>,
    browser: &'static str,
    kind: KnownBrowser,
    completions: mpsc::Sender<Completion>,
}

fn spawn_fill<H: BrowserHost + 'static, F: FillFlow + 'static>(
    fills: &Arc<F>,
    host: &Arc<H>,
    task: FillTask,
) -> InFlight {
    let FillTask {
        id,
        key,
        origin,
        path,
        choose,
        fields,
        epoch,
        remembered,
        browser,
        kind,
        completions,
    } = task;
    let (cancel, cancelled) = oneshot::channel::<()>();
    let fills = Arc::clone(fills);
    let host = Arc::clone(host);
    let task = tokio::spawn(async move {
        let (answer, abandoned) = tokio::select! {
            done = run_fill(&*fills, &host, FillInput { browser, kind, origin, path, choose, fields, remembered }) => done,
            _ = cancelled => return,
        };
        let _ = completions
            .send(Completion {
                id,
                origin: key,
                epoch,
                answer,
                abandoned,
            })
            .await;
    });
    InFlight {
        id,
        _cancel: cancel,
        task,
    }
}

struct FillInput {
    browser: &'static str,
    kind: KnownBrowser,
    origin: String,
    path: String,
    choose: bool,
    fields: FillFields,
    remembered: Option<ItemId>,
}

/// A locked vault shows the lock screen first; the picker follows once it is unlocked.
async fn run_fill<H: BrowserHost, F: FillFlow>(
    fills: &F,
    host: &Arc<H>,
    input: FillInput,
) -> (Result<Filled, ErrorCode>, bool) {
    let abandoned = Arc::new(AtomicBool::new(false));
    let answer = run_fill_inner(fills, host, input, &abandoned).await;
    (answer, abandoned.load(Ordering::SeqCst))
}

async fn run_fill_inner<H: BrowserHost, F: FillFlow>(
    fills: &F,
    host: &Arc<H>,
    input: FillInput,
    abandoned: &Arc<AtomicBool>,
) -> Result<Filled, ErrorCode> {
    let return_to = host.return_to().await;
    let mut input = input;
    if host.status().0 == State::Locked {
        // The approvals epoch moves a moment after the lock, so a remembered approval read
        // before it must not survive a lock seen here.
        input.remembered = None;
        let _ = tokio::time::timeout(UNLOCK_WAIT, host.unlock()).await;
        if host.status().0 == State::Locked {
            return Err(ErrorCode::Locked);
        }
    }
    let FillInput {
        browser,
        kind,
        origin,
        path,
        choose,
        fields,
        remembered,
    } = input;
    let touch_id = host.browser_touch_id();
    let fill_single = host.browser_fill_single();
    let reason = format!("fill a login in {browser}");
    fills
        .run(
            FillRequest {
                browser: browser.to_owned(),
                choose,
                fill_single,
                remembered,
                origin,
                path,
                fields,
                default_match: host.default_match(),
                touch_id,
                return_to,
            },
            |prompt| async {
                match host.prompt(prompt).await {
                    BrowserReply::Abandoned => {
                        abandoned.store(true, Ordering::SeqCst);
                        BrowserReply::Dismissed
                    }
                    reply => reply,
                }
            },
            || host.presence(&reason),
            || async { host.enabled(kind) },
        )
        .await
}

const fn caller_kind(connection: &BrowserConnection) -> KnownBrowser {
    match connection.hello.caller {
        Caller::Chromium { .. } => KnownBrowser::Chrome,
        Caller::Firefox { .. } => KnownBrowser::Firefox,
    }
}

const fn browser_name(browser: KnownBrowser) -> &'static str {
    match browser {
        KnownBrowser::Chrome => "Google Chrome",
        KnownBrowser::Firefox => "Firefox",
    }
}

const fn id_of(request: &Request) -> u64 {
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
