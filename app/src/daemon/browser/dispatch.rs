//! Request dispatch for one authenticated browser connection.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
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
            AppView, Caller, ErrorCode, Event, FieldLimits, FillFields, GeneratedPassword,
            KnownBrowser, PasskeyResult, Request, SaveKind, State, Theme,
        },
    },
};
use vk_vault::{Vault, model::ItemId, uri_match::DefaultMatch};
use zeroize::Zeroizing;

use super::{
    auth::{authenticate, connection_browser},
    choices::ChoiceStore,
    fill::{self, FillRequest, Filled, Via},
    limits::Limits,
    pairing::PairingStore,
    passkey::{self, PasskeyCeremony, PasskeyRequest},
    remembered::Remembered,
    request,
};

const UNLOCK_WAIT: Duration = Duration::from_secs(120);
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

    /// A page's passkey request; returns the credential's JSON.
    fn passkey<P, PFut, T, TFut, A, AFut>(
        &self,
        request: PasskeyRequest,
        prompt: P,
        presence: T,
        authorized: A,
    ) -> impl Future<Output = Result<serde_json::Value, ErrorCode>> + Send
    where
        P: FnOnce(BrowserPrompt) -> PFut + Send,
        PFut: Future<Output = BrowserReply> + Send,
        T: FnOnce() -> TFut + Send,
        TFut: Future<Output = bool> + Send,
        A: FnOnce() -> AFut + Send,
        AFut: Future<Output = bool> + Send,
    {
        let _ = (request, prompt, presence, authorized);
        async { Err(ErrorCode::Fallback) }
    }
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

    fn passkey<P, PFut, T, TFut, A, AFut>(
        &self,
        request: PasskeyRequest,
        prompt: P,
        presence: T,
        authorized: A,
    ) -> impl Future<Output = Result<serde_json::Value, ErrorCode>> + Send
    where
        P: FnOnce(BrowserPrompt) -> PFut + Send,
        PFut: Future<Output = BrowserReply> + Send,
        T: FnOnce() -> TFut + Send,
        TFut: Future<Output = bool> + Send,
        A: FnOnce() -> AFut + Send,
        AFut: Future<Output = bool> + Send,
    {
        passkey::passkey(&self.vault, request, prompt, presence, authorized)
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
    /// The logins picked per site, shared by every connection. They outlive locks and
    /// reconnects; the daemon clears them on log out and account switch.
    fn choices(&self) -> Arc<std::sync::Mutex<ChoiceStore>>;
    fn default_match(&self) -> DefaultMatch;
    fn browser_touch_id(&self) -> bool;
    fn browser_fill_single(&self) -> bool;
    /// Off by default: fills the remembered login as a page opens, with no click.
    fn browser_autofill(&self) -> bool;
    fn browser_passkeys(&self) -> bool;
    /// Passkeys always ask for Touch ID; without it they are left to the browser.
    fn touch_id_available(&self) -> bool {
        true
    }
    /// Integration and the per-request permission must still hold right now.
    fn enabled(&self, browser: KnownBrowser) -> bool;
    /// Changes whenever remembered approvals must be forgotten: lock, logout, account switch,
    /// sleep or screen lock.
    fn approvals_epoch(&self) -> u64;
    /// Hands a validated candidate to the daemon's bounded, account-bound queue.
    fn candidate(&self, candidate: Candidate);
    /// A password from the user's generator that fits `limits`, kept sealed for `origin` until
    /// it is saved. The vault must be unlocked.
    fn generate(&self, origin: &str, limits: FieldLimits) -> Result<Zeroizing<String>, ErrorCode>;
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
    pub has_current: bool,
}

enum Answer {
    Fill(Result<Filled, ErrorCode>),
    Passkey(Result<serde_json::Value, ErrorCode>),
}

struct Completion {
    id: u64,
    origin: String,
    epoch: u64,
    answer: Answer,
    /// The user walked away (the picker lost focus): not a cancel for the cooldown.
    abandoned: bool,
    /// The user turned a passkey prompt down, which the answer reports as a fallback.
    declined: bool,
}

struct InFlight {
    id: u64,
    /// The canonical origin of a passkey request, which a `passkey_cancel` from it may end.
    passkey_origin: Option<String>,
    /// Set for passkeys, whose cancel must not cut a vault write short.
    commit: Option<Arc<Commit>>,
    /// Held for its Drop: dropping it cancels the fill, dropping the prompt, which the UI
    /// counts as dismissed.
    _cancel: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

struct Closed;

/// A cancel wins only until the passkey's vault write begins; from then on the write runs to the
/// end and the page gets its real outcome, so it is never told "cancelled" about a stored passkey.
#[derive(Default)]
struct Commit(AtomicU8);

impl Commit {
    const RUNNING: u8 = 0;
    const WRITING: u8 = 1;
    const CANCELLED: u8 = 2;

    fn begin_write(&self) -> bool {
        self.move_from_running(Self::WRITING)
    }

    fn cancel(&self) -> bool {
        self.move_from_running(Self::CANCELLED)
    }

    fn move_from_running(&self, to: u8) -> bool {
        self.0
            .compare_exchange(Self::RUNNING, to, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

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
    /// At most one: it may wait for an unlock, so it runs beside the request loop too.
    generating: JoinSet<(u64, Result<Zeroizing<String>, ErrorCode>)>,
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
    let Some(browser_kind) = connection_browser(&connection.hello) else {
        return;
    };
    if !host.enabled(browser_kind) {
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
    let caller = match hello.caller {
        Caller::Chromium { origin } => origin,
        Caller::Firefox { extension_id } => extension_id,
    };
    let browser = browser_kind.display_name();
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
        remembered: Remembered::new(host.approvals_epoch(), host.choices(), STANDARD.encode(key)),
        inflight: None,
        unlocks: JoinSet::new(),
        generating: JoinSet::new(),
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
            Some(generated) = dispatcher.generating.join_next() => match generated {
                Ok((id, result)) => {
                    let answer = result.map(|password| GeneratedPassword { password });
                    dispatcher.respond(id, answer).await
                }
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
                auto,
                ..
            } => self.fill(id, origin, path, (choose, auto), fields).await,
            Request::SaveCandidate { .. } => self.save(id, &request).await,
            Request::GeneratePassword { .. } => self.generate(id, &request).await,
            Request::PasskeyCreate {
                origin, options, ..
            } => {
                self.passkey(id, PasskeyCeremony::Create, origin, options)
                    .await
            }
            Request::PasskeyGet {
                origin, options, ..
            } => {
                self.passkey(id, PasskeyCeremony::Get, origin, options)
                    .await
            }
            Request::PasskeyCancel { origin, .. } => self.cancel_passkey(id, &origin).await,
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
        (choose, auto): (bool, bool),
        fields: FillFields,
    ) -> Result<(), Closed> {
        if auto {
            return if choose {
                self.respond::<()>(id, Err(ErrorCode::BadRequest)).await
            } else {
                self.auto_fill(id, origin, path, fields).await
            };
        }
        if self.inflight.is_some() {
            return self.respond::<()>(id, Err(ErrorCode::Busy)).await;
        }
        let key = canonical_origin(&origin);
        if !self.limit(|limits| limits.fill(&key, Instant::now())) {
            return self.respond::<()>(id, Err(ErrorCode::RateLimited)).await;
        }
        let epoch = self.host.approvals_epoch();
        let remembered = self.remembered.get(epoch, &key);
        let persisted = self.remembered.persisted(&key);
        let task = FillTask {
            id,
            key,
            origin,
            path,
            choose,
            auto: false,
            fields,
            epoch,
            remembered,
            persisted,
            browser: self.browser,
            kind: self.kind,
            completions: self.completions.clone(),
        };
        self.inflight = Some(spawn_fill(&self.fills, &self.host, task));
        Ok(())
    }

    /// A page-load fill. Every refusal is the quiet `no_auto`, answered before anything is
    /// spawned: the vault is not unlocked, no window is shown and no presence check is asked.
    /// The budget is charged only for a request that has a remembered login to release.
    async fn auto_fill(
        &mut self,
        id: u64,
        origin: String,
        path: String,
        fields: FillFields,
    ) -> Result<(), Closed> {
        let key = canonical_origin(&origin);
        let epoch = self.host.approvals_epoch();
        let allowed = self.inflight.is_none()
            && self.host.browser_autofill()
            && !self.host.browser_touch_id()
            && self.host.status().0 == State::Unlocked
            && key.starts_with("https://");
        let remembered = if allowed {
            self.remembered.get(epoch, &key)
        } else {
            None
        };
        if remembered.is_none() || !self.limit(|limits| limits.auto_fill(&key, Instant::now())) {
            return self.respond::<()>(id, Err(ErrorCode::NoAuto)).await;
        }
        let task = FillTask {
            id,
            key,
            origin,
            path,
            choose: false,
            auto: true,
            fields,
            epoch,
            remembered,
            persisted: None,
            browser: self.browser,
            kind: self.kind,
            completions: self.completions.clone(),
        };
        self.inflight = Some(spawn_fill(&self.fills, &self.host, task));
        Ok(())
    }

    /// Shares the fill's slot, limits and cooldown: a page can ask for these prompts at will.
    async fn passkey(
        &mut self,
        id: u64,
        ceremony: PasskeyCeremony,
        origin: String,
        options: serde_json::Value,
    ) -> Result<(), Closed> {
        if !self.host.browser_passkeys() || !self.host.touch_id_available() {
            return self.respond::<()>(id, Err(ErrorCode::Fallback)).await;
        }
        if self.inflight.is_some() {
            return self.respond::<()>(id, Err(ErrorCode::Busy)).await;
        }
        let key = canonical_origin(&origin);
        if !self.limit(|limits| limits.fill(&key, Instant::now())) {
            return self.respond::<()>(id, Err(ErrorCode::RateLimited)).await;
        }
        let task = PasskeyTask {
            id,
            key,
            epoch: self.host.approvals_epoch(),
            ceremony,
            origin,
            options,
            browser: self.browser,
            kind: self.kind,
            completions: self.completions.clone(),
        };
        self.inflight = Some(spawn_passkey(&self.fills, &self.host, task));
        Ok(())
    }

    /// Dropping the task drops its prompt, which the UI closes.
    async fn cancel_passkey(&mut self, id: u64, origin: &str) -> Result<(), Closed> {
        let origin = canonical_origin(origin);
        if let Some(inflight) = self
            .inflight
            .take_if(|inflight| inflight.passkey_origin.as_deref() == Some(origin.as_str()))
        {
            if inflight
                .commit
                .as_ref()
                .is_none_or(|commit| commit.cancel())
            {
                inflight.task.abort();
                self.respond::<()>(inflight.id, Err(ErrorCode::Cancelled))
                    .await?;
            } else {
                self.inflight = Some(inflight);
            }
        }
        self.respond(id, Ok(serde_json::json!({}))).await
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
            has_current,
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
            has_current: *has_current,
        });
        Ok(())
    }

    /// Generates once the vault is unlocked, showing the lock screen when it is not.
    async fn generate(&mut self, id: u64, request: &Request) -> Result<(), Closed> {
        let Request::GeneratePassword { origin, limits, .. } = request else {
            return self.respond::<()>(id, Err(ErrorCode::BadRequest)).await;
        };
        // Plain http is refused except on the local network, as for fills and saves.
        if let Err(code) = request::validate(request) {
            return self.respond::<()>(id, Err(code)).await;
        }
        if !self.generating.is_empty() {
            return self.respond::<()>(id, Err(ErrorCode::Busy)).await;
        }
        if !self.limit(|limits| limits.generate(Instant::now())) {
            return self.respond::<()>(id, Err(ErrorCode::RateLimited)).await;
        }
        let host = Arc::clone(&self.host);
        let (origin, limits) = (origin.clone(), *limits);
        self.generating.spawn(async move {
            match host.status().0 {
                State::LoggedOut => return (id, Err(ErrorCode::LoggedOut)),
                State::Locked => {
                    let _ = tokio::time::timeout(UNLOCK_WAIT, host.unlock()).await;
                }
                State::Unlocked => {}
            }
            let result = match host.status().0 {
                State::Unlocked => host.generate(&origin, limits),
                State::Locked => Err(ErrorCode::Locked),
                State::LoggedOut => Err(ErrorCode::LoggedOut),
            };
            (id, result)
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
        // A cancel may have answered this request already while its completion sat queued.
        let Some(inflight) = self.inflight.take_if(|inflight| inflight.id == done.id) else {
            return Ok(());
        };
        inflight.task.abort();
        let Completion {
            id,
            origin,
            epoch,
            answer,
            abandoned,
            declined,
        } = done;
        let answer = match answer {
            Answer::Passkey(answer) => {
                if declined && !abandoned {
                    self.limit(|limits| limits.cancelled(&origin, Instant::now()));
                }
                if answer.is_ok() {
                    self.host.note_activity();
                }
                return self
                    .respond(id, answer.map(|credential| PasskeyResult { credential }))
                    .await;
            }
            Answer::Fill(answer) => answer,
        };
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
        // A page opening is not the user using the vault: it must not postpone the auto-lock.
        if filled.via != Via::Auto {
            self.host.note_activity();
        }
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

    async fn respond<T: Serialize>(
        &self,
        id: u64,
        result: Result<T, ErrorCode>,
    ) -> Result<(), Closed> {
        let bytes = match result {
            Ok(result) => wiped_json(&Success {
                id,
                ok: true,
                result,
            }),
            Err(error) => wiped_json(&Failure {
                id,
                ok: false,
                error,
            }),
        }
        .ok_or(Closed)?;
        self.outgoing.send(bytes).await.map_err(|_| Closed)
    }
}

/// Measures first, then serialises straight into a wiped buffer of exactly that size, so a
/// password never sits in an intermediate tree or a reallocated, unwiped prefix.
fn wiped_json<V: Serialize>(value: &V) -> Option<Zeroizing<Vec<u8>>> {
    let mut length = ByteCount(0);
    serde_json::to_writer(&mut length, value).ok()?;
    if length.0 > RESPONSE_CAPACITY {
        tracing::warn!(
            length = length.0,
            "browser response exceeds the frame limit"
        );
        return None;
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length.0));
    serde_json::to_writer(&mut *bytes, value).ok()?;
    Some(bytes)
}

struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
pub(super) fn canonical_origin(origin: &str) -> String {
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
    auto: bool,
    fields: FillFields,
    epoch: u64,
    remembered: Option<ItemId>,
    persisted: Option<ItemId>,
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
        auto,
        fields,
        epoch,
        remembered,
        persisted,
        browser,
        kind,
        completions,
    } = task;
    let (cancel, cancelled) = oneshot::channel::<()>();
    let fills = Arc::clone(fills);
    let host = Arc::clone(host);
    let task = tokio::spawn(async move {
        let (answer, abandoned) = tokio::select! {
            done = run_fill(&*fills, &host, FillInput { browser, kind, origin, path, choose, auto, fields, remembered, persisted }) => done,
            _ = cancelled => return,
        };
        let _ = completions
            .send(Completion {
                id,
                origin: key,
                epoch,
                answer: Answer::Fill(answer),
                abandoned,
                declined: false,
            })
            .await;
    });
    InFlight {
        id,
        passkey_origin: None,
        commit: None,
        _cancel: cancel,
        task,
    }
}

struct PasskeyTask {
    id: u64,
    key: String,
    epoch: u64,
    ceremony: PasskeyCeremony,
    origin: String,
    options: serde_json::Value,
    browser: &'static str,
    kind: KnownBrowser,
    completions: mpsc::Sender<Completion>,
}

fn spawn_passkey<H: BrowserHost + 'static, F: FillFlow + 'static>(
    fills: &Arc<F>,
    host: &Arc<H>,
    task: PasskeyTask,
) -> InFlight {
    let id = task.id;
    let passkey_origin = Some(task.key.clone());
    let (cancel, cancelled) = oneshot::channel::<()>();
    let fills = Arc::clone(fills);
    let host = Arc::clone(host);
    let commit = Arc::new(Commit::default());
    let gate = Arc::clone(&commit);
    let handle = tokio::spawn(async move {
        let abandoned = Arc::new(AtomicBool::new(false));
        let declined = Arc::new(AtomicBool::new(false));
        let answer = {
            let run = run_passkey(&*fills, &host, &task, &gate, &abandoned, &declined);
            tokio::pin!(run);
            tokio::select! {
                answer = &mut run => answer,
                _ = cancelled => {
                    if gate.cancel() {
                        return;
                    }
                    run.await
                }
            }
        };
        let _ = task
            .completions
            .send(Completion {
                id: task.id,
                origin: task.key,
                epoch: task.epoch,
                answer: Answer::Passkey(answer),
                abandoned: abandoned.load(Ordering::SeqCst),
                declined: declined.load(Ordering::SeqCst),
            })
            .await;
    });
    InFlight {
        id,
        passkey_origin,
        commit: Some(commit),
        _cancel: cancel,
        task: handle,
    }
}

async fn run_passkey<H: BrowserHost, F: FillFlow>(
    fills: &F,
    host: &Arc<H>,
    task: &PasskeyTask,
    commit: &Commit,
    abandoned: &Arc<AtomicBool>,
    declined: &Arc<AtomicBool>,
) -> Result<serde_json::Value, ErrorCode> {
    // Unlike a fill, a page asks for passkeys on its own, often for a security key the vault
    // does not hold; waiting for an unlock would hold up the browser's dialog for every site.
    if host.status().0 != State::Unlocked {
        return Err(ErrorCode::Fallback);
    }
    let return_to = host.return_to().await;
    let reason = format!("use a passkey in {}", task.browser);
    let kind = task.kind;
    fills
        .passkey(
            PasskeyRequest {
                browser: task.browser.to_owned(),
                ceremony: task.ceremony,
                origin: task.origin.clone(),
                options: task.options.clone(),
                default_match: host.default_match(),
                return_to,
            },
            |prompt| async {
                match host.prompt(prompt).await {
                    BrowserReply::Abandoned => {
                        abandoned.store(true, Ordering::SeqCst);
                        declined.store(true, Ordering::SeqCst);
                        BrowserReply::Dismissed
                    }
                    BrowserReply::Dismissed => {
                        declined.store(true, Ordering::SeqCst);
                        BrowserReply::Dismissed
                    }
                    reply => reply,
                }
            },
            || host.presence(&reason),
            // The last check before the vault is touched; past it a cancel no longer applies.
            || async move { host.enabled(kind) && commit.begin_write() },
        )
        .await
}

struct FillInput {
    browser: &'static str,
    kind: KnownBrowser,
    origin: String,
    path: String,
    choose: bool,
    auto: bool,
    fields: FillFields,
    remembered: Option<ItemId>,
    /// The choice that outlives a lock, unlike the connection's approval in `remembered`.
    persisted: Option<ItemId>,
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
    if input.auto {
        return run_auto(fills, host, input).await;
    }
    let return_to = host.return_to().await;
    let mut input = input;
    if host.status().0 == State::Locked {
        // The approvals epoch moves a moment after the lock, so a remembered approval read
        // before it must not survive a lock seen here; the persisted choice does.
        input.remembered = input.persisted.take();
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
        ..
    } = input;
    let touch_id = host.browser_touch_id();
    let fill_single = host.browser_fill_single();
    let reason = format!("fill a login in {browser}");
    fills
        .run(
            FillRequest {
                browser: browser.to_owned(),
                choose,
                auto: false,
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

/// The vault is read only if it is unlocked right now. The prompt, presence and return-to hooks
/// are inert, so no flow can show a window, ask Touch ID or wait for an unlock from here; any
/// failure is the quiet `no_auto`.
async fn run_auto<H: BrowserHost, F: FillFlow>(
    fills: &F,
    host: &Arc<H>,
    input: FillInput,
) -> Result<Filled, ErrorCode> {
    if host.status().0 != State::Unlocked {
        return Err(ErrorCode::NoAuto);
    }
    let FillInput {
        browser,
        kind,
        origin,
        path,
        fields,
        remembered,
        ..
    } = input;
    fills
        .run(
            FillRequest {
                browser: browser.to_owned(),
                choose: false,
                auto: true,
                fill_single: false,
                remembered,
                origin,
                path,
                fields,
                default_match: host.default_match(),
                touch_id: host.browser_touch_id(),
                return_to: None,
            },
            |_| async { BrowserReply::Dismissed },
            || async { false },
            || async { host.enabled(kind) && host.browser_autofill() },
        )
        .await
        .map_err(|_| ErrorCode::NoAuto)
}

const fn id_of(request: &Request) -> u64 {
    match request {
        Request::Hello { id, .. }
        | Request::Prove { id, .. }
        | Request::Status { id }
        | Request::Fill { id, .. }
        | Request::SaveCandidate { id, .. }
        | Request::GeneratePassword { id, .. }
        | Request::Unlock { id }
        | Request::OpenApp { id, .. }
        | Request::PasskeyCreate { id, .. }
        | Request::PasskeyGet { id, .. }
        | Request::PasskeyCancel { id, .. } => *id,
    }
}
