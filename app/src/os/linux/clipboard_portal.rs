//! The GNOME clipboard link (clipboard chain, link 2): the RemoteDesktop portal with its Clipboard
//! extension. GNOME offers no data-control protocol, so the app owns a RemoteDesktop session whose
//! only use is `SetSelection`, and serves the text itself when a paste asks for it.
//!
//! The flow (CreateSession, SelectDevices with a persisted grant, RequestClipboard before Start,
//! SelectionTransfer answered through SelectionWrite) follows Bitwarden's
//! `desktop_native/core/src/clipboard/portal_backend.rs` (GPL-3.0). It differs in three ways: the
//! session stays open so a copy can be cleared later, only the keyboard device is requested, and the
//! restore token lives in the data directory with mode 0600.
//!
//! The keyboard device stays in the request although nothing here types: GNOME's dialog enables
//! "Share" only with "Allow Remote Interaction" switched on, and xdg-desktop-portal-gnome stores
//! no restore token for a session without devices, so asking for none would bring the dialog back
//! on every start.
//!
//! One task on the daemon's runtime owns the session, so callers on any thread (the clearer,
//! blocking-pool copies) only exchange messages with it.

use std::{
    future::Future,
    path::Path,
    pin::Pin,
    sync::mpsc,
    time::{Duration, Instant},
};

use ashpd::desktop::{
    PersistMode, ResponseError, Session,
    clipboard::{Clipboard, RequestClipboardOptions, SelectionOwnerChanged, SetSelectionOptions},
    remote_desktop::{DeviceType, RemoteDesktop, SelectDevicesOptions, StartOptions},
};
use futures_util::{FutureExt as _, Stream, StreamExt as _};
use tokio::net::unix::pipe;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use vk_platform::{
    Error, Result,
    clipboard::{ClipboardBackend, PortalClipboard},
    security::Probe,
};
use zeroize::Zeroizing;

use super::{portal::ensure_registered, portal_token::TokenStore};
use crate::os::layout::CLIPBOARD_PORTAL_TOKEN_FILE;

const TEXT_MIME: &str = "text/plain;charset=utf-8";
const SECRET_HINT_MIME: &str = "x-kde-passwordManagerHint";
/// Mutter's clipboard manager copies every text or image selection and offers that copy again
/// once the owner is gone, so releasing the secret alone brings it back. A selection of a type it
/// does not keep makes it drop its copy first.
const CLEARED_MIME: &str = "application/x-vaultkeeper-cleared";
/// RemoteDesktop gained the clipboard in version 2.
const MIN_PORTAL_VERSION: u32 = 2;
/// Told apart from other failures: a dismissed dialog must not be followed by a second one.
const DIALOG_DISMISSED: &str = "the clipboard permission dialog was dismissed";
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);
/// What the secret hint carries; only its presence matters to history managers.
const SECRET_HINT_VALUE: &[u8] = b"secret";
/// A first copy waits for the user to answer the permission dialog, plus the bounded calls
/// around it.
const SET_TIMEOUT: Duration = Duration::from_secs(240);
const DIALOG_TIMEOUT: Duration = Duration::from_secs(180);
/// Every portal call except `Start`, which waits on the dialog; a stuck portal must not wedge the
/// single worker.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const QUICK_TIMEOUT: Duration = Duration::from_secs(5);
/// What a caller waits for a clear. The worst case inside is 5.25 s (two SetSelection calls, the
/// confirmation and its settle time, SelectionRead and the read), and a lock-time clear holds the
/// clipboard state for as long, so the parts are kept short.
const CLEAR_TIMEOUT: Duration = Duration::from_secs(8);
const CLEAR_CALL_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the owner change that follows a release may take to arrive.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(1);
/// A copy put back by the desktop is announced right after the release; this covers the gap.
const CONFIRM_SETTLE: Duration = Duration::from_millis(250);
/// After a refused or failed grant, copies go to the next link instead of asking again.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(300);

type Reply<T> = mpsc::SyncSender<T>;
type Transfers<'a> = Pin<Box<dyn Stream<Item = (Session<RemoteDesktop>, String, u32)> + Send + 'a>>;
type Owners<'a> = Pin<Box<dyn Stream<Item = OwnerChange> + Send + 'a>>;

/// What the desktop said about a new clipboard owner; a released clipboard has no types.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerChange {
    mime_types: Vec<String>,
    ours: Option<bool>,
}

impl From<SelectionOwnerChanged> for OwnerChange {
    fn from(change: SelectionOwnerChanged) -> Self {
        Self {
            mime_types: change.mime_types().to_vec(),
            ours: change.session_is_owner(),
        }
    }
}

enum Command {
    Set(Zeroizing<String>, Reply<std::result::Result<(), String>>),
    Read(Reply<Option<Zeroizing<String>>>),
    Clear(Reply<std::result::Result<(), String>>),
}

/// The handle `vk-platform`'s chain holds.
pub struct PortalLink {
    commands: UnboundedSender<Command>,
}

/// Starts the worker as a task on the current tokio runtime; `None` outside one. The portal is
/// reported as available without asking: activating it can take longer than startup may wait, so
/// the first copy decides and a failure there moves the chain on.
#[must_use]
pub fn spawn(data_dir: &Path) -> Option<Box<dyn PortalClipboard>> {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            "no tokio runtime for the clipboard portal; GNOME copies use the plain link"
        );
        return None;
    };
    let (commands, receiver) = unbounded_channel();
    let token = TokenStore::new(data_dir.join(CLIPBOARD_PORTAL_TOKEN_FILE));
    runtime.spawn(async move {
        // The first portal caller's runtime also hosts ashpd's connection and the registry
        // watcher, so this runs on the daemon's runtime and not on a private one.
        register().await;
        Worker::new(token).serve(receiver).await;
    });
    Some(Box::new(PortalLink { commands }))
}

impl PortalLink {
    fn ask<T>(&self, timeout: Duration, build: impl FnOnce(Reply<T>) -> Command) -> Result<T> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.commands
            .send(build(reply))
            .map_err(|_| Error::Clipboard("the clipboard portal worker stopped".into()))?;
        // From a runtime worker (lock-time clears) the wait must hand the worker over: the portal
        // task may sit in this very worker's run queue, where no other worker can take it.
        let wait = || {
            answer
                .recv_timeout(timeout)
                .map_err(|_| Error::Clipboard("the clipboard portal did not answer".into()))
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime)
                if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
            {
                tokio::task::block_in_place(wait)
            }
            _ => wait(),
        }
    }
}

impl ClipboardBackend for PortalLink {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        let text = Zeroizing::new(text.to_owned());
        self.ask(SET_TIMEOUT, |reply| Command::Set(text, reply))?
            .map_err(Error::Clipboard)
    }

    fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
        self.ask(QUICK_TIMEOUT, Command::Read)
    }

    fn clear(&mut self) -> Result<()> {
        self.ask(CLEAR_TIMEOUT, Command::Clear)?
            .map_err(Error::Clipboard)
    }
}

impl PortalClipboard for PortalLink {
    fn availability(&self) -> Probe {
        Probe::Degraded("not verified until the first copy".into())
    }
}

/// A started RemoteDesktop session with clipboard access.
struct Open {
    clipboard: Clipboard,
    session: Session<RemoteDesktop>,
}

/// What `handle` leaves for the session loop to do next.
enum Flow {
    Continue,
    /// The session ends without a retry.
    Close,
    /// The session is closed and this copy should go through a fresh one.
    Retry(Zeroizing<String>, Reply<std::result::Result<(), String>>),
}

/// How a session ended.
enum Ended {
    Idle,
    Stopped,
    Retry(Zeroizing<String>, Reply<std::result::Result<(), String>>),
}

enum Event {
    Transfer(String, u32),
    Owner(Option<bool>),
}

struct Worker {
    token: TokenStore,
    text: Option<Zeroizing<String>>,
    owned: bool,
    no_retry_before: Option<Instant>,
}

impl Worker {
    const fn new(token: TokenStore) -> Self {
        Self {
            token,
            text: None,
            owned: false,
            no_retry_before: None,
        }
    }

    /// Idle until a copy arrives; the session lives only as long as `serve_session` runs.
    async fn serve(mut self, mut commands: UnboundedReceiver<Command>) {
        while let Some(command) = commands.recv().await {
            let (mut text, mut reply) = match command {
                Command::Read(reply) => {
                    drop(reply.send(None));
                    continue;
                }
                Command::Clear(reply) => {
                    drop(reply.send(Ok(())));
                    continue;
                }
                Command::Set(text, reply) => (text, reply),
            };
            loop {
                match self.serve_session(text, reply, &mut commands).await {
                    Ended::Idle => break,
                    Ended::Stopped => return,
                    Ended::Retry(retry_text, retry_reply) => {
                        text = retry_text;
                        reply = retry_reply;
                    }
                }
            }
        }
    }

    async fn serve_session(
        &mut self,
        text: Zeroizing<String>,
        reply: Reply<std::result::Result<(), String>>,
        commands: &mut UnboundedReceiver<Command>,
    ) -> Ended {
        let open = match self.open_for_copy().await {
            Ok(open) => open,
            Err(error) => {
                drop(reply.send(Err(error)));
                return Ended::Idle;
            }
        };
        // Subscribed before the first SetSelection so no transfer request is missed.
        let (mut transfers, mut owners) = match subscribe(&open.clipboard).await {
            Ok(streams) => streams,
            Err(error) => {
                self.fail(&open, &error).await;
                drop(reply.send(Err(error)));
                return Ended::Idle;
            }
        };
        if let Err(error) = self.set_selection(&open, text, &mut owners).await {
            self.fail(&open, &error).await;
            drop(reply.send(Err(error)));
            return Ended::Idle;
        }
        if reply.send(Ok(())).is_err() {
            // The caller gave up while the permission dialog was open and the chain moved on to
            // another link, so nothing would ever clear this selection.
            tracing::info!("clipboard portal copy abandoned by its caller; releasing it");
            self.end_session(&open, true, &mut owners).await;
            return Ended::Idle;
        }
        let mut open_channel = true;
        let mut usable = true;
        let mut retry = None;
        while open_channel {
            let event = tokio::select! {
                // Owner changes first: a command must not act on ownership that a queued
                // change already ended.
                biased;
                Some(change) = owners.next() => Event::Owner(change.ours),
                Some((_, mime, serial)) = transfers.next() => Event::Transfer(mime, serial),
                command = commands.recv() => {
                    match command {
                        None => open_channel = false,
                        Some(command) => match self.handle(&open, command, &mut owners).await {
                            Flow::Continue => {}
                            Flow::Close => break,
                            Flow::Retry(text, reply) => {
                                usable = false;
                                retry = Some((text, reply));
                                break;
                            }
                        },
                    }
                    continue;
                }
                else => break,
            };
            match event {
                Event::Transfer(mime, serial) => self.answer_transfer(&open, &mime, serial).await,
                Event::Owner(Some(owned)) => self.ownership_changed(owned),
                // Unknown ownership stays as it was, so a clear still removes our secret.
                Event::Owner(None) => tracing::debug!("portal owner change without ownership"),
            }
        }
        self.end_session(&open, usable, &mut owners).await;
        match retry {
            Some((text, reply)) => Ended::Retry(text, reply),
            None if open_channel => Ended::Idle,
            None => Ended::Stopped,
        }
    }

    /// While the session is usable, removes the selection if it is still ours (never another
    /// app's copy) and closes the session.
    async fn end_session(&mut self, open: &Open, usable: bool, owners: &mut Owners<'_>) {
        if !usable {
            self.text = None;
            self.owned = false;
            return;
        }
        // Closing a session that still owns the text would leave the desktop's copy of it behind.
        if let Err(error) = self.clear(open, owners).await {
            tracing::warn!(%error, "could not clear the portal clipboard before closing");
        }
        close(open).await;
    }

    /// Removes our selection so that nothing offers the text any more, and says so only once the
    /// desktop confirmed it. Nothing to do when the selection is no longer ours.
    async fn clear(
        &mut self,
        open: &Open,
        owners: &mut Owners<'_>,
    ) -> std::result::Result<(), String> {
        let owned = self.owned;
        self.owned = false;
        let Some(text) = self.text.take().filter(|_| owned) else {
            return Ok(());
        };
        // SetSelection takes the clipboard whoever owns it. A copy made in another app whose
        // owner change has not reached us yet (two D-Bus hops behind the compositor) is still
        // replaced; that window cannot be closed from here.
        if another_app_took_over(owners) {
            tracing::debug!("another app owns the clipboard; nothing of ours to clear");
            return Ok(());
        }
        set_selection(open, &[CLEARED_MIME]).await?;
        set_selection(open, &[]).await?;
        confirm_cleared(open, &text, owners).await
    }

    async fn handle(&mut self, open: &Open, command: Command, owners: &mut Owners<'_>) -> Flow {
        match command {
            Command::Read(reply) => {
                drop(reply.send(self.text.clone().filter(|_| self.owned)));
                Flow::Continue
            }
            Command::Clear(reply) => {
                drop(reply.send(self.clear(open, owners).await));
                Flow::Continue
            }
            Command::Set(text, reply) => {
                let Err(error) = self.set_selection(open, text, owners).await else {
                    drop(reply.send(Ok(())));
                    return Flow::Continue;
                };
                // The portal or compositor may have ended the session (revoked permission, portal
                // restart) without telling us; one fresh session tells that apart from a real
                // failure before the chain is told to avoid this link for minutes.
                let Some(text) = self.text.take() else {
                    self.fail(open, &error).await;
                    drop(reply.send(Err(error)));
                    return Flow::Close;
                };
                tracing::info!(%error, "clipboard portal session no longer accepts copies; reopening");
                self.owned = false;
                close(open).await;
                Flow::Retry(text, reply)
            }
        }
    }

    async fn open_for_copy(&mut self) -> std::result::Result<Open, String> {
        if self
            .no_retry_before
            .is_some_and(|until| until > Instant::now())
        {
            return Err("the clipboard portal permission was refused recently".to_owned());
        }
        let opened = self.open().await;
        if let Err(error) = &opened {
            tracing::warn!(%error, "clipboard portal session failed");
            self.no_retry_before = Some(Instant::now() + RETRY_AFTER_FAILURE);
        }
        opened
    }

    async fn fail(&mut self, open: &Open, error: &str) {
        tracing::warn!(%error, "clipboard portal copy failed");
        self.no_retry_before = Some(Instant::now() + RETRY_AFTER_FAILURE);
        self.text = None;
        self.owned = false;
        close(open).await;
    }

    async fn set_selection(
        &mut self,
        open: &Open,
        text: Zeroizing<String>,
        owners: &mut Owners<'_>,
    ) -> std::result::Result<(), String> {
        // Owner changes still queued from before this copy would read as "someone else copied".
        while owners.next().now_or_never().flatten().is_some() {}
        // The text is held first: a paste can arrive before SetSelection returns.
        self.text = Some(text);
        bounded(
            CALL_TIMEOUT,
            open.clipboard.set_selection(
                &open.session,
                SetSelectionOptions::default().set_mime_types(&[TEXT_MIME, SECRET_HINT_MIME]),
            ),
            "SetSelection",
        )
        .await?;
        tracing::debug!("copied through the clipboard portal");
        self.owned = true;
        self.no_retry_before = None;
        Ok(())
    }

    /// Once another app owns the clipboard nothing reads or clears our copy again, so the text
    /// would otherwise stay in memory until the next copy.
    fn ownership_changed(&mut self, owned: bool) {
        self.owned = self.text.is_some() && owned;
        if !owned {
            self.text = None;
        }
    }

    async fn answer_transfer(&self, open: &Open, mime: &str, serial: u32) {
        let served = match (self.text.as_ref(), mime) {
            (Some(text), TEXT_MIME) => write_transfer(open, serial, text.as_bytes()).await,
            (Some(_), SECRET_HINT_MIME) => write_transfer(open, serial, SECRET_HINT_VALUE).await,
            _ => Err("nothing to offer for that type".to_owned()),
        };
        let ok = served.is_ok();
        if let Err(error) = &served {
            tracing::debug!(%error, "clipboard transfer refused");
        }
        if let Err(error) = bounded(
            CALL_TIMEOUT,
            open.clipboard
                .selection_write_done(&open.session, serial, ok),
            "SelectionWriteDone",
        )
        .await
        {
            tracing::warn!(%error, "could not finish a clipboard transfer");
        }
    }

    async fn open(&self) -> std::result::Result<Open, String> {
        register().await;
        let remote = tokio::time::timeout(CALL_TIMEOUT, RemoteDesktop::new())
            .await
            .map_err(|_| "the RemoteDesktop portal did not answer in time".to_owned())?
            .map_err(|error| format!("no RemoteDesktop portal: {error}"))?;
        if remote.version() < MIN_PORTAL_VERSION {
            return Err(format!(
                "RemoteDesktop portal version {} has no clipboard support",
                remote.version()
            ));
        }
        let clipboard = bounded(CALL_TIMEOUT, Clipboard::new(), "Clipboard portal").await?;
        let restored = match self.token.load() {
            Some(token) => match establish(&remote, &clipboard, Some(&token)).await {
                Ok(established) => Some(established),
                Err(error) if error == DIALOG_DISMISSED => return Err(error),
                Err(error) => {
                    tracing::info!(%error, "stored clipboard grant not accepted; asking again");
                    self.token.forget();
                    None
                }
            },
            None => None,
        };
        let (session, token) = match restored {
            Some(established) => established,
            None => establish(&remote, &clipboard, None).await?,
        };
        if let Some(token) = token {
            self.token.save(&token);
        }
        Ok(Open { clipboard, session })
    }
}

async fn register() {
    if tokio::time::timeout(CALL_TIMEOUT, ensure_registered())
        .await
        .is_err()
    {
        tracing::warn!("registering with the portal timed out");
    }
}

async fn bounded<T>(
    limit: Duration,
    call: impl Future<Output = std::result::Result<T, ashpd::Error>>,
    what: &str,
) -> std::result::Result<T, String> {
    match tokio::time::timeout(limit, call).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{what} failed: {error}")),
        Err(_) => Err(format!("{what} did not answer in time")),
    }
}

async fn subscribe(
    clipboard: &Clipboard,
) -> std::result::Result<(Transfers<'_>, Owners<'_>), String> {
    let transfers = bounded(
        CALL_TIMEOUT,
        clipboard.receive_selection_transfer::<RemoteDesktop>(),
        "SelectionTransfer subscription",
    )
    .await?;
    let owners = bounded(
        CALL_TIMEOUT,
        clipboard.receive_selection_owner_changed::<RemoteDesktop>(),
        "SelectionOwnerChanged subscription",
    )
    .await?;
    let owners = owners.map(|(_, change)| OwnerChange::from(change));
    Ok((Box::pin(transfers), Box::pin(owners)))
}

/// No types releases the selection.
async fn set_selection(open: &Open, mime_types: &[&str]) -> std::result::Result<(), String> {
    bounded(
        CLEAR_CALL_TIMEOUT,
        open.clipboard.set_selection(
            &open.session,
            SetSelectionOptions::default().set_mime_types(mime_types),
        ),
        "SetSelection",
    )
    .await
}

/// Empties the queue of owner changes and tells whether one of them names another owner.
fn another_app_took_over(owners: &mut Owners<'_>) -> bool {
    let mut taken = false;
    while let Some(change) = owners.next().now_or_never().flatten() {
        taken |= change.ours == Some(false);
    }
    taken
}

/// The last owner change after our release, once `settle` passed without another; `None` when
/// the desktop said nothing within `limit`.
async fn change_after_release(
    owners: &mut Owners<'_>,
    limit: Duration,
    settle: Duration,
) -> Option<OwnerChange> {
    let mut after_release = None;
    let mut wait = limit;
    while let Ok(Some(change)) = tokio::time::timeout(wait, owners.next()).await {
        // Our own placeholder selection is announced first.
        if change.ours != Some(true) {
            after_release = Some(change);
            wait = settle;
        }
    }
    after_release
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Cleared,
    Unconfirmed,
    /// Something offers text again; only reading that type tells whether it is ours.
    ReadBack(String),
}

/// An empty clipboard is the proof. An owner without a text type cannot be yielding our text.
fn verdict(after_release: Option<&OwnerChange>) -> Verdict {
    let Some(change) = after_release else {
        return Verdict::Unconfirmed;
    };
    change
        .mime_types
        .iter()
        .find(|mime| mime.starts_with("text/plain"))
        .map_or(Verdict::Cleared, |mime| Verdict::ReadBack(mime.clone()))
}

fn judge_read_back(offered: &[u8], text: &str) -> std::result::Result<(), String> {
    if offered == text.as_bytes() {
        return Err("the desktop still offers the copied text after the clear".to_owned());
    }
    Ok(())
}

async fn confirm_cleared(
    open: &Open,
    text: &str,
    owners: &mut Owners<'_>,
) -> std::result::Result<(), String> {
    let after_release = change_after_release(owners, CONFIRM_TIMEOUT, CONFIRM_SETTLE).await;
    tracing::debug!(left = ?after_release, "clipboard after the clear");
    match verdict(after_release.as_ref()) {
        Verdict::Cleared => Ok(()),
        Verdict::Unconfirmed => {
            Err("the desktop did not confirm that the clipboard was cleared".to_owned())
        }
        Verdict::ReadBack(mime) => {
            let offered = read_selection(open, &mime, text.len()).await?;
            judge_read_back(&offered, text)
        }
    }
}

/// At most one byte more than `limit`: enough to tell whether the content equals our text.
async fn read_selection(
    open: &Open,
    mime: &str,
    limit: usize,
) -> std::result::Result<Zeroizing<Vec<u8>>, String> {
    let fd = bounded(
        CLEAR_CALL_TIMEOUT,
        open.clipboard.selection_read(&open.session, mime),
        "SelectionRead",
    )
    .await?;
    let pipe = pipe::Receiver::from_owned_fd(std::os::fd::OwnedFd::from(fd))
        .map_err(|error| format!("the read fd is not a pipe: {error}"))?;
    let mut bytes = Zeroizing::new(vec![0_u8; limit.saturating_add(1)]);
    let read = tokio::time::timeout(CLEAR_CALL_TIMEOUT, read_up_to(&pipe, &mut bytes))
        .await
        .map_err(|_| "the clipboard owner did not answer in time".to_owned())?
        .map_err(|error| error.to_string())?;
    bytes.truncate(read);
    Ok(bytes)
}

async fn read_up_to(pipe: &pipe::Receiver, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        pipe.readable().await?;
        match pipe.try_read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

async fn close(open: &Open) {
    let closed = bounded(CALL_TIMEOUT, open.session.close(), "Close").await;
    if let Err(error) = closed {
        tracing::debug!(%error, "closing the clipboard portal session failed");
    }
}

#[allow(
    clippy::default_trait_access,
    reason = "ashpd keeps CreateSessionOptions out of its public paths"
)]
async fn establish(
    remote: &RemoteDesktop,
    clipboard: &Clipboard,
    restore_token: Option<&str>,
) -> std::result::Result<(Session<RemoteDesktop>, Option<String>), String> {
    let session = bounded(
        CALL_TIMEOUT,
        remote.create_session(Default::default()),
        "CreateSession",
    )
    .await?;
    match start(remote, clipboard, &session, restore_token).await {
        Ok(token) => Ok((session, token)),
        Err(error) => {
            let closed = bounded(CALL_TIMEOUT, session.close(), "Close").await;
            if let Err(close) = closed {
                tracing::debug!(error = %close, "closing the failed clipboard session failed");
            }
            Err(error)
        }
    }
}

async fn start(
    remote: &RemoteDesktop,
    clipboard: &Clipboard,
    session: &Session<RemoteDesktop>,
    restore_token: Option<&str>,
) -> std::result::Result<Option<String>, String> {
    bounded(
        CALL_TIMEOUT,
        remote.select_devices(
            session,
            SelectDevicesOptions::default()
                .set_devices(DeviceType::KEYBOARD)
                .set_persist_mode(PersistMode::ExplicitlyRevoked)
                .set_restore_token(restore_token),
        ),
        "SelectDevices",
    )
    .await?;
    // The portal rejects RequestClipboard once the session has started.
    bounded(
        CALL_TIMEOUT,
        clipboard.request(session, RequestClipboardOptions::default()),
        "RequestClipboard",
    )
    .await?;
    let selected = bounded(
        DIALOG_TIMEOUT,
        remote.start(session, None, StartOptions::default()),
        "Start",
    )
    .await?
    .response()
    .map_err(|error| match error {
        ashpd::Error::Response(ResponseError::Cancelled) => DIALOG_DISMISSED.to_owned(),
        other => format!("the permission was not granted: {other}"),
    })?;
    if !selected.is_clipboard_enabled() {
        return Err("the session was started without clipboard access".to_owned());
    }
    Ok(selected.restore_token().map(ToOwned::to_owned))
}

async fn write_transfer(open: &Open, serial: u32, bytes: &[u8]) -> std::result::Result<(), String> {
    let fd = bounded(
        CALL_TIMEOUT,
        open.clipboard.selection_write(&open.session, serial),
        "SelectionWrite",
    )
    .await?;
    let pipe = pipe::Sender::from_owned_fd(std::os::fd::OwnedFd::from(fd))
        .map_err(|error| format!("the transfer fd is not a pipe: {error}"))?;
    // A reader that never drains the pipe must not stall the session; the bytes go straight from
    // our zeroized buffer.
    let written = tokio::time::timeout(TRANSFER_TIMEOUT, write_all(&pipe, bytes)).await;
    match written {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("the paste target did not read in time".to_owned()),
    }
}

async fn write_all(pipe: &pipe::Sender, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        pipe.writable().await?;
        match pipe.try_write(bytes) {
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(30);

    fn change(mime_types: &[&str], ours: Option<bool>) -> OwnerChange {
        OwnerChange {
            mime_types: mime_types.iter().map(|&mime| mime.to_owned()).collect(),
            ours,
        }
    }

    /// Delivers `changes` and then stays silent, as the portal's signal stream does.
    fn owners(changes: Vec<OwnerChange>) -> Owners<'static> {
        Box::pin(futures_util::stream::iter(changes).chain(futures_util::stream::pending()))
    }

    fn after_release(changes: Vec<OwnerChange>) -> Option<OwnerChange> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(change_after_release(&mut owners(changes), SHORT, SHORT))
    }

    #[test]
    fn a_copy_made_elsewhere_before_the_clear_is_left_alone() {
        let mut queued = owners(vec![
            change(&[TEXT_MIME, SECRET_HINT_MIME], Some(true)),
            change(&[TEXT_MIME], Some(false)),
        ]);
        assert!(another_app_took_over(&mut queued));
        assert!(
            queued.next().now_or_never().is_none(),
            "the queue was emptied"
        );
    }

    #[test]
    fn our_own_owner_change_does_not_stop_the_clear() {
        let mut queued = owners(vec![
            change(&[TEXT_MIME, SECRET_HINT_MIME], Some(true)),
            change(&[], None),
        ]);
        assert!(!another_app_took_over(&mut queued));
    }

    #[test]
    fn an_empty_clipboard_after_the_release_confirms_the_clear() {
        let seen = after_release(vec![change(&[CLEARED_MIME], Some(true)), change(&[], None)]);
        assert_eq!(seen, Some(change(&[], None)));
        assert_eq!(verdict(seen.as_ref()), Verdict::Cleared);
    }

    #[test]
    fn a_desktop_that_stays_silent_does_not_confirm() {
        let seen = after_release(vec![change(&[CLEARED_MIME], Some(true))]);
        assert_eq!(seen, None, "the placeholder alone proves nothing");
        assert_eq!(verdict(seen.as_ref()), Verdict::Unconfirmed);
    }

    #[test]
    fn text_offered_after_the_release_is_read_back() {
        let seen = after_release(vec![
            change(&[CLEARED_MIME], Some(true)),
            change(&[], None),
            change(&["text/html", TEXT_MIME], Some(false)),
        ]);
        assert_eq!(
            verdict(seen.as_ref()),
            Verdict::ReadBack(TEXT_MIME.to_owned())
        );
    }

    #[test]
    fn an_owner_without_text_cannot_hold_the_secret() {
        let image = change(&["image/png"], Some(false));
        assert_eq!(verdict(Some(&image)), Verdict::Cleared);
    }

    #[test]
    fn only_the_same_text_read_back_fails_the_clear() {
        assert!(judge_read_back(b"hunter2", "hunter2").is_err());
        assert!(judge_read_back(b"hello", "hunter2").is_ok());
        assert!(judge_read_back(b"hunter2\n", "hunter2").is_ok());
        assert!(judge_read_back(b"", "hunter2").is_ok());
    }

    #[test]
    fn a_copy_taken_over_by_another_app_is_dropped() {
        let mut worker = Worker::new(TokenStore::new(std::path::PathBuf::new()));
        worker.text = Some(Zeroizing::new("hunter2".to_owned()));
        worker.owned = true;
        worker.ownership_changed(true);
        assert!(
            worker.owned && worker.text.is_some(),
            "our own change keeps the copy"
        );
        worker.ownership_changed(false);
        assert!(!worker.owned);
        assert!(worker.text.is_none(), "the secret outlived the ownership");
    }

    /// One worker thread: the answering task shares it with the caller, as in the daemon.
    #[test]
    fn a_clear_issued_from_a_runtime_worker_gets_its_answer() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let cleared = runtime.block_on(async {
            tokio::spawn(async {
                let (commands, mut receiver) = unbounded_channel::<Command>();
                tokio::spawn(async move {
                    while let Some(command) = receiver.recv().await {
                        if let Command::Clear(reply) = command {
                            drop(reply.send(Ok(())));
                        }
                    }
                });
                let mut link = PortalLink { commands };
                link.clear()
            })
            .await
            .expect("task")
        });
        assert!(cleared.is_ok(), "{cleared:?}");
    }
}
