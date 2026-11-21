//! The GNOME and KDE route: `NotifyKeyboardKeysym` on a RemoteDesktop portal session whose
//! keyboard grant is persisted (`ExplicitlyRevoked` plus a restore token), so the user is asked
//! once. The flow mirrors the clipboard link in `os::linux::clipboard_portal`, but the session is
//! its own, opened per typing job and closed afterwards: a keyboard-control session has no
//! business staying open between jobs.
//!
//! The desktop types a keysym only when the active layout has it, so the text is checked against
//! the session's keymap first ([`typeable`]) and nothing is typed when a character would be lost.
//!
//! The work runs on a small runtime of its own. The typing thread is a plain thread that blocks
//! on it, so no tokio worker of another runtime ever waits.

use std::{
    future::Future,
    sync::{
        Mutex, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use ashpd::desktop::{
    PersistMode, ResponseError, Session,
    remote_desktop::{
        DeviceType, KeyState, NotifyKeyboardKeysymOptions, RemoteDesktop, SelectDevicesOptions,
        StartOptions,
    },
    settings::Settings,
};
use tokio::runtime::Runtime;

use super::{
    FOCUS_SETTLE, Failure, PACE,
    typeable::{self, Refusal, Seen, Verdict},
};
use crate::os::linux::{portal::ensure_registered, portal_token::TokenStore};

/// The first use waits for the user to answer the permission dialog.
const DIALOG_TIMEOUT: Duration = Duration::from_secs(180);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// After a dismissed dialog, the next jobs stop at once instead of showing it again.
const RETRY_AFTER_DISMISSAL: Duration = Duration::from_secs(300);
/// GNOME's "switch input sources individually for each window".
const INPUT_SOURCES: &str = "org.gnome.desktop.input-sources";
const PER_WINDOW: &str = "per-window";

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static DISMISSED_AT: Mutex<Option<Instant>> = Mutex::new(None);

fn runtime() -> Result<&'static Runtime, Failure> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let built = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("vaultkeeper-autotype-rt")
        .enable_all()
        .build()
        .map_err(|error| Failure::Stopped(format!("cannot start the portal runtime ({error})")))?;
    Ok(RUNTIME.get_or_init(|| built))
}

/// Types `keysyms` through the portal; blocks, so it runs on the typing thread.
pub(super) fn type_keysyms(
    tokens: &TokenStore,
    keysyms: &[u32],
    keyboard: Result<&Seen, &str>,
    cancel: &AtomicBool,
) -> Result<(), Failure> {
    runtime()?.block_on(async {
        if tokio::time::timeout(CALL_TIMEOUT, ensure_registered())
            .await
            .is_err()
        {
            tracing::warn!("registering with the portal timed out");
        }
        type_through_portal(tokens, keysyms, keyboard, cancel).await
    })
}

async fn type_through_portal(
    tokens: &TokenStore,
    keysyms: &[u32],
    keyboard: Result<&Seen, &str>,
    cancel: &AtomicBool,
) -> Result<(), Failure> {
    if dismissed_recently() {
        return Err(Failure::Dismissed);
    }
    let remote = match tokio::time::timeout(CALL_TIMEOUT, RemoteDesktop::new()).await {
        Ok(Ok(remote)) => remote,
        Ok(Err(error)) => {
            return Err(Failure::Unavailable(format!(
                "no RemoteDesktop portal ({error})"
            )));
        }
        Err(_) => {
            return Err(Failure::Stopped(
                "the RemoteDesktop portal did not answer in time".to_owned(),
            ));
        }
    };
    let offered = bounded(
        CALL_TIMEOUT,
        remote.available_device_types(),
        "AvailableDeviceTypes",
    )
    .await
    .map_err(|failure| Failure::Unavailable(failure.reason()))?;
    if !offered.contains(DeviceType::KEYBOARD) {
        return Err(Failure::Unavailable(
            "the RemoteDesktop portal offers no keyboard".to_owned(),
        ));
    }
    // Before the permission dialog and the first key: a refused text types nothing at all, so
    // the next link of the chain may still type it.
    let keysyms = match typeable::examine(keyboard, keysyms) {
        Verdict::TypeUnlessLayoutPerWindow(_) if layout_per_window().await => {
            return Err(refused(&Refusal::LayoutPerWindow));
        }
        Verdict::Type(keysyms) | Verdict::TypeUnlessLayoutPerWindow(keysyms) => keysyms,
        Verdict::Refuse(refusal) => return Err(refused(&refusal)),
    };
    let (session, interactive) = open(&remote, tokens).await.inspect_err(|failure| {
        if matches!(failure, Failure::Dismissed) {
            *DISMISSED_AT.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        }
    })?;
    if interactive {
        // The permission dialog had the focus; give it back to the target window first.
        tokio::time::sleep(FOCUS_SETTLE).await;
    }
    let typed = press_all(&remote, &session, &keysyms, cancel).await;
    if let Err(error) = session.close().await {
        tracing::debug!(%error, "closing the auto-type portal session failed");
    }
    typed
}

fn refused(refusal: &Refusal) -> Failure {
    super::refusal_failure(refusal)
}

/// Whether the target window may have another layout than the Quick Panel had. Desktops without
/// the GNOME setting answer with an error, which reads as "no".
async fn layout_per_window() -> bool {
    let read = async {
        Settings::new()
            .await?
            .read::<bool>(INPUT_SOURCES, PER_WINDOW)
            .await
    };
    match tokio::time::timeout(CALL_TIMEOUT, read).await {
        Ok(Ok(per_window)) => per_window,
        Ok(Err(error)) => {
            tracing::debug!(%error, "no per-window layout setting");
            false
        }
        Err(_) => {
            tracing::debug!("reading the per-window layout setting timed out");
            false
        }
    }
}

fn dismissed_recently() -> bool {
    DISMISSED_AT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some_and(|at| at.elapsed() < RETRY_AFTER_DISMISSAL)
}

/// A started session with keyboard access, and whether the user had to answer a dialog for it.
/// A stored grant the portal no longer accepts is dropped and asked for again, but a dismissed
/// dialog is final.
async fn open(
    remote: &RemoteDesktop,
    tokens: &TokenStore,
) -> Result<(Session<RemoteDesktop>, bool), Failure> {
    if let Some(stored) = tokens.load() {
        match establish(remote, Some(&stored)).await {
            Ok(established) => return Ok((keep(tokens, established), false)),
            Err(Failure::Dismissed) => return Err(Failure::Dismissed),
            Err(failure) => {
                tracing::info!(reason = %failure.reason(), "stored auto-type grant not accepted; asking again");
                tokens.forget();
            }
        }
    }
    establish(remote, None)
        .await
        .map(|established| (keep(tokens, established), true))
}

fn keep(
    tokens: &TokenStore,
    (session, token): (Session<RemoteDesktop>, Option<String>),
) -> Session<RemoteDesktop> {
    if let Some(token) = token {
        tokens.save(&token);
    }
    session
}

#[allow(
    clippy::default_trait_access,
    reason = "ashpd keeps CreateSessionOptions out of its public paths"
)]
async fn establish(
    remote: &RemoteDesktop,
    restore_token: Option<&str>,
) -> Result<(Session<RemoteDesktop>, Option<String>), Failure> {
    let session = bounded(
        CALL_TIMEOUT,
        remote.create_session(Default::default()),
        "CreateSession",
    )
    .await?;
    match start(remote, &session, restore_token).await {
        Ok(token) => Ok((session, token)),
        Err(failure) => {
            if let Err(error) = session.close().await {
                tracing::debug!(%error, "closing the failed auto-type session failed");
            }
            Err(failure)
        }
    }
}

async fn start(
    remote: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    restore_token: Option<&str>,
) -> Result<Option<String>, Failure> {
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
    let request = bounded(
        DIALOG_TIMEOUT,
        remote.start(session, None, StartOptions::default()),
        "Start",
    )
    .await?;
    let selected = request.response().map_err(|error| match error {
        ashpd::Error::Response(ResponseError::Cancelled) => Failure::Dismissed,
        other => Failure::Stopped(format!("the keyboard permission was not granted ({other})")),
    })?;
    if !selected.devices().contains(DeviceType::KEYBOARD) {
        return Err(Failure::Stopped(
            "the session was started without keyboard access".to_owned(),
        ));
    }
    Ok(selected.restore_token().map(ToOwned::to_owned))
}

async fn press_all(
    remote: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    keysyms: &[u32],
    cancel: &AtomicBool,
) -> Result<(), Failure> {
    for keysym in keysyms {
        if cancel.load(Ordering::Relaxed) {
            return Err(Failure::Cancelled);
        }
        let keysym = i32::try_from(*keysym)
            .map_err(|_| Failure::Stopped("a keysym is out of range".to_owned()))?;
        if let Err(failure) = notify(remote, session, keysym, KeyState::Pressed).await {
            // A press that timed out may still have gone through; a stuck key is worse than a
            // second release.
            drop(notify(remote, session, keysym, KeyState::Released).await);
            return Err(failure);
        }
        notify(remote, session, keysym, KeyState::Released).await?;
        tokio::time::sleep(PACE).await;
    }
    Ok(())
}

async fn notify(
    remote: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    keysym: i32,
    state: KeyState,
) -> Result<(), Failure> {
    bounded(
        CALL_TIMEOUT,
        remote.notify_keyboard_keysym(
            session,
            keysym,
            state,
            NotifyKeyboardKeysymOptions::default(),
        ),
        "NotifyKeyboardKeysym",
    )
    .await
}

async fn bounded<T>(
    limit: Duration,
    call: impl Future<Output = Result<T, ashpd::Error>>,
    what: &str,
) -> Result<T, Failure> {
    match tokio::time::timeout(limit, call).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(Failure::Stopped(format!("{what} failed ({error})"))),
        Err(_) => Err(Failure::Stopped(format!("{what} did not answer in time"))),
    }
}
