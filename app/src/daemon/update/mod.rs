//! Self-update from GitHub releases, run by the daemon.
//!
//! Sparkle is not used: the app is signed with a self-signed certificate (no Team ID), so the
//! hardened runtime's library validation would only load Sparkle.framework with validation turned
//! off, letting same-user code swap a library inside the bundle the daemon trusts by signature.
//!
//! Trust is the app's own signature: an update installs only when it satisfies the running
//! app's designated requirement (the signing certificate). With "Update automatically" on, a
//! verified update installs once the vault is locked and no window is open; off, nothing
//! touches the network until "Check for Updates…" is clicked.

mod github;
mod install;
pub mod release;

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::{Notify, watch};
use url::Url;
use vk_vault::model::SessionState;

use self::{
    github::{CheckError, GitHub},
    install::{Blocked, Installer, SwapError},
    release::{Release, Version},
};
use super::Daemon;

const FIRST_CHECK: Duration = Duration::from_secs(60);
const CHECK_EVERY: Duration = Duration::from_hours(24);
const RATE_LIMIT_BACKOFF: Duration = Duration::from_hours(1);
const TICK: Duration = Duration::from_secs(60);
/// The previous app is kept this long after a start, in case the new one fails right away.
const KEEP_PREVIOUS: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Idle,
    Checking,
    UpToDate,
    Downloading(Version),
    /// Verified and staged: installs at the next lock (automatic) or on click.
    Ready(Version),
    /// A newer release this copy cannot install itself; the click opens its page.
    Manual {
        version: Version,
        page: Url,
    },
    Failed,
}

impl Status {
    #[must_use]
    pub fn tray_label(&self) -> String {
        match self {
            Self::Idle => "Check for Updates…".to_owned(),
            Self::Checking => "Checking for Updates…".to_owned(),
            Self::UpToDate => "Vaultkeeper Is Up to Date".to_owned(),
            Self::Downloading(version) => format!("Downloading Vaultkeeper {version}…"),
            Self::Ready(version) => format!("Install Vaultkeeper {version} and Restart"),
            Self::Manual { version, .. } => format!("Download Vaultkeeper {version}…"),
            Self::Failed => "Update Failed – Try Again".to_owned(),
        }
    }

    #[must_use]
    pub const fn tray_enabled(&self) -> bool {
        !matches!(self, Self::Checking | Self::Downloading(_))
    }
}

pub struct Updater {
    github: GitHub,
    installer: Result<Installer, Blocked>,
    /// Set when macOS refused the swap: later releases only link to their page.
    swap_refused: AtomicBool,
    status: watch::Sender<Status>,
    wake: Notify,
    check_requested: AtomicBool,
    install_requested: AtomicBool,
    /// The verified update and its release page.
    staged: Mutex<Option<(Version, PathBuf, Url)>>,
}

impl Updater {
    /// `work` is an owner-only directory in the app's data directory.
    pub fn new(work: PathBuf) -> anyhow::Result<Self> {
        let installer = Installer::for_running_app(work);
        match &installer {
            // A development build run from target/ has no release to update to.
            Err(Blocked::NotBundled) => anyhow::bail!("not running from an app bundle"),
            Err(blocked) => tracing::info!(%blocked, "updates will only link to the release page"),
            Ok(_) => {}
        }
        Ok(Self {
            github: GitHub::new()?,
            installer,
            swap_refused: AtomicBool::new(false),
            status: watch::Sender::new(Status::Idle),
            wake: Notify::new(),
            check_requested: AtomicBool::new(false),
            install_requested: AtomicBool::new(false),
            staged: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }

    #[must_use]
    pub fn status(&self) -> Status {
        self.status.borrow().clone()
    }

    /// The tray item: check, install the staged update, or open the release page.
    pub fn clicked(&self) {
        match self.status() {
            Status::Checking | Status::Downloading(_) => {}
            Status::Ready(_) => {
                self.install_requested.store(true, Ordering::SeqCst);
                self.wake.notify_one();
            }
            Status::Manual { page, .. } => open_page(&page),
            Status::Idle | Status::UpToDate | Status::Failed => {
                self.check_requested.store(true, Ordering::SeqCst);
                self.wake.notify_one();
            }
        }
    }

    fn set(&self, status: Status) {
        self.status.send_replace(status);
    }

    fn staged(&self) -> Option<(Version, PathBuf, Url)> {
        self.staged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The updater's task for the daemon's lifetime.
pub async fn run(daemon: Arc<Daemon>, updater: Arc<Updater>) {
    if let Ok(installer) = &updater.installer {
        tokio::task::block_in_place(|| installer.clean(true));
    }
    let started = Instant::now();
    let mut previous_kept = true;
    let mut next_check = Instant::now() + FIRST_CHECK;
    loop {
        tokio::select! {
            () = updater.wake.notified() => {}
            () = tokio::time::sleep(TICK) => {}
        }
        if previous_kept && started.elapsed() >= KEEP_PREVIOUS {
            previous_kept = false;
            if let Ok(installer) = &updater.installer
                && updater.staged().is_none()
            {
                tokio::task::block_in_place(|| installer.clean(false));
            }
        }
        let auto = daemon.settings().auto_update;
        let manual = updater.check_requested.swap(false, Ordering::SeqCst);
        if manual || (auto && Instant::now() >= next_check) {
            next_check = Instant::now() + check(&updater, manual).await;
        }
        let Some((version, staged, page)) = updater.staged() else {
            continue;
        };
        let clicked = updater.install_requested.swap(false, Ordering::SeqCst);
        if clicked || (auto && daemon.quiet_for_update()) {
            install(&daemon, &updater, version, &staged, page);
        }
    }
}

/// One check, and a download when a newer release exists. Returns the delay to the next
/// automatic check.
async fn check(updater: &Updater, manual: bool) -> Duration {
    let before = updater.status();
    updater.set(Status::Checking);
    let release = match updater.github.latest().await {
        Ok(Some(release)) if release.version > Version::current() => release,
        Ok(_) => {
            updater.set(Status::UpToDate);
            return CHECK_EVERY;
        }
        Err(error) => {
            tracing::info!(%error, "update check failed");
            updater.set(if manual { Status::Failed } else { before });
            return match error {
                CheckError::RateLimited => RATE_LIMIT_BACKOFF,
                CheckError::Offline => TICK * 30,
                CheckError::Status(_) | CheckError::Release(_) => CHECK_EVERY,
            };
        }
    };
    match &updater.installer {
        _ if updater.swap_refused.load(Ordering::SeqCst) => updater.set(Status::Manual {
            version: release.version,
            page: release.page.clone(),
        }),
        Err(_) => updater.set(Status::Manual {
            version: release.version,
            page: release.page.clone(),
        }),
        Ok(_)
            if updater
                .staged()
                .is_some_and(|(staged, _, _)| staged == release.version) =>
        {
            updater.set(Status::Ready(release.version));
        }
        Ok(installer) => {
            // A staged older version is replaced by this one; if this one fails, nothing is staged.
            *updater
                .staged
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = None;
            updater.set(Status::Downloading(release.version));
            match download_and_stage(updater, installer, &release).await {
                Ok(staged) => {
                    tracing::info!(version = %release.version, "update ready");
                    *updater
                        .staged
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) =
                        Some((release.version, staged, release.page.clone()));
                    updater.set(Status::Ready(release.version));
                }
                Err(error) => {
                    tracing::warn!(error = format!("{error:#}"), version = %release.version, "update not staged");
                    updater.set(Status::Failed);
                }
            }
        }
    }
    CHECK_EVERY
}

async fn download_and_stage(
    updater: &Updater,
    installer: &Installer,
    release: &Release,
) -> anyhow::Result<PathBuf> {
    let zip = installer.zip_path();
    updater.github.download(release, &zip).await?;
    let version = release.version;
    // Unpacking and the signature check block; the daemon's multi-thread runtime moves other
    // tasks off this worker meanwhile.
    tokio::task::block_in_place(|| installer.stage(&zip, version))
}

/// A refused swap (macOS may protect apps in `/Applications` from other apps) is not retried:
/// this and later releases then only link to their page instead of downloading again.
fn install(daemon: &Arc<Daemon>, updater: &Updater, version: Version, staged: &Path, page: Url) {
    let Ok(installer) = &updater.installer else {
        return;
    };
    let swapped = tokio::task::block_in_place(|| installer.swap_in(staged, version));
    *updater
        .staged
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = None;
    match swapped {
        Ok(()) => {
            tracing::info!(%version, bundle = %installer.bundle().display(), "update installed; restarting");
            daemon.restart_for_update(installer.bundle().to_path_buf());
        }
        Err(SwapError::Refused(error)) => {
            tracing::error!(%error, %version, "macOS refused to replace the app");
            updater.swap_refused.store(true, Ordering::SeqCst);
            tokio::task::block_in_place(|| installer.clean(true));
            updater.set(Status::Manual { version, page });
        }
        Err(SwapError::Rejected(error)) => {
            tracing::error!(error = format!("{error:#}"), %version, "update not installed");
            tokio::task::block_in_place(|| installer.clean(true));
            updater.set(Status::Failed);
        }
        // The old app may only exist in the work directory now: leave it for the user.
        Err(error @ SwapError::Broken(_)) => {
            tracing::error!(error = format!("{error:#}"), %version, "update left the app broken");
            updater.swap_refused.store(true, Ordering::SeqCst);
            updater.set(Status::Failed);
        }
    }
}

/// `open` hands the URL to the browser and returns at once; waiting reaps it.
fn open_page(page: &Url) {
    match std::process::Command::new("/usr/bin/open")
        .arg(page.as_str())
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => tracing::warn!(%status, "cannot open the release page"),
        Err(error) => tracing::warn!(%error, "cannot open the release page"),
    }
}

/// Whether an automatic install may restart the app now: nothing unlocked, no UI process (one
/// starting but not yet connected counts).
#[must_use]
pub fn quiet(state: &SessionState, ui_running: bool) -> bool {
    !ui_running && !matches!(state, SessionState::Unlocked { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tray_item_follows_the_status() {
        let version: Version = "1.2.3".parse().expect("version");
        assert_eq!(Status::Idle.tray_label(), "Check for Updates…");
        assert_eq!(
            Status::Ready(version).tray_label(),
            "Install Vaultkeeper 1.2.3 and Restart"
        );
        assert!(!Status::Checking.tray_enabled());
        assert!(!Status::Downloading(version).tray_enabled());
        assert!(Status::Failed.tray_enabled());
    }

    #[test]
    fn automatic_installs_wait_for_a_locked_vault_without_windows() {
        let server = Url::parse("https://vault.example").expect("url");
        let locked = SessionState::Locked {
            server: server.clone(),
            email: "a@example.com".to_owned(),
        };
        let unlocked = SessionState::Unlocked {
            server,
            email: "a@example.com".to_owned(),
        };
        assert!(quiet(&SessionState::LoggedOut, false));
        assert!(quiet(&locked, false));
        assert!(!quiet(&locked, true), "a UI process is running or starting");
        assert!(!quiet(&unlocked, false));
    }
}
