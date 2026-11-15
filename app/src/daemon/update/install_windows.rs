//! Windows: an update is the signed setup exe, run silently by the daemon once it has stopped
//! everything that holds the installed exe. Running the installer (not swapping the exe) keeps
//! the Add/Remove Programs version, and so winget, correct.
//!
//! The setup exe is verified and run from the same private download directory, through one handle
//! that denies writers from the first check until the process is spawned, so nothing can be
//! swapped in between.

use std::{
    fs::File,
    os::windows::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use anyhow::Context as _;

use super::setup_policy::{self, Refusal};

/// `FILE_SHARE_READ` without write or delete sharing.
const SHARE_READ_ONLY: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Blocked {
    #[error("{0}")]
    Unsigned(Refusal),
}

/// A private, randomly named directory under the data directory (never the shared temp
/// directory, where another process could swap a file between verification and use), removed
/// when dropped.
pub struct Downloads(PathBuf);

impl Downloads {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Downloads {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            tracing::debug!(%error, "download directory not removed");
        }
    }
}

/// The verified setup exe: `_file` is declared first so it closes before the directory goes.
struct Pinned {
    _file: File,
    path: PathBuf,
    _downloads: Downloads,
}

pub struct Installer {
    updates: PathBuf,
    pinned: Mutex<Option<Pinned>>,
}

impl Installer {
    /// `work` is the owner-only root for downloads. Fails when the running exe is not validly
    /// signed: such builds are updated by hand.
    pub fn for_running_app(work: PathBuf) -> Result<Self, Blocked> {
        let running =
            std::env::current_exe().is_ok_and(|exe| vk_win::authenticode::is_validly_signed(&exe));
        setup_policy::decide(running, true).map_err(Blocked::Unsigned)?;
        Ok(Self {
            updates: work,
            pinned: Mutex::new(None),
        })
    }

    pub fn new_download(&self) -> anyhow::Result<Downloads> {
        vk_platform::fs::ensure_private_dir(&self.updates)?;
        let dir = self.updates.join(uuid::Uuid::new_v4().simple().to_string());
        vk_platform::fs::ensure_private_dir(&dir)?;
        Ok(Downloads(dir))
    }

    /// Pins `asset_name` in `downloads`, runs `verify` (the Ed25519 check) and the Authenticode
    /// check on it, and keeps it for [`Installer::run`]. A previously staged installer is
    /// replaced. On failure the download directory is removed.
    pub fn stage(
        &self,
        downloads: Downloads,
        asset_name: &str,
        verify: impl FnOnce(&Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<PathBuf> {
        let path = downloads.path().join(asset_name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_READ_ONLY)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let pinned = Pinned {
            _file: file,
            path: path.clone(),
            _downloads: downloads,
        };
        verify(&path)?;
        setup_policy::decide(true, vk_win::authenticode::is_validly_signed(&path))?;
        *self.pinned.lock().unwrap_or_else(PoisonError::into_inner) = Some(pinned);
        Ok(path)
    }

    /// Removes downloads left by an earlier run. Only the startup sweep does it: a later one
    /// could delete a download in progress.
    pub fn clean(&self, keep_previous: bool) {
        if !keep_previous {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&self.updates) else {
            return;
        };
        for entry in entries.flatten() {
            if let Err(error) = std::fs::remove_dir_all(entry.path()) {
                tracing::debug!(%error, "stale download not removed");
            }
        }
    }

    /// Starts the staged installer detached; `setup` must be the path [`Installer::stage`]
    /// returned. The pinned handle stays open until the daemon exits.
    pub fn run(&self, setup: &Path) -> anyhow::Result<()> {
        let pinned = self.pinned.lock().unwrap_or_else(PoisonError::into_inner);
        let staged = pinned
            .as_ref()
            .filter(|pinned| pinned.path == setup)
            .context("the installer is not the one that was verified")?;
        crate::os::detached::spawn_detached(&staged.path, &setup_policy::setup_args())
            .context("start the installer")
    }
}
