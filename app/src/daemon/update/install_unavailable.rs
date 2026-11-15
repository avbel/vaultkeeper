//! Stand-in for the bundle installer on targets without one: updates only link to the release
//! page.

use std::path::{Path, PathBuf};

use super::release::Version;

/// How a swap ended when it did not install the update.
#[allow(
    dead_code,
    reason = "mirrors the macOS installer's errors; nothing swaps here"
)]
#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    #[error("the platform refused to replace the app: {0}")]
    Refused(std::io::Error),
    #[error(transparent)]
    Rejected(anyhow::Error),
    #[error("the previous app could not be restored: {0:#}")]
    Broken(anyhow::Error),
}

/// Why this copy cannot replace itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Blocked {
    #[error("updates are not installed on this platform yet")]
    Unavailable,
}

/// Cannot be constructed: [`Installer::for_running_app`] always refuses.
pub struct Installer(std::convert::Infallible);

impl Installer {
    // Windows: step 5h - the updater installs through the installer.
    pub fn for_running_app(_work: PathBuf) -> Result<Self, Blocked> {
        Err(Blocked::Unavailable)
    }

    pub fn bundle(&self) -> &Path {
        match self.0 {}
    }

    pub fn stage(&self, _zip: &Path, _version: Version) -> anyhow::Result<PathBuf> {
        match self.0 {}
    }

    pub fn swap_in(&self, _staged: &Path, _version: Version) -> Result<(), SwapError> {
        match self.0 {}
    }

    pub fn clean(&self, _keep_previous: bool) {
        match self.0 {}
    }
}
