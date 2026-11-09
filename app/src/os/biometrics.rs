//! Touch ID per account: `accounts/<user_id>/touchid.bin`, so the log out wipe of that directory
//! removes the enrolment too.
//!
//! [`TouchId`] is the daemon's Secure Enclave access (it holds the vault, so the user key never
//! leaves it); [`DaemonTouchId`] is what the `--ui` process uses: enrol and unlock are requests
//! to the daemon, and only the enrolment file check runs locally.

use std::{path::PathBuf, sync::Arc};

use bwl_ipc::{RemoteVault, TouchIdBackend, TouchIdFailure};
use bwl_platform::{Error as PlatformError, biometric};
use zeroize::Zeroizing;

use super::layout::touch_id_file;
use crate::hooks::{Biometrics, HookError, HookResult};

pub const INVALIDATED: &str =
    "fingerprints changed since enrolment · unlock with your master password and enrol again";

/// What the daemon shows in the system prompt; the UI cannot choose the text.
const UNLOCK_REASON: &str = "unlock your vault";

/// The daemon's Touch ID. Besides the [`TouchIdBackend`] calls the UI can ask for, it checks
/// presence for SSH approvals itself.
pub trait DaemonBiometrics: TouchIdBackend {
    /// Plain presence check; blocks until the user answers.
    fn authenticate(&self, reason: &str) -> Result<(), TouchIdFailure>;
}

pub struct TouchId {
    data_dir: PathBuf,
}

impl TouchId {
    #[must_use]
    pub const fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn file(&self, account_id: &str) -> Result<PathBuf, TouchIdFailure> {
        touch_id_file(&self.data_dir, account_id)
            .ok_or_else(|| TouchIdFailure::Failed(format!("unexpected account id {account_id:?}")))
    }
}

fn failure(error: PlatformError) -> TouchIdFailure {
    match error {
        PlatformError::Unsupported => TouchIdFailure::Unavailable,
        PlatformError::BiometricFailed => TouchIdFailure::Cancelled,
        PlatformError::BiometricInvalidated => TouchIdFailure::Invalidated,
        other => TouchIdFailure::Failed(other.to_string()),
    }
}

impl TouchIdBackend for TouchId {
    fn enroll(&self, account_id: &str, user_key: &[u8]) -> Result<(), TouchIdFailure> {
        let path = self.file(account_id)?;
        if !path.parent().is_some_and(std::path::Path::is_dir) {
            return Err(TouchIdFailure::Failed(
                "this account has no local data yet; log in first".to_owned(),
            ));
        }
        biometric::enroll(&path, user_key).map_err(failure)
    }

    /// An invalidated enrolment can never work again, so its file goes right away; the lock
    /// screen then offers only the master password until the user enrols again.
    fn unlock(&self, account_id: &str) -> Result<Zeroizing<Vec<u8>>, TouchIdFailure> {
        let path = self.file(account_id)?;
        biometric::unlock(&path, UNLOCK_REASON).map_err(|error| {
            if matches!(error, PlatformError::BiometricInvalidated)
                && let Err(remove) = biometric::unenroll(&path)
            {
                tracing::warn!(%remove, "cannot remove an invalidated Touch ID enrolment");
            }
            failure(error)
        })
    }
}

impl DaemonBiometrics for TouchId {
    fn authenticate(&self, reason: &str) -> Result<(), TouchIdFailure> {
        biometric::authenticate(reason).map_err(failure)
    }
}

/// `touchid.bin` per account, as the UI sees it: whether it exists, and removing it (no secret
/// involved, so this stays local).
pub struct EnrolmentFiles {
    data_dir: PathBuf,
}

impl EnrolmentFiles {
    #[must_use]
    pub const fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn file(&self, account_id: &str) -> HookResult<PathBuf> {
        touch_id_file(&self.data_dir, account_id)
            .ok_or_else(|| HookError::Failed(format!("unexpected account id {account_id:?}")))
    }

    #[must_use]
    pub fn is_enrolled(&self, account_id: &str) -> bool {
        self.file(account_id)
            .is_ok_and(|path| biometric::is_enrolled(&path))
    }

    pub fn unenroll(&self, account_id: &str) -> HookResult<()> {
        biometric::unenroll(&self.file(account_id)?)
            .map_err(|error| HookError::Failed(error.to_string()))
    }
}

/// The `--ui` process's Touch ID: the daemon does the Secure Enclave work.
pub struct DaemonTouchId {
    files: EnrolmentFiles,
    daemon: Arc<RemoteVault>,
}

impl DaemonTouchId {
    #[must_use]
    pub const fn new(data_dir: PathBuf, daemon: Arc<RemoteVault>) -> Self {
        Self {
            files: EnrolmentFiles::new(data_dir),
            daemon,
        }
    }
}

fn hook_error(failure: TouchIdFailure) -> HookError {
    match failure {
        TouchIdFailure::Unavailable => HookError::Unavailable("Touch ID"),
        TouchIdFailure::Cancelled => HookError::Cancelled,
        TouchIdFailure::Invalidated => HookError::Failed(INVALIDATED.to_owned()),
        other => HookError::Failed(other.to_string()),
    }
}

fn settle(outcome: bwl_vault::Result<Result<(), TouchIdFailure>>) -> HookResult<()> {
    match outcome {
        Ok(result) => result.map_err(hook_error),
        Err(error) => Err(HookError::Failed(crate::viewmodel::error_text(&error))),
    }
}

impl Biometrics for DaemonTouchId {
    fn is_available(&self) -> bool {
        biometric::is_available()
    }

    fn is_enrolled(&self, account_id: &str) -> bool {
        self.files.is_enrolled(account_id)
    }

    fn enroll(&self, account_id: &str) -> HookResult<()> {
        settle(self.daemon.enroll_touch_id(account_id))
    }

    fn unlock(&self, account_id: &str) -> HookResult<()> {
        settle(self.daemon.unlock_with_touch_id(account_id))
    }

    fn unenroll(&self, account_id: &str) -> HookResult<()> {
        self.files.unenroll(account_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";

    #[test]
    fn enrolment_state_follows_the_account_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let files = EnrolmentFiles::new(dir.path().to_owned());
        assert!(!files.is_enrolled(USER));
        let file = touch_id_file(dir.path(), USER).expect("path");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(&file, b"sealed").expect("write");
        assert!(files.is_enrolled(USER));
        files.unenroll(USER).expect("unenroll");
        assert!(!files.is_enrolled(USER));
        files.unenroll(USER).expect("unenrolling twice is fine");
        assert!(!files.is_enrolled("../escape"));
        assert!(files.unenroll("../escape").is_err());
    }

    #[test]
    fn enrolling_without_an_account_directory_fails_before_touching_the_enclave() {
        let dir = tempfile::tempdir().expect("tempdir");
        let touch_id = TouchId::new(dir.path().to_owned());
        assert!(matches!(
            touch_id.enroll(USER, &[1; 64]),
            Err(TouchIdFailure::Failed(_))
        ));
    }

    #[test]
    fn bad_account_ids_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let touch_id = TouchId::new(dir.path().to_owned());
        assert!(touch_id.enroll("../escape", &[1; 64]).is_err());
        assert!(touch_id.unlock("a/b").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_corrupt_enrolment_is_invalidated_and_removed_without_a_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let touch_id = TouchId::new(dir.path().to_owned());
        let file = touch_id_file(dir.path(), USER).expect("path");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(&file, b"BWLT\x01 garbage").expect("write");
        assert_eq!(touch_id.unlock(USER), Err(TouchIdFailure::Invalidated));
        assert!(!file.exists(), "the dead enrolment is gone");
    }

    #[test]
    fn platform_errors_map_to_touch_id_failures() {
        assert_eq!(
            failure(PlatformError::Unsupported),
            TouchIdFailure::Unavailable
        );
        assert_eq!(
            failure(PlatformError::BiometricFailed),
            TouchIdFailure::Cancelled
        );
        assert_eq!(
            failure(PlatformError::BiometricInvalidated),
            TouchIdFailure::Invalidated
        );
    }

    #[test]
    fn daemon_failures_map_to_what_the_lock_screen_shows() {
        assert!(matches!(
            hook_error(TouchIdFailure::Unavailable),
            HookError::Unavailable(_)
        ));
        assert!(matches!(
            hook_error(TouchIdFailure::Cancelled),
            HookError::Cancelled
        ));
        assert!(
            matches!(hook_error(TouchIdFailure::Invalidated), HookError::Failed(text) if text == INVALIDATED)
        );
        assert!(
            matches!(
                settle(Err(bwl_vault::Error::Locked)),
                Err(HookError::Failed(_))
            ),
            "vault errors reach the user as text"
        );
        assert!(settle(Ok(Ok(()))).is_ok());
    }
}
