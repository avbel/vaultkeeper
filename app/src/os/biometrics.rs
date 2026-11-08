//! Touch ID per account: `accounts/<user_id>/touchid.bin`, so the log out wipe of that directory
//! removes the enrolment too.

use std::path::PathBuf;

use bwl_platform::{Error as PlatformError, biometric};
use zeroize::Zeroizing;

use super::layout::touch_id_file;
use crate::hooks::{Biometrics, HookError, HookResult};

pub const INVALIDATED: &str =
    "fingerprints changed since enrolment · unlock with your master password and enrol again";

pub struct TouchId {
    data_dir: PathBuf,
}

impl TouchId {
    #[must_use]
    pub const fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn file(&self, account_id: &str) -> HookResult<PathBuf> {
        touch_id_file(&self.data_dir, account_id)
            .ok_or_else(|| HookError::Failed(format!("unexpected account id {account_id:?}")))
    }
}

fn hook_error(error: PlatformError) -> HookError {
    match error {
        PlatformError::Unsupported => HookError::Unavailable("Touch ID"),
        PlatformError::BiometricFailed => HookError::Cancelled,
        PlatformError::BiometricInvalidated => HookError::Failed(INVALIDATED.to_owned()),
        other => HookError::Failed(other.to_string()),
    }
}

impl Biometrics for TouchId {
    fn is_available(&self) -> bool {
        biometric::is_available()
    }

    fn is_enrolled(&self, account_id: &str) -> bool {
        self.file(account_id)
            .is_ok_and(|path| biometric::is_enrolled(&path))
    }

    fn enroll(&self, account_id: &str, user_key: &[u8]) -> HookResult<()> {
        let path = self.file(account_id)?;
        if !path.parent().is_some_and(std::path::Path::is_dir) {
            return Err(HookError::Failed(
                "this account has no local data yet; log in first".to_owned(),
            ));
        }
        biometric::enroll(&path, user_key).map_err(hook_error)
    }

    /// An invalidated enrolment can never work again, so its file goes right away; the lock
    /// screen then offers only the master password until the user enrols again.
    fn unlock(&self, account_id: &str, reason: &str) -> HookResult<Zeroizing<Vec<u8>>> {
        let path = self.file(account_id)?;
        biometric::unlock(&path, reason).map_err(|error| {
            if matches!(error, PlatformError::BiometricInvalidated)
                && let Err(remove) = biometric::unenroll(&path)
            {
                tracing::warn!(%remove, "cannot remove an invalidated Touch ID enrolment");
            }
            hook_error(error)
        })
    }

    fn unenroll(&self, account_id: &str) -> HookResult<()> {
        biometric::unenroll(&self.file(account_id)?).map_err(hook_error)
    }

    fn authenticate(&self, reason: &str) -> HookResult<()> {
        biometric::authenticate(reason).map_err(hook_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";

    #[test]
    fn enrolment_state_follows_the_account_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let touch_id = TouchId::new(dir.path().to_owned());
        assert!(!touch_id.is_enrolled(USER));
        let file = touch_id_file(dir.path(), USER).expect("path");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(&file, b"sealed").expect("write");
        assert!(touch_id.is_enrolled(USER));
        touch_id.unenroll(USER).expect("unenroll");
        assert!(!touch_id.is_enrolled(USER));
        touch_id.unenroll(USER).expect("unenrolling twice is fine");
    }

    #[test]
    fn enrolling_without_an_account_directory_fails_before_touching_the_enclave() {
        let dir = tempfile::tempdir().expect("tempdir");
        let touch_id = TouchId::new(dir.path().to_owned());
        assert!(matches!(
            touch_id.enroll(USER, &[1; 64]),
            Err(HookError::Failed(_))
        ));
    }

    #[test]
    fn bad_account_ids_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let touch_id = TouchId::new(dir.path().to_owned());
        assert!(!touch_id.is_enrolled("../escape"));
        assert!(touch_id.unenroll("../escape").is_err());
        assert!(touch_id.unlock("a/b", "unlock").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_corrupt_enrolment_is_invalidated_and_removed_without_a_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let touch_id = TouchId::new(dir.path().to_owned());
        let file = touch_id_file(dir.path(), USER).expect("path");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(&file, b"BWLT\x01 garbage").expect("write");
        let error = touch_id
            .unlock(USER, "unlock your vault")
            .expect_err("corrupt");
        assert!(
            matches!(&error, HookError::Failed(text) if text == INVALIDATED),
            "{error}"
        );
        assert!(!touch_id.is_enrolled(USER), "the dead enrolment is gone");
    }

    #[test]
    fn platform_errors_map_to_what_the_lock_screen_shows() {
        assert!(matches!(
            hook_error(PlatformError::Unsupported),
            HookError::Unavailable(_)
        ));
        assert!(matches!(
            hook_error(PlatformError::BiometricFailed),
            HookError::Cancelled
        ));
    }
}
