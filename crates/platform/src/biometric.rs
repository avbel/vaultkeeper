//! Touch ID. The user key is wrapped to a Secure Enclave P-256 key whose use requires the
//! currently enrolled biometrics (CryptoKit, `.biometryCurrentSet`). See the solution doc.
//!
//! The functions that show a prompt block until the user answers it, so call them from a
//! background thread, never from the UI event loop.

// The wrap/unwrap core builds and is tested on every target but is wired up on macOS only.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod envelope;
#[cfg(target_os = "macos")]
mod secure_enclave;

use std::path::Path;

use zeroize::Zeroizing;

use crate::{Error, Result};

// Status codes returned by the Swift shim; mirrored there.
const STATUS_OK: i32 = 0;
const STATUS_INVALIDATED: i32 = 2;
const STATUS_UNAVAILABLE: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Enroll,
    Unlock,
    Authenticate,
}

/// Only definitive outcomes become [`Error::BiometricInvalidated`], because the app discards the
/// enrollment on it. Lockout or a closed lid ("unavailable") are temporary and fall back to the
/// master password as [`Error::BiometricFailed`].
fn status_result(status: i32, operation: Operation, detail: &str) -> Result<()> {
    match (status, operation) {
        (STATUS_OK, _) => Ok(()),
        (STATUS_INVALIDATED, Operation::Unlock) => Err(Error::BiometricInvalidated),
        (STATUS_UNAVAILABLE, Operation::Enroll) => Err(Error::Unsupported),
        (_, Operation::Enroll) => Err(Error::Io(std::io::Error::other(format!(
            "Secure Enclave key creation failed: {detail}"
        )))),
        (_, Operation::Unlock | Operation::Authenticate) => Err(Error::BiometricFailed),
    }
}

/// True when this Mac has a Secure Enclave and at least one enrolled fingerprint.
#[must_use]
pub fn is_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        secure_enclave::is_available()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Creates a new Secure Enclave key and writes the wrapped `user_key` to `path` (mode 0600).
/// Replaces an earlier enrollment atomically. Never prompts.
pub fn enroll(path: &Path, user_key: &[u8]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let key = secure_enclave::generate()?;
        let device_key = envelope::DeviceKey {
            blob: &key.blob,
            biometry_state: &key.biometry_state,
        };
        let sealed = envelope::seal(&key.public, &device_key, user_key)?;
        Ok(crate::fs::write_private_atomic(path, &sealed)?)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, user_key);
        Err(Error::Unsupported)
    }
}

#[must_use]
pub fn is_enrolled(path: &Path) -> bool {
    path.exists()
}

/// Shows the Touch ID prompt with `reason` and returns the unwrapped user key.
///
/// [`Error::BiometricInvalidated`] means the enrollment can never work again (fingerprints
/// changed, or the file is corrupt or from another Mac): unlock with the master password and
/// enroll again. [`Error::BiometricFailed`] covers cancel, no match and temporary unavailability.
pub fn unlock(path: &Path, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "macos")]
    {
        let reason = secure_enclave::prompt_reason(reason)?;
        let bytes = std::fs::read(path)?;
        envelope::open(&bytes, &secure_enclave::SecureEnclave { reason: &reason })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, reason);
        Err(Error::Unsupported)
    }
}

/// Deletes the enrollment without reading it, so a corrupt file is removed too. Deleting the
/// file destroys the only reference to the Secure Enclave key. Missing files are fine.
pub fn unenroll(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err.into()),
        _ => Ok(()),
    }
}

/// Plain Touch ID check (no key), used to approve SSH sign requests. Blocks until answered.
pub fn authenticate(reason: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        secure_enclave::authenticate(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_FAILED: i32 = 1;
    const STATUS_ERROR: i32 = 4;

    #[test]
    fn success_maps_to_ok_for_every_operation() {
        for operation in [
            Operation::Enroll,
            Operation::Unlock,
            Operation::Authenticate,
        ] {
            assert!(
                status_result(STATUS_OK, operation, "").is_ok(),
                "{operation:?}"
            );
        }
    }

    #[test]
    fn only_a_definitive_unlock_failure_invalidates() {
        assert!(matches!(
            status_result(STATUS_INVALIDATED, Operation::Unlock, ""),
            Err(Error::BiometricInvalidated)
        ));
        for status in [STATUS_FAILED, STATUS_UNAVAILABLE, STATUS_ERROR, 99] {
            assert!(
                matches!(
                    status_result(status, Operation::Unlock, ""),
                    Err(Error::BiometricFailed)
                ),
                "status {status}"
            );
        }
    }

    #[test]
    fn authenticate_failures_never_invalidate() {
        for status in [
            STATUS_FAILED,
            STATUS_INVALIDATED,
            STATUS_UNAVAILABLE,
            STATUS_ERROR,
        ] {
            assert!(
                matches!(
                    status_result(status, Operation::Authenticate, ""),
                    Err(Error::BiometricFailed)
                ),
                "status {status}"
            );
        }
    }

    #[test]
    fn enroll_without_secure_enclave_is_unsupported() {
        assert!(matches!(
            status_result(STATUS_UNAVAILABLE, Operation::Enroll, ""),
            Err(Error::Unsupported)
        ));
        let err = status_result(STATUS_ERROR, Operation::Enroll, "CryptoTokenKit -3")
            .expect_err("error status");
        assert!(err.to_string().contains("CryptoTokenKit -3"), "{err}");
    }

    #[test]
    fn unenroll_removes_corrupt_files_and_tolerates_missing_ones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("touchid.bin");
        std::fs::write(&path, b"not an enrollment").expect("write");
        assert!(is_enrolled(&path));
        unenroll(&path).expect("unenroll corrupt");
        assert!(!is_enrolled(&path));
        unenroll(&path).expect("unenroll missing");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn empty_or_nul_reasons_are_rejected_before_prompting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("touchid.bin");
        for reason in ["", "   ", "a\0b"] {
            assert!(
                matches!(unlock(&path, reason), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput),
                "{reason:?}"
            );
            assert!(
                matches!(authenticate(reason), Err(Error::Io(_))),
                "{reason:?}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unlock_of_a_missing_file_is_an_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = unlock(&dir.path().join("missing.bin"), "unlock the vault");
        assert!(matches!(result, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unlock_of_a_corrupt_file_is_invalidated_without_prompting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("touchid.bin");
        std::fs::write(&path, b"BWLT\x01 garbage").expect("write");
        assert!(matches!(
            unlock(&path, "unlock the vault"),
            Err(Error::BiometricInvalidated)
        ));
    }

    /// Creates a real Secure Enclave key; creation never prompts but fails with
    /// errSecInteractionNotAllowed (-25308) while the session is locked, so it is opt-in:
    /// `cargo test -p vk-platform -- --ignored`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs an unlocked interactive macOS session with a Secure Enclave"]
    fn enroll_writes_a_private_parsable_file() {
        use std::os::unix::fs::PermissionsExt;

        if !is_available() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("touchid.bin");
        enroll(&path, &[0x42; 64]).expect("enroll");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let bytes = std::fs::read(&path).expect("read");
        let parsed = envelope::Envelope::parse(&bytes).expect("parse");
        assert_ne!(parsed.key.blob.len(), 0, "Secure Enclave blob is stored");
        unenroll(&path).expect("unenroll");
    }
}
