//! Touch ID. The user key is wrapped to a Secure Enclave P-256 key whose use requires the
//! currently enrolled biometrics (CryptoKit, `.biometryCurrentSet`). See the solution doc.

use std::path::Path;

use zeroize::Zeroizing;

use crate::Result;

#[must_use]
pub fn is_available() -> bool {
    todo!("step 6")
}

/// Creates a new Secure Enclave key and writes the wrapped `user_key` to `path` (mode 0600).
pub fn enroll(path: &Path, user_key: &[u8]) -> Result<()> {
    let _ = (path, user_key);
    todo!("step 6")
}

#[must_use]
pub fn is_enrolled(path: &Path) -> bool {
    path.exists()
}

/// Shows the Touch ID prompt with `reason` and returns the unwrapped user key.
pub fn unlock(path: &Path, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
    let _ = (path, reason);
    todo!("step 6")
}

pub fn unenroll(path: &Path) -> Result<()> {
    let _ = path;
    todo!("step 6")
}

/// Plain Touch ID check (no key), used to approve SSH sign requests.
pub fn authenticate(reason: &str) -> Result<()> {
    let _ = reason;
    todo!("step 6")
}
