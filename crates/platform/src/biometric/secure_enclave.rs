//! Calls into the Swift shim (`swift/Sources/BwlPlatform/SecureEnclave.swift`).

use std::ffi::{CStr, CString, c_char};

use p256::PublicKey;
use zeroize::Zeroizing;

use super::envelope::{DeviceKey, KeyAgreement, POINT_LEN, SHARED_SECRET_LEN, SharedSecret};
use super::{Operation, STATUS_OK, status_result};
use crate::{Error, Result};

// Measured on an M2 Max (macOS 27): blob 569 bytes, biometry state 32 bytes.
const BLOB_CAP: usize = 2048;
const STATE_CAP: usize = 255;
const DIAG_CAP: usize = 512;

unsafe extern "C" {
    safe fn bwl_se_is_available() -> bool;
    fn bwl_se_generate(
        blob_out: *mut u8,
        blob_cap: usize,
        blob_len: *mut usize,
        public_key_out: *mut u8,
        state_out: *mut u8,
        state_cap: usize,
        state_len: *mut usize,
        diag: *mut c_char,
        diag_cap: usize,
    ) -> i32;
    fn bwl_se_ecdh(
        blob: *const u8,
        blob_len: usize,
        enrolled_state: *const u8,
        enrolled_state_len: usize,
        peer: *const u8,
        peer_len: usize,
        reason: *const c_char,
        secret_out: *mut u8,
        diag: *mut c_char,
        diag_cap: usize,
    ) -> i32;
    fn bwl_la_authenticate(reason: *const c_char, diag: *mut c_char, diag_cap: usize) -> i32;
}

pub(super) fn is_available() -> bool {
    bwl_se_is_available()
}

pub(super) struct GeneratedKey {
    pub blob: Vec<u8>,
    pub public: PublicKey,
    pub biometry_state: Vec<u8>,
}

pub(super) fn generate() -> Result<GeneratedKey> {
    let mut blob = vec![0_u8; BLOB_CAP];
    let mut blob_len = 0;
    let mut public = [0_u8; POINT_LEN];
    let mut state = [0_u8; STATE_CAP];
    let mut state_len = 0;
    let mut diag = Diag::new();
    // SAFETY: every out pointer is valid for the capacity passed next to it, `public` holds the
    // 65 bytes the shim writes, and all buffers outlive the synchronous call.
    let status = unsafe {
        bwl_se_generate(
            blob.as_mut_ptr(),
            blob.len(),
            &raw mut blob_len,
            public.as_mut_ptr(),
            state.as_mut_ptr(),
            state.len(),
            &raw mut state_len,
            diag.as_mut_ptr(),
            DIAG_CAP,
        )
    };
    diag.log(status, "Secure Enclave key generation");
    status_result(status, Operation::Enroll, &diag.text())?;
    blob.truncate(blob_len.min(BLOB_CAP));
    let public = PublicKey::from_sec1_bytes(&public).map_err(|_| {
        Error::Io(std::io::Error::other(
            "Secure Enclave returned a bad public key",
        ))
    })?;
    Ok(GeneratedKey {
        blob,
        public,
        biometry_state: state[..state_len.min(STATE_CAP)].to_vec(),
    })
}

pub(super) fn authenticate(reason: &str) -> Result<()> {
    let reason = prompt_reason(reason)?;
    let mut diag = Diag::new();
    // SAFETY: `reason` is NUL-terminated and `diag` is valid for DIAG_CAP bytes; both outlive
    // the call, which blocks until the prompt is answered.
    let status = unsafe { bwl_la_authenticate(reason.as_ptr(), diag.as_mut_ptr(), DIAG_CAP) };
    diag.log(status, "Touch ID check");
    status_result(status, Operation::Authenticate, &diag.text())
}

/// The prompt text must be non-empty: LocalAuthentication raises an Objective-C exception
/// (which aborts the process) on an empty reason.
pub(super) fn prompt_reason(reason: &str) -> Result<CString> {
    if reason.trim().is_empty() {
        return Err(invalid_reason("Touch ID prompt reason must not be empty"));
    }
    CString::new(reason).map_err(|_| invalid_reason("Touch ID prompt reason contains NUL"))
}

fn invalid_reason(message: &'static str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// Shows the Touch ID prompt as part of the Secure Enclave key agreement.
pub(super) struct SecureEnclave<'a> {
    pub reason: &'a CStr,
}

impl KeyAgreement for SecureEnclave<'_> {
    fn shared_secret(&self, key: &DeviceKey<'_>, peer: &PublicKey) -> Result<SharedSecret> {
        let peer = super::envelope::encode_point(peer);
        let mut secret = Zeroizing::new([0_u8; SHARED_SECRET_LEN]);
        let mut diag = Diag::new();
        // SAFETY: input slices are valid for the lengths passed, `reason` is NUL-terminated,
        // `secret` holds the 32 bytes the shim writes and `diag` DIAG_CAP bytes; all outlive
        // the call, which blocks until the prompt is answered.
        let status = unsafe {
            bwl_se_ecdh(
                key.blob.as_ptr(),
                key.blob.len(),
                key.biometry_state.as_ptr(),
                key.biometry_state.len(),
                peer.as_ptr(),
                peer.len(),
                self.reason.as_ptr(),
                secret.as_mut_ptr(),
                diag.as_mut_ptr(),
                DIAG_CAP,
            )
        };
        diag.log(status, "Secure Enclave key agreement");
        status_result(status, Operation::Unlock, &diag.text())?;
        Ok(secret)
    }
}

struct Diag([u8; DIAG_CAP]);

impl Diag {
    const fn new() -> Self {
        Self([0; DIAG_CAP])
    }

    fn as_mut_ptr(&mut self) -> *mut c_char {
        self.0.as_mut_ptr().cast()
    }

    fn text(&self) -> String {
        CStr::from_bytes_until_nul(&self.0)
            .map(|text| text.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn log(&self, status: i32, operation: &str) {
        if status != STATUS_OK {
            tracing::warn!(status, detail = %self.text(), "{operation} failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{CString, c_char};

    use crate::Error;

    unsafe extern "C" {
        fn bwl_se_key_init_status_for_test(
            domain: *const c_char,
            code: isize,
            underlying_domain: *const c_char,
            underlying_code: isize,
            enrolled_changed: bool,
        ) -> i32;
    }

    const TK: &str = "CryptoTokenKit";
    const OS_STATUS: &str = "NSOSStatusErrorDomain";
    const CRYPTO_KIT: &str = "CryptoKit.CryptoKitError";

    /// What an unlock reports when restoring the Secure Enclave key fails with this error.
    fn unlock_after_key_init_failure(
        error: (&str, isize),
        underlying: Option<(&str, isize)>,
        enrolled_changed: bool,
    ) -> crate::Result<()> {
        let domain = CString::new(error.0).expect("domain");
        let (under_domain, under_code) = underlying.unwrap_or(("", 0));
        let under_domain = CString::new(under_domain).expect("domain");
        // SAFETY: both strings are NUL-terminated and outlive the call, which only reads them.
        let status = unsafe {
            bwl_se_key_init_status_for_test(
                domain.as_ptr(),
                error.1,
                under_domain.as_ptr(),
                under_code,
                enrolled_changed,
            )
        };
        super::status_result(status, super::Operation::Unlock, "")
    }

    fn invalidates(result: &crate::Result<()>) -> bool {
        matches!(result, Err(Error::BiometricInvalidated))
    }

    #[test]
    fn only_a_gone_or_corrupt_key_or_changed_fingers_delete_the_enrolment() {
        // TKError.Code (CryptoTokenKit/TKError.h): corruptedData -3, objectNotFound -6,
        // tokenNotFound -7 mean the key can never be used again.
        for code in [-3, -6, -7] {
            assert!(
                invalidates(&unlock_after_key_init_failure((TK, code), None, false)),
                "TKError {code}"
            );
        }
        assert!(invalidates(&unlock_after_key_init_failure(
            (CRYPTO_KIT, 1),
            Some((TK, -6)),
            false
        )));
        assert!(
            invalidates(&unlock_after_key_init_failure((CRYPTO_KIT, 1), None, true)),
            "fingers changed since enrolment"
        );
    }

    #[test]
    fn transient_key_init_failures_keep_the_enrolment() {
        // communicationError -2 (Secure Enclave busy), errSecInteractionNotAllowed -25308
        // (keychain locked with the screen), an unclassified CryptoKit error.
        for (domain, code) in [(TK, -2), (OS_STATUS, -25_308), (CRYPTO_KIT, 3)] {
            let result = unlock_after_key_init_failure((domain, code), None, false);
            assert!(
                matches!(result, Err(Error::BiometricFailed)),
                "{domain} {code}: {result:?}"
            );
        }
    }
}
