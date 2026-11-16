//! Windows Hello: the user key is sealed to an RSA key held in the Passport key storage provider,
//! whose private use requires the currently enrolled Hello gesture (face, fingerprint or PIN).
//!
//! The NCrypt call sequence mirrors `crates/platform/examples/hello_check.rs` (the step 4a spike)
//! exactly: open the provider, open or create `<SID>//Vaultkeeper//Vaultkeeper`, export the public
//! key, wrap a fresh 32-byte key-encryption key with RSA PKCS#1 v1.5, and seal the user key with
//! AES-256-GCM into a version 2 envelope (see `super::envelope`). Unlock unwraps the KEK with one
//! `NCryptDecrypt` that Windows Hello gates behind a gesture, then opens the envelope.
//!
//! Error mapping keeps the biometric invariant (docs/solutions/windows-support.md §3.2): the
//! enrollment is only ever `BiometricInvalidated` when the KSP key is gone, the stored public key
//! no longer matches the KSP, or the user key fails its AES-GCM check after a successful unwrap.
//! Every other failure — cancel, lockout, a down NGC service, RDP, the foreground retry — is
//! `BiometricFailed`, so it falls back to the master password without discarding the enrollment.

use std::{
    path::Path,
    ptr::{null, null_mut},
};

use rand::{TryRng, rngs::SysRng};
use vk_win::current_user_sid;
use windows::Security::Credentials::UI::UserConsentVerifierAvailability;
use windows_sys::{
    Win32::{
        Foundation::{NTE_BAD_KEYSET, NTE_BAD_LEN, NTE_NO_KEY},
        Security::Cryptography::{
            BCRYPT_RSA_ALGORITHM, BCRYPT_RSAPUBLIC_BLOB, MS_NGC_KEY_STORAGE_PROVIDER,
            NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
            NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_PKCS1_FLAG,
            NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY, NCRYPT_PROV_HANDLE,
            NCRYPT_USE_CONTEXT_PROPERTY, NCRYPT_WINDOW_HANDLE_PROPERTY, NCryptCreatePersistedKey,
            NCryptDecrypt, NCryptEncrypt, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
            NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
        },
        UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION},
    },
    core::PCWSTR,
};
use zeroize::Zeroizing;

use super::consent;
use super::envelope::v2::{self, Primitive, V2Envelope, V2Header};
use crate::{Error, Result};

const KEY_BITS: u32 = 2048;
const KEK_LEN: usize = 32;
// 0x80098044: the Hello dialog was not in the foreground; the second attempt usually succeeds.
#[expect(clippy::cast_possible_wrap)]
const NTE_FOREGROUND: i32 = 0x8009_8044_u32 as i32;

type NcResult<T> = std::result::Result<T, i32>;

/// Owns an NCrypt provider or key handle and frees it on drop.
struct Handle(usize);

impl Handle {
    fn raw(&self) -> usize {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from an NCrypt call, is owned by this wrapper only and is
            // freed exactly once.
            let status = unsafe { NCryptFreeObject(self.0) };
            if status != 0 {
                tracing::debug!(status = %hex(status), "NCryptFreeObject failed");
            }
        }
    }
}

/// True when the Passport KSP is reachable, the session is a local console (not RDP) and the user
/// has Windows Hello set up. Not cached: the answer changes the moment the user adds a PIN, and the
/// check is a single quick WinRT call.
pub(super) fn is_available() -> bool {
    // SAFETY: `GetSystemMetrics` takes no pointers; a non-zero answer for `SM_REMOTESESSION`
    // means the session is remote and Windows Hello gestures are unavailable.
    if unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0 {
        return false;
    }
    if open_provider().is_err() {
        return false;
    }
    consent::availability().is_some_and(hello_usable)
}

fn hello_usable(availability: UserConsentVerifierAvailability) -> bool {
    availability == UserConsentVerifierAvailability::Available
}

/// Hello that is certainly not set up for the user; transient states (policy, busy device) are
/// left to the key creation to report.
fn not_set_up(availability: UserConsentVerifierAvailability) -> bool {
    matches!(
        availability,
        UserConsentVerifierAvailability::NotConfiguredForUser
            | UserConsentVerifierAvailability::DeviceNotPresent
    )
}

/// `NTE_BAD_KEYSET` on key creation means the user has no Hello container yet.
fn creation_failure(status: i32) -> Error {
    if status == NTE_BAD_KEYSET {
        return Error::BiometricNotSetUp;
    }
    Error::Io(std::io::Error::other(format!(
        "Windows Hello key creation failed: {}",
        hex(status)
    )))
}

/// Creates or reuses the Passport key and writes a v2 envelope sealing `user_key` to it.
/// Never asks for a gesture (only the first-time key creation can prompt).
pub(super) fn enroll(path: &Path, user_key: &[u8], parent_window: Option<u64>) -> Result<()> {
    let sid = current_user_sid()?;
    let name = key_name(&sid);
    let wide_name = wide(&name);

    if consent::availability().is_some_and(not_set_up) {
        return Err(Error::BiometricNotSetUp);
    }

    let provider = open_provider().map_err(|status| {
        tracing::warn!(status = %hex(status), "Passport KSP unavailable during enrolment");
        Error::Unsupported
    })?;

    let key = open_or_create(&provider, &wide_name, parent_window).map_err(|status| {
        tracing::warn!(status = %hex(status), "Windows Hello key creation failed");
        creation_failure(status)
    })?;

    let public = export_public(&key).map_err(|status| {
        Error::Io(std::io::Error::other(format!(
            "could not export the Windows Hello public key: {}",
            hex(status)
        )))
    })?;

    let mut kek = Zeroizing::new([0_u8; KEK_LEN]);
    SysRng
        .try_fill_bytes(kek.as_mut_slice())
        .map_err(rng_error)?;

    let wrapped = wrap_kek(&key, kek.as_slice()).map_err(|status| {
        Error::Io(std::io::Error::other(format!(
            "could not wrap the key-encryption key: {}",
            hex(status)
        )))
    })?;

    let header = V2Header {
        primitive: Primitive::PassportRsaPkcs1,
        key_name: &name,
        public_key: &public,
        user_sid: &sid,
        wrapped_kek: &wrapped,
    };
    let sealed = v2::seal_v2(&header, &kek, user_key)?;
    Ok(crate::fs::write_private_atomic(path, &sealed)?)
}

/// Unwraps the user key from `path`, showing one Windows Hello gesture.
pub(super) fn unlock(
    path: &Path,
    reason: &str,
    parent_window: Option<u64>,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = std::fs::read(path)?;
    let envelope = V2Envelope::parse(&bytes)?;
    if envelope.primitive != Primitive::PassportRsaPkcs1 {
        return Err(Error::BiometricInvalidated);
    }
    // An envelope copied from another account can never be opened by this user, so it is a
    // definitive "enrol again" rather than a transient failure.
    let sid = current_user_sid()?;
    if envelope.user_sid != sid || envelope.key_name != key_name(&sid) {
        tracing::warn!("the Windows Hello enrollment belongs to another user");
        return Err(Error::BiometricInvalidated);
    }

    let provider = open_provider().map_err(|status| {
        tracing::warn!(status = %hex(status), "Passport KSP unavailable during unlock");
        Error::BiometricFailed
    })?;

    let wide_name = wide(envelope.key_name);
    let key = open_key(&provider, &wide_name).map_err(open_key_failure)?;

    let public = export_public(&key).map_err(|status| {
        tracing::warn!(status = %hex(status), "could not export the Windows Hello public key");
        Error::BiometricFailed
    })?;
    if public != envelope.public_key {
        tracing::warn!("the Windows Hello key no longer matches the enrollment");
        return Err(Error::BiometricInvalidated);
    }

    let kek = unwrap_kek(&key, envelope.wrapped_kek, reason, parent_window)?;
    Ok(envelope.decrypt(&kek)?)
}

/// The `<SID>//Vaultkeeper//Vaultkeeper` key name, kept pure so it is testable without hardware.
fn key_name(sid: &str) -> String {
    format!("{sid}//Vaultkeeper//Vaultkeeper")
}

fn open_provider() -> NcResult<Handle> {
    let mut provider: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: the out-param points at a live local and the provider name is a static string.
    let status =
        unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_NGC_KEY_STORAGE_PROVIDER, 0) };
    if status != 0 {
        return Err(status);
    }
    Ok(Handle(provider))
}

fn open_key(provider: &Handle, name: &[u16]) -> NcResult<Handle> {
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: the provider handle is open, `name` is NUL-terminated and the out-param points at a
    // live local.
    let status = unsafe { NCryptOpenKey(provider.raw(), &raw mut key, name.as_ptr(), 0, 0) };
    if status != 0 {
        return Err(status);
    }
    Ok(Handle(key))
}

/// Only a key that is gone (`NTE_BAD_KEYSET`/`NTE_NO_KEY`) invalidates the enrollment; any other
/// open failure is transient.
fn open_key_failure(status: i32) -> Error {
    match status {
        NTE_BAD_KEYSET | NTE_NO_KEY => Error::BiometricInvalidated,
        _ => Error::BiometricFailed,
    }
}

fn create_key(provider: &Handle, name: &[u16], parent_window: Option<u64>) -> NcResult<Handle> {
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: the provider handle is open, the algorithm and `name` are NUL-terminated and the
    // out-param points at a live local.
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.raw(),
            &raw mut key,
            BCRYPT_RSA_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    };
    if status != 0 {
        return Err(status);
    }
    let key = Handle(key);
    set_property(key.raw(), NCRYPT_LENGTH_PROPERTY, &KEY_BITS.to_ne_bytes())?;
    set_property(
        key.raw(),
        NCRYPT_KEY_USAGE_PROPERTY,
        &NCRYPT_ALLOW_DECRYPT_FLAG.to_ne_bytes(),
    )?;
    // The first-time key creation can prompt once for a Hello gesture, so parent it like a decrypt.
    parent_prompt(&key, parent_window);
    // SAFETY: the key handle is valid and not yet finalized.
    let status = unsafe { NCryptFinalizeKey(key.raw(), 0) };
    if status != 0 {
        return Err(status);
    }
    Ok(key)
}

fn open_or_create(provider: &Handle, name: &[u16], parent_window: Option<u64>) -> NcResult<Handle> {
    match open_key(provider, name) {
        Ok(key) => Ok(key),
        Err(NTE_BAD_KEYSET | NTE_NO_KEY) => create_key(provider, name, parent_window),
        Err(status) => Err(status),
    }
}

fn export_public(key: &Handle) -> NcResult<Vec<u8>> {
    let mut len = 0_u32;
    // SAFETY: a null output buffer with size 0 asks for the required length only.
    let status = unsafe {
        NCryptExportKey(
            key.raw(),
            0,
            BCRYPT_RSAPUBLIC_BLOB,
            null(),
            null_mut(),
            0,
            &raw mut len,
            0,
        )
    };
    if status != 0 {
        return Err(status);
    }
    let mut blob = vec![0_u8; usize::try_from(len).expect("u32 fits in usize on 64-bit")];
    // SAFETY: `blob` is `len` bytes long and the out-param points at a live local.
    let status = unsafe {
        NCryptExportKey(
            key.raw(),
            0,
            BCRYPT_RSAPUBLIC_BLOB,
            null(),
            blob.as_mut_ptr(),
            len,
            &raw mut len,
            0,
        )
    };
    if status != 0 {
        return Err(status);
    }
    blob.truncate(usize::try_from(len).expect("u32 fits in usize on 64-bit"));
    Ok(blob)
}

/// RSA PKCS#1 v1.5 wraps the KEK with the key's public half, so it needs no gesture.
///
/// PKCS#1 v1.5 rather than OAEP because the Passport KSP rejects OAEP with NTE_INVALID_PARAMETER
/// (measured on hardware). A Bleichenbacher padding oracle is not practical here: every decrypt
/// needs a Hello gesture, and the unwrapped KEK is authenticated by the envelope's AES-GCM tag, so
/// a wrong KEK fails to open the envelope.
#[expect(clippy::cast_possible_truncation)]
fn wrap_kek(key: &Handle, kek: &[u8]) -> NcResult<Vec<u8>> {
    let mut len = 0_u32;
    // SAFETY: a null output buffer with size 0 asks for the required length only; PKCS#1 padding
    // takes no padding info, so null is valid.
    let status = unsafe {
        NCryptEncrypt(
            key.raw(),
            kek.as_ptr(),
            kek.len() as u32,
            null(),
            null_mut(),
            0,
            &raw mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    };
    if status != 0 {
        return Err(status);
    }
    let mut out = vec![0_u8; usize::try_from(len).expect("u32 fits in usize on 64-bit")];
    // SAFETY: `out` is `len` bytes long; PKCS#1 padding takes no padding info.
    let status = unsafe {
        NCryptEncrypt(
            key.raw(),
            kek.as_ptr(),
            kek.len() as u32,
            null(),
            out.as_mut_ptr(),
            len,
            &raw mut len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    };
    if status != 0 {
        return Err(status);
    }
    out.truncate(usize::try_from(len).expect("u32 fits in usize on 64-bit"));
    Ok(out)
}

/// Sets the properties the spike proved out, then decrypts the wrapped KEK, retrying once on the
/// "dialog was not foreground" status.
fn unwrap_kek(
    key: &Handle,
    wrapped: &[u8],
    reason: &str,
    parent_window: Option<u64>,
) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    prepare_decrypt(key, reason, parent_window);
    match decrypt_once(key, wrapped) {
        Ok(kek) => Ok(kek),
        Err(NTE_FOREGROUND) => {
            tracing::debug!("0x80098044 on the first attempt, retrying once");
            decrypt_once(key, wrapped).map_err(unwrap_failure)
        }
        Err(status) => Err(unwrap_failure(status)),
    }
}

fn unwrap_failure(status: i32) -> Error {
    tracing::warn!(status = %hex(status), "Windows Hello unlock failed");
    Error::BiometricFailed
}

fn prepare_decrypt(key: &Handle, reason: &str, parent_window: Option<u64>) {
    parent_prompt(key, parent_window);
    let context: Vec<u8> = wide(reason)
        .into_iter()
        .flat_map(u16::to_ne_bytes)
        .collect();
    if let Err(status) = set_property(key.raw(), NCRYPT_USE_CONTEXT_PROPERTY, &context) {
        tracing::warn!(status = %hex(status), "could not set the Hello prompt context");
    }
    if let Err(status) = set_property(
        key.raw(),
        NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY,
        &1_u32.to_ne_bytes(),
    ) {
        tracing::warn!(status = %hex(status), "could not require a fresh Hello gesture");
    }
}

/// Parents the prompt to the caller's window. Without one the prompt gets no owner: falling back
/// to the foreground window could parent it to a window that belongs to another program.
fn parent_prompt(key: &Handle, parent_window: Option<u64>) {
    let Some(hwnd) = parent_window.and_then(|hwnd| usize::try_from(hwnd).ok()) else {
        tracing::debug!("no window to parent the Hello prompt to");
        return;
    };
    let bytes = hwnd.to_ne_bytes();
    if let Err(status) = set_property(key.raw(), NCRYPT_WINDOW_HANDLE_PROPERTY, &bytes) {
        tracing::warn!(status = %hex(status), "could not parent the Hello prompt");
    }
}

/// One `NCryptDecrypt` of the wrapped KEK (PKCS#1 v1.5, see `wrap_kek`). A successful decrypt must yield exactly 32 bytes.
#[expect(clippy::cast_possible_truncation)]
fn decrypt_once(key: &Handle, wrapped: &[u8]) -> NcResult<Zeroizing<[u8; KEK_LEN]>> {
    // RSA providers can demand a modulus-sized buffer even when the plaintext is shorter.
    let mut out = Zeroizing::new(vec![0_u8; wrapped.len().max(KEK_LEN)]);
    let mut written = 0_u32;
    // SAFETY: `wrapped` is a live slice and `out` is as long as the length passed; PKCS#1 padding
    // takes no padding info.
    let status = unsafe {
        NCryptDecrypt(
            key.raw(),
            wrapped.as_ptr(),
            wrapped.len() as u32,
            null(),
            out.as_mut_ptr(),
            out.len() as u32,
            &raw mut written,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    };
    if status != 0 {
        return Err(status);
    }
    let written = usize::try_from(written).expect("u32 fits in usize on 64-bit");
    if written != KEK_LEN {
        tracing::warn!(
            written,
            "Hello returned a key-encryption key of the wrong length"
        );
        return Err(NTE_BAD_LEN);
    }
    let mut kek = Zeroizing::new([0_u8; KEK_LEN]);
    kek.copy_from_slice(&out[..KEK_LEN]);
    Ok(kek)
}

#[expect(clippy::cast_possible_truncation)]
fn set_property(handle: usize, name: PCWSTR, value: &[u8]) -> NcResult<()> {
    // SAFETY: `name` is a static NUL-terminated string and `value` is a live slice whose length is
    // passed alongside it; the handle is valid for the caller's lifetime.
    let status = unsafe { NCryptSetProperty(handle, name, value.as_ptr(), value.len() as u32, 0) };
    if status == 0 { Ok(()) } else { Err(status) }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

#[expect(clippy::cast_sign_loss)]
fn hex(status: i32) -> String {
    // NTSTATUS and HRESULT values are conventionally displayed unsigned, with the error bit set.
    format!("{:#010x}", status as u32)
}

fn rng_error(err: rand::rngs::SysError) -> Error {
    Error::Io(std::io::Error::other(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_name_is_sid_prefixed_and_ncrypt_style() {
        assert_eq!(
            key_name("S-1-5-21-1"),
            "S-1-5-21-1//Vaultkeeper//Vaultkeeper"
        );
    }

    #[test]
    fn wide_encodes_utf16_and_terminates_with_nul() {
        assert_eq!(wide("hi"), vec![u16::from(b'h'), u16::from(b'i'), 0]);
        assert_eq!(wide(""), vec![0]);
    }

    #[test]
    fn hex_shows_hrresults_unsigned() {
        assert_eq!(hex(NTE_BAD_KEYSET), "0x80090016");
        assert_eq!(hex(0), "0x00000000");
    }

    #[test]
    fn only_a_configured_hello_is_available() {
        assert!(hello_usable(UserConsentVerifierAvailability::Available));
        for other in [
            UserConsentVerifierAvailability::DeviceNotPresent,
            UserConsentVerifierAvailability::NotConfiguredForUser,
            UserConsentVerifierAvailability::DisabledByPolicy,
            UserConsentVerifierAvailability::DeviceBusy,
        ] {
            assert!(!hello_usable(other));
        }
    }

    #[test]
    fn missing_or_unconfigured_hello_is_reported_as_not_set_up() {
        assert!(not_set_up(
            UserConsentVerifierAvailability::NotConfiguredForUser
        ));
        assert!(not_set_up(
            UserConsentVerifierAvailability::DeviceNotPresent
        ));
        assert!(!not_set_up(UserConsentVerifierAvailability::Available));
        assert!(!not_set_up(
            UserConsentVerifierAvailability::DisabledByPolicy
        ));
        assert!(!not_set_up(UserConsentVerifierAvailability::DeviceBusy));
    }

    #[test]
    fn a_bad_keyset_on_creation_means_hello_is_not_set_up() {
        assert!(matches!(
            creation_failure(NTE_BAD_KEYSET),
            Error::BiometricNotSetUp
        ));
        assert!(matches!(creation_failure(NTE_FOREGROUND), Error::Io(_)));
        assert!(matches!(creation_failure(-1), Error::Io(_)));
    }

    #[test]
    fn only_a_missing_key_invalidates_the_enrolment() {
        assert!(matches!(
            open_key_failure(NTE_BAD_KEYSET),
            Error::BiometricInvalidated
        ));
        assert!(matches!(
            open_key_failure(NTE_NO_KEY),
            Error::BiometricInvalidated
        ));
        assert!(matches!(
            open_key_failure(NTE_FOREGROUND),
            Error::BiometricFailed
        ));
        assert!(matches!(open_key_failure(-1), Error::BiometricFailed));
    }
}
