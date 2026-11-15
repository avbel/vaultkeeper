//! DPAPI wrapping for secrets that must stay bound to this machine and this user's logon.
//!
//! The app adapts these functions to its token store's blob-wrapper seam; keeping the crate split
//! means `vk-platform` never has to know about `SecretStore`.

use std::{io, ptr, slice};

use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::Zeroizing;

/// Encrypts `data` under the current user's DPAPI key.
///
/// `entropy` is a public second factor that only stops generic DPAPI tools from decrypting our
/// blobs; callers pass a constant plus the user id.
pub fn protect(data: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
    let input = checked_blob(data)?;
    let entropy = optional_blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` reads `data`, which outlives the call, and both optional pointers point at
    // values that live until the function returns; null is the documented "no entropy" encoding.
    if unsafe {
        CryptProtectData(
            &raw const input,
            ptr::null(),
            entropy.as_ref().map_or(ptr::null(), ptr::from_ref),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `output` holds a `LocalAlloc`'d buffer of `output.cbData` bytes.
    Ok(unsafe { take_blob(output) })
}

/// Decrypts a blob produced by [`protect`] for the same user, machine and entropy.
pub fn unprotect(blob: &[u8], entropy: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let input = checked_blob(blob)?;
    let entropy = optional_blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: same pointer contract as `protect`; a null description out-parameter is allowed
    // because we do not need the stored label.
    if unsafe {
        CryptUnprotectData(
            &raw const input,
            ptr::null_mut(),
            entropy.as_ref().map_or(ptr::null(), ptr::from_ref),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `output` holds a `LocalAlloc`'d buffer of `output.cbData` bytes.
    Ok(Zeroizing::new(unsafe { take_blob(output) }))
}

fn checked_blob(data: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    let len = u32::try_from(data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DPAPI blob is longer than 4 GiB",
        )
    })?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: len,
        // The field is mutable only because the struct is shared with APIs that write; both DPAPI
        // calls treat the input as read-only.
        pbData: data.as_ptr().cast_mut(),
    })
}

fn optional_blob(data: &[u8]) -> io::Result<Option<CRYPT_INTEGER_BLOB>> {
    if data.is_empty() {
        Ok(None)
    } else {
        checked_blob(data).map(Some)
    }
}

/// Copies a `LocalAlloc`'d output blob and releases it.
///
/// # Safety
/// `blob.pbData` must come from a Win32 call that allocated it with `LocalAlloc`, and
/// `blob.cbData` must be its byte length.
unsafe fn take_blob(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if blob.pbData.is_null() {
        return Vec::new();
    }
    let len = usize::try_from(blob.cbData).expect("u32 fits in usize on 64-bit");
    // SAFETY: the caller promises the buffer is `cbData` bytes long and still ours.
    let copied = unsafe { slice::from_raw_parts(blob.pbData, len) }.to_vec();
    // SAFETY: `LocalFree` matches the allocation the DPAPI call made.
    unsafe {
        LocalFree(blob.pbData.cast());
    }
    copied
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8] = b"vaultkeeper test entropy";

    #[test]
    fn round_trip_returns_the_plaintext() {
        let blob = protect(b"refresh token material", ENTROPY).expect("protect");
        assert_ne!(blob, b"refresh token material");
        let plaintext = unprotect(&blob, ENTROPY).expect("unprotect");
        assert_eq!(plaintext.as_slice(), b"refresh token material");
    }

    #[test]
    fn wrong_entropy_does_not_decrypt() {
        let blob = protect(b"secret", ENTROPY).expect("protect");
        assert!(unprotect(&blob, b"other entropy").is_err());
    }

    #[test]
    fn tampered_blob_does_not_decrypt() {
        let mut blob = protect(b"secret", ENTROPY).expect("protect");
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(unprotect(&blob, ENTROPY).is_err());
    }
}
