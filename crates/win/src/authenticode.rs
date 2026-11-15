//! Authenticode trust and signer lookup.
//!
//! The browser-host parent check (5e) needs to know who published the process's image, and the
//! updater (5h) needs to know whether an installer carries a valid signature at all. Revocation is
//! not checked: the check must also work on a machine that is offline or behind a captive portal.

use std::{
    ffi::c_void,
    io,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt as _,
    path::Path,
    ptr,
};

use windows_sys::Win32::Security::{
    Cryptography::{
        CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CertCloseStore,
        CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose,
        CryptMsgGetParam, CryptQueryObject, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    },
    WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    },
};

// Both structs are far below 4 GiB, so the casts cannot truncate.
#[expect(clippy::cast_possible_truncation)]
const WINTRUST_DATA_LEN: u32 = size_of::<WINTRUST_DATA>() as u32;
#[expect(clippy::cast_possible_truncation)]
const WINTRUST_FILE_INFO_LEN: u32 = size_of::<WINTRUST_FILE_INFO>() as u32;

/// The subject name of the certificate that signed `path`, or `None` when the file is unsigned or
/// its signature does not verify.
///
/// Only embedded signatures are inspected. Catalog-signed files (such as `explorer.exe`) have no
/// embedded signer and are reported as unsigned (`Ok(None)`).
pub fn signer_subject(path: &Path) -> io::Result<Option<String>> {
    let wide = wide_path(path);
    if !verify_trust(&wide) {
        return Ok(None);
    }
    signer_subject_of_file(&wide)
}

/// Whether `path` carries a signature that chains to a trusted root. Revocation is not checked.
#[must_use]
pub fn is_validly_signed(path: &Path) -> bool {
    verify_trust(&wide_path(path))
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn verify_trust(wide: &[u16]) -> bool {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: WINTRUST_FILE_INFO_LEN,
        pcwszFilePath: wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };
    // SAFETY: `WINTRUST_DATA` is a plain C struct of integers and pointers, so all-zero is a valid
    // initial value; the fields that must not stay zero are set below.
    let mut data: WINTRUST_DATA = unsafe { zeroed() };
    data.cbStruct = WINTRUST_DATA_LEN;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &raw mut file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `action` is a live copy of the static GUID, `data` points at a fully valid structure
    // and no UI is requested because `WTD_UI_NONE` is set.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &raw mut action,
            (&raw mut data).cast::<c_void>(),
        )
    };

    // WinVerifyTrust allocates state during VERIFY even when it fails, and only CLOSE releases it.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same as the call above; the state action now frees the state the first call created.
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &raw mut action,
            (&raw mut data).cast::<c_void>(),
        );
    }

    status == 0
}

fn signer_subject_of_file(wide: &[u16]) -> io::Result<Option<String>> {
    let mut store: HCERTSTORE = ptr::null_mut();
    let mut message: *mut c_void = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and lives for the call; the store and message out pointers
    // are ours, and the three type out pointers are unused (null).
    let query = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr().cast::<c_void>(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut store,
            &raw mut message,
            ptr::null_mut(),
        )
    };
    if query == 0 {
        // No embedded PKCS#7 signature: the file is unsigned or catalog-signed.
        return Ok(None);
    }
    // SAFETY: the query succeeded, so both handles are ours and each wrapper closes its own.
    let store = unsafe { CertStore::from_raw(store) };
    let message = unsafe { CertificateMessage::from_raw(message) };

    let mut size = 0_u32;
    // SAFETY: a null buffer with a zero length queries the required size.
    if unsafe {
        CryptMsgGetParam(
            message.0,
            CMSG_SIGNER_INFO_PARAM,
            0,
            ptr::null_mut(),
            &raw mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // `CMSG_SIGNER_INFO` holds pointers, so the buffer must be pointer-aligned; `u64` gives the
    // same alignment on every Windows target.
    let mut buffer = vec![
        0_u64;
        usize::try_from(size)
            .expect("u32 fits in usize on 64-bit")
            .div_ceil(size_of::<u64>())
    ];
    // SAFETY: the buffer is at least `size` bytes and aligned; the call writes at most `size`.
    if unsafe {
        CryptMsgGetParam(
            message.0,
            CMSG_SIGNER_INFO_PARAM,
            0,
            buffer.as_mut_ptr().cast::<c_void>(),
            &raw mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the call succeeded, so the buffer starts with a `CMSG_SIGNER_INFO` whose pointers
    // point into the same message; both stay valid until `message` drops.
    let signer_info = unsafe { &*buffer.as_ptr().cast::<CMSG_SIGNER_INFO>() };
    // SAFETY: `CERT_FIND_SUBJECT_CERT` expects a `CERT_INFO` prefix, which the signer info starts
    // with (issuer and serial number); `store` is live for the call.
    let certificate = unsafe {
        CertFindCertificateInStore(
            store.0,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            ptr::from_ref(signer_info).cast::<c_void>(),
            ptr::null(),
        )
    };
    if certificate.is_null() {
        return Ok(None);
    }
    // SAFETY: the find call returned a context this process owns.
    let certificate = unsafe { CertificateContext::from_raw(certificate) };

    let len = subject_len(&certificate);
    let mut name = vec![0_u16; usize::try_from(len).expect("u32 fits in usize on 64-bit")];
    // SAFETY: `name` has exactly the length the first call asked for and the context stays live.
    let written = unsafe {
        CertGetNameStringW(
            certificate.0,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            ptr::null(),
            name.as_mut_ptr(),
            len,
        )
    };
    if written <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the signer certificate has no subject name",
        ));
    }
    let written = usize::try_from(written).expect("u32 fits in usize on 64-bit");
    Ok(Some(String::from_utf16_lossy(&name[..written - 1])))
}

fn subject_len(certificate: &CertificateContext) -> u32 {
    // SAFETY: with a null buffer and zero length the call only reports the required length,
    // including the terminating NUL.
    unsafe {
        CertGetNameStringW(
            certificate.0,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            ptr::null(),
            ptr::null_mut(),
            0,
        )
    }
}

struct CertStore(HCERTSTORE);

impl CertStore {
    /// # Safety
    /// `raw` must be a store handle we own and have not wrapped elsewhere.
    unsafe fn from_raw(raw: HCERTSTORE) -> Self {
        Self(raw)
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CryptQueryObject` and is wrapped only here.
        unsafe {
            CertCloseStore(self.0, 0);
        }
    }
}

struct CertificateMessage(*mut c_void);

impl CertificateMessage {
    /// # Safety
    /// `raw` must be a message handle we own and have not wrapped elsewhere.
    unsafe fn from_raw(raw: *mut c_void) -> Self {
        Self(raw)
    }
}

impl Drop for CertificateMessage {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CryptQueryObject` and is wrapped only here.
        unsafe {
            CryptMsgClose(self.0);
        }
    }
}

struct CertificateContext(*const CERT_CONTEXT);

impl CertificateContext {
    /// # Safety
    /// `raw` must be a certificate context we own and have not wrapped elsewhere.
    unsafe fn from_raw(raw: *const CERT_CONTEXT) -> Self {
        Self(raw)
    }
}

impl Drop for CertificateContext {
    fn drop(&mut self) {
        // SAFETY: the context came from `CertFindCertificateInStore` and is wrapped only here.
        unsafe {
            CertFreeCertificateContext(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{is_validly_signed, signer_subject};

    const EDGE_PATHS: [&str; 2] = [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ];

    #[test]
    fn edge_reports_a_microsoft_signer() {
        let Some(path) = EDGE_PATHS.iter().map(Path::new).find(|path| path.exists()) else {
            // Edge is not installed everywhere; explorer.exe is catalog-signed so it cannot stand in.
            return;
        };
        let subject = signer_subject(path)
            .expect("verifying msedge.exe")
            .expect("msedge.exe carries an embedded signature");
        assert!(
            subject.contains("Microsoft"),
            "unexpected signer {subject:?} for msedge.exe"
        );
        assert!(is_validly_signed(path));
    }

    #[test]
    fn catalog_signed_files_have_no_embedded_signer() {
        let path = Path::new("C:\\Windows\\explorer.exe");
        assert!(
            signer_subject(path)
                .expect("looking up explorer.exe")
                .is_none()
        );
    }
}
