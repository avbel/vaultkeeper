//! Code-signature checks for the self-updater: the running app's designated requirement, and
//! whether a downloaded app bundle satisfies it.
//!
//! The requirement comes from the loaded code, not the file on disk, so a bundle swapped under a
//! running process cannot lower the bar. Only a certificate-signed app has a requirement worth
//! trusting: an ad-hoc one names a single cdhash, which no new build can ever match.

use std::path::Path;

use crate::Result;

/// The running app's designated requirement, e.g.
/// `identifier "org.vaultkeeper.desktop" and certificate leaf = H"…"`. Fails for unsigned and
/// ad-hoc signed code.
pub fn own_designated_requirement() -> Result<String> {
    imp::own_designated_requirement()
}

/// Accepts `bundle` only when its signature is intact (strict, nested code, every architecture),
/// satisfies `requirement`, carries `identifier` and uses the hardened runtime. The daemon trusts
/// its UI process by signature, so a build without the hardened runtime must never be installed.
pub fn verify_app_bundle(bundle: &Path, requirement: &str, identifier: &str) -> Result<()> {
    imp::verify_app_bundle(bundle, requirement, identifier)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::{ffi::c_void, path::Path, str::FromStr as _};

    use core_foundation::{
        array::CFArray,
        base::{CFType, TCFType},
        dictionary::{CFDictionary, CFDictionaryRef},
        number::CFNumber,
        string::{CFString, CFStringRef},
        url::CFURL,
    };
    use security_framework::os::macos::code_signing::{
        Flags, SecCode, SecRequirement, SecStaticCode,
    };

    use crate::{Error, Result};

    /// `kSecCSSigningInformation` (SecCode.h); not exported by security-framework-sys.
    const SIGNING_INFORMATION: u32 = 1 << 1;
    /// `CS_RUNTIME` (cs_blobs.h): the hardened runtime.
    const CS_RUNTIME: i64 = 0x1_0000;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecCodeInfoCertificates: CFStringRef;
        static kSecCodeInfoFlags: CFStringRef;
        static kSecCodeInfoIdentifier: CFStringRef;
        // Both take a SecStaticCodeRef; Apple documents that a SecCodeRef is accepted too.
        fn SecCodeCopySigningInformation(
            code: *const c_void,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
        fn SecCodeCopyDesignatedRequirement(
            code: *const c_void,
            flags: u32,
            requirement: *mut *const c_void,
        ) -> i32;
        fn SecRequirementCopyString(
            requirement: *const c_void,
            flags: u32,
            text: *mut CFStringRef,
        ) -> i32;
    }

    fn failed(what: &str, error: impl std::fmt::Display) -> Error {
        Error::CodeSignature(format!("{what}: {error}"))
    }

    fn signing_information(code: *const c_void) -> Result<CFDictionary<CFString, CFType>> {
        let mut info: CFDictionaryRef = std::ptr::null();
        // SAFETY: `code` is a live SecCode/SecStaticCode owned by the caller for the whole call;
        // `info` is a writable out pointer that receives a +1 dictionary on success.
        let status =
            unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &raw mut info) };
        if status != 0 || info.is_null() {
            return Err(failed("SecCodeCopySigningInformation", status));
        }
        // SAFETY: a non-null dictionary returned under the create rule.
        Ok(unsafe { CFDictionary::wrap_under_create_rule(info) })
    }

    fn lookup(info: &CFDictionary<CFString, CFType>, key: CFStringRef) -> Option<CFType> {
        // SAFETY: framework constants remain valid for the life of the process.
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        info.find(&key).map(|value| value.clone())
    }

    pub(super) fn own_designated_requirement() -> Result<String> {
        let code =
            SecCode::for_self(Flags::NONE).map_err(|error| failed("SecCodeCopySelf", error))?;
        let info = signing_information(code.as_CFTypeRef())?;
        // SAFETY: framework constant (see `lookup`).
        let certificates = lookup(&info, unsafe { kSecCodeInfoCertificates })
            .and_then(|value| value.downcast::<CFArray>())
            .map_or(0, |list| list.len());
        if certificates == 0 {
            return Err(Error::CodeSignature(
                "this app is not signed with a certificate (ad-hoc or unsigned)".to_owned(),
            ));
        }
        let mut requirement: *const c_void = std::ptr::null();
        // SAFETY: `code` is live; `requirement` receives a +1 SecRequirementRef on success.
        let status = unsafe {
            SecCodeCopyDesignatedRequirement(code.as_CFTypeRef(), 0, &raw mut requirement)
        };
        if status != 0 || requirement.is_null() {
            return Err(failed("SecCodeCopyDesignatedRequirement", status));
        }
        // SAFETY: a non-null requirement returned under the create rule.
        let requirement =
            unsafe { SecRequirement::wrap_under_create_rule(requirement.cast_mut().cast()) };
        let mut text: CFStringRef = std::ptr::null();
        // SAFETY: `requirement` is live; `text` receives a +1 CFString on success.
        let status =
            unsafe { SecRequirementCopyString(requirement.as_CFTypeRef(), 0, &raw mut text) };
        if status != 0 || text.is_null() {
            return Err(failed("SecRequirementCopyString", status));
        }
        // SAFETY: a non-null string returned under the create rule.
        let text = unsafe { CFString::wrap_under_create_rule(text) }.to_string();
        // An explicit requirement could name only the identifier, which any ad-hoc build matches.
        if !text.contains("certificate") {
            return Err(Error::CodeSignature(format!(
                "the designated requirement pins no certificate: {text}"
            )));
        }
        Ok(text)
    }

    pub(super) fn verify_app_bundle(
        bundle: &Path,
        requirement: &str,
        identifier: &str,
    ) -> Result<()> {
        let url = CFURL::from_path(bundle, true)
            .ok_or_else(|| Error::CodeSignature(format!("not a path: {}", bundle.display())))?;
        let code = SecStaticCode::from_path(&url, Flags::NONE)
            .map_err(|error| failed("SecStaticCodeCreateWithPath", error))?;
        let parsed = SecRequirement::from_str(requirement)
            .map_err(|error| failed("SecRequirementCreateWithString", error))?;
        code.check_validity(
            Flags::STRICT_VALIDATE
                | Flags::CHECK_NESTED_CODE
                | Flags::CHECK_ALL_ARCHITECTURES
                | Flags::RESTRICT_SYMLINKS,
            &parsed,
        )
        .map_err(|error| failed("SecStaticCodeCheckValidity", error))?;
        let info = signing_information(code.as_CFTypeRef())?;
        // SAFETY: framework constants (see `lookup`).
        let signed_as = lookup(&info, unsafe { kSecCodeInfoIdentifier })
            .and_then(|value| value.downcast::<CFString>())
            .map(|value| value.to_string());
        if signed_as.as_deref() != Some(identifier) {
            return Err(Error::CodeSignature(format!(
                "signed as {signed_as:?}, expected {identifier}"
            )));
        }
        // SAFETY: framework constant (see `lookup`).
        let flags = lookup(&info, unsafe { kSecCodeInfoFlags })
            .and_then(|value| value.downcast::<CFNumber>())
            .and_then(|value| value.to_i64())
            .unwrap_or(0);
        if flags & CS_RUNTIME == 0 {
            return Err(Error::CodeSignature(
                "the bundle does not use the hardened runtime".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::path::Path;

    use crate::{Error, Result};

    pub(super) fn own_designated_requirement() -> Result<String> {
        Err(Error::Unsupported)
    }

    pub(super) fn verify_app_bundle(_: &Path, _: &str, _: &str) -> Result<()> {
        Err(Error::Unsupported)
    }
}
