//! Windows half of [`super::harden_process`]: loader search path, process DACL and mitigation
//! policies, in that order so the DACL cleanup does not race with the mitigations it protects.
//!
//! Layout and rationale: docs/solutions/windows-support.md §5.1. The process DACL is the shape
//! Bitwarden applies in `core/src/process_isolation/windows.rs` (same GPL-3.0 licence).

use std::{
    ffi::c_void,
    io,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use tracing::{info, warn};
use vk_win::{SecurityDescriptor, current_user_sid, sddl};
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    Security::{
        ACL,
        Authorization::{SE_KERNEL_OBJECT, SetSecurityInfo},
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    },
    System::{
        Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode},
        LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories},
        Threading::{
            GetCurrentProcess, PROCESS_MITIGATION_POLICY, ProcessDynamicCodePolicy,
            ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSignaturePolicy,
            ProcessStrictHandleCheckPolicy, SetProcessMitigationPolicy,
        },
    },
};

use super::Role;

/// `NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images`.
const IMAGE_LOAD_FLAGS: u32 = 0b111;
/// `ProhibitDynamicCode`; Slint and Rust have no JIT.
const DYNAMIC_CODE_FLAGS: u32 = 0b1;
/// `DisableExtensionPoints`, which also turns off legacy IMEs.
const EXTENSION_POINT_FLAGS: u32 = 0b1;
/// `RaiseExceptionOnInvalidHandleReference | HandleExceptionsPermanentlyEnabled`.
const STRICT_HANDLE_FLAGS: u32 = 0b11;
/// `MicrosoftSignedOnly`: blocks arbitrary unsigned images, including AV user-mode hooks.
const BINARY_SIGNATURE_FLAGS: u32 = 0b1;

/// A mitigation policy and the flag word Windows takes for it.
pub type Policy = (PROCESS_MITIGATION_POLICY, u32);

/// The policies every UI process runs under. `ProhibitDynamicCode` is not in the set: it can break
/// IMEs and screen readers that inject code, so the UI gets it only in strict mode. Exported so the daemon can pass the same set to
/// `spawn_hardened` (step 2e), where a policy must be in place before the UI's first instruction.
/// The UI deliberately never gets `MicrosoftSignedOnly`: its file dialog loads third-party shell
/// extensions (OneDrive, Dropbox, TortoiseGit).
pub const UI_MITIGATIONS: &[Policy] = &[
    (ProcessImageLoadPolicy, IMAGE_LOAD_FLAGS),
    (ProcessStrictHandleCheckPolicy, STRICT_HANDLE_FLAGS),
];

pub(super) static DACL_APPLIED: AtomicBool = AtomicBool::new(false);

pub(super) fn harden(role: Role) {
    // A crash must end the process at once: the daemon reaps a UI that is stuck in the system's
    // crash dialog only after its 20 s hang timeout, and logs nothing about why.
    // SAFETY: takes flag values only and changes this process's error mode.
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
    set_loader_search_path();

    match current_user_sid() {
        Ok(sid) => match apply_process_dacl(&sid) {
            Ok(()) => {
                DACL_APPLIED.store(true, Ordering::Relaxed);
                info!("process DACL applied");
            }
            Err(error) => warn!(%error, "could not apply the process DACL"),
        },
        Err(error) => warn!(%error, "could not read the user SID for the process DACL"),
    }

    for (policy, flags) in policies(role, strict_enabled()) {
        match apply_policy(policy, flags) {
            Ok(()) => {}
            Err(error) => warn!(policy, flags, %error, "mitigation policy not applied"),
        }
    }
}

/// `MicrosoftSignedOnly` and the UI's `ProhibitDynamicCode` and `ExtensionPointDisable` stay off until the antivirus, IME
/// and screen-reader tests in checklist 7a pass; they break common same-user software.
fn strict_enabled() -> bool {
    std::env::var("VAULTKEEPER_STRICT_MITIGATIONS").is_ok_and(|value| value == "1")
}

fn policies(role: Role, strict: bool) -> Vec<Policy> {
    let mut policies = UI_MITIGATIONS.to_vec();
    if role == Role::Daemon || strict {
        policies.push((ProcessDynamicCodePolicy, DYNAMIC_CODE_FLAGS));
        policies.push((ProcessExtensionPointDisablePolicy, EXTENSION_POINT_FLAGS));
    }
    if role == Role::Daemon && strict {
        policies.push((ProcessSignaturePolicy, BINARY_SIGNATURE_FLAGS));
    }
    policies
}

fn set_loader_search_path() {
    // SAFETY: the call takes no pointers and only changes this process's DLL search order.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        warn!(
            error = %io::Error::last_os_error(),
            "could not restrict the DLL search path to System32"
        );
    }
}

fn apply_process_dacl(sid: &str) -> io::Result<()> {
    let sddl = sddl::process(sid)?;
    let descriptor = SecurityDescriptor::from_sddl(&sddl)?;

    let mut present = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: `descriptor` owns a live security descriptor; the three out pointers are ours and
    // the descriptor outlives the call.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process SDDL produced no DACL",
        ));
    }

    // SAFETY: the pseudo-handle has full access to this process; `dacl` points into `descriptor`,
    // which outlives the call, and PROTECTED_DACL stops a child's inherited ACE from widening it.
    let result = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(match i32::try_from(result) {
            Ok(code) => io::Error::from_raw_os_error(code),
            Err(_) => io::Error::other(format!("SetSecurityInfo failed with {result:#x}")),
        })
    }
}

fn apply_policy(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> io::Result<()> {
    // Every policy used here is a single 32-bit flag word in a one-field union, so a `u32` has the
    // exact layout `SetProcessMitigationPolicy` reads.
    // SAFETY: `flags` outlives the call and the size matches the union Windows expects.
    if unsafe {
        SetProcessMitigationPolicy(
            policy,
            (&raw const flags).cast::<c_void>(),
            size_of::<u32>(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(policies: &[Policy], policy: PROCESS_MITIGATION_POLICY) -> bool {
        policies.iter().any(|(candidate, _)| *candidate == policy)
    }

    #[test]
    fn daemon_disables_extension_points_and_signs_binaries_only_in_strict_mode() {
        let relaxed = policies(Role::Daemon, false);
        assert!(contains(&relaxed, ProcessExtensionPointDisablePolicy));
        assert!(!contains(&relaxed, ProcessSignaturePolicy));

        let strict = policies(Role::Daemon, true);
        assert!(contains(&strict, ProcessExtensionPointDisablePolicy));
        assert!(contains(&strict, ProcessSignaturePolicy));
    }

    #[test]
    fn hardening_records_the_applied_process_dacl() {
        harden(Role::Daemon);
        assert!(DACL_APPLIED.load(Ordering::Relaxed));
    }

    #[test]
    fn ui_never_requires_microsoft_signed_binaries() {
        for strict in [false, true] {
            let policies = policies(Role::Ui, strict);
            assert!(!contains(&policies, ProcessSignaturePolicy));
            assert_eq!(
                contains(&policies, ProcessExtensionPointDisablePolicy),
                strict
            );
            assert_eq!(contains(&policies, ProcessDynamicCodePolicy), strict);
        }
    }

    #[test]
    fn every_ui_policy_is_in_the_exported_set() {
        for (policy, flags) in policies(Role::Ui, false) {
            assert!(
                UI_MITIGATIONS.contains(&(policy, flags)),
                "policy {policy} missing from UI_MITIGATIONS"
            );
        }
    }
}
