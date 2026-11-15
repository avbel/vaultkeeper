//! Windows Hello presence check without a key: `UserConsentVerifier`, parented to a window of the
//! UI process so the dialog comes up in the foreground (docs/solutions/windows-support.md §3.3).

use std::{ffi::c_void, ptr, thread};

use windows::{
    Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier},
    Win32::{
        Foundation::HWND,
        System::WinRT::{
            IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize,
        },
    },
    core::{HSTRING, factory},
};

use windows_future::IAsyncOperation;

use crate::{Error, Result};

/// Only `Verified` passes: cancel, retries exhausted, no Hello set up and policy blocks all deny,
/// and so does a missing window, because the interop call has nothing to parent the dialog to.
pub(super) fn authenticate(reason: &str, parent_window: Option<u64>) -> Result<()> {
    let hwnd = parent_window
        .and_then(|hwnd| usize::try_from(hwnd).ok())
        .ok_or_else(|| {
            tracing::debug!("no UI window to parent the Windows Hello check to");
            Error::BiometricFailed
        })?;
    let reason = reason.to_owned();
    // A fresh thread, because WinRT needs the multithreaded apartment and a pooled blocking thread
    // may already be initialised differently.
    let worker = thread::Builder::new()
        .name("hello-consent".to_owned())
        .spawn(move || verify(hwnd, &reason))
        .map_err(Error::Io)?;
    worker.join().map_err(|_| Error::BiometricFailed)?
}

fn verify(hwnd: usize, reason: &str) -> Result<()> {
    // SAFETY: balanced by the `RoUninitialize` below on every path that gets this far; the thread
    // is private to this call.
    if let Err(error) = unsafe { RoInitialize(RO_INIT_MULTITHREADED) } {
        tracing::warn!(%error, "RoInitialize failed");
        return Err(Error::BiometricFailed);
    }
    let result = request(hwnd, reason);
    // SAFETY: pairs with the successful `RoInitialize` above, after every WinRT object is dropped.
    unsafe { RoUninitialize() };
    match result {
        Ok(result) if result == UserConsentVerificationResult::Verified => Ok(()),
        Ok(result) => {
            tracing::info!(result = result.0, "Windows Hello did not verify");
            Err(Error::BiometricFailed)
        }
        Err(error) => {
            tracing::warn!(%error, "Windows Hello check failed");
            Err(Error::BiometricFailed)
        }
    }
}

fn request(hwnd: usize, reason: &str) -> windows::core::Result<UserConsentVerificationResult> {
    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let window = HWND(ptr::with_exposed_provenance_mut::<c_void>(hwnd));
    // SAFETY: the handle is a plain value the daemon already checked against the UI process; a
    // window that went away makes the call fail, not misbehave.
    let operation: IAsyncOperation<UserConsentVerificationResult> =
        unsafe { interop.RequestVerificationForWindowAsync(window, &HSTRING::from(reason)) }?;
    operation.join()
}
