//! The Windows backend over `webauthn.dll` (windows-sys `Win32_Networking_WindowsWebServices`).
//! Windows draws the PIN and touch UI itself, so no `Touch` or `Pin` event is ever sent and the
//! login window only says to follow the Windows prompt.
//!
//! Bitwarden's `win_webauthn` crate wraps the plugin side of `webauthn.dll` only, so the client
//! `GetAssertion` call is written here.

use std::{ptr, slice, thread};

use vk_webauthn::{Assertion, Ceremony, ClientDataJson, RequestOptions, UserVerification};
use windows_sys::{
    Win32::{
        Foundation::HWND,
        Networking::WindowsWebServices::{
            WEBAUTHN_ASSERTION, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
            WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
            WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4, WEBAUTHN_CLIENT_DATA,
            WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_EX,
            WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST,
            WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_BLE,
            WEBAUTHN_CTAP_TRANSPORT_NFC, WEBAUTHN_CTAP_TRANSPORT_USB,
            WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED, WebAuthNAuthenticatorGetAssertion,
            WebAuthNCancelCurrentOperation, WebAuthNFreeAssertion, WebAuthNGetApiVersionNumber,
            WebAuthNGetCancellationId,
        },
        UI::WindowsAndMessaging::GetForegroundWindow,
    },
    core::GUID,
};

use super::{DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, relying_party, status::error_for};
use crate::hooks::{HookError, HookResult, KeyCeremony, KeyEvent, KeyEvents};

/// The first API version whose options carry the allow-credential list and the cancellation id.
const MIN_API_VERSION: u32 = 4;
/// Every external transport; platform (Hello) and hybrid credentials are not security keys.
const KEY_TRANSPORTS: u32 =
    WEBAUTHN_CTAP_TRANSPORT_USB | WEBAUTHN_CTAP_TRANSPORT_NFC | WEBAUTHN_CTAP_TRANSPORT_BLE;

pub(super) fn sign(
    options: &RequestOptions,
    origin: &str,
    parent: Option<u64>,
    events: KeyEvents,
) -> HookResult<Box<dyn KeyCeremony>> {
    // SAFETY: the function takes no arguments and only reads the loaded DLL's version.
    if unsafe { WebAuthNGetApiVersionNumber() } < MIN_API_VERSION {
        return Err(HookError::Unavailable("Security key access"));
    }
    let request = Request::new(options, origin, parent)?;
    let mut cancellation = GUID::from_u128(0);
    // SAFETY: `cancellation` is a valid GUID the call fills in.
    let hresult = unsafe { WebAuthNGetCancellationId(&raw mut cancellation) };
    if hresult < 0 {
        return Err(error_for(hresult));
    }
    thread::Builder::new()
        .name("security-key-webauthn".to_owned())
        .spawn(move || {
            let _ = events.send(KeyEvent::Done(request.run(&mut cancellation)));
        })
        .map_err(|error| HookError::Failed(error.to_string()))?;
    Ok(Box::new(WindowsCeremony { cancellation }))
}

struct WindowsCeremony {
    cancellation: GUID,
}

impl KeyCeremony for WindowsCeremony {
    // Windows asks for the PIN in its own dialog.
    fn enter_pin(&self, _pin: zeroize::Zeroizing<String>) {}

    fn cancel(&self) {
        // SAFETY: the id was issued by WebAuthNGetCancellationId; cancelling a call that has
        // already finished is a harmless error.
        let hresult = unsafe { WebAuthNCancelCurrentOperation(&raw const self.cancellation) };
        if hresult < 0 {
            tracing::debug!(hresult, "security key cancel");
        }
    }
}

/// Everything the blocking call points into, owned in one place so the pointers stay valid.
struct Request {
    parent: Option<u64>,
    rp_id: Vec<u16>,
    client_data: ClientDataJson,
    credential_ids: Vec<Vec<u8>>,
    app_id: Option<Vec<u16>>,
    user_verification: u32,
    timeout_ms: u32,
}

// SAFETY: it holds only owned buffers and an HWND number; the pointers into them are built on
// the thread that runs the call.
unsafe impl Send for Request {}

impl Request {
    fn new(options: &RequestOptions, origin: &str, parent: Option<u64>) -> HookResult<Self> {
        let rp_id = relying_party(options, origin)?;
        let client_data = ClientDataJson::new(Ceremony::Get, &options.challenge.0, origin);
        let timeout_ms = options
            .timeout
            .filter(|ms| *ms > 0)
            .map_or(DEFAULT_TIMEOUT_MS, |ms| ms.min(MAX_TIMEOUT_MS));
        Ok(Self {
            parent,
            rp_id: wide(&rp_id),
            client_data,
            credential_ids: options
                .allow_credentials
                .iter()
                .map(|credential| credential.id.0.clone())
                .collect(),
            app_id: options.extensions.appid.as_deref().map(wide),
            user_verification: match options.user_verification {
                UserVerification::Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                UserVerification::Preferred => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
                UserVerification::Discouraged => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            },
            timeout_ms: u32::try_from(timeout_ms).unwrap_or(u32::MAX),
        })
    }

    fn run(&self, cancellation: &mut GUID) -> HookResult<Assertion> {
        let hwnd: HWND = match self.parent {
            Some(handle) => {
                usize::try_from(handle).map_or(ptr::null_mut(), ptr::with_exposed_provenance_mut)
            }
            // SAFETY: no arguments; a null result is accepted by the API as "no parent".
            None => unsafe { GetForegroundWindow() },
        };
        let mut data = self.client_data.as_bytes().to_vec();
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: u32::try_from(data.len())
                .map_err(|_| HookError::Failed("The security key challenge is too large".into()))?,
            pbClientDataJSON: data.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut credentials = Vec::with_capacity(self.credential_ids.len());
        for id in &self.credential_ids {
            credentials.push(WEBAUTHN_CREDENTIAL_EX {
                dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                cbId: u32::try_from(id.len())
                    .map_err(|_| HookError::Failed("A credential id is too large".into()))?,
                pbId: id.as_ptr().cast_mut(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                dwTransports: KEY_TRANSPORTS,
            });
        }
        let mut pointers: Vec<*mut WEBAUTHN_CREDENTIAL_EX> =
            credentials.iter_mut().map(ptr::from_mut).collect();
        let mut list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: u32::try_from(pointers.len()).unwrap_or(u32::MAX),
            ppCredentials: pointers.as_mut_ptr(),
        };
        let mut app_id_used = 0;
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4,
            dwTimeoutMilliseconds: self.timeout_ms,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
            dwUserVerificationRequirement: self.user_verification,
            pwszU2fAppId: self.app_id.as_ref().map_or(ptr::null(), Vec::as_ptr),
            pbU2fAppId: if self.app_id.is_some() {
                &raw mut app_id_used
            } else {
                ptr::null_mut()
            },
            pCancellationId: cancellation,
            pAllowCredentialList: if pointers.is_empty() {
                ptr::null_mut()
            } else {
                &raw mut list
            },
            ..WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS::default()
        };
        let mut assertion: *mut WEBAUTHN_ASSERTION = ptr::null_mut();
        // SAFETY: every pointer refers to a buffer that lives until the call returns on this
        // thread (`self`, `data`, `credentials`, `pointers`, `list`, `app_id_used`,
        // `cancellation`); `hwnd` is the login window or the foreground window, and the API
        // allocates `assertion`, which `Assertion::take` frees.
        let hresult = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                hwnd,
                self.rp_id.as_ptr(),
                &raw const client,
                &raw const options,
                &raw mut assertion,
            )
        };
        if hresult < 0 {
            return Err(error_for(hresult));
        }
        let mut result = take_assertion(assertion, &data)?;
        result.appid_used = self.app_id.is_some().then_some(app_id_used != 0);
        Ok(result)
    }
}

struct Freed(*mut WEBAUTHN_ASSERTION);

impl Drop for Freed {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful GetAssertion and is freed once.
        unsafe { WebAuthNFreeAssertion(self.0) };
    }
}

/// Copies the bytes out of the DLL's allocation and frees it.
fn take_assertion(assertion: *mut WEBAUTHN_ASSERTION, client_data: &[u8]) -> HookResult<Assertion> {
    if assertion.is_null() {
        return Err(HookError::Failed(
            "The security key returned no answer".to_owned(),
        ));
    }
    let guard = Freed(assertion);
    // SAFETY: a successful call returns a valid WEBAUTHN_ASSERTION until it is freed.
    let raw = unsafe { &*guard.0 };
    let copy = |bytes: *const u8, len: u32| -> Vec<u8> {
        if bytes.is_null() || len == 0 {
            return Vec::new();
        }
        // SAFETY: the DLL reports `len` readable bytes at `bytes` inside the assertion.
        unsafe { slice::from_raw_parts(bytes, len as usize) }.to_vec()
    };
    let credential_id = copy(raw.Credential.pbId, raw.Credential.cbId);
    if credential_id.is_empty() {
        return Err(HookError::Failed(
            "The security key did not name its key".to_owned(),
        ));
    }
    let user_handle = copy(raw.pbUserId, raw.cbUserId);
    Ok(Assertion {
        credential_id,
        authenticator_data: copy(raw.pbAuthenticatorData, raw.cbAuthenticatorData),
        client_data_json: client_data.to_vec(),
        signature: copy(raw.pbSignature, raw.cbSignature),
        user_handle: (!user_handle.is_empty()).then_some(user_handle),
        appid_used: None,
    })
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
