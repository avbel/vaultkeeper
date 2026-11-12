//! Security keys over USB HID with Mozilla's `authenticator` crate (CTAP2 and CTAP1/U2F). It
//! runs in the `--ui` process: an assertion carries no secret, and the login window that shows
//! the touch and PIN prompts lives here.
//!
//! macOS asks for no permission: FIDO devices (HID usage page 0xF1D0) are not keyboards, so
//! Input Monitoring does not apply to them.

use std::{
    sync::{
        Arc, Mutex, PoisonError,
        mpsc::{Sender, channel},
    },
    thread,
};

use authenticator::{
    Pin, SignResult, StatusPinUv, StatusUpdate,
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor, Transport,
        UserVerificationRequirement,
    },
    errors::{AuthenticatorError, PinError, U2FTokenError},
    statecallback::StateCallback,
};
use vk_webauthn::{Assertion, Ceremony, ClientDataJson, RequestOptions, UserVerification};
use zeroize::Zeroizing;

use crate::hooks::{HookError, HookResult, KeyCeremony, KeyEvent, KeyEvents, SecurityKeys};

/// Vaultwarden asks for 60 s; a missing or absurd timeout gets the WebAuthn default range.
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const MAX_TIMEOUT_MS: u64 = 600_000;

pub struct UsbSecurityKeys;

impl SecurityKeys for UsbSecurityKeys {
    fn sign(
        &self,
        options: RequestOptions,
        origin: String,
        events: KeyEvents,
    ) -> HookResult<Box<dyn KeyCeremony>> {
        let rp_id = options
            .rp_id
            .clone()
            .or_else(|| {
                url::Url::parse(&origin)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
            })
            .ok_or_else(|| HookError::Failed("The server sent no relying party".to_owned()))?;
        let client_data = ClientDataJson::new(Ceremony::Get, &options.challenge.0, &origin);
        let only_allowed = match options.allow_credentials.as_slice() {
            [single] => Some(single.id.0.clone()),
            _ => None,
        };
        let args = SignArgs {
            client_data_hash: client_data.hash(),
            origin,
            relying_party_id: rp_id,
            allow_list: options
                .allow_credentials
                .iter()
                .map(|credential| PublicKeyCredentialDescriptor {
                    id: credential.id.0.clone(),
                    transports: vec![Transport::USB],
                })
                .collect(),
            user_verification_req: match options.user_verification {
                UserVerification::Required => UserVerificationRequirement::Required,
                UserVerification::Preferred => UserVerificationRequirement::Preferred,
                UserVerification::Discouraged => UserVerificationRequirement::Discouraged,
            },
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                app_id: options.extensions.appid.clone(),
                ..AuthenticationExtensionsClientInputs::default()
            },
            pin: None,
            use_ctap1_fallback: false,
        };
        let timeout = options
            .timeout
            .filter(|ms| *ms > 0)
            .map_or(DEFAULT_TIMEOUT_MS, |ms| ms.min(MAX_TIMEOUT_MS));

        let pin = PinSlot::default();
        let (status_tx, status_rx) = channel();
        let status_events = events.clone();
        let status_pin = pin.clone();
        thread::Builder::new()
            .name("security-key-status".to_owned())
            .spawn(move || {
                for update in status_rx {
                    if let Some(event) = status_event(update, &status_pin) {
                        let _ = status_events.send(event);
                    }
                }
            })
            .map_err(|error| HookError::Failed(error.to_string()))?;

        let callback = StateCallback::new(Box::new(
            move |result: authenticator::Result<SignResult>| {
                let _ = events.send(KeyEvent::Done(outcome(result, &client_data, only_allowed)));
            },
        ));
        let mut service = AuthenticatorService::new().map_err(|error| platform_error(&error))?;
        service.add_u2f_usb_hid_platform_transports();
        service
            .sign(timeout, args, status_tx, callback)
            .map_err(|error| platform_error(&error))?;
        Ok(Box::new(UsbCeremony {
            service: Mutex::new(service),
            pin,
        }))
    }
}

/// Where the key's last PIN request waits for the answer.
#[derive(Clone, Default)]
struct PinSlot(Arc<Mutex<Option<Sender<Pin>>>>);

impl PinSlot {
    fn wait(&self, sender: Sender<Pin>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(sender);
    }

    fn take(&self) -> Option<Sender<Pin>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

struct UsbCeremony {
    service: Mutex<AuthenticatorService>,
    pin: PinSlot,
}

impl KeyCeremony for UsbCeremony {
    fn enter_pin(&self, pin: Zeroizing<String>) {
        if let Some(sender) = self.pin.take() {
            let _ = sender.send(Pin::new(&pin));
        }
    }

    fn cancel(&self) {
        // Dropping a pending PIN request lets the state machine see the cancel at once.
        drop(self.pin.take());
        let result = self
            .service
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cancel();
        if let Err(error) = result {
            tracing::debug!(%error, "security key cancel");
        }
    }
}

fn status_event(update: StatusUpdate, pin: &PinSlot) -> Option<KeyEvent> {
    match update {
        StatusUpdate::PresenceRequired => Some(KeyEvent::Touch),
        StatusUpdate::SelectDeviceNotice => Some(KeyEvent::ChooseKey),
        StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
            pin.wait(sender);
            Some(KeyEvent::Pin {
                wrong: false,
                attempts_left: None,
            })
        }
        StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts_left)) => {
            pin.wait(sender);
            Some(KeyEvent::Pin {
                wrong: true,
                attempts_left,
            })
        }
        // A 2FA challenge always names the allowed credential; take the first account.
        StatusUpdate::SelectResultNotice(sender, _) => {
            let _ = sender.send(Some(0));
            None
        }
        // The other PIN states end the request; its error reaches the result callback.
        StatusUpdate::PinUvError(_) | StatusUpdate::InteractiveManagement(_) => None,
    }
}

/// CTAP2 lets a key leave out the credential when the allow list had a single entry, and
/// authenticator-rs passes that on: `only_allowed` is that entry.
fn outcome(
    result: authenticator::Result<SignResult>,
    client_data: &ClientDataJson,
    only_allowed: Option<Vec<u8>>,
) -> HookResult<Assertion> {
    let result = result.map_err(sign_error)?;
    let credential_id = result
        .assertion
        .credentials
        .map(|credential| credential.id)
        .or(only_allowed)
        .ok_or_else(|| HookError::Failed("The security key did not name its key".to_owned()))?;
    Ok(Assertion {
        credential_id,
        authenticator_data: result.assertion.auth_data.to_vec(),
        client_data_json: client_data.as_bytes().to_vec(),
        signature: result.assertion.signature,
        user_handle: result.assertion.user.map(|user| user.id),
        appid_used: result.extensions.app_id,
    })
}

fn sign_error(error: AuthenticatorError) -> HookError {
    let text = match error {
        AuthenticatorError::CancelledByUser => return HookError::Cancelled,
        AuthenticatorError::U2FToken(U2FTokenError::NotAllowed) => {
            "No registered security key answered in time"
        }
        AuthenticatorError::U2FToken(U2FTokenError::InvalidState) => {
            "This security key is not registered for this account"
        }
        AuthenticatorError::PinError(error) => return pin_error(&error),
        other => {
            tracing::warn!(error = %other, "security key failed");
            "The security key could not be used"
        }
    };
    HookError::Failed(text.to_owned())
}

fn pin_error(error: &PinError) -> HookError {
    let text = match error {
        PinError::PinBlocked => "The security key's PIN is blocked: reset the key to use it again",
        PinError::PinAuthBlocked => "Too many wrong PINs: unplug the key and plug it in again",
        PinError::UvBlocked => "Fingerprint checks are blocked on this key: use its PIN",
        PinError::PinIsTooShort => "That PIN is too short",
        PinError::PinIsTooLong(_) => "That PIN is too long",
        _ => "The security key refused the PIN",
    };
    HookError::Failed(text.to_owned())
}

fn platform_error(error: &AuthenticatorError) -> HookError {
    tracing::warn!(%error, "security key access failed");
    HookError::Unavailable("Security key access")
}
