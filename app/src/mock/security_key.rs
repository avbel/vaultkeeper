//! A software security key for `--mock` and the UI tests: it asks for a touch, waits a moment
//! and signs. For servers whose host contains "pin" it first asks for [`MOCK_KEY_PIN`].

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender, channel},
    },
    thread,
    time::Duration,
};

use vk_webauthn::{
    Ceremony, ClientDataJson, FLAG_USER_PRESENT, FLAG_USER_VERIFIED, PasskeyKey, RequestOptions,
};
use zeroize::Zeroizing;

use crate::hooks::{HookError, HookResult, KeyCeremony, KeyEvent, KeyEvents, SecurityKeys};

/// The credential the mock server allows and the mock key holds.
pub const MOCK_KEY_ID: &[u8] = b"mock-security-key";
pub const MOCK_KEY_PIN: &str = "1234";

/// Long enough to see the "touch your key" prompt in `--mock`.
const TOUCH_DELAY: Duration = Duration::from_millis(1200);

#[derive(Default)]
pub struct MockSecurityKey {
    /// Answer at once, for the headless UI tests.
    pub instant: bool,
}

impl SecurityKeys for MockSecurityKey {
    fn sign(
        &self,
        options: RequestOptions,
        origin: String,
        events: KeyEvents,
    ) -> HookResult<Box<dyn KeyCeremony>> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let (pin_tx, pin_rx) = channel();
        let ceremony = MockCeremony {
            cancelled: Arc::clone(&cancelled),
            pin: pin_tx,
        };
        let delay = if self.instant {
            Duration::ZERO
        } else {
            TOUCH_DELAY
        };
        let run = move || {
            let result = touch_and_sign(&options, &origin, &events, &pin_rx, &cancelled, delay);
            let _ = events.send(KeyEvent::Done(result));
        };
        if self.instant {
            run();
        } else {
            thread::spawn(run);
        }
        Ok(Box::new(ceremony))
    }
}

struct MockCeremony {
    cancelled: Arc<AtomicBool>,
    pin: Sender<Zeroizing<String>>,
}

impl KeyCeremony for MockCeremony {
    fn enter_pin(&self, pin: Zeroizing<String>) {
        let _ = self.pin.send(pin);
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let _ = self.pin.send(Zeroizing::new(String::new()));
    }
}

fn touch_and_sign(
    options: &RequestOptions,
    origin: &str,
    events: &KeyEvents,
    pin: &Receiver<Zeroizing<String>>,
    cancelled: &AtomicBool,
    delay: Duration,
) -> HookResult<vk_webauthn::Assertion> {
    let rp_id = options.rp_id.clone().unwrap_or_default();
    let mut flags = FLAG_USER_PRESENT;
    if rp_id.contains("pin") {
        let mut wrong = false;
        loop {
            let _ = events.send(KeyEvent::Pin {
                wrong,
                attempts_left: wrong.then_some(7),
            });
            let entered = pin.recv().map_err(|_| HookError::Cancelled)?;
            if cancelled.load(Ordering::SeqCst) {
                return Err(HookError::Cancelled);
            }
            if entered.as_str() == MOCK_KEY_PIN {
                break;
            }
            wrong = true;
        }
        flags |= FLAG_USER_VERIFIED;
    }
    let _ = events.send(KeyEvent::Touch);
    thread::sleep(delay);
    if cancelled.load(Ordering::SeqCst) {
        return Err(HookError::Cancelled);
    }
    if !options
        .allow_credentials
        .iter()
        .any(|credential| credential.id.0 == MOCK_KEY_ID)
    {
        return Err(HookError::Failed(
            "This security key is not registered for this account".to_owned(),
        ));
    }
    let key = PasskeyKey::generate().map_err(|error| HookError::Failed(error.to_string()))?;
    let client_data = ClientDataJson::new(Ceremony::Get, &options.challenge.0, origin);
    Ok(vk_webauthn::get_assertion(
        &key,
        MOCK_KEY_ID,
        &rp_id,
        flags,
        0,
        &client_data,
    ))
}
