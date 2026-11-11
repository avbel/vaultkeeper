//! Per-connection challenge and pairing state.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use vk_ipc::browser::protocol::ErrorCode;

use super::pairing::{PairingStore, fingerprint, public_key, verify};

enum State {
    New,
    Challenged {
        key: [u8; 65],
        challenge: [u8; 32],
        known: bool,
    },
    Pending {
        key: [u8; 65],
    },
    Paired {
        key: [u8; 65],
    },
    Denied,
}

pub struct PairingSession {
    caller: String,
    state: State,
}

pub struct Challenge {
    pub challenge: String,
    pub known: bool,
}

pub enum Proof {
    Paired,
    ApprovalRequired { fingerprint: String },
}

impl PairingSession {
    #[must_use]
    pub fn new(caller: String) -> Self {
        Self {
            caller,
            state: State::New,
        }
    }

    pub fn hello(
        &mut self,
        protocol: u32,
        encoded_key: &str,
        store: &PairingStore,
    ) -> Result<Challenge, ErrorCode> {
        if !matches!(self.state, State::New) {
            return Err(ErrorCode::Denied);
        }
        if protocol != 1 {
            return Err(ErrorCode::BadRequest);
        }
        let key = public_key(encoded_key).map_err(|_| ErrorCode::BadRequest)?;
        let known = store.contains(&key, &self.caller);
        let challenge = rand::random::<[u8; 32]>();
        self.state = State::Challenged {
            key,
            challenge,
            known,
        };
        Ok(Challenge {
            challenge: STANDARD.encode(challenge),
            known,
        })
    }

    pub fn prove(&mut self, signature: &str, store: &PairingStore) -> Result<Proof, ErrorCode> {
        if !matches!(self.state, State::Challenged { .. }) {
            return Err(ErrorCode::Unpaired);
        }
        let State::Challenged {
            key,
            challenge,
            known,
        } = std::mem::replace(&mut self.state, State::Denied)
        else {
            return Err(ErrorCode::Unpaired);
        };
        if !verify(&key, &challenge, &self.caller, signature) {
            return Err(ErrorCode::Denied);
        }
        if known && store.contains(&key, &self.caller) {
            self.state = State::Paired { key };
            Ok(Proof::Paired)
        } else {
            self.state = State::Pending { key };
            Ok(Proof::ApprovalRequired {
                fingerprint: fingerprint(&key),
            })
        }
    }

    /// Approval becomes effective only after the caller has persisted the pairing.
    #[must_use]
    pub fn pending_key(&self) -> Option<&[u8; 65]> {
        match &self.state {
            State::Pending { key } => Some(key),
            _ => None,
        }
    }

    pub fn finish_pairing(&mut self, persisted: bool) -> Result<(), ErrorCode> {
        let State::Pending { key } = std::mem::replace(&mut self.state, State::Denied) else {
            return Err(ErrorCode::Unpaired);
        };
        if !persisted {
            return Err(ErrorCode::Denied);
        }
        self.state = State::Paired { key };
        Ok(())
    }

    #[must_use]
    pub fn paired_key(&self) -> Option<&[u8; 65]> {
        match &self.state {
            State::Paired { key } => Some(key),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use vk_ipc::browser::protocol::KnownBrowser;

    fn sign(key: &SigningKey, challenge: &str, caller: &str) -> String {
        let challenge = STANDARD.decode(challenge).expect("challenge");
        let mut message = b"vaultkeeper-browser-v1\0".to_vec();
        message.extend_from_slice(&challenge);
        message.extend_from_slice(caller.as_bytes());
        let signature: Signature = key.sign(&message);
        STANDARD.encode(signature.to_bytes())
    }

    #[test]
    fn unknown_requires_persisted_approval_and_known_key_proves_silently() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = PairingStore::load(&dir.path().join("browsers.json")).expect("store");
        let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
        let encoded = STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes());
        let caller = "extension";
        let mut session = PairingSession::new(caller.into());
        assert!(matches!(
            session.prove("too early", &store),
            Err(ErrorCode::Unpaired)
        ));
        assert!(session.paired_key().is_none());
        let challenge = session.hello(1, &encoded, &store).expect("hello");
        assert!(!challenge.known);
        assert!(matches!(
            session.prove(&sign(&key, &challenge.challenge, caller), &store),
            Ok(Proof::ApprovalRequired { .. })
        ));
        assert!(session.paired_key().is_none());
        assert!(session.pending_key().is_some());
        let pending = *session.pending_key().expect("pending key");
        store
            .approve(&pending, KnownBrowser::Firefox, caller, 1)
            .expect("persist");
        session.finish_pairing(true).expect("approve");
        assert!(session.paired_key().is_some());
        let mut next = PairingSession::new(caller.into());
        let challenge = next.hello(1, &encoded, &store).expect("hello");
        assert!(challenge.known);
        assert!(matches!(
            next.prove(&sign(&key, &challenge.challenge, caller), &store),
            Ok(Proof::Paired)
        ));
    }

    #[test]
    fn revocation_between_hello_and_prove_requires_new_approval() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = PairingStore::load(&dir.path().join("browsers.json")).expect("store");
        let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
        let encoded = STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes());
        let bytes = public_key(&encoded).expect("public key");
        store
            .approve(&bytes, KnownBrowser::Firefox, "extension", 1)
            .expect("approve");
        let mut session = PairingSession::new("extension".into());
        let challenge = session.hello(1, &encoded, &store).expect("hello");
        assert!(challenge.known);
        store.paired.clear();
        assert!(matches!(
            session.prove(&sign(&key, &challenge.challenge, "extension"), &store),
            Ok(Proof::ApprovalRequired { .. })
        ));
        assert!(session.paired_key().is_none());
    }

    #[test]
    fn invalid_proof_is_terminal() {
        let dir = tempfile::tempdir().expect("dir");
        let store = PairingStore::load(&dir.path().join("browsers.json")).expect("store");
        let key = SigningKey::from_bytes((&[7_u8; 32]).into()).expect("key");
        let encoded = STANDARD.encode(key.verifying_key().to_sec1_point(false).as_bytes());
        let mut session = PairingSession::new("extension".into());
        session.hello(1, &encoded, &store).expect("hello");
        assert!(matches!(
            session.prove("invalid", &store),
            Err(ErrorCode::Denied)
        ));
        assert!(matches!(
            session.hello(1, &encoded, &store),
            Err(ErrorCode::Denied)
        ));
        assert!(session.paired_key().is_none());
    }
}
