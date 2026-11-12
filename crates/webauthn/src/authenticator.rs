//! A software authenticator for vault passkeys: P-256 keys, `authenticatorData`, the `none`
//! attestation and ES256 assertions, laid out byte for byte as the Bitwarden clients do
//! (libs/common/src/platform/services/fido2/fido2-authenticator.service.ts).

use std::fmt;

use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    elliptic_curve::Generate as _,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _},
};
use rand::rngs::SysRng;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{ClientDataJson, Error, Result};

pub const FLAG_USER_PRESENT: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x04;
pub const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
pub const FLAG_BACKED_UP: u8 = 0x10;
pub const FLAG_ATTESTED_DATA: u8 = 0x40;

/// Flags of a synced vault passkey: always backup eligible and backed up.
pub const PASSKEY_FLAGS: u8 = FLAG_USER_PRESENT | FLAG_BACKUP_ELIGIBLE | FLAG_BACKED_UP;

/// Vaultkeeper's own authenticator model id (5168fedb-cda8-451b-9975-f6fb9e667cbd), so sites
/// that name the provider of a passkey do not attribute ours to another product.
pub const AAGUID: [u8; 16] = [
    0x51, 0x68, 0xfe, 0xdb, 0xcd, 0xa8, 0x45, 0x1b, 0x99, 0x75, 0xf6, 0xfb, 0x9e, 0x66, 0x7c, 0xbd,
];

/// The private key of one passkey. Stored in the vault as base64url PKCS#8 (`keyValue`).
pub struct PasskeyKey(SigningKey);

impl fmt::Debug for PasskeyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyKey(..)")
    }
}

impl PasskeyKey {
    pub fn generate() -> Result<Self> {
        let secret = SecretKey::try_generate_from_rng(&mut SysRng)
            .map_err(|error| Error::Random(error.to_string()))?;
        Ok(Self(SigningKey::from(&secret)))
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        SigningKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let document = self.0.to_pkcs8_der().map_err(|_| Error::InvalidKey)?;
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }

    /// SubjectPublicKeyInfo DER, what `AuthenticatorAttestationResponse.getPublicKey()` returns.
    pub fn public_key_spki_der(&self) -> Result<Vec<u8>> {
        self.0
            .verifying_key()
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Error::InvalidKey)
    }

    /// COSE_Key (EC2, ES256, P-256) in CTAP2 canonical CBOR.
    #[must_use]
    pub fn cose_public_key(&self) -> Vec<u8> {
        // P-256 keys serialize uncompressed: 0x04 || x || y.
        let point = self.0.verifying_key().to_sec1_bytes();
        let (x, y) = point[1..].split_at(32);
        let mut cose = Vec::with_capacity(77);
        // {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
        cose.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        cose.extend_from_slice(x);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(y);
        cose
    }

    /// ES256 over `authenticatorData || SHA-256(clientDataJSON)`, DER encoded as WebAuthn requires.
    fn sign(&self, authenticator_data: &[u8], client_data_hash: &[u8; 32]) -> Vec<u8> {
        let mut message = authenticator_data.to_vec();
        message.extend_from_slice(client_data_hash);
        let signature: Signature = self.0.sign(&message);
        signature.to_der().as_bytes().to_vec()
    }
}

/// `rpIdHash || flags || signCount` plus, when `attested` is given, the attested credential data.
#[must_use]
pub fn authenticator_data(
    rp_id: &str,
    flags: u8,
    counter: u32,
    attested: Option<(&[u8], &PasskeyKey)>,
) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    let flags = if attested.is_some() {
        flags | FLAG_ATTESTED_DATA
    } else {
        flags & !FLAG_ATTESTED_DATA
    };
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    if let Some((credential_id, key)) = attested {
        data.extend_from_slice(&AAGUID);
        let length = u16::try_from(credential_id.len()).unwrap_or(u16::MAX);
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(&key.cose_public_key());
    }
    data
}

/// `{"fmt": "none", "attStmt": {}, "authData": ...}` in CTAP2 canonical key order.
#[must_use]
pub fn attestation_object_none(authenticator_data: &[u8]) -> Vec<u8> {
    let mut object = vec![0xa3, 0x63];
    object.extend_from_slice(b"fmt");
    object.push(0x64);
    object.extend_from_slice(b"none");
    object.push(0x67);
    object.extend_from_slice(b"attStmt");
    object.push(0xa0);
    object.push(0x68);
    object.extend_from_slice(b"authData");
    match u8::try_from(authenticator_data.len()) {
        Ok(length) if length < 24 => object.push(0x40 | length),
        Ok(length) => object.extend_from_slice(&[0x58, length]),
        Err(_) => {
            let length = u16::try_from(authenticator_data.len()).unwrap_or(u16::MAX);
            object.push(0x59);
            object.extend_from_slice(&length.to_be_bytes());
        }
    }
    object.extend_from_slice(authenticator_data);
    object
}

/// The result of `navigator.credentials.get()`, before it is shaped for its recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    /// `Some(true)` when a security key answered for the U2F AppID instead of the rpId.
    pub appid_used: Option<bool>,
}

/// The result of `navigator.credentials.create()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub public_key_spki: Vec<u8>,
}

pub fn make_credential(
    key: &PasskeyKey,
    credential_id: &[u8],
    rp_id: &str,
    flags: u8,
    client_data: &ClientDataJson,
) -> Result<Registration> {
    let authenticator_data = authenticator_data(rp_id, flags, 0, Some((credential_id, key)));
    Ok(Registration {
        credential_id: credential_id.to_vec(),
        client_data_json: client_data.as_bytes().to_vec(),
        attestation_object: attestation_object_none(&authenticator_data),
        authenticator_data,
        public_key_spki: key.public_key_spki_der()?,
    })
}

#[must_use]
pub fn get_assertion(
    key: &PasskeyKey,
    credential_id: &[u8],
    rp_id: &str,
    flags: u8,
    counter: u32,
    client_data: &ClientDataJson,
) -> Assertion {
    let authenticator_data = authenticator_data(rp_id, flags, counter, None);
    let signature = key.sign(&authenticator_data, &client_data.hash());
    Assertion {
        credential_id: credential_id.to_vec(),
        authenticator_data,
        client_data_json: client_data.as_bytes().to_vec(),
        signature,
        user_handle: None,
        appid_used: None,
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{VerifyingKey, signature::Verifier as _};

    use super::*;
    use crate::Ceremony;

    #[test]
    fn assertion_signature_verifies_over_auth_data_and_client_data_hash() {
        let key = PasskeyKey::generate().expect("key");
        let client_data = ClientDataJson::new(Ceremony::Get, b"challenge", "https://example.com");
        let assertion = get_assertion(&key, b"id", "example.com", PASSKEY_FLAGS, 7, &client_data);

        let data = &assertion.authenticator_data;
        assert_eq!(data.len(), 37);
        assert_eq!(data[..32], Sha256::digest(b"example.com")[..]);
        assert_eq!(data[32], 0x19);
        assert_eq!(data[33..37], [0, 0, 0, 7]);

        let mut message = data.clone();
        message.extend_from_slice(&client_data.hash());
        let signature = Signature::from_der(&assertion.signature).expect("DER signature");
        VerifyingKey::from(&key.0)
            .verify(&message, &signature)
            .expect("signature verifies");
    }

    #[test]
    fn registration_carries_aaguid_credential_and_cose_key_in_a_none_attestation() {
        let key = PasskeyKey::generate().expect("key");
        let client_data = ClientDataJson::new(Ceremony::Create, b"c", "https://example.com");
        let id = [9_u8; 16];
        let registration = make_credential(&key, &id, "example.com", PASSKEY_FLAGS, &client_data)
            .expect("registration");

        let data = &registration.authenticator_data;
        assert_eq!(data[32], 0x59);
        assert_eq!(data[37..53], AAGUID);
        assert_eq!(data[53..55], [0, 16]);
        assert_eq!(data[55..71], id);
        let cose = &data[71..];
        assert_eq!(cose.len(), 77);
        let point = key.0.verifying_key().to_sec1_bytes();
        assert_eq!(&cose[10..42], &point[1..33]);
        assert_eq!(&cose[45..77], &point[33..65]);

        let object = &registration.attestation_object;
        assert_eq!(
            object[..28],
            *b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData"
        );
        assert_eq!(object[28..30], [0x58, 148]);
        assert_eq!(&object[30..], data.as_slice());
    }

    #[test]
    fn pkcs8_round_trip_keeps_the_key() {
        let key = PasskeyKey::generate().expect("key");
        let der = key.to_pkcs8_der().expect("PKCS#8");
        let again = PasskeyKey::from_pkcs8_der(&der).expect("decoded key");
        assert_eq!(again.cose_public_key(), key.cose_public_key());
        assert!(PasskeyKey::from_pkcs8_der(b"junk").is_err());
        assert_eq!(key.public_key_spki_der().expect("SPKI").len(), 91);
    }
}
