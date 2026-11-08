use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{EncString, Error, Kdf, Result, primitives::fill_random};

const KEY_LEN: usize = 32;
const SERVER_HASH_ITERATIONS: u32 = 1;

/// 32-byte key derived from the master password; never leaves the client.
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    /// PBKDF2-SHA256(password, salt) or Argon2id(password, SHA-256(salt)).
    /// The salt is `email.trim().to_lowercase()`. Calls [`Kdf::validate`] first.
    pub fn derive(password: &[u8], email: &str, kdf: &Kdf) -> Result<Self> {
        let salt = email.trim().to_lowercase();
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        kdf.derive_into(password, salt.as_bytes(), &mut key)?;
        Ok(Self(key))
    }

    /// Base64 of PBKDF2-SHA256(password = master key, salt = master password, 1 iteration);
    /// sent to the server as the login password.
    #[must_use]
    pub fn server_hash(&self, password: &[u8]) -> String {
        let mut hash = Zeroizing::new([0u8; KEY_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha256>(&*self.0, password, SERVER_HASH_ITERATIONS, &mut *hash);
        STANDARD.encode(*hash)
    }

    /// HKDF-Expand(SHA-256) with info "enc" and "mac" (no extract step) into a 64-byte key.
    #[must_use]
    pub fn stretch(&self) -> SymmetricKey {
        let hkdf = Hkdf::<Sha256>::from_prk(&*self.0)
            .expect("a 32-byte PRK is long enough for HKDF-SHA256");
        let mut enc = Zeroizing::new([0u8; KEY_LEN]);
        let mut mac = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(b"enc", &mut *enc)
            .expect("32 bytes is within the HKDF-SHA256 output limit");
        hkdf.expand(b"mac", &mut *mac)
            .expect("32 bytes is within the HKDF-SHA256 output limit");
        SymmetricKey {
            enc,
            mac: Some(mac),
        }
    }

    /// Unwraps the account's protected user key (`Key` in the token response / profile).
    ///
    /// Type 2 is wrapped by the stretched key. Accounts created before key stretching still carry
    /// a type-0 user key wrapped by the raw master key, which [`MasterKey::stretch`] can't open.
    pub fn decrypt_user_key(&self, protected: &EncString) -> Result<SymmetricKey> {
        let wrapping_key = match protected {
            EncString::AesCbc256 { .. } => SymmetricKey {
                enc: self.0.clone(),
                mac: None,
            },
            EncString::AesCbc256HmacSha256 { .. } | EncString::Rsa2048OaepSha1 { .. } => {
                self.stretch()
            }
        };
        SymmetricKey::from_bytes(&protected.decrypt(&wrapping_key)?)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(..)")
    }
}

/// AES-256-CBC key with optional HMAC-SHA256 key (64 bytes = enc || mac; 32 bytes = legacy enc only).
pub struct SymmetricKey {
    enc: Zeroizing<[u8; KEY_LEN]>,
    mac: Option<Zeroizing<[u8; KEY_LEN]>>,
}

impl SymmetricKey {
    /// Fresh random 64-byte key (for per-cipher keys).
    #[must_use]
    pub fn generate() -> Self {
        let mut enc = Zeroizing::new([0u8; KEY_LEN]);
        let mut mac = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(&mut *enc);
        fill_random(&mut *mac);
        Self {
            enc,
            mac: Some(mac),
        }
    }

    /// Accepts 64 bytes (enc || mac) or 32 bytes (legacy, no MAC).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            len if len == 2 * KEY_LEN => {
                let (enc, mac) = bytes.split_at(KEY_LEN);
                Ok(Self {
                    enc: copy_key(enc),
                    mac: Some(copy_key(mac)),
                })
            }
            KEY_LEN => Ok(Self {
                enc: copy_key(bytes),
                mac: None,
            }),
            len => Err(Error::InvalidKeyLength(len)),
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Full capacity up front: a reallocation would leave an unzeroized copy on the heap.
        let mut bytes = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
        bytes.extend_from_slice(&*self.enc);
        if let Some(mac) = &self.mac {
            bytes.extend_from_slice(&**mac);
        }
        bytes
    }

    pub(crate) fn enc_key(&self) -> &[u8; KEY_LEN] {
        &self.enc
    }

    pub(crate) fn mac_key(&self) -> Option<&[u8; KEY_LEN]> {
        self.mac.as_deref()
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("has_mac", &self.mac.is_some())
            .finish_non_exhaustive()
    }
}

fn copy_key(bytes: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(bytes);
    key
}

/// RSA-2048 private key (PKCS#8 DER plaintext of the profile's `privateKey` EncString).
pub struct PrivateKey(rsa::PrivateKey);

impl PrivateKey {
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        <rsa::PrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| Error::InvalidPrivateKey)
    }

    pub(crate) fn inner(&self) -> &rsa::PrivateKey {
        &self.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    fn nz(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("test values are non-zero")
    }

    fn b64(text: &str) -> Vec<u8> {
        STANDARD.decode(text).expect("test vector is valid base64")
    }

    fn argon2(iterations: u32, memory_mib: u32, parallelism: u32) -> Kdf {
        Kdf::Argon2id {
            iterations: nz(iterations),
            memory_mib: nz(memory_mib),
            parallelism: nz(parallelism),
        }
    }

    // sdk-internal keys/kdf.rs `test_master_key_derive_pbkdf2`.
    const PBKDF2_MASTER_KEY: [u8; 32] = [
        31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69, 167,
        254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
    ];

    #[test]
    fn derives_pbkdf2_master_key() {
        let kdf = Kdf::Pbkdf2 {
            iterations: nz(10_000),
        };
        let key = MasterKey::derive(b"67t9b5g67$%Dh89n", "test_key", &kdf).expect("valid KDF");
        assert_eq!(*key.0, PBKDF2_MASTER_KEY);
    }

    // sdk-internal keys/kdf.rs `test_master_key_derive_argon2`.
    #[test]
    fn derives_argon2id_master_key() {
        let key = MasterKey::derive(b"67t9b5g67$%Dh89n", "test_key", &argon2(4, 32, 2))
            .expect("valid KDF");
        assert_eq!(
            *key.0,
            [
                207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147,
                237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242
            ]
        );
    }

    // sdk-internal keys/master_key.rs `test_password_hash_pbkdf2`: the salt is trimmed and
    // lowercased, so all three spellings give the same hash.
    #[test]
    fn server_hash_pbkdf2_normalizes_email() {
        let kdf = Kdf::Pbkdf2 {
            iterations: nz(100_000),
        };
        for email in [
            "test@bitwarden.com",
            "TEST@bitwarden.com",
            " test@bitwarden.com",
        ] {
            let key = MasterKey::derive(b"asdfasdf", email, &kdf).expect("valid KDF");
            assert_eq!(
                key.server_hash(b"asdfasdf"),
                "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=",
                "email {email:?}"
            );
        }
    }

    // sdk-internal keys/master_key.rs `test_password_hash_argon2id`.
    #[test]
    fn server_hash_argon2id() {
        let key =
            MasterKey::derive(b"asdfasdf", "test_salt", &argon2(4, 32, 2)).expect("valid KDF");
        assert_eq!(
            key.server_hash(b"asdfasdf"),
            "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ="
        );
    }

    #[test]
    fn derive_rejects_kdf_below_minimum() {
        for kdf in [
            Kdf::Pbkdf2 {
                iterations: nz(4_999),
            },
            argon2(1, 16, 1),
            argon2(2, 15, 1),
        ] {
            let result = MasterKey::derive(b"password", "user@example.com", &kdf);
            assert!(
                matches!(result, Err(Error::KdfTooWeak(_))),
                "{kdf:?} accepted"
            );
        }
    }

    #[test]
    fn derive_rejects_kdf_above_maximum() {
        for kdf in [
            Kdf::Pbkdf2 {
                iterations: nz(2_000_001),
            },
            argon2(11, 16, 1),
            argon2(2, 1025, 1),
            argon2(2, 16, 17),
        ] {
            let result = MasterKey::derive(b"password", "user@example.com", &kdf);
            assert!(
                matches!(result, Err(Error::KdfOutOfRange(_))),
                "{kdf:?} accepted"
            );
        }
    }

    // sdk-internal keys/utils.rs `test_stretch_kdf_key`.
    #[test]
    fn stretches_master_key_with_hkdf_expand() {
        let stretched = MasterKey(Zeroizing::new(PBKDF2_MASTER_KEY)).stretch();
        assert_eq!(
            *stretched.enc_key(),
            [
                111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
                134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96
            ]
        );
        assert_eq!(
            stretched.mac_key(),
            Some(&[
                221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
                166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155
            ])
        );
    }

    // sdk-internal keys/master_key.rs `test_decrypt_cbc256`: legacy type-0 user key wrapped by
    // the raw (unstretched) master key.
    #[test]
    fn decrypts_legacy_type0_user_key_with_raw_master_key() {
        let raw: [u8; 32] = b64("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe08=")
            .try_into()
            .expect("32-byte key");
        let protected: EncString = "0.tn/heK4HLbbEe+yEkC+kvw==|8QM94f7aVTtjm/bmvRdVxOxiLiiZtHYYO7+oBdjFCkilncesx0iVrXPl+tMKqW+Jo7+FtZdPNsTrL6RdoG7i5QbCRVwK+9010+xm7MTQY8s="
            .parse()
            .expect("valid EncString");

        let user_key = MasterKey(Zeroizing::new(raw))
            .decrypt_user_key(&protected)
            .expect("decrypts");

        assert_eq!(
            *user_key.enc_key(),
            [
                116, 170, 187, 43, 80, 212, 193, 202, 234, 181, 57, 66, 151, 249, 59, 47, 70, 16,
                57, 4, 170, 78, 85, 241, 152, 232, 91, 57, 9, 87, 209, 245,
            ]
        );
        assert_eq!(
            user_key.mac_key(),
            Some(&[
                40, 245, 106, 140, 2, 225, 138, 213, 98, 223, 92, 168, 135, 208, 22, 194, 31, 21,
                178, 252, 203, 198, 35, 174, 53, 218, 254, 151, 235, 57, 7, 98,
            ])
        );
    }

    #[test]
    fn decrypts_type2_user_key_with_stretched_master_key() {
        let master_key = MasterKey(Zeroizing::new(PBKDF2_MASTER_KEY));
        let user_key = SymmetricKey::generate();
        let protected =
            EncString::encrypt(&user_key.to_bytes(), &master_key.stretch()).expect("encrypts");

        let decrypted = master_key.decrypt_user_key(&protected).expect("decrypts");

        assert_eq!(decrypted.to_bytes(), user_key.to_bytes());
    }

    #[test]
    fn decrypt_user_key_rejects_type2_wrapped_by_raw_key() {
        let master_key = MasterKey(Zeroizing::new(PBKDF2_MASTER_KEY));
        let mut raw_as_key = PBKDF2_MASTER_KEY.to_vec();
        raw_as_key.extend_from_slice(&PBKDF2_MASTER_KEY);
        let wrong_wrapping = SymmetricKey::from_bytes(&raw_as_key).expect("64-byte key");
        let protected = EncString::encrypt(&SymmetricKey::generate().to_bytes(), &wrong_wrapping)
            .expect("encrypts");

        let result = master_key.decrypt_user_key(&protected);

        assert!(matches!(result, Err(Error::MacMismatch)));
    }

    #[test]
    fn generate_makes_distinct_64_byte_keys() {
        let first = SymmetricKey::generate();
        let second = SymmetricKey::generate();
        assert_eq!(first.to_bytes().len(), 64);
        assert!(first.mac_key().is_some());
        assert_ne!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn from_bytes_splits_enc_and_mac() {
        let bytes: Vec<u8> = (0..64).collect();
        let key = SymmetricKey::from_bytes(&bytes).expect("64-byte key");
        assert_eq!(key.enc_key()[..], bytes[..32]);
        assert_eq!(key.mac_key().map(|mac| &mac[..]), Some(&bytes[32..]));
        assert_eq!(key.to_bytes().as_slice(), bytes.as_slice());
    }

    #[test]
    fn from_bytes_accepts_legacy_32_byte_key() {
        let bytes = [5u8; 32];
        let key = SymmetricKey::from_bytes(&bytes).expect("32-byte key");
        assert_eq!(*key.enc_key(), bytes);
        assert_eq!(key.mac_key(), None);
        assert_eq!(key.to_bytes().as_slice(), bytes.as_slice());
    }

    #[test]
    fn from_bytes_rejects_other_lengths() {
        for len in [0, 16, 31, 33, 48, 63, 65, 128] {
            let result = SymmetricKey::from_bytes(&vec![0u8; len]);
            assert!(
                matches!(result, Err(Error::InvalidKeyLength(got)) if got == len),
                "length {len} gave {result:?}"
            );
        }
    }

    #[test]
    fn private_key_rejects_invalid_der() {
        for der in [&b""[..], b"not a key", &[0x30, 0x03, 0x02, 0x01, 0x00]] {
            assert!(matches!(
                PrivateKey::from_pkcs8_der(der),
                Err(Error::InvalidPrivateKey)
            ));
        }
    }

    #[test]
    fn debug_output_hides_key_material() {
        let key = SymmetricKey::from_bytes(&[0xAB; 64]).expect("64-byte key");
        let master_key = MasterKey(Zeroizing::new([0xAB; 32]));
        assert_eq!(format!("{key:?}"), "SymmetricKey { has_mac: true, .. }");
        assert_eq!(format!("{master_key:?}"), "MasterKey(..)");
    }
}
