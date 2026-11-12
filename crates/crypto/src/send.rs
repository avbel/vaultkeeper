//! Send keys, as the official clients make them (`SendService.encrypt`).
//!
//! A Send is encrypted with a key derived from a 16-byte seed. The seed travels in the share
//! link's fragment, so the server never sees it; the owner keeps it wrapped by the user key.

use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result, SymmetricKey, primitives::fill_random};

pub const SEED_LEN: usize = 16;
const KEY_SALT: &[u8] = b"bitwarden-send";
const KEY_INFO: &[u8] = b"send";
/// `SEND_KDF_ITERATIONS` in the clients; the server hashes the result again with its own salt.
const PASSWORD_ITERATIONS: u32 = 100_000;
const PASSWORD_HASH_LEN: usize = 32;

pub struct SendKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    key: SymmetricKey,
}

impl SendKey {
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        fill_random(&mut *seed);
        Self::derive(seed)
    }

    /// The seed as stored (decrypted from the Send's `key`) or taken from a link.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; SEED_LEN] = seed
            .try_into()
            .map_err(|_| Error::InvalidKeyLength(seed.len()))?;
        Ok(Self::derive(Zeroizing::new(seed)))
    }

    fn derive(seed: Zeroizing<[u8; SEED_LEN]>) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(KEY_SALT), &*seed);
        let mut bytes = Zeroizing::new([0u8; 64]);
        hkdf.expand(KEY_INFO, &mut *bytes)
            .expect("64 bytes is within the HKDF-SHA256 output limit");
        let key = SymmetricKey::from_bytes(&*bytes).expect("64 bytes is a valid key length");
        Self { seed, key }
    }

    #[must_use]
    pub fn seed(&self) -> &[u8] {
        &*self.seed
    }

    /// Encrypts and decrypts the Send's name, text and notes.
    #[must_use]
    pub const fn key(&self) -> &SymmetricKey {
        &self.key
    }

    /// The last segment of the share link: the seed, base64url without padding.
    #[must_use]
    pub fn url_key(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(*self.seed))
    }

    /// The `password` sent to the server: base64 of PBKDF2-SHA256(password, seed). It proves the
    /// recipient knows the password; it is not an encryption key.
    #[must_use]
    pub fn password_hash(&self, password: &str) -> String {
        let mut hash = Zeroizing::new([0u8; PASSWORD_HASH_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            &*self.seed,
            PASSWORD_ITERATIONS,
            &mut *hash,
        );
        STANDARD.encode(*hash)
    }
}

impl fmt::Debug for SendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SendKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Computed with Node's `crypto.hkdfSync` and `crypto.pbkdf2Sync`, not with this module.
    const SEED: [u8; SEED_LEN] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const KEY_HEX: &str = "063a955a1c01b4e1aacb7cd359c919b2cb61041c0c05c94c0eb76fb9a9e144b3fbeca074de1437a1a2330ad2833138abf3be2561a3a30ae1f33e15e1a2f7ca04";
    const URL_KEY: &str = "AAECAwQFBgcICQoLDA0ODw";
    const PASSWORD_HASH: &str = "V/LC8HOXSNUWQZsGKohGZjI8WD6krhZVBKgfe1PGKgk=";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn the_key_is_hkdf_of_the_seed_with_the_send_salt_and_purpose() {
        let send = SendKey::from_seed(&SEED).expect("a 16-byte seed");
        assert_eq!(hex(&send.key().to_bytes()), KEY_HEX);
        assert_eq!(send.seed(), SEED);
    }

    #[test]
    fn the_link_key_is_the_unpadded_base64url_seed() {
        let send = SendKey::from_seed(&SEED).expect("a 16-byte seed");
        assert_eq!(send.url_key().as_str(), URL_KEY);
    }

    #[test]
    fn the_password_hash_is_pbkdf2_salted_with_the_seed() {
        let send = SendKey::from_seed(&SEED).expect("a 16-byte seed");
        assert_eq!(send.password_hash("correct horse"), PASSWORD_HASH);
    }

    #[test]
    fn seeds_of_another_length_are_refused() {
        assert!(matches!(
            SendKey::from_seed(&[0; 32]),
            Err(Error::InvalidKeyLength(32))
        ));
    }

    #[test]
    fn generated_keys_round_trip_through_their_seed() {
        let first = SendKey::generate();
        let again = SendKey::from_seed(first.seed()).expect("its own seed");
        assert_eq!(first.key().to_bytes(), again.key().to_bytes());
        assert_ne!(first.seed(), SendKey::generate().seed());
    }
}
