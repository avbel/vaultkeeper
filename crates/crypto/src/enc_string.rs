use std::{fmt, str::FromStr};

use zeroize::Zeroizing;

use crate::{Error, PrivateKey, Result, SymmetricKey};

/// Bitwarden `EncString`. Wire form `<type>.<b64>|<b64>|<b64>`; a string without a header is type 0.
///
/// - 0 `iv|ct`: AES-256-CBC, no MAC (decrypt only, legacy)
/// - 2 `iv|ct|mac`: AES-256-CBC + HMAC-SHA256 over iv||ct (the only type we write)
/// - 4 `ct`: RSA-2048-OAEP-SHA1 (organization keys)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncString {
    AesCbc256 {
        iv: [u8; 16],
        data: Vec<u8>,
    },
    AesCbc256HmacSha256 {
        iv: [u8; 16],
        data: Vec<u8>,
        mac: [u8; 32],
    },
    Rsa2048OaepSha1 {
        data: Vec<u8>,
    },
}

impl EncString {
    /// Encrypts as type 2 with a random IV. Fails with [`Error::MissingMacKey`] for 32-byte keys.
    pub fn encrypt(plaintext: &[u8], key: &SymmetricKey) -> Result<Self> {
        let _ = (plaintext, key);
        todo!("step 2")
    }

    /// Decrypts types 0 and 2. The MAC is checked in constant time before decrypting.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>> {
        let _ = key;
        todo!("step 2")
    }

    pub fn decrypt_string(&self, key: &SymmetricKey) -> Result<Zeroizing<String>> {
        let bytes = self.decrypt(key)?;
        String::from_utf8(bytes.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidUtf8)
    }

    /// Decrypts type 4 (org keys) with the account's RSA private key.
    pub fn decrypt_with_private_key(&self, key: &PrivateKey) -> Result<Zeroizing<Vec<u8>>> {
        let _ = key.inner();
        todo!("step 2")
    }
}

impl FromStr for EncString {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        todo!("step 2")
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        todo!("step 2")
    }
}
