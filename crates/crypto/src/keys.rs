use zeroize::Zeroizing;

use crate::{Kdf, Result};

/// 32-byte key derived from the master password; never leaves the client.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// PBKDF2-SHA256(password, salt) or Argon2id(password, SHA-256(salt)).
    /// The salt is `email.trim().to_lowercase()`. Calls [`Kdf::validate`] first.
    pub fn derive(password: &[u8], email: &str, kdf: &Kdf) -> Result<Self> {
        let _ = (password, email, kdf);
        todo!("step 2")
    }

    /// Base64 of PBKDF2-SHA256(password = master key, salt = master password, 1 iteration);
    /// sent to the server as the login password.
    #[must_use]
    pub fn server_hash(&self, password: &[u8]) -> String {
        let _ = (password, &self.0);
        todo!("step 2")
    }

    /// HKDF-Expand(SHA-256) with info "enc" and "mac" (no extract step) into a 64-byte key.
    #[must_use]
    pub fn stretch(&self) -> SymmetricKey {
        todo!("step 2")
    }
}

/// AES-256-CBC key with optional HMAC-SHA256 key (64 bytes = enc || mac; 32 bytes = legacy enc only).
pub struct SymmetricKey {
    enc: Zeroizing<[u8; 32]>,
    mac: Option<Zeroizing<[u8; 32]>>,
}

impl SymmetricKey {
    /// Fresh random 64-byte key (for per-cipher keys).
    #[must_use]
    pub fn generate() -> Self {
        todo!("step 2")
    }

    /// Accepts 64 bytes (enc || mac) or 32 bytes (legacy, no MAC).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let _ = bytes;
        todo!("step 2")
    }

    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let _ = (&self.enc, &self.mac);
        todo!("step 2")
    }
}

/// RSA-2048 private key (PKCS#8 DER plaintext of the profile's `privateKey` EncString).
pub struct PrivateKey(rsa::PrivateKey);

impl PrivateKey {
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let _ = (der, &Self::from_pkcs8_der);
        todo!("step 2")
    }

    pub(crate) fn inner(&self) -> &rsa::PrivateKey {
        &self.0
    }
}
