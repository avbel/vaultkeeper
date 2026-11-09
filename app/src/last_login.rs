//! The server URL and email last typed into the login form, so the next login starts filled in.
//!
//! Stored in `settings.json` as a type-2 EncString under a key compiled into the app. That keeps
//! the email out of plain text in the file and in backups; anyone holding the binary can still
//! decrypt it, so nothing secret goes in here.

use serde::{Deserialize, Serialize};
use vk_crypto::{EncString, SymmetricKey};

const KEY: [u8; 64] = [
    0xa4, 0xbe, 0xe3, 0x5b, 0x9f, 0x0a, 0x7b, 0x80, 0x87, 0x8d, 0x07, 0xa2, 0x51, 0xc1, 0x16, 0x83,
    0x04, 0xae, 0x41, 0x48, 0xff, 0xa1, 0xef, 0x33, 0x89, 0xa8, 0x6e, 0x97, 0xbf, 0xcc, 0x81, 0xff,
    0x20, 0x5c, 0xdf, 0xbe, 0x2d, 0x66, 0xa3, 0xda, 0xdd, 0x1f, 0xff, 0xb5, 0xf4, 0x95, 0x8b, 0x72,
    0xfb, 0x22, 0xde, 0x43, 0x7b, 0x22, 0xa3, 0x97, 0xc0, 0x07, 0xbb, 0xe5, 0x11, 0x8c, 0x9a, 0xcb,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastLogin {
    /// As shown in the form (`server_url::display`), not the normalized URL.
    pub server: String,
    pub email: String,
}

fn key() -> Option<SymmetricKey> {
    SymmetricKey::from_bytes(&KEY).ok()
}

#[must_use]
pub fn seal(login: &LastLogin) -> Option<String> {
    let json = serde_json::to_vec(login).ok()?;
    EncString::encrypt(&json, &key()?)
        .ok()
        .map(|sealed| sealed.to_string())
}

/// `None` for anything that doesn't decrypt, such as a hand-edited or truncated value.
#[must_use]
pub fn open(sealed: &str) -> Option<LastLogin> {
    let plain = sealed.parse::<EncString>().ok()?.decrypt(&key()?).ok()?;
    serde_json::from_slice(&plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LastLogin {
        LastLogin {
            server: "vault.example.com".to_owned(),
            email: "alice@example.com".to_owned(),
        }
    }

    #[test]
    fn round_trips_and_keeps_the_email_out_of_the_stored_text() {
        let sealed = seal(&sample()).expect("sealed");
        assert!(sealed.starts_with("2."), "a type-2 EncString: {sealed}");
        assert!(!sealed.contains("alice"));
        assert!(!sealed.contains("example"));
        assert_eq!(open(&sealed), Some(sample()));
    }

    #[test]
    fn each_save_uses_a_fresh_iv() {
        assert_ne!(seal(&sample()), seal(&sample()));
    }

    #[test]
    fn tampered_or_foreign_values_are_ignored() {
        let sealed = seal(&sample()).expect("sealed");
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 3;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(open(&String::from_utf8(tampered).expect("utf8")), None);
        let other_key = SymmetricKey::generate();
        let foreign = EncString::encrypt(br#"{"server":"x","email":"y"}"#, &other_key)
            .expect("encrypt")
            .to_string();
        assert_eq!(open(&foreign), None);
        assert_eq!(open("not an enc string"), None);
    }
}
