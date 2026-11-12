use std::fmt;

use base64::{
    Engine as _, alphabet,
    engine::{
        GeneralPurpose,
        general_purpose::{NO_PAD_INDIFFERENT, URL_SAFE_NO_PAD},
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

const URL_SAFE_LENIENT: GeneralPurpose =
    GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD_INDIFFERENT);
const STANDARD_LENIENT: GeneralPurpose =
    GeneralPurpose::new(&alphabet::STANDARD, NO_PAD_INDIFFERENT);

/// WebAuthn's binary encoding: base64url without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Accepts base64url and plain base64, padded or not: servers and sites are not consistent.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let engine = if text.contains(['+', '/']) {
        &STANDARD_LENIENT
    } else {
        &URL_SAFE_LENIENT
    };
    engine.decode(text).map_err(|_| Error::Base64)
}

/// Bytes that travel as a base64url string in WebAuthn JSON.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Base64Url(pub Vec<u8>);

impl fmt::Debug for Base64Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode(&self.0))
    }
}

impl Serialize for Base64Url {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Url {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid base64url"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_url_safe_standard_and_padded_forms() {
        let bytes = [0xfb, 0xff, 0xfe];
        assert_eq!(encode(&bytes), "-__-");
        assert_eq!(decode("-__-").expect("valid base64"), bytes);
        assert_eq!(decode("+//+").expect("valid base64"), bytes);
        assert_eq!(decode("AQ==").expect("valid base64"), [1]);
        assert_eq!(decode("AQ").expect("valid base64"), [1]);
        assert!(decode("*").is_err());
    }
}
