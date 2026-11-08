use std::{fmt, str::FromStr};

use base64::{
    Engine as _,
    display::Base64Display,
    engine::{GeneralPurpose, general_purpose::STANDARD},
};
use rsa::Oaep;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::{
    Error, PrivateKey, Result, SymmetricKey,
    primitives::{BLOCK_LEN, cbc_decrypt, cbc_encrypt, fill_random, hmac_tag, verify_hmac},
};

const TYPE_AES_CBC: u8 = 0;
/// AES-128-CBC + HMAC, removed from Bitwarden; only reachable through header-less 3-part strings.
const TYPE_LEGACY_AES128_CBC_HMAC: u8 = 1;
const TYPE_AES_CBC_HMAC: u8 = 2;
const TYPE_RSA_OAEP_SHA1: u8 = 4;

const MAC_LEN: usize = 32;

/// Bitwarden `EncString`. Wire form `<type>.<b64>|<b64>|<b64>`; a string without a header is type 0.
///
/// - 0 `iv|ct`: AES-256-CBC, no MAC (decrypt only, legacy, 32-byte keys only)
/// - 2 `iv|ct|mac`: AES-256-CBC + HMAC-SHA256 over iv||ct (the only type we write)
/// - 4 `ct`: RSA-2048-OAEP-SHA1 (organization keys)
///
/// Parsing rejects the other Bitwarden types (1, 3, 5, 6, 7) with [`Error::UnsupportedEncType`].
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
        let mac_key = key.mac_key().ok_or(Error::MissingMacKey)?;
        let mut iv = [0u8; BLOCK_LEN];
        fill_random(&mut iv);
        let data = cbc_encrypt(key.enc_key(), &iv, plaintext);
        let mac = hmac_tag(mac_key, &iv, &data);
        Ok(Self::AesCbc256HmacSha256 { iv, data, mac })
    }

    /// Decrypts types 0 and 2. The MAC is checked in constant time before decrypting.
    ///
    /// Type 0 is accepted only with a 32-byte legacy key. With a 64-byte key it fails with
    /// [`Error::MacRequired`], so a server can't strip the MAC off a type-2 string and have it
    /// decrypted unauthenticated. Type 4 needs [`EncString::decrypt_with_private_key`] and fails
    /// with [`Error::UnsupportedEncType`].
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::AesCbc256 { iv, data } => {
                if key.mac_key().is_some() {
                    return Err(Error::MacRequired);
                }
                cbc_decrypt(key.enc_key(), iv, data)
            }
            Self::AesCbc256HmacSha256 { iv, data, mac } => {
                let mac_key = key.mac_key().ok_or(Error::MissingMacKey)?;
                verify_hmac(mac_key, iv, data, mac)?;
                cbc_decrypt(key.enc_key(), iv, data)
            }
            Self::Rsa2048OaepSha1 { .. } => Err(Error::UnsupportedEncType(self.enc_type())),
        }
    }

    pub fn decrypt_string(&self, key: &SymmetricKey) -> Result<Zeroizing<String>> {
        let mut bytes = self.decrypt(key)?;
        // Moving the buffer out (instead of copying) keeps exactly one plaintext allocation,
        // and the error path hands it back so it can be wiped too.
        String::from_utf8(std::mem::take(&mut *bytes))
            .map(Zeroizing::new)
            .map_err(|err| {
                drop(Zeroizing::new(err.into_bytes()));
                Error::InvalidUtf8
            })
    }

    /// Decrypts type 4 (org keys) with the account's RSA private key.
    /// Types 0 and 2 fail with [`Error::UnsupportedEncType`].
    pub fn decrypt_with_private_key(&self, key: &PrivateKey) -> Result<Zeroizing<Vec<u8>>> {
        let Self::Rsa2048OaepSha1 { data } = self else {
            return Err(Error::UnsupportedEncType(self.enc_type()));
        };
        key.inner()
            .decrypt(Oaep::<Sha1>::new(), data)
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt)
    }

    const fn enc_type(&self) -> u8 {
        match self {
            Self::AesCbc256 { .. } => TYPE_AES_CBC,
            Self::AesCbc256HmacSha256 { .. } => TYPE_AES_CBC_HMAC,
            Self::Rsa2048OaepSha1 { .. } => TYPE_RSA_OAEP_SHA1,
        }
    }
}

impl FromStr for EncString {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (enc_type, body) = split_header(s)?;
        match enc_type {
            TYPE_AES_CBC => {
                let [iv, data] = split_parts(body)?;
                Ok(Self::AesCbc256 {
                    iv: decode_array(iv, "IV must be 16 bytes")?,
                    data: decode_cbc_data(data)?,
                })
            }
            TYPE_AES_CBC_HMAC => {
                let [iv, data, mac] = split_parts(body)?;
                Ok(Self::AesCbc256HmacSha256 {
                    iv: decode_array(iv, "IV must be 16 bytes")?,
                    data: decode_cbc_data(data)?,
                    mac: decode_array::<MAC_LEN>(mac, "MAC must be 32 bytes")?,
                })
            }
            TYPE_RSA_OAEP_SHA1 => {
                let [data] = split_parts(body)?;
                let data = decode(data)?;
                if data.is_empty() {
                    return Err(Error::MalformedEncString("RSA ciphertext is empty"));
                }
                Ok(Self::Rsa2048OaepSha1 { data })
            }
            other => Err(Error::UnsupportedEncType(other)),
        }
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let enc_type = self.enc_type();
        match self {
            Self::AesCbc256 { iv, data } => write!(f, "{enc_type}.{}|{}", b64(iv), b64(data)),
            Self::AesCbc256HmacSha256 { iv, data, mac } => {
                write!(f, "{enc_type}.{}|{}|{}", b64(iv), b64(data), b64(mac))
            }
            Self::Rsa2048OaepSha1 { data } => write!(f, "{enc_type}.{}", b64(data)),
        }
    }
}

fn b64(bytes: &[u8]) -> Base64Display<'_, 'static, GeneralPurpose> {
    Base64Display::new(bytes, &STANDARD)
}

fn split_header(s: &str) -> Result<(u8, &str)> {
    let Some((header, body)) = s.split_once('.') else {
        // Header-less strings predate the type prefix: 2 parts are type 0, 3 parts type 1.
        let legacy_type = if s.split('|').count() == 3 {
            TYPE_LEGACY_AES128_CBC_HMAC
        } else {
            TYPE_AES_CBC
        };
        return Ok((legacy_type, s));
    };
    // `u8::from_str` also takes a leading '+', which is not a valid header.
    if header.is_empty() || !header.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::MalformedEncString("invalid type header"));
    }
    let enc_type = header
        .parse()
        .map_err(|_| Error::MalformedEncString("invalid type header"))?;
    Ok((enc_type, body))
}

fn split_parts<const N: usize>(body: &str) -> Result<[&str; N]> {
    let mut parts = body.split('|');
    let mut out = [""; N];
    for slot in &mut out {
        *slot = parts
            .next()
            .ok_or(Error::MalformedEncString("wrong number of parts"))?;
    }
    if parts.next().is_some() {
        return Err(Error::MalformedEncString("wrong number of parts"));
    }
    Ok(out)
}

fn decode(part: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(part)
        .map_err(|_| Error::MalformedEncString("invalid base64"))
}

fn decode_array<const N: usize>(part: &str, wrong_len: &'static str) -> Result<[u8; N]> {
    decode(part)?
        .as_slice()
        .try_into()
        .map_err(|_| Error::MalformedEncString(wrong_len))
}

fn decode_cbc_data(part: &str) -> Result<Vec<u8>> {
    let data = decode(part)?;
    if data.is_empty() || !data.len().is_multiple_of(BLOCK_LEN) {
        return Err(Error::MalformedEncString(
            "ciphertext must be a non-empty multiple of 16 bytes",
        ));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // sdk-internal enc_string/symmetric.rs `test_enc_string_serialization`.
    const SDK_TYPE2: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
    // sdk-internal enc_string/symmetric.rs `test_from_str_cbc256`.
    const SDK_TYPE0: &str = "0.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==";
    const SDK_TYPE0_IV: [u8; 16] = [
        164, 196, 186, 254, 39, 19, 64, 0, 109, 186, 92, 57, 218, 154, 182, 150,
    ];
    const SDK_TYPE0_DATA: [u8; 16] = [
        93, 118, 241, 43, 16, 211, 135, 233, 150, 136, 221, 71, 140, 125, 141, 215,
    ];
    // sdk-internal enc_string/asymmetric.rs `test_enc_string_rsa2048_oaep_sha1_b64`.
    const SDK_TYPE4: &str = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";

    fn parse(text: &str) -> Result<EncString> {
        text.parse()
    }

    fn key64() -> SymmetricKey {
        SymmetricKey::generate()
    }

    #[test]
    fn type2_round_trips_exactly() {
        let parsed = parse(SDK_TYPE2).expect("valid type 2");
        assert!(matches!(parsed, EncString::AesCbc256HmacSha256 { .. }));
        assert_eq!(parsed.to_string(), SDK_TYPE2);
    }

    #[test]
    fn type0_parses_to_upstream_bytes() {
        let parsed = parse(SDK_TYPE0).expect("valid type 0");
        assert_eq!(
            parsed,
            EncString::AesCbc256 {
                iv: SDK_TYPE0_IV,
                data: SDK_TYPE0_DATA.to_vec(),
            }
        );
        assert_eq!(parsed.to_string(), SDK_TYPE0);
    }

    #[test]
    fn headerless_string_is_type0_and_displays_with_header() {
        let headerless = SDK_TYPE0.trim_start_matches("0.");
        let parsed = parse(headerless).expect("valid header-less type 0");
        assert_eq!(parsed, parse(SDK_TYPE0).expect("valid type 0"));
        assert_eq!(parsed.to_string(), SDK_TYPE0);
    }

    #[test]
    fn type4_round_trips_exactly() {
        let parsed = parse(SDK_TYPE4).expect("valid type 4");
        let EncString::Rsa2048OaepSha1 { data } = &parsed else {
            panic!("expected type 4, got {parsed:?}");
        };
        assert_eq!(data.len(), 256);
        assert_eq!(parsed.to_string(), SDK_TYPE4);
    }

    #[test]
    fn rejects_unsupported_types_before_reading_the_body() {
        let cases = [
            (
                "1.AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODw==|AA==",
                1,
            ),
            ("AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODw==|AA==", 1),
            ("3.SUx5gWrgmAKs", 3),
            ("5.not base64|AA==", 5),
            (
                "6.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf|AA==",
                6,
            ),
            ("7.ABC", 7),
            ("9.", 9),
            ("255.x", 255),
        ];
        for (text, expected) in cases {
            let result = parse(text);
            assert!(
                matches!(result, Err(Error::UnsupportedEncType(got)) if got == expected),
                "{text:?} gave {result:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_strings() {
        let cases = [
            "",
            ".AAAA",
            "x.AAAA",
            "+2.AAAA",
            "-1.AAAA",
            "256.AAAA",
            "2.",
            "2.AAAA",
            "2.a|b",
            // sdk-internal `test_from_str_unparseable_roundtrips`: 4-byte IV, 4-byte MAC, bad base64.
            "2.AAECAw==|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "2.AAECAwQFBgcICQoLDA0ODw==|Y3Q=|AAECAw==",
            "0.AAECAw==|Y3Q=",
            "2.!!!!|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            // Valid IV and MAC, but the ciphertext is not whole AES blocks.
            "2.AAECAwQFBgcICQoLDA0ODw==|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "2.AAECAwQFBgcICQoLDA0ODw==||AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "0.AAECAwQFBgcICQoLDA0ODw==|",
            "0.AAECAwQFBgcICQoLDA0ODw==|AAECAwQFBgcICQoLDA0ODw==|AA==|AA==",
            "AAECAwQFBgcICQoLDA0ODw==",
            "4.",
            "4.AAAA|AAAA",
            "4.@@@@",
            "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=|",
        ];
        for text in cases {
            let result = parse(text);
            assert!(
                matches!(result, Err(Error::MalformedEncString(_))),
                "{text:?} gave {result:?}"
            );
        }
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = key64();
        for plaintext in [
            &b""[..],
            b"a",
            b"exactly 16 bytes",
            b"a longer secret spanning blocks",
        ] {
            let encrypted = EncString::encrypt(plaintext, &key).expect("encrypts");
            let reparsed = parse(&encrypted.to_string()).expect("own output parses");
            assert_eq!(reparsed, encrypted);
            assert_eq!(
                reparsed.decrypt(&key).expect("decrypts").as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn encrypt_uses_a_fresh_iv_each_time() {
        let key = key64();
        let first = EncString::encrypt(b"same", &key).expect("encrypts");
        let second = EncString::encrypt(b"same", &key).expect("encrypts");
        assert_ne!(first, second);
    }

    #[test]
    fn decrypt_string_returns_utf8_text() {
        let key = key64();
        let encrypted = EncString::encrypt("pässwörd".as_bytes(), &key).expect("encrypts");
        assert_eq!(
            encrypted.decrypt_string(&key).expect("decrypts").as_str(),
            "pässwörd"
        );
    }

    #[test]
    fn decrypt_string_rejects_invalid_utf8() {
        let key = key64();
        let encrypted = EncString::encrypt(&[0xff, 0xfe], &key).expect("encrypts");
        assert!(matches!(
            encrypted.decrypt_string(&key),
            Err(Error::InvalidUtf8)
        ));
    }

    #[test]
    fn encrypt_requires_a_mac_key() {
        let legacy = SymmetricKey::from_bytes(&[1u8; 32]).expect("32-byte key");
        assert!(matches!(
            EncString::encrypt(b"data", &legacy),
            Err(Error::MissingMacKey)
        ));
    }

    #[test]
    fn type2_decrypt_requires_a_mac_key() {
        let key = key64();
        let encrypted = EncString::encrypt(b"data", &key).expect("encrypts");
        let enc_only = SymmetricKey::from_bytes(&key.to_bytes()[..32]).expect("32-byte key");
        assert!(matches!(
            encrypted.decrypt(&enc_only),
            Err(Error::MissingMacKey)
        ));
    }

    #[test]
    fn tampering_with_any_authenticated_part_fails_the_mac() {
        let key = key64();
        let EncString::AesCbc256HmacSha256 { iv, data, mac } =
            EncString::encrypt(b"secret value", &key).expect("encrypts")
        else {
            panic!("encrypt must produce type 2");
        };
        let mut tampered = Vec::new();
        for index in [0, iv.len() - 1] {
            let mut iv = iv;
            iv[index] ^= 1;
            tampered.push(EncString::AesCbc256HmacSha256 {
                iv,
                data: data.clone(),
                mac,
            });
        }
        for index in [0, data.len() - 1] {
            let mut data = data.clone();
            data[index] ^= 1;
            tampered.push(EncString::AesCbc256HmacSha256 { iv, data, mac });
        }
        let mut bad_mac = mac;
        bad_mac[MAC_LEN - 1] ^= 1;
        tampered.push(EncString::AesCbc256HmacSha256 {
            iv,
            data,
            mac: bad_mac,
        });

        for enc in tampered {
            assert!(
                matches!(enc.decrypt(&key), Err(Error::MacMismatch)),
                "{enc}"
            );
        }
    }

    #[test]
    fn type2_wrong_key_fails_the_mac() {
        let encrypted = EncString::encrypt(b"secret", &key64()).expect("encrypts");
        assert!(matches!(
            encrypted.decrypt(&key64()),
            Err(Error::MacMismatch)
        ));
    }

    #[test]
    fn type0_decrypts_with_a_32_byte_key() {
        let legacy = SymmetricKey::from_bytes(&[6u8; 32]).expect("32-byte key");
        let iv = [3u8; BLOCK_LEN];
        let data = cbc_encrypt(legacy.enc_key(), &iv, b"legacy data");
        let decrypted = EncString::AesCbc256 { iv, data }
            .decrypt(&legacy)
            .expect("decrypts");
        assert_eq!(decrypted.as_slice(), b"legacy data");
    }

    #[test]
    fn type0_is_rejected_with_a_64_byte_key() {
        let key = key64();
        let iv = [3u8; BLOCK_LEN];
        let data = cbc_encrypt(key.enc_key(), &iv, b"legacy data");
        let result = EncString::AesCbc256 { iv, data }.decrypt(&key);
        assert!(matches!(result, Err(Error::MacRequired)), "{result:?}");
    }

    #[test]
    fn type2_with_mac_stripped_to_type0_is_rejected() {
        let key = key64();
        let encrypted = EncString::encrypt(b"secret", &key)
            .expect("encrypts")
            .to_string();
        let (iv_and_data, _mac) = encrypted
            .trim_start_matches("2.")
            .rsplit_once('|')
            .expect("type 2 has three parts");
        for downgraded in [format!("0.{iv_and_data}"), iv_and_data.to_owned()] {
            let result = parse(&downgraded).expect("valid type 0").decrypt(&key);
            assert!(
                matches!(result, Err(Error::MacRequired)),
                "{downgraded}: {result:?}"
            );
        }
    }

    #[test]
    fn wrong_operation_for_the_type_is_rejected() {
        let type4 = parse(SDK_TYPE4).expect("valid type 4");
        assert!(matches!(
            type4.decrypt(&key64()),
            Err(Error::UnsupportedEncType(4))
        ));
    }
}
