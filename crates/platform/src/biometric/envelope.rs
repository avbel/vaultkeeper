//! The Touch ID enrollment file and the wrap/unwrap of the user key, independent of the Secure
//! Enclave so it can be tested with a software P-256 key.
//!
//! Version 1 layout (multi-byte lengths big-endian):
//!
//! | field                   | size        |
//! |-------------------------|-------------|
//! | magic `BWLT`            | 4           |
//! | version (`1`)           | 1           |
//! | device public key x9.63 | 65          |
//! | ephemeral public key    | 65          |
//! | AES-GCM nonce           | 12          |
//! | device key blob length  | 2           |
//! | device key blob         | blob length |
//! | biometry state length   | 1           |
//! | biometry state          | state length|
//! | ciphertext + tag        | rest (>=16) |
//!
//! Everything before the ciphertext is the AES-GCM associated data, so no field can be swapped
//! without failing decryption. Wrapping key = HKDF-SHA256(ikm = ECDH x-coordinate,
//! salt = ephemeral public ‖ device public, info = "vaultkeeper touchid v1").

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use p256::{
    PublicKey,
    ecdh::EphemeralSecret,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use rand::{TryRng, rngs::SysRng};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"BWLT";
const VERSION: u8 = 1;
pub(super) const POINT_LEN: usize = 65;
pub(super) const SHARED_SECRET_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const KDF_INFO: &[u8] = b"vaultkeeper touchid v1";
const FIXED_HEADER_LEN: usize = MAGIC.len() + 1 + 2 * POINT_LEN + NONCE_LEN;

pub(super) type SharedSecret = Zeroizing<[u8; SHARED_SECRET_LEN]>;

/// The Secure Enclave key as stored on disk: an opaque blob only this Mac's enclave can use,
/// plus the biometry state hash captured at enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeviceKey<'a> {
    pub blob: &'a [u8],
    pub biometry_state: &'a [u8],
}

/// The private half of the key agreement: the Secure Enclave in production, a software key in
/// tests. Returns the raw ECDH x-coordinate.
pub(super) trait KeyAgreement {
    fn shared_secret(&self, key: &DeviceKey<'_>, peer: &PublicKey) -> Result<SharedSecret>;
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum EnvelopeError {
    #[error("not a vaultkeeper Touch ID file")]
    BadMagic,
    #[error("unsupported Touch ID file version {0}")]
    UnsupportedVersion(u8),
    #[error("Touch ID file is truncated")]
    Truncated,
    #[error("Touch ID file holds an invalid public key")]
    BadPublicKey,
    #[error("user key failed to decrypt")]
    Decrypt,
}

impl From<EnvelopeError> for Error {
    fn from(err: EnvelopeError) -> Self {
        tracing::warn!(error = %err, "Touch ID enrollment is unusable");
        Self::BiometricInvalidated
    }
}

#[derive(Debug)]
pub(super) struct Envelope<'a> {
    pub device_public: PublicKey,
    pub ephemeral_public: PublicKey,
    pub nonce: [u8; NONCE_LEN],
    pub key: DeviceKey<'a>,
    header: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> Envelope<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        let mut reader = Reader { bytes, pos: 0 };
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let version = reader.take(1)?[0];
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let device_public = parse_point(reader.take(POINT_LEN)?)?;
        let ephemeral_public = parse_point(reader.take(POINT_LEN)?)?;
        let nonce = reader
            .take(NONCE_LEN)?
            .try_into()
            .map_err(|_| EnvelopeError::Truncated)?;
        let blob_len = u16::from_be_bytes(
            reader
                .take(2)?
                .try_into()
                .map_err(|_| EnvelopeError::Truncated)?,
        );
        let blob = reader.take(usize::from(blob_len))?;
        let state_len = reader.take(1)?[0];
        let biometry_state = reader.take(usize::from(state_len))?;
        let (header, ciphertext) = bytes.split_at(reader.pos);
        if ciphertext.len() < TAG_LEN {
            return Err(EnvelopeError::Truncated);
        }
        Ok(Self {
            device_public,
            ephemeral_public,
            nonce,
            key: DeviceKey {
                blob,
                biometry_state,
            },
            header,
            ciphertext,
        })
    }

    pub fn decrypt(&self, shared: &SharedSecret) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let key = wrapping_key(shared, &self.ephemeral_public, &self.device_public);
        let cipher = Aes256Gcm::new(&(*key).into());
        cipher
            .decrypt(
                &self.nonce.into(),
                Payload {
                    msg: self.ciphertext,
                    aad: self.header,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| EnvelopeError::Decrypt)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], EnvelopeError> {
        let end = self.pos.checked_add(len).ok_or(EnvelopeError::Truncated)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(EnvelopeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }
}

fn parse_point(bytes: &[u8]) -> Result<PublicKey, EnvelopeError> {
    // CryptoKit's x963Representation initializer accepts only uncompressed points.
    if bytes.first() != Some(&0x04) {
        return Err(EnvelopeError::BadPublicKey);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| EnvelopeError::BadPublicKey)
}

pub(super) fn encode_point(key: &PublicKey) -> [u8; POINT_LEN] {
    let point = key.to_sec1_point(false);
    point
        .as_bytes()
        .try_into()
        .expect("an uncompressed P-256 point is 65 bytes")
}

fn wrapping_key(
    shared: &SharedSecret,
    ephemeral: &PublicKey,
    device: &PublicKey,
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut salt = [0_u8; 2 * POINT_LEN];
    salt[..POINT_LEN].copy_from_slice(&encode_point(ephemeral));
    salt[POINT_LEN..].copy_from_slice(&encode_point(device));
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&salt), shared.as_slice())
        .expand(KDF_INFO, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Wraps `user_key` to `device_public` with a fresh ephemeral key and nonce.
pub(super) fn seal(
    device_public: &PublicKey,
    key: &DeviceKey<'_>,
    user_key: &[u8],
) -> Result<Vec<u8>> {
    let ephemeral = EphemeralSecret::try_generate_from_rng(&mut SysRng).map_err(rng_error)?;
    let mut nonce = [0_u8; NONCE_LEN];
    SysRng.try_fill_bytes(&mut nonce).map_err(rng_error)?;
    seal_with(&ephemeral, nonce, device_public, key, user_key)
}

fn seal_with(
    ephemeral: &EphemeralSecret,
    nonce: [u8; NONCE_LEN],
    device_public: &PublicKey,
    key: &DeviceKey<'_>,
    user_key: &[u8],
) -> Result<Vec<u8>> {
    let blob_len = u16::try_from(key.blob.len())
        .map_err(|_| std::io::Error::other("Secure Enclave key blob exceeds 64 KiB"))?;
    let state_len = u8::try_from(key.biometry_state.len())
        .map_err(|_| std::io::Error::other("biometry state exceeds 255 bytes"))?;
    let ephemeral_public = ephemeral.public_key();

    let mut out = Vec::with_capacity(
        FIXED_HEADER_LEN + 3 + key.blob.len() + key.biometry_state.len() + user_key.len() + TAG_LEN,
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&encode_point(device_public));
    out.extend_from_slice(&encode_point(&ephemeral_public));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&blob_len.to_be_bytes());
    out.extend_from_slice(key.blob);
    out.push(state_len);
    out.extend_from_slice(key.biometry_state);

    let shared = ephemeral.diffie_hellman(device_public);
    let shared: SharedSecret = Zeroizing::new((*shared.raw_secret_bytes()).into());
    let wrapping = wrapping_key(&shared, &ephemeral_public, device_public);
    let ciphertext = Aes256Gcm::new(&(*wrapping).into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: user_key,
                aad: &out,
            },
        )
        .map_err(|_| std::io::Error::other("AES-GCM refused the user key"))?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwraps the user key from an enrollment file, asking `agreement` for the ECDH secret.
pub(super) fn open(bytes: &[u8], agreement: &impl KeyAgreement) -> Result<Zeroizing<Vec<u8>>> {
    let envelope = Envelope::parse(bytes)?;
    let shared = agreement.shared_secret(&envelope.key, &envelope.ephemeral_public)?;
    Ok(envelope.decrypt(&shared)?)
}

fn rng_error(err: rand::rngs::SysError) -> Error {
    Error::Io(std::io::Error::other(err))
}

#[cfg(test)]
mod tests {
    use p256::{SecretKey, ecdh::diffie_hellman};

    use super::*;

    const BLOB: &[u8] = b"opaque secure enclave blob";
    const STATE: &[u8] = &[7; 32];
    const USER_KEY: &[u8; 64] = &[0x5a; 64];

    struct SoftwareKey(SecretKey);

    impl SoftwareKey {
        fn random() -> Self {
            Self(SecretKey::generate_from_rng(&mut rand::rng()))
        }

        fn public(&self) -> PublicKey {
            self.0.public_key()
        }
    }

    impl KeyAgreement for SoftwareKey {
        fn shared_secret(&self, _key: &DeviceKey<'_>, peer: &PublicKey) -> Result<SharedSecret> {
            let shared = diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new((*shared.raw_secret_bytes()).into()))
        }
    }

    struct FailingAgreement;

    impl KeyAgreement for FailingAgreement {
        fn shared_secret(&self, _key: &DeviceKey<'_>, _peer: &PublicKey) -> Result<SharedSecret> {
            Err(Error::BiometricFailed)
        }
    }

    fn device_key() -> DeviceKey<'static> {
        DeviceKey {
            blob: BLOB,
            biometry_state: STATE,
        }
    }

    fn sealed_for(device: &SoftwareKey) -> Vec<u8> {
        seal(&device.public(), &device_key(), USER_KEY).expect("seal")
    }

    fn rfc5903_point(x: &str, y: &str) -> PublicKey {
        let bytes = hex(&format!("04{x}{y}"));
        PublicKey::from_sec1_bytes(&bytes).expect("RFC 5903 point")
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn round_trip_with_software_key() {
        let device = SoftwareKey::random();
        let unwrapped = open(&sealed_for(&device), &device).expect("open");
        assert_eq!(unwrapped.as_slice(), USER_KEY.as_slice());
    }

    #[test]
    fn device_key_fields_survive_the_file() {
        let device = SoftwareKey::random();
        let bytes = sealed_for(&device);
        let envelope = Envelope::parse(&bytes).expect("parse");
        assert_eq!(envelope.key, device_key());
        assert_eq!(envelope.device_public, device.public());
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key_and_nonce() {
        let device = SoftwareKey::random();
        let first = sealed_for(&device);
        let second = sealed_for(&device);
        let (a, b) = (
            Envelope::parse(&first).expect("a"),
            Envelope::parse(&second).expect("b"),
        );
        assert_ne!(a.ephemeral_public, b.ephemeral_public);
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn layout_starts_with_magic_version_and_keys() {
        let device = SoftwareKey::random();
        let bytes = sealed_for(&device);
        assert_eq!(&bytes[..4], b"BWLT");
        assert_eq!(bytes[4], 1);
        assert_eq!(&bytes[5..70], &encode_point(&device.public()));
        let blob_len_at = FIXED_HEADER_LEN;
        assert_eq!(
            &bytes[blob_len_at..blob_len_at + 2],
            &[0, 26],
            "BLOB is 26 bytes"
        );
        assert_eq!(&bytes[blob_len_at + 2..blob_len_at + 28], BLOB);
        assert_eq!(bytes[blob_len_at + 28], 32);
        assert_eq!(
            bytes.len(),
            blob_len_at + 28 + 1 + 32 + USER_KEY.len() + TAG_LEN
        );
    }

    #[test]
    fn wrong_device_key_fails_to_decrypt() {
        let bytes = sealed_for(&SoftwareKey::random());
        let other = SoftwareKey::random();
        let envelope = Envelope::parse(&bytes).expect("parse");
        let shared = other
            .shared_secret(&envelope.key, &envelope.ephemeral_public)
            .expect("ecdh");
        assert_eq!(
            envelope.decrypt(&shared).expect_err("wrong key"),
            EnvelopeError::Decrypt
        );
        assert!(matches!(
            open(&bytes, &other),
            Err(Error::BiometricInvalidated)
        ));
    }

    #[test]
    fn tampering_with_any_byte_is_rejected() {
        let device = SoftwareKey::random();
        let bytes = sealed_for(&device);
        let header_len = Envelope::parse(&bytes).expect("parse").header.len();
        // One byte in each authenticated field plus the ciphertext and the tag.
        let offsets = [
            5,
            69,
            70,
            134,
            135,
            146,
            FIXED_HEADER_LEN + 2,
            header_len - 1,
            header_len,
        ];
        for offset in offsets.into_iter().chain([bytes.len() - 1]) {
            let mut tampered = bytes.clone();
            tampered[offset] ^= 0x01;
            let result = open(&tampered, &device);
            assert!(
                matches!(result, Err(Error::BiometricInvalidated)),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn length_fields_cannot_point_past_the_end() {
        let device = SoftwareKey::random();
        let mut bytes = sealed_for(&device);
        bytes[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            Envelope::parse(&bytes).expect_err("blob length"),
            EnvelopeError::Truncated
        );
    }

    #[test]
    fn bad_magic_and_version_are_rejected() {
        let device = SoftwareKey::random();
        let bytes = sealed_for(&device);

        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            Envelope::parse(&bad_magic).expect_err("magic"),
            EnvelopeError::BadMagic
        );

        let mut future = bytes;
        future[4] = 2;
        assert_eq!(
            Envelope::parse(&future).expect_err("version"),
            EnvelopeError::UnsupportedVersion(2)
        );
        assert!(matches!(
            open(&future, &device),
            Err(Error::BiometricInvalidated)
        ));
    }

    #[test]
    fn truncated_files_are_rejected() {
        let device = SoftwareKey::random();
        let bytes = sealed_for(&device);
        for len in [
            0,
            3,
            5,
            70,
            FIXED_HEADER_LEN,
            bytes.len() - TAG_LEN - USER_KEY.len() + 3,
        ] {
            assert_eq!(
                Envelope::parse(&bytes[..len]).expect_err("truncated"),
                EnvelopeError::Truncated,
                "len {len}"
            );
        }
    }

    #[test]
    fn compressed_or_invalid_points_are_rejected() {
        let device = SoftwareKey::random();
        let mut bytes = sealed_for(&device);
        bytes[5] = 0x02;
        assert_eq!(
            Envelope::parse(&bytes).expect_err("compressed"),
            EnvelopeError::BadPublicKey
        );
        bytes[5] = 0x04;
        bytes[6..70].fill(0);
        assert_eq!(
            Envelope::parse(&bytes).expect_err("off curve"),
            EnvelopeError::BadPublicKey
        );
    }

    #[test]
    fn agreement_errors_pass_through_unchanged() {
        let bytes = sealed_for(&SoftwareKey::random());
        assert!(matches!(
            open(&bytes, &FailingAgreement),
            Err(Error::BiometricFailed)
        ));
    }

    #[test]
    fn oversized_blob_is_refused_at_seal_time() {
        let device = SoftwareKey::random();
        let blob = vec![0_u8; usize::from(u16::MAX) + 1];
        let key = DeviceKey {
            blob: &blob,
            biometry_state: STATE,
        };
        assert!(matches!(
            seal(&device.public(), &key, USER_KEY),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn software_agreement_matches_rfc5903_p256_vector() {
        // RFC 5903 section 8.1: i, g^r and g^ir x-coordinate.
        let scalar = hex("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        let secret = SecretKey::from_slice(&scalar).expect("scalar");
        let responder = rfc5903_point(
            "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63",
            "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
        );
        let shared = SoftwareKey(secret)
            .shared_secret(&device_key(), &responder)
            .expect("ecdh");
        assert_eq!(
            shared.as_slice(),
            hex("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")
        );
    }

    #[test]
    fn wrapping_key_matches_independent_hkdf() {
        // Expected value computed with Python's hmac/hashlib HKDF over the RFC 5903 points
        // (salt = g^i ‖ g^r, ikm = g^ir x-coordinate, info = "vaultkeeper touchid v1").
        let ephemeral = rfc5903_point(
            "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180",
            "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
        );
        let device = rfc5903_point(
            "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63",
            "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
        );
        let shared: SharedSecret = Zeroizing::new(
            hex("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")
                .try_into()
                .expect("32 bytes"),
        );
        let key = wrapping_key(&shared, &ephemeral, &device);
        assert_eq!(
            key.as_slice(),
            hex("fb61f56f9bdefc0f32f391037da4f731f965395f9a62ce1c04b11c6b237283e8")
        );
    }
}
