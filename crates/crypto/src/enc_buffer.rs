//! Bitwarden binary EncString ("EncArrayBuffer"), used for attachment files:
//!
//! ```text
//! type (1 byte, always 2) | IV (16) | HMAC-SHA256(mac key, IV || ciphertext) (32) | AES-256-CBC ciphertext
//! ```
//!
//! The streaming functions work in fixed 64 KiB buffers, so memory use does not grow with the
//! file size. Errors are checked in this order: header ([`Error::MalformedEncString`] when
//! truncated, [`Error::UnsupportedEncType`] for a type other than 2), then the MAC
//! ([`Error::MacMismatch`]), then the ciphertext length and padding.

use std::io::{self, Read, Seek, SeekFrom, Write};

use aes::Aes256;
use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, array::Array, block_padding::Pkcs7,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    Error, Result, SymmetricKey,
    primitives::{BLOCK_LEN, cbc_decrypt, cbc_encrypt, fill_random, hmac_tag, verify_hmac},
};

const BUFFER_TYPE: u8 = 2;
const IV_LEN: usize = BLOCK_LEN;
const MAC_LEN: usize = 32;
const MAC_OFFSET: usize = 1 + IV_LEN;
/// Length of `type | IV | MAC` in front of the ciphertext.
pub const HEADER_LEN: usize = MAC_OFFSET + MAC_LEN;
const CHUNK_LEN: usize = 64 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// Encrypts all of `reader` into `writer` and returns the number of bytes written
/// (header + ciphertext, the size Bitwarden expects for an attachment upload).
///
/// The MAC slot is written as zeros first and filled in at the end, so `writer` must be seekable.
/// Afterwards `writer` is positioned after the last ciphertext byte. On error it holds an
/// incomplete file with a zeroed MAC, which must be discarded.
pub fn encrypt_stream(
    key: &SymmetricKey,
    mut reader: impl Read,
    mut writer: impl Write + Seek,
) -> Result<u64> {
    let mac_key = key.mac_key().ok_or(Error::MissingMacKey)?;
    let mut iv = [0u8; IV_LEN];
    fill_random(&mut iv);

    let start = writer.stream_position()?;
    writer.write_all(&[BUFFER_TYPE])?;
    writer.write_all(&iv)?;
    writer.write_all(&[0u8; MAC_LEN])?;

    let mut mac = new_hmac(mac_key);
    mac.update(&iv);
    let mut encryptor = cbc::Encryptor::<Aes256>::new(key.enc_key().into(), (&iv).into());
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_LEN]);
    // One block of the buffer stays free so the final read always has room for its padding.
    let read_len = CHUNK_LEN - BLOCK_LEN;
    let mut ciphertext_len = 0u64;
    loop {
        let filled = read_full(&mut reader, &mut buf[..read_len])?;
        if filled < read_len {
            let last = encryptor
                .encrypt_padded::<Pkcs7>(&mut buf, filled)
                .expect("the buffer keeps a free block for padding");
            mac.update(last);
            writer.write_all(last)?;
            ciphertext_len += len_u64(last.len());
            break;
        }
        let chunk = &mut buf[..read_len];
        encryptor.encrypt_blocks(Array::slice_as_chunks_mut(chunk).0);
        mac.update(chunk);
        writer.write_all(chunk)?;
        ciphertext_len += len_u64(read_len);
    }

    let total = len_u64(HEADER_LEN) + ciphertext_len;
    writer.seek(SeekFrom::Start(start + len_u64(MAC_OFFSET)))?;
    writer.write_all(&mac.finalize().into_bytes())?;
    writer.seek(SeekFrom::Start(start + total))?;
    Ok(total)
}

/// Reads the whole stream and checks its MAC in constant time, without decrypting.
pub fn verify_stream(key: &SymmetricKey, mut reader: impl Read) -> Result<()> {
    let mac_key = key.mac_key().ok_or(Error::MissingMacKey)?;
    let header = read_header(&mut reader)?;
    let mut mac = new_hmac(mac_key);
    mac.update(header.iv());
    let mut buf = vec![0u8; CHUNK_LEN];
    let mut ciphertext_len = 0u64;
    loop {
        let filled = read_full(&mut reader, &mut buf)?;
        mac.update(&buf[..filled]);
        ciphertext_len += len_u64(filled);
        if filled < CHUNK_LEN {
            break;
        }
    }
    check_mac(mac, header.mac())?;
    check_ciphertext_len(ciphertext_len)
}

/// Decrypts the stream into `writer` and returns the number of plaintext bytes written.
///
/// Plaintext is written before the end of the stream is reached, so callers should run
/// [`verify_stream`] first. The MAC is checked again at the end and a mismatch still fails with
/// [`Error::MacMismatch`]; on any error, `writer` may hold partial plaintext that must be
/// discarded.
pub fn decrypt_stream(
    key: &SymmetricKey,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<u64> {
    let mac_key = key.mac_key().ok_or(Error::MissingMacKey)?;
    let header = read_header(&mut reader)?;
    let mut mac = new_hmac(mac_key);
    mac.update(header.iv());
    let mut decryptor = cbc::Decryptor::<Aes256>::new(key.enc_key().into(), header.iv().into());
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_LEN]);
    // The last ciphertext block carries the padding, so one block is held back until EOF.
    let ready_len = CHUNK_LEN - BLOCK_LEN;
    let mut held = 0;
    let mut plaintext_len = 0u64;
    loop {
        let filled = held + read_full(&mut reader, &mut buf[held..])?;
        if filled < CHUNK_LEN {
            held = filled;
            break;
        }
        let chunk = &mut buf[..ready_len];
        mac.update(chunk);
        decryptor.decrypt_blocks(Array::slice_as_chunks_mut(chunk).0);
        writer.write_all(chunk)?;
        plaintext_len += len_u64(ready_len);
        buf.copy_within(ready_len.., 0);
        held = BLOCK_LEN;
    }

    let last = &mut buf[..held];
    mac.update(last);
    check_mac(mac, header.mac())?;
    check_ciphertext_len(plaintext_len + len_u64(held))?;
    let last = decryptor
        .decrypt_padded::<Pkcs7>(last)
        .map_err(|_| Error::Decrypt)?;
    writer.write_all(last)?;
    Ok(plaintext_len + len_u64(last.len()))
}

/// In-memory form of [`encrypt_stream`] for small payloads.
pub fn encrypt_bytes(key: &SymmetricKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mac_key = key.mac_key().ok_or(Error::MissingMacKey)?;
    let mut iv = [0u8; IV_LEN];
    fill_random(&mut iv);
    let ciphertext = cbc_encrypt(key.enc_key(), &iv, plaintext);
    let mac = hmac_tag(mac_key, &iv, &ciphertext);
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(BUFFER_TYPE);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// In-memory form of [`verify_stream`] + [`decrypt_stream`] for small payloads.
pub fn decrypt_bytes(key: &SymmetricKey, buffer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mac_key = key.mac_key().ok_or(Error::MissingMacKey)?;
    let header_bytes = buffer.get(..HEADER_LEN).unwrap_or(buffer);
    let header = parse_header(header_bytes)?;
    let ciphertext = &buffer[HEADER_LEN..];
    verify_hmac(mac_key, header.iv(), ciphertext, header.mac())?;
    check_ciphertext_len(len_u64(ciphertext.len()))?;
    cbc_decrypt(key.enc_key(), header.iv(), ciphertext)
}

struct Header([u8; HEADER_LEN]);

impl Header {
    fn iv(&self) -> &[u8; IV_LEN] {
        self.0[1..MAC_OFFSET]
            .try_into()
            .expect("the IV range is IV_LEN bytes")
    }

    fn mac(&self) -> &[u8; MAC_LEN] {
        self.0[MAC_OFFSET..]
            .try_into()
            .expect("the MAC range is MAC_LEN bytes")
    }
}

fn read_header(reader: &mut impl Read) -> Result<Header> {
    let mut bytes = [0u8; HEADER_LEN];
    let filled = read_full(reader, &mut bytes)?;
    parse_header(&bytes[..filled])
}

/// `bytes` is the start of the buffer, at most [`HEADER_LEN`] long.
fn parse_header(bytes: &[u8]) -> Result<Header> {
    match bytes.first() {
        None => Err(Error::MalformedEncString("encrypted buffer is empty")),
        Some(&enc_type) if enc_type != BUFFER_TYPE => Err(Error::UnsupportedEncType(enc_type)),
        Some(_) => bytes
            .try_into()
            .map(Header)
            .map_err(|_| Error::MalformedEncString("encrypted buffer is shorter than its header")),
    }
}

fn check_mac(mac: HmacSha256, expected: &[u8; MAC_LEN]) -> Result<()> {
    let tag = mac.finalize().into_bytes();
    if bool::from(tag[..].ct_eq(&expected[..])) {
        Ok(())
    } else {
        Err(Error::MacMismatch)
    }
}

fn check_ciphertext_len(len: u64) -> Result<()> {
    if len == 0 || !len.is_multiple_of(len_u64(BLOCK_LEN)) {
        return Err(Error::MalformedEncString(
            "ciphertext must be a non-empty multiple of 16 bytes",
        ));
    }
    Ok(())
}

fn new_hmac(key: &[u8; 32]) -> HmacSha256 {
    <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length")
}

/// Reads until `buf` is full or the reader reports EOF; a short count therefore means EOF.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).expect("buffer lengths fit in u64")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// Hands out at most `step` bytes per `read`, like a pipe or socket would.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).expect("below 256"))
            .collect()
    }

    fn encrypt_to_vec(key: &SymmetricKey, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        let written = encrypt_stream(key, plaintext, &mut out).expect("encrypts");
        assert_eq!(written, len_u64(out.get_ref().len()));
        out.into_inner()
    }

    fn decrypt_to_vec(key: &SymmetricKey, buffer: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let written = decrypt_stream(key, buffer, &mut out)?;
        assert_eq!(written, len_u64(out.len()));
        Ok(out)
    }

    fn padded_len(plaintext_len: usize) -> usize {
        (plaintext_len / BLOCK_LEN + 1) * BLOCK_LEN
    }

    #[test]
    fn stream_round_trips_around_buffer_boundaries() {
        let key = SymmetricKey::generate();
        let sizes = [
            0,
            1,
            15,
            16,
            17,
            CHUNK_LEN - BLOCK_LEN - 1,
            CHUNK_LEN - BLOCK_LEN,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN + 5,
        ];
        for size in sizes {
            let plaintext = pattern(size);
            let encrypted = encrypt_to_vec(&key, &plaintext);
            assert_eq!(
                encrypted.len(),
                HEADER_LEN + padded_len(size),
                "size {size}"
            );
            verify_stream(&key, encrypted.as_slice()).expect("valid MAC");
            assert_eq!(
                decrypt_to_vec(&key, &encrypted).expect("decrypts"),
                plaintext,
                "size {size}"
            );
        }
    }

    #[test]
    fn stream_round_trips_ten_megabytes() {
        let key = SymmetricKey::generate();
        let plaintext = pattern(10 * 1024 * 1024);
        let encrypted = encrypt_to_vec(&key, &plaintext);
        verify_stream(&key, encrypted.as_slice()).expect("valid MAC");
        let decrypted = decrypt_to_vec(&key, &encrypted).expect("decrypts");
        assert!(decrypted == plaintext, "10 MB round trip differs");
    }

    #[test]
    fn stream_handles_short_reads() {
        let key = SymmetricKey::generate();
        let plaintext = pattern(CHUNK_LEN * 2 + 33);
        let mut out = Cursor::new(Vec::new());
        encrypt_stream(
            &key,
            Trickle {
                data: &plaintext,
                step: 7,
            },
            &mut out,
        )
        .expect("encrypts");
        let encrypted = out.into_inner();
        verify_stream(
            &key,
            Trickle {
                data: &encrypted,
                step: 5,
            },
        )
        .expect("valid MAC");
        let mut decrypted = Vec::new();
        decrypt_stream(
            &key,
            Trickle {
                data: &encrypted,
                step: 3,
            },
            &mut decrypted,
        )
        .expect("decrypts");
        assert!(decrypted == plaintext, "short-read round trip differs");
    }

    #[test]
    fn encrypt_stream_fills_the_mac_relative_to_the_start_position() {
        let key = SymmetricKey::generate();
        let mut out = Cursor::new(b"prefix".to_vec());
        out.set_position(6);
        let written = encrypt_stream(&key, &b"attachment"[..], &mut out).expect("encrypts");
        assert_eq!(out.position(), 6 + written);
        let bytes = out.into_inner();
        assert_eq!(&bytes[..6], b"prefix");
        assert_eq!(
            decrypt_bytes(&key, &bytes[6..])
                .expect("decrypts")
                .as_slice(),
            b"attachment"
        );
    }

    #[test]
    fn stream_and_bytes_forms_are_interchangeable() {
        let key = SymmetricKey::generate();
        let plaintext = pattern(1000);
        let from_stream = encrypt_to_vec(&key, &plaintext);
        let from_bytes = encrypt_bytes(&key, &plaintext).expect("encrypts");
        assert_eq!(from_bytes.len(), from_stream.len());
        assert_eq!(
            decrypt_bytes(&key, &from_stream)
                .expect("decrypts")
                .as_slice(),
            plaintext
        );
        assert_eq!(
            decrypt_to_vec(&key, &from_bytes).expect("decrypts"),
            plaintext
        );
    }

    #[test]
    fn bytes_round_trip_empty_and_one_byte() {
        let key = SymmetricKey::generate();
        for plaintext in [&b""[..], b"x"] {
            let encrypted = encrypt_bytes(&key, plaintext).expect("encrypts");
            assert_eq!(encrypted.len(), HEADER_LEN + BLOCK_LEN);
            assert_eq!(encrypted[0], BUFFER_TYPE);
            assert_eq!(
                decrypt_bytes(&key, &encrypted)
                    .expect("decrypts")
                    .as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn encryption_uses_a_fresh_iv() {
        let key = SymmetricKey::generate();
        let first = encrypt_bytes(&key, b"same").expect("encrypts");
        let second = encrypt_bytes(&key, b"same").expect("encrypts");
        assert_ne!(first[1..MAC_OFFSET], second[1..MAC_OFFSET]);
        assert_ne!(first, second);
    }

    fn assert_rejected(key: &SymmetricKey, buffer: &[u8], expected: fn(&Error) -> bool) {
        let results = [
            verify_stream(key, buffer).err(),
            decrypt_to_vec(key, buffer).err(),
            decrypt_bytes(key, buffer).err(),
        ];
        for (op, result) in ["verify_stream", "decrypt_stream", "decrypt_bytes"]
            .iter()
            .zip(results)
        {
            assert!(
                result.as_ref().is_some_and(expected),
                "{op} gave {result:?}"
            );
        }
    }

    #[test]
    fn tampering_fails_the_mac() {
        let key = SymmetricKey::generate();
        let encrypted = encrypt_to_vec(&key, &pattern(CHUNK_LEN + 100));
        let last = encrypted.len() - 1;
        for index in [
            1,
            MAC_OFFSET - 1,
            MAC_OFFSET,
            HEADER_LEN - 1,
            HEADER_LEN,
            HEADER_LEN + CHUNK_LEN,
            last,
        ] {
            let mut tampered = encrypted.clone();
            tampered[index] ^= 0x01;
            assert_rejected(&key, &tampered, |err| matches!(err, Error::MacMismatch));
        }
    }

    #[test]
    fn truncated_or_extended_ciphertext_fails_the_mac() {
        let key = SymmetricKey::generate();
        let encrypted = encrypt_to_vec(&key, &pattern(100));
        let mut extended = encrypted.clone();
        extended.extend_from_slice(&[0u8; BLOCK_LEN]);
        for buffer in [
            &encrypted[..encrypted.len() - 10],
            &encrypted[..encrypted.len() - BLOCK_LEN],
            &encrypted[..HEADER_LEN],
            &extended[..],
        ] {
            assert_rejected(&key, buffer, |err| matches!(err, Error::MacMismatch));
        }
    }

    #[test]
    fn wrong_key_fails_the_mac() {
        let encrypted = encrypt_to_vec(&SymmetricKey::generate(), b"secret");
        assert_rejected(&SymmetricKey::generate(), &encrypted, |err| {
            matches!(err, Error::MacMismatch)
        });
    }

    #[test]
    fn wrong_type_byte_is_rejected() {
        let key = SymmetricKey::generate();
        let mut encrypted = encrypt_to_vec(&key, b"secret");
        for enc_type in [0u8, 1, 3, 4, 7, 255] {
            encrypted[0] = enc_type;
            assert_rejected(
                &key,
                &encrypted,
                |err| matches!(err, Error::UnsupportedEncType(t) if *t != BUFFER_TYPE),
            );
        }
    }

    #[test]
    fn truncated_header_is_rejected() {
        let key = SymmetricKey::generate();
        let encrypted = encrypt_to_vec(&key, b"secret");
        for len in [0, 1, MAC_OFFSET, HEADER_LEN - 1] {
            assert_rejected(&key, &encrypted[..len], |err| {
                matches!(err, Error::MalformedEncString(_))
            });
        }
    }

    #[test]
    fn authenticated_partial_block_is_rejected_after_the_mac() {
        let key = SymmetricKey::generate();
        let iv = [4u8; IV_LEN];
        let ciphertext = [5u8; BLOCK_LEN - 1];
        let mac_key = key.mac_key().expect("generated keys have a MAC key");
        let mut buffer = vec![BUFFER_TYPE];
        buffer.extend_from_slice(&iv);
        buffer.extend_from_slice(&hmac_tag(mac_key, &iv, &ciphertext));
        buffer.extend_from_slice(&ciphertext);
        assert_rejected(&key, &buffer, |err| {
            matches!(err, Error::MalformedEncString(_))
        });
    }

    #[test]
    fn decrypt_stream_rejects_bad_padding_after_a_valid_mac() {
        let key = SymmetricKey::generate();
        let iv = [4u8; IV_LEN];
        // A block whose plaintext ends in 0x00 can never carry valid PKCS#7 padding.
        let mut ciphertext = [0u8; BLOCK_LEN];
        cbc::Encryptor::<Aes256>::new(key.enc_key().into(), (&iv).into())
            .encrypt_blocks(Array::slice_as_chunks_mut(&mut ciphertext).0);
        let mac_key = key.mac_key().expect("generated keys have a MAC key");
        let mut buffer = vec![BUFFER_TYPE];
        buffer.extend_from_slice(&iv);
        buffer.extend_from_slice(&hmac_tag(mac_key, &iv, &ciphertext));
        buffer.extend_from_slice(&ciphertext);
        verify_stream(&key, buffer.as_slice()).expect("the MAC itself is valid");
        assert!(matches!(decrypt_to_vec(&key, &buffer), Err(Error::Decrypt)));
        assert!(matches!(decrypt_bytes(&key, &buffer), Err(Error::Decrypt)));
    }

    #[test]
    fn every_operation_requires_a_mac_key() {
        let enc_only = SymmetricKey::from_bytes(&[1u8; 32]).expect("32-byte key");
        let encrypted = encrypt_to_vec(&SymmetricKey::generate(), b"secret");
        let mut sink = Cursor::new(Vec::new());
        assert!(matches!(
            encrypt_stream(&enc_only, &b"x"[..], &mut sink),
            Err(Error::MissingMacKey)
        ));
        assert!(
            sink.get_ref().is_empty(),
            "nothing is written without a MAC key"
        );
        assert!(matches!(
            encrypt_bytes(&enc_only, b"x"),
            Err(Error::MissingMacKey)
        ));
        assert_rejected(&enc_only, &encrypted, |err| {
            matches!(err, Error::MissingMacKey)
        });
    }

    #[test]
    fn reader_errors_are_reported() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("disk gone"))
            }
        }
        let key = SymmetricKey::generate();
        let mut sink = Cursor::new(Vec::new());
        assert!(matches!(
            encrypt_stream(&key, Broken, &mut sink),
            Err(Error::Io(_))
        ));
        assert!(matches!(verify_stream(&key, Broken), Err(Error::Io(_))));
        assert!(matches!(
            decrypt_stream(&key, Broken, Vec::new()),
            Err(Error::Io(_))
        ));
    }
}
