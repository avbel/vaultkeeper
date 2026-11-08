use aes::Aes256;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, KeyInit, Mac};
use rand::{TryRng, rngs::SysRng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub(crate) const BLOCK_LEN: usize = 16;

pub(crate) fn fill_random(buf: &mut [u8]) {
    // Without OS entropy no key or IV can be made safely, so there is no state to fall back to.
    SysRng
        .try_fill_bytes(buf)
        .expect("the OS random number generator failed");
}

/// AES-256-CBC with PKCS#7 padding, encrypted in place so no plaintext copy outlives the call.
pub(crate) fn cbc_encrypt(key: &[u8; 32], iv: &[u8; BLOCK_LEN], plaintext: &[u8]) -> Vec<u8> {
    let msg_len = plaintext.len();
    let mut buf = vec![0u8; (msg_len / BLOCK_LEN + 1) * BLOCK_LEN];
    buf[..msg_len].copy_from_slice(plaintext);
    cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
        .expect("the buffer has room for a full padding block");
    buf
}

pub(crate) fn cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; BLOCK_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plaintext_len = cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| Error::Decrypt)?
        .len();
    buf.truncate(plaintext_len);
    Ok(buf)
}

/// HMAC-SHA256 over `iv || data`, the authenticated part of a type-2 EncString.
pub(crate) fn hmac_tag(key: &[u8; 32], iv: &[u8; BLOCK_LEN], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(iv);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn verify_hmac(
    key: &[u8; 32],
    iv: &[u8; BLOCK_LEN],
    data: &[u8],
    expected: &[u8; 32],
) -> Result<()> {
    let tag = hmac_tag(key, iv, data);
    if bool::from(tag[..].ct_eq(&expected[..])) {
        Ok(())
    } else {
        Err(Error::MacMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const IV: [u8; BLOCK_LEN] = [9; BLOCK_LEN];

    #[test]
    fn cbc_pads_to_the_next_block() {
        for (plaintext_len, ciphertext_len) in [(0, 16), (15, 16), (16, 32), (17, 32)] {
            let ciphertext = cbc_encrypt(&KEY, &IV, &vec![1u8; plaintext_len]);
            assert_eq!(
                ciphertext.len(),
                ciphertext_len,
                "plaintext of {plaintext_len} bytes"
            );
        }
    }

    #[test]
    fn cbc_round_trips() {
        let plaintext = b"exactly sixteen!and some more";
        let ciphertext = cbc_encrypt(&KEY, &IV, plaintext);
        let decrypted = cbc_decrypt(&KEY, &IV, &ciphertext).expect("valid ciphertext");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn cbc_decrypt_rejects_partial_blocks() {
        assert!(matches!(
            cbc_decrypt(&KEY, &IV, &[0u8; 15]),
            Err(Error::Decrypt)
        ));
        assert!(matches!(cbc_decrypt(&KEY, &IV, &[]), Err(Error::Decrypt)));
    }

    #[test]
    fn verify_hmac_accepts_own_tag_and_rejects_others() {
        let tag = hmac_tag(&KEY, &IV, b"data");
        verify_hmac(&KEY, &IV, b"data", &tag).expect("matching tag");
        assert!(matches!(
            verify_hmac(&KEY, &IV, b"datA", &tag),
            Err(Error::MacMismatch)
        ));
        assert!(matches!(
            verify_hmac(&[8; 32], &IV, b"data", &tag),
            Err(Error::MacMismatch)
        ));
    }

    #[test]
    fn fill_random_produces_distinct_output() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        fill_random(&mut first);
        fill_random(&mut second);
        assert_ne!(first, second);
    }
}
