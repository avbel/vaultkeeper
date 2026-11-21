//! Which key a `systemd-creds` blob is sealed with, read from the blob itself.
//!
//! The tool prints base64 of a packed structure that starts with the 16-byte key-type id
//! (`struct encrypted_credential_header.id` in systemd `src/shared/creds-util.c`, ids in
//! `creds-util.h`). Decryption picks its keys by that id, so it states what protects the blob.
//! Nothing else does: an unprivileged `encrypt` is carried out by the root service, which never
//! sees `--with-key`, and its automatic mode silently falls back from TPM2 plus host key to the
//! host key alone when sealing to the TPM2 fails.

use thiserror::Error;

const ID_LEN: usize = 16;
/// Base64 groups covering the id: six groups of four characters decode to 18 bytes.
const ID_GROUPS: usize = 6;

type Id = [u8; ID_LEN];

const fn id(value: u128) -> Id {
    value.to_be_bytes()
}

/// `CRED_AES256_GCM_BY_HOST`, `…_HOST_SCOPED`.
const HOST: [Id; 2] = [
    id(0x5a1c_6a86_df9d_4096_b1d5_a65e_0862_f19a),
    id(0x55b9_ed1d_3859_4d43_a831_9d2e_bb33_2ac6),
];

/// `CRED_AES256_GCM_BY_TPM2_HMAC`, `…_WITH_PK`, `…_PINNED_SRK`, `…_WITH_PK_PINNED_SRK`.
const TPM: [Id; 4] = [
    id(0x0c7c_c07b_1176_4591_9c4b_0bea_08bc_20fe),
    id(0xfaf7_eb93_41e3_412c_a1a4_36f9_5a29_362f),
    id(0xd406_2dfb_71ad_4c86_804b_40ef_1180_f1fc),
    id(0x5e2d_5c76_0372_4eaf_843c_6fb5_f640_98f5),
];

/// `CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC` and its `_SCOPED`, `_WITH_PK`, `_PINNED_SRK`
/// combinations.
const TPM_AND_HOST: [Id; 8] = [
    id(0x93a8_9409_4874_4490_90ca_f2fc_93ca_b553),
    id(0xef4a_c136_79a9_480e_a7db_6889_7f9f_165d),
    id(0xaf49_50a8_4913_4eb1_a738_4630_4ff3_0c05),
    id(0xadbc_4ca3_efb6_4201_ba88_1b6f_2e40_95ea),
    id(0x1414_2588_18a2_40cd_900b_ce86_2db5_c7b9),
    id(0x2a1f_877a_4275_431a_b3f9_ed1f_5d8f_6601),
    id(0xafbf_eaac_eb6a_4a37_9541_9d13_5c47_f37b),
    id(0x16e4_9294_9f94_4002_8675_8f94_b7c5_2bc7),
];

/// `CRED_AES256_GCM_BY_NULL`: a fixed key, so integrity only.
const NULL: Id = id(0x0584_69da_f6f5_4324_8005_49da_0f8e_a2fb);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sealing {
    TpmAndHost,
    Tpm,
    Host,
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HeaderError {
    #[error("the output does not start with a credential header")]
    Malformed,
    #[error("unrecognized credential key type {}", hex(.0))]
    UnknownKey(Id),
}

fn hex(id: &Id) -> String {
    format!("{:032x}", u128::from_be_bytes(*id))
}

/// The key type of a blob as `systemd-creds encrypt` printed it (base64, possibly line-wrapped).
pub fn sealing(output: &[u8]) -> Result<Sealing, HeaderError> {
    let id = key_id(output).ok_or(HeaderError::Malformed)?;
    if TPM_AND_HOST.contains(&id) {
        Ok(Sealing::TpmAndHost)
    } else if TPM.contains(&id) {
        Ok(Sealing::Tpm)
    } else if HOST.contains(&id) {
        Ok(Sealing::Host)
    } else if id == NULL {
        Ok(Sealing::Null)
    } else {
        Err(HeaderError::UnknownKey(id))
    }
}

fn key_id(output: &[u8]) -> Option<Id> {
    let mut sextets = output
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|&byte| sextet(byte));
    let mut decoded = [0_u8; ID_GROUPS * 3];
    for triple in decoded.as_chunks_mut::<3>().0 {
        let mut group = 0_u32;
        for _ in 0..4 {
            group = (group << 6) | u32::from(sextets.next()??);
        }
        let [_, bytes @ ..] = group.to_be_bytes();
        *triple = bytes;
    }
    decoded.first_chunk::<ID_LEN>().copied()
}

const fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
