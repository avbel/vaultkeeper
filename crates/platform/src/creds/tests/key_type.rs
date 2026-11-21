//! Fixtures are `struct encrypted_credential_header` of systemd v262 (`src/shared/creds-util.c`:
//! id, then `key_size` 32, `block_size` 1, `iv_size` 12, `tag_size` 16 as le32, then the IV) in
//! base64, one per `SD_ID128_MAKE` constant of `creds-util.h`, generated outside this crate.

use super::super::header::{HeaderError, Sealing, sealing};

const HOST: [&str; 2] = [
    // CRED_AES256_GCM_BY_HOST 5a1c6a86df9d4096b1d5a65e0862f19a
    "Whxqht+dQJax1aZeCGLxmiAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_SCOPED 55b9ed1d38594d43a8319d2ebb332ac6
    "VbntHThZTUOoMZ0uuzMqxiAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
];

const TPM: [&str; 4] = [
    // CRED_AES256_GCM_BY_TPM2_HMAC 0c7cc07b117645919c4b0bea08bc20fe
    "DHzAexF2RZGcSwvqCLwg/iAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK faf7eb9341e3412ca1a436f95a29362f
    "+vfrk0HjQSyhpDb5Wik2LyAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_TPM2_HMAC_PINNED_SRK d4062dfb71ad4c86804b40ef1180f1fc
    "1AYt+3GtTIaAS0DvEYDx/CAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK_PINNED_SRK 5e2d5c7603724eaf843c6fb5f64098f5
    "Xi1cdgNyTq+EPG+19kCY9SAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
];

const TPM_AND_HOST: [&str; 8] = [
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC 93a894094874449090caf2fc93cab553
    "k6iUCUh0RJCQyvL8k8q1UyAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED ef4ac13679a9480ea7db68897f9f165d
    "70rBNnmpSA6n22iJf58WXSAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK af4950a849134eb1a73846304ff30c05
    "r0lQqEkTTrGnOEYwT/MMBSAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED adbc4ca3efb64201ba881b6f2e4095ea
    "rbxMo++2QgG6iBtvLkCV6iAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_PINNED_SRK 1414258818a240cd900bce862db5c7b9
    "FBQliBiiQM2QC86GLbXHuSAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED_PINNED_SRK 2a1f877a4275431ab3f9ed1f5d8f6601
    "Kh+HekJ1Qxqz+e0fXY9mASAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_PINNED_SRK afbfeaaceb6a4a3795419d135c47f37b
    "r7/qrOtqSjeVQZ0TXEfzeyAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED_PINNED_SRK 16e492949f94400286758f94b7c52bc7
    "FuSSlJ+UQAKGdY+Ut8UrxyAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
];

// CRED_AES256_GCM_BY_NULL 058469daf6f54324800549da0f8ea2fb
const NULL: &str = "BYRp2vb1QySABUnaD46i+yAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=";

/// The `_CRED_AUTO*` selectors, which systemd never stores in a blob.
const NEVER_WRITTEN: [&str; 5] = [
    "ohnLB4WyTASxbRjKudLuASAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    "RfOmfgwSQlak7nXrRMZabyAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    "2vZ6YNPrR7Opvi/V/sIVIiAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    "AtyO3joCQ6up7FScBeagcSAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
    "I4iWhW90SIqceG9qsOc7aiAAAAABAAAADAAAABAAAAAAAQIDBAUGBwgJCgs=",
];

/// The start of what `systemd-creds --user encrypt --with-key=auto` printed on Fedora 45
/// (systemd 262.1) with a TPM2, line wrap included.
const REAL_WITH_TPM2: &str = "Kh+HekJ1Qxqz+e0fXY9mASAAAAABAAAADAAAABAAAADI4ZWp5N3bZ/sMQnsAAAAAAAAAAAAAAAALACM\nA8AAAACAAAAAAngAgqxU+v3KQK0oncGYB3Ll3GMVgf00OhhDa+djMUFUkMqAAEBtGcvdSq9RYvCDBIO\n";

#[test]
fn every_key_type_maps_to_the_keys_it_needs() {
    for blob in HOST {
        assert_eq!(sealing(blob.as_bytes()), Ok(Sealing::Host), "{blob}");
    }
    for blob in TPM {
        assert_eq!(sealing(blob.as_bytes()), Ok(Sealing::Tpm), "{blob}");
    }
    for blob in TPM_AND_HOST {
        assert_eq!(sealing(blob.as_bytes()), Ok(Sealing::TpmAndHost), "{blob}");
    }
    assert_eq!(sealing(NULL.as_bytes()), Ok(Sealing::Null));
}

#[test]
fn a_real_blob_from_a_machine_with_a_tpm2_is_sealed_to_both_keys() {
    assert_eq!(sealing(REAL_WITH_TPM2.as_bytes()), Ok(Sealing::TpmAndHost));
}

#[test]
fn line_wraps_inside_the_id_are_skipped() {
    let wrapped = format!(
        "{}\r\n{} {}",
        &HOST[1][..5],
        &HOST[1][5..20],
        &HOST[1][20..]
    );
    assert_eq!(sealing(wrapped.as_bytes()), Ok(Sealing::Host));
}

#[test]
fn an_id_systemd_does_not_write_is_reported_in_hex() {
    for blob in NEVER_WRITTEN {
        assert!(
            matches!(sealing(blob.as_bytes()), Err(HeaderError::UnknownKey(_))),
            "{blob}"
        );
    }
    let error = sealing(NEVER_WRITTEN[4].as_bytes()).expect_err("unknown");
    assert_eq!(
        error.to_string(),
        "unrecognized credential key type 238896856f74488a9c786f6ab0e73b6a"
    );
}

#[test]
fn short_or_non_base64_output_is_malformed() {
    let cases: [&[u8]; 5] = [
        b"",
        &HOST[0].as_bytes()[..23],
        b"Whxqht+dQJax1aZeCGLx=iAA",
        b"Whxqht+dQJax1aZeCGLx-iAA",
        &[0xff; 32],
    ];
    for case in cases {
        assert_eq!(sealing(case), Err(HeaderError::Malformed), "{case:?}");
    }
}
