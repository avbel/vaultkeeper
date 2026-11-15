//! Ed25519 detached signatures for release assets, in the minisign container format.
//!
//! Each asset ships next to a `.minisig` file: an untrusted comment, a base64 signature blob
//! (algorithm, key id, signature), the trusted comment `vaultkeeper <version> <asset name>`, and
//! a base64 global signature over that comment. Signatures are prehashed Ed25519: the asset is
//! hashed with SHA-512 and the digest is signed, so a multi-hundred-megabyte download never sits
//! in memory. Trust is the Ed25519 key embedded below, shared with the Linux plan (§8.3); it
//! survives a change of code-signing certificate.

use std::{fs::File, io::Read as _, path::Path};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha512};

use super::release::{self, Release, Version};

/// Prehashed Ed25519 over SHA-512, the only algorithm this updater accepts.
const SIG_ALG: [u8; 2] = *b"Ed";
const KEY_ID_LEN: usize = 8;
const SIGNATURE_LEN: usize = 64;

/// The public key that signs release assets. All zeroes until the project's release key is
/// generated; the placeholder must refuse every update, never accept one.
const UPDATE_PUBLIC_KEY: [u8; 32] = [0_u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("the embedded update key is still the placeholder; updates are refused")]
    PlaceholderKey,
    #[error("the signature file is malformed: {0}")]
    Format(String),
    #[error("the signature does not match the asset")]
    Invalid,
    #[error("the trusted comment is malformed: {0}")]
    Comment(String),
    #[error("the signature is for version {signed}, not {expected}")]
    VersionMismatch { signed: Version, expected: Version },
    #[error("the update {signed} is not newer than {current}")]
    Downgrade { signed: Version, current: Version },
    #[error("the signature covers {signed:?}, not {expected:?}")]
    AssetMismatch { signed: String, expected: String },
}

/// The release-signing key embedded in the binary; `Err(PlaceholderKey)` until the real key is
/// generated, which must refuse every update.
pub fn public_key() -> Result<VerifyingKey, VerifyError> {
    if UPDATE_PUBLIC_KEY.iter().all(|byte| *byte == 0) {
        return Err(VerifyError::PlaceholderKey);
    }
    VerifyingKey::from_bytes(&UPDATE_PUBLIC_KEY).map_err(|_| VerifyError::PlaceholderKey)
}

/// Verifies `asset` against its `signature` file and that the trusted comment names `release`'s
/// version and asset, newer than the running app.
pub fn verify(asset: &Path, signature: &Path, release: &Release) -> Result<(), VerifyError> {
    verify_with(asset, signature, release, &public_key()?)
}

fn verify_with(
    asset: &Path,
    signature_path: &Path,
    release: &Release,
    key: &VerifyingKey,
) -> Result<(), VerifyError> {
    let comment = verify_signature(asset, signature_path, key)?;
    check_comment(&comment, release)
}

struct TrustedComment {
    version: Version,
    asset: String,
}

/// The crypto check, independent of the release policy: returns the signed trusted comment.
fn verify_signature(
    asset: &Path,
    signature_path: &Path,
    key: &VerifyingKey,
) -> Result<TrustedComment, VerifyError> {
    let text = std::fs::read_to_string(signature_path)
        .map_err(|error| VerifyError::Format(error.to_string()))?;
    let parsed = parse(&text)?;
    if parsed.sig_alg != SIG_ALG {
        return Err(VerifyError::Format(
            "unsupported signature algorithm".to_owned(),
        ));
    }
    if parsed.key_id != key_id_of(key) {
        return Err(VerifyError::Invalid);
    }
    // The global signature binds the trusted comment to the primary signature.
    let mut global_message =
        Vec::with_capacity(2 + KEY_ID_LEN + SIGNATURE_LEN + parsed.trusted.len());
    global_message.extend_from_slice(&SIG_ALG);
    global_message.extend_from_slice(&parsed.key_id);
    global_message.extend_from_slice(&parsed.signature.to_bytes());
    global_message.extend_from_slice(parsed.trusted.as_bytes());
    key.verify(&global_message, &parsed.global)
        .map_err(|_| VerifyError::Invalid)?;
    // The primary signature covers the SHA-512 prehash of the asset.
    let mut message = Vec::with_capacity(2 + KEY_ID_LEN + 64);
    message.extend_from_slice(&SIG_ALG);
    message.extend_from_slice(&parsed.key_id);
    message.extend_from_slice(
        &sha512_of_file(asset).map_err(|error| VerifyError::Format(error.to_string()))?,
    );
    key.verify(&message, &parsed.signature)
        .map_err(|_| VerifyError::Invalid)?;
    parse_comment(&parsed.trusted)
}

fn check_comment(comment: &TrustedComment, release: &Release) -> Result<(), VerifyError> {
    if comment.version != release.version {
        return Err(VerifyError::VersionMismatch {
            signed: comment.version,
            expected: release.version,
        });
    }
    let current = Version::current();
    if comment.version <= current {
        return Err(VerifyError::Downgrade {
            signed: comment.version,
            current,
        });
    }
    let expected = release::asset_name(release.version);
    if comment.asset != expected {
        return Err(VerifyError::AssetMismatch {
            signed: comment.asset.clone(),
            expected,
        });
    }
    Ok(())
}

fn parse_comment(text: &str) -> Result<TrustedComment, VerifyError> {
    let malformed = || VerifyError::Comment(text.to_owned());
    let rest = text.strip_prefix("vaultkeeper ").ok_or_else(malformed)?;
    let (version, asset) = rest.split_once(' ').ok_or_else(malformed)?;
    let version = version.parse().map_err(|_| malformed())?;
    Ok(TrustedComment {
        version,
        asset: asset.to_owned(),
    })
}

struct Parsed {
    sig_alg: [u8; 2],
    key_id: [u8; KEY_ID_LEN],
    signature: Signature,
    trusted: String,
    global: Signature,
}

fn parse(text: &str) -> Result<Parsed, VerifyError> {
    let malformed = || VerifyError::Format("expected a minisign signature".to_owned());
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let untrusted = lines.next().ok_or_else(malformed)?;
    if !untrusted.starts_with("untrusted comment: ") {
        return Err(malformed());
    }
    let blob = BASE64
        .decode(lines.next().ok_or_else(malformed)?)
        .map_err(|error| VerifyError::Format(error.to_string()))?;
    if blob.len() != 2 + KEY_ID_LEN + SIGNATURE_LEN {
        return Err(malformed());
    }
    let trusted = lines
        .next()
        .and_then(|line| line.strip_prefix("trusted comment: "))
        .ok_or_else(malformed)?;
    let global = BASE64
        .decode(lines.next().ok_or_else(malformed)?)
        .map_err(|error| VerifyError::Format(error.to_string()))?;
    if global.len() != SIGNATURE_LEN || lines.next().is_some() {
        return Err(malformed());
    }
    let sig_alg: [u8; 2] = blob[..2].try_into().expect("length checked");
    let key_id: [u8; KEY_ID_LEN] = blob[2..2 + KEY_ID_LEN].try_into().expect("length checked");
    let signature =
        Signature::from_bytes(&blob[2 + KEY_ID_LEN..].try_into().expect("length checked"));
    let global = Signature::from_bytes(&global.try_into().expect("length checked"));
    Ok(Parsed {
        sig_alg,
        key_id,
        signature,
        trusted: trusted.to_owned(),
        global,
    })
}

fn key_id_of(key: &VerifyingKey) -> [u8; KEY_ID_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(SIG_ALG);
    hasher.update(key.to_bytes());
    let digest = hasher.finalize();
    digest[..KEY_ID_LEN].try_into().expect("8 bytes")
}

fn sha512_of_file(path: &Path) -> std::io::Result<[u8; 64]> {
    let mut hasher = Sha512::new();
    let mut file = File::open(path)?;
    // On the heap: a 64 KiB array trips the large-stack-arrays lint.
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ed25519_dalek::{Signer as _, SigningKey};
    use url::Url;

    use super::*;

    const SECRET: [u8; 32] = [7_u8; 32];

    fn release(version: Version) -> Release {
        let base = "https://github.com/avbel/vaultkeeper/releases/download";
        Release {
            version,
            asset: Url::parse(&format!("{base}/x/asset")).expect("url"),
            asset_size: 1,
            signature: Some(Url::parse(&format!("{base}/x/asset.minisig")).expect("url")),
            page: Url::parse("https://github.com/avbel/vaultkeeper").expect("url"),
        }
    }

    fn sign_text(secret: &[u8; 32], asset: &[u8], comment: &str) -> String {
        let key = SigningKey::from_bytes(secret);
        let public = key.verifying_key();
        let key_id = key_id_of(&public);

        let mut message = Vec::new();
        message.extend_from_slice(&SIG_ALG);
        message.extend_from_slice(&key_id);
        message.extend_from_slice(&Sha512::digest(asset));
        let signature = key.sign(&message);

        let mut global_message = Vec::new();
        global_message.extend_from_slice(&SIG_ALG);
        global_message.extend_from_slice(&key_id);
        global_message.extend_from_slice(&signature.to_bytes());
        global_message.extend_from_slice(comment.as_bytes());
        let global = key.sign(&global_message);

        let mut blob = Vec::new();
        blob.extend_from_slice(&SIG_ALG);
        blob.extend_from_slice(&key_id);
        blob.extend_from_slice(&signature.to_bytes());
        format!(
            "untrusted comment: test\n\n{}\n\ntrusted comment: {comment}\n{}\n",
            BASE64.encode(&blob),
            BASE64.encode(global.to_bytes())
        )
    }

    fn signed_asset(
        dir: &Path,
        secret: &[u8; 32],
        asset: &[u8],
        comment: &str,
    ) -> (PathBuf, PathBuf) {
        let asset_path = dir.join("asset");
        std::fs::write(&asset_path, asset).expect("asset");
        let signature_path = dir.join("asset.minisig");
        std::fs::write(&signature_path, sign_text(secret, asset, comment)).expect("signature");
        (asset_path, signature_path)
    }

    fn test_key() -> VerifyingKey {
        SigningKey::from_bytes(&SECRET).verifying_key()
    }

    #[test]
    fn accepts_a_good_signature() {
        let dir = tempfile::tempdir().expect("temp dir");
        let version: Version = "99.0.0".parse().expect("version");
        let comment = format!("vaultkeeper {version} {}", release::asset_name(version));
        let (asset, signature) = signed_asset(dir.path(), &SECRET, b"payload", &comment);
        verify_with(&asset, &signature, &release(version), &test_key()).expect("valid");
    }

    #[test]
    fn refuses_a_tampered_asset() {
        let dir = tempfile::tempdir().expect("temp dir");
        let version: Version = "99.0.0".parse().expect("version");
        let comment = format!("vaultkeeper {version} {}", release::asset_name(version));
        let (asset, signature) = signed_asset(dir.path(), &SECRET, b"payload", &comment);
        std::fs::write(&asset, b"tampered").expect("tamper");
        assert!(matches!(
            verify_with(&asset, &signature, &release(version), &test_key()),
            Err(VerifyError::Invalid)
        ));
    }

    #[test]
    fn refuses_a_downgrade() {
        let dir = tempfile::tempdir().expect("temp dir");
        let version = Version::current();
        let comment = format!("vaultkeeper {version} {}", release::asset_name(version));
        let (asset, signature) = signed_asset(dir.path(), &SECRET, b"payload", &comment);
        assert!(matches!(
            verify_with(&asset, &signature, &release(version), &test_key()),
            Err(VerifyError::Downgrade { .. })
        ));
    }

    #[test]
    fn refuses_a_swapped_asset_name() {
        let dir = tempfile::tempdir().expect("temp dir");
        let version: Version = "99.0.0".parse().expect("version");
        // A different asset name under a valid signature for the same version.
        let comment = format!("vaultkeeper {version} Vaultkeeper-v{version}-x64-setup.exe");
        let (asset, signature) = signed_asset(dir.path(), &SECRET, b"payload", &comment);
        assert!(matches!(
            verify_with(&asset, &signature, &release(version), &test_key()),
            Err(VerifyError::AssetMismatch { .. })
        ));
    }

    #[test]
    fn the_placeholder_key_refuses_everything() {
        let dir = tempfile::tempdir().expect("temp dir");
        let version: Version = "99.0.0".parse().expect("version");
        let comment = format!("vaultkeeper {version} {}", release::asset_name(version));
        let (asset, signature) = signed_asset(dir.path(), &SECRET, b"payload", &comment);
        assert!(matches!(public_key(), Err(VerifyError::PlaceholderKey)));
        assert!(matches!(
            verify(&asset, &signature, &release(version)),
            Err(VerifyError::PlaceholderKey)
        ));
    }

    #[test]
    fn rejects_a_wrong_key_and_a_mangled_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let version: Version = "99.0.0".parse().expect("version");
        let comment = format!("vaultkeeper {version} {}", release::asset_name(version));
        let (asset, signature) = signed_asset(dir.path(), &SECRET, b"payload", &comment);

        let other = SigningKey::from_bytes(&[9_u8; 32]).verifying_key();
        assert!(matches!(
            verify_with(&asset, &signature, &release(version), &other),
            Err(VerifyError::Invalid)
        ));

        std::fs::write(&signature, "not a minisign file").expect("mangle");
        assert!(matches!(
            verify_with(&asset, &signature, &release(version), &test_key()),
            Err(VerifyError::Format(_))
        ));
    }
}
