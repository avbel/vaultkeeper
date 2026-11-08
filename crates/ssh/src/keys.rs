use anyhow::Result;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{
    DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo, SecretDocument,
    der::{
        Decode, Reader, SliceReader, Tag, TagNumber, Tagged,
        asn1::{AnyRef, BitStringRef, OctetStringRef},
    },
};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};
use ssh_key::{
    Algorithm, Error as SshKeyError, HashAlg, LineEnding, PrivateKey,
    private::{EcdsaKeypair, Ed25519Keypair, RsaKeypair},
    rand_core::OsRng,
};
use zeroize::Zeroizing;

use crate::ImportError;

const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

const OPENSSH: &str = "OpenSSH";
const PKCS8: &str = "PKCS#8";
const RSA: &str = "RSA";
const EC: &str = "EC";

const PEM_BEGIN: &str = "-----BEGIN ";
const LEGACY_PEM_ENCRYPTED_MARKER: &str = "Proc-Type: 4,ENCRYPTED";

/// `(private_pem, public_openssh, sha256_fingerprint)`.
pub type KeyMaterial = (Zeroizing<String>, String, String);

/// Converts a pasted private key into the unencrypted OpenSSH form stored in the vault.
///
/// Accepted: OpenSSH (with or without passphrase), PKCS#8 (`PRIVATE KEY`), traditional RSA
/// (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`, P-256 and P-384). Encrypted PKCS#8 and legacy
/// encrypted PEM are refused with [`ImportError::EncryptedPemUnsupported`]; the passphrase only
/// applies to OpenSSH keys. The output is unencrypted because the vault encrypts it at rest.
///
/// Failures are [`ImportError`] values inside the `anyhow::Error`.
pub fn import_key(input: &str, passphrase: Option<&str>) -> Result<KeyMaterial> {
    let key = parse(input.trim(), passphrase)?;
    Ok(describe(&key)?)
}

/// Generates a new Ed25519 key; same tuple as [`import_key`].
pub fn generate_ed25519() -> Result<KeyMaterial> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(ImportError::Encode)?;
    Ok(describe(&key)?)
}

fn parse(input: &str, passphrase: Option<&str>) -> Result<PrivateKey, ImportError> {
    match pem_label(input).ok_or(ImportError::NotAPrivateKey)? {
        "OPENSSH PRIVATE KEY" => from_openssh(input, passphrase),
        "PRIVATE KEY" => from_pkcs8(input),
        "RSA PRIVATE KEY" => reject_legacy_encryption(input).and_then(|()| from_pkcs1(input)),
        "EC PRIVATE KEY" => reject_legacy_encryption(input).and_then(|()| from_sec1(input)),
        "ENCRYPTED PRIVATE KEY" => Err(ImportError::EncryptedPemUnsupported),
        other => Err(ImportError::UnsupportedFormat(other.to_owned())),
    }
}

fn pem_label(input: &str) -> Option<&str> {
    let (label, _) = input.strip_prefix(PEM_BEGIN)?.split_once("-----")?;
    Some(label)
}

fn reject_legacy_encryption(input: &str) -> Result<(), ImportError> {
    if input.contains(LEGACY_PEM_ENCRYPTED_MARKER) {
        return Err(ImportError::EncryptedPemUnsupported);
    }
    Ok(())
}

fn from_openssh(input: &str, passphrase: Option<&str>) -> Result<PrivateKey, ImportError> {
    let key = PrivateKey::from_openssh(input).map_err(malformed(OPENSSH))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let passphrase = passphrase.ok_or(ImportError::PassphraseRequired)?;
    key.decrypt(passphrase).map_err(|error| match error {
        SshKeyError::Crypto => ImportError::WrongPassphrase,
        _ => ImportError::Malformed(OPENSSH),
    })
}

fn from_pkcs8(pem: &str) -> Result<PrivateKey, ImportError> {
    let (_, document) = SecretDocument::from_pem(pem).map_err(malformed(PKCS8))?;
    let der = document.as_bytes();
    let info = PrivateKeyInfo::from_der(der).map_err(malformed(PKCS8))?;
    let algorithm = info.algorithm.oid;
    if algorithm == OID_ED25519 {
        let seed = OctetStringRef::from_der(info.private_key).map_err(malformed(PKCS8))?;
        let seed = <&[u8; 32]>::try_from(seed.as_bytes()).map_err(malformed(PKCS8))?;
        to_private_key(Ed25519Keypair::from_seed(seed), PKCS8)
    } else if algorithm == OID_RSA {
        let key = RsaPrivateKey::from_pkcs8_der(der).map_err(malformed(PKCS8))?;
        rsa_private_key(&key, PKCS8)
    } else if algorithm == OID_EC {
        ec_from_pkcs8(&info)
    } else {
        Err(ImportError::UnsupportedAlgorithm(algorithm.to_string()))
    }
}

fn ec_from_pkcs8(info: &PrivateKeyInfo<'_>) -> Result<PrivateKey, ImportError> {
    // Explicit curve parameters (macOS ssh-keygen/LibreSSL writes them) leave no OID to read.
    let named_curve = info.algorithm.parameters_oid().ok();
    ec_private_key(info.private_key, named_curve, PKCS8)
}

fn from_pkcs1(pem: &str) -> Result<PrivateKey, ImportError> {
    let key = RsaPrivateKey::from_pkcs1_pem(pem).map_err(malformed(RSA))?;
    rsa_private_key(&key, RSA)
}

fn from_sec1(pem: &str) -> Result<PrivateKey, ImportError> {
    let (_, document) = SecretDocument::from_pem(pem).map_err(malformed(EC))?;
    ec_private_key(document.as_bytes(), None, EC)
}

/// The curve is picked by scalar length and confirmed by the embedded public key or, when that
/// is absent, by the named-curve OID. Parsing the DER here instead of through the `sec1` crate
/// keeps keys with explicit curve parameters importable.
fn ec_private_key(
    der: &[u8],
    named_curve: Option<ObjectIdentifier>,
    format: &'static str,
) -> Result<PrivateKey, ImportError> {
    let key = parse_ec_private_key(der).map_err(malformed(format))?;
    let keypair = match key.scalar.len() {
        32 => {
            let secret = p256::SecretKey::from_slice(key.scalar).map_err(malformed(format))?;
            let derived = secret.public_key().to_encoded_point(false);
            confirm_curve(&key, derived.as_bytes(), named_curve, OID_P256, format)?;
            p256_keypair(secret)
        }
        48 => {
            let secret = p384::SecretKey::from_slice(key.scalar).map_err(malformed(format))?;
            let derived = secret.public_key().to_encoded_point(false);
            confirm_curve(&key, derived.as_bytes(), named_curve, OID_P384, format)?;
            p384_keypair(secret)
        }
        other => {
            return Err(ImportError::UnsupportedAlgorithm(format!(
                "EC key with a {other}-byte scalar"
            )));
        }
    };
    to_private_key(keypair, format)
}

fn confirm_curve(
    key: &EcPrivateKey<'_>,
    derived_public: &[u8],
    named_curve: Option<ObjectIdentifier>,
    expected_curve: ObjectIdentifier,
    format: &'static str,
) -> Result<(), ImportError> {
    if let Some(curve) = named_curve
        && curve != expected_curve
    {
        return Err(ImportError::UnsupportedAlgorithm(format!(
            "EC curve {curve}"
        )));
    }
    match key.public {
        Some(embedded) if embedded == derived_public => Ok(()),
        None if named_curve.is_some() => Ok(()),
        _ => Err(ImportError::Malformed(format)),
    }
}

/// RFC 5915 `ECPrivateKey`, minus the curve parameters.
struct EcPrivateKey<'a> {
    scalar: &'a [u8],
    public: Option<&'a [u8]>,
}

fn parse_ec_private_key(der: &[u8]) -> Result<EcPrivateKey<'_>, pkcs8::der::Error> {
    const PUBLIC_KEY_FIELD: Tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber::N1,
    };
    SliceReader::new(der)?.sequence(|reader| {
        if u8::decode(reader)? != 1 {
            return Err(Tag::Integer.value_error());
        }
        let scalar = OctetStringRef::decode(reader)?.as_bytes();
        let mut public = None;
        while !reader.is_finished() {
            let field = AnyRef::decode(reader)?;
            if field.tag() == PUBLIC_KEY_FIELD {
                public = BitStringRef::from_der(field.value())?.as_bytes();
            }
        }
        Ok(EcPrivateKey { scalar, public })
    })
}

fn rsa_private_key(key: &RsaPrivateKey, format: &'static str) -> Result<PrivateKey, ImportError> {
    let keypair = RsaKeypair::try_from(key).map_err(malformed(format))?;
    to_private_key(keypair, format)
}

fn p256_keypair(secret: p256::SecretKey) -> EcdsaKeypair {
    EcdsaKeypair::NistP256 {
        public: secret.public_key().into(),
        private: secret.into(),
    }
}

fn p384_keypair(secret: p384::SecretKey) -> EcdsaKeypair {
    EcdsaKeypair::NistP384 {
        public: secret.public_key().into(),
        private: secret.into(),
    }
}

fn to_private_key(
    keypair: impl Into<ssh_key::private::KeypairData>,
    format: &'static str,
) -> Result<PrivateKey, ImportError> {
    PrivateKey::new(keypair.into(), "").map_err(malformed(format))
}

fn malformed<E>(format: &'static str) -> impl Fn(E) -> ImportError + Copy {
    move |_| ImportError::Malformed(format)
}

fn describe(key: &PrivateKey) -> Result<KeyMaterial, ImportError> {
    if !matches!(
        key.algorithm(),
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }
    ) {
        return Err(ImportError::UnsupportedAlgorithm(
            key.algorithm().to_string(),
        ));
    }
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(ImportError::Encode)?;
    let public = key.public_key();
    let openssh = public.to_openssh().map_err(ImportError::Encode)?;
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    Ok((pem, openssh, fingerprint))
}

#[cfg(test)]
mod tests {
    use ssh_agent::SSHKeyData;

    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/",
                $name
            ))
        };
    }

    // Fingerprints are the output of `ssh-keygen -lf` for the fixture keys.
    const ED25519_FP: &str = "SHA256:rF76hBWb1V0J5igckCIocsvRL9TfsRHL4dzyBYomAa0";
    const ED25519_ENC_FP: &str = "SHA256:sbDXaF0710r/b2tkG9eZmGV3g5cyvz52D0r4HOwIPW4";
    const ED25519_PKCS8_FP: &str = "SHA256:sfDG1iJ6szTs6TIfzFKLBsc6ZruG2ApNpekhnev6am4";
    const RSA_FP: &str = "SHA256:DDEvzDILSLX3RqcKRjabBq/ncqjldlJnPha+r6SWMeI";
    const P256_FP: &str = "SHA256:jdfYG3IiAOeOqqQBvDxLCM7vCPiubTKAj2l9ZL0ZiL4";
    const P384_FP: &str = "SHA256:rB1OqyWe21WDzoBM0pRFxkhx1PtjZ/ivypsQnR/e1Tw";
    const P521_FP: &str = "SHA256:k1/80l/NzP7tFj3xC7n5HKSz4v6UjDnfFhPyDscDeOY";
    const PASSPHRASE: &str = "correct horse";

    struct Case {
        label: &'static str,
        private_key: &'static str,
        public_key: &'static str,
        passphrase: Option<&'static str>,
        fingerprint: &'static str,
    }

    fn cases() -> Vec<Case> {
        let mut all = ed25519_and_rsa_cases();
        all.extend(ec_cases());
        all
    }

    fn ed25519_and_rsa_cases() -> Vec<Case> {
        vec![
            Case {
                label: "OpenSSH ed25519",
                private_key: fixture!("ed25519"),
                public_key: fixture!("ed25519.pub"),
                passphrase: None,
                fingerprint: ED25519_FP,
            },
            Case {
                label: "OpenSSH ed25519 with passphrase",
                private_key: fixture!("ed25519_enc"),
                public_key: fixture!("ed25519_enc.pub"),
                passphrase: Some(PASSPHRASE),
                fingerprint: ED25519_ENC_FP,
            },
            Case {
                label: "PKCS#8 ed25519",
                private_key: fixture!("ed25519_pkcs8"),
                public_key: fixture!("ed25519_pkcs8.pub"),
                passphrase: None,
                fingerprint: ED25519_PKCS8_FP,
            },
            Case {
                label: "OpenSSH rsa",
                private_key: fixture!("rsa"),
                public_key: fixture!("rsa.pub"),
                passphrase: None,
                fingerprint: RSA_FP,
            },
            Case {
                label: "traditional RSA PEM",
                private_key: fixture!("rsa_traditional"),
                public_key: fixture!("rsa.pub"),
                passphrase: None,
                fingerprint: RSA_FP,
            },
            Case {
                label: "PKCS#8 rsa",
                private_key: fixture!("rsa_pkcs8"),
                public_key: fixture!("rsa.pub"),
                passphrase: None,
                fingerprint: RSA_FP,
            },
        ]
    }

    fn ec_cases() -> Vec<Case> {
        vec![
            Case {
                label: "OpenSSH p256",
                private_key: fixture!("ecdsa_p256"),
                public_key: fixture!("ecdsa_p256.pub"),
                passphrase: None,
                fingerprint: P256_FP,
            },
            Case {
                label: "PKCS#8 p256",
                private_key: fixture!("ecdsa_p256_pkcs8"),
                public_key: fixture!("ecdsa_p256.pub"),
                passphrase: None,
                fingerprint: P256_FP,
            },
            Case {
                label: "PKCS#8 p256 with a named curve",
                private_key: fixture!("ecdsa_p256_pkcs8_named"),
                public_key: fixture!("ecdsa_p256.pub"),
                passphrase: None,
                fingerprint: P256_FP,
            },
            Case {
                label: "SEC1 p256 with a named curve",
                private_key: fixture!("ecdsa_p256_sec1_named"),
                public_key: fixture!("ecdsa_p256.pub"),
                passphrase: None,
                fingerprint: P256_FP,
            },
            Case {
                label: "SEC1 p256",
                private_key: fixture!("ecdsa_p256_sec1"),
                public_key: fixture!("ecdsa_p256.pub"),
                passphrase: None,
                fingerprint: P256_FP,
            },
            Case {
                label: "OpenSSH p384",
                private_key: fixture!("ecdsa_p384"),
                public_key: fixture!("ecdsa_p384.pub"),
                passphrase: None,
                fingerprint: P384_FP,
            },
            Case {
                label: "PKCS#8 p384",
                private_key: fixture!("ecdsa_p384_pkcs8"),
                public_key: fixture!("ecdsa_p384.pub"),
                passphrase: None,
                fingerprint: P384_FP,
            },
            Case {
                label: "PKCS#8 p384 with a named curve",
                private_key: fixture!("ecdsa_p384_pkcs8_named"),
                public_key: fixture!("ecdsa_p384.pub"),
                passphrase: None,
                fingerprint: P384_FP,
            },
            Case {
                label: "OpenSSH p521",
                private_key: fixture!("ecdsa_p521"),
                public_key: fixture!("ecdsa_p521.pub"),
                passphrase: None,
                fingerprint: P521_FP,
            },
        ]
    }

    fn import_error(input: &str, passphrase: Option<&str>) -> ImportError {
        import_key(input, passphrase)
            .expect_err("import must fail")
            .downcast::<ImportError>()
            .expect("a typed ImportError")
    }

    fn key_type_and_blob(public_openssh: &str) -> (&str, &str) {
        let mut fields = public_openssh.split_whitespace();
        (
            fields.next().expect("key type"),
            fields.next().expect("key blob"),
        )
    }

    #[test]
    fn every_format_imports_with_the_ssh_keygen_fingerprint() {
        for case in cases() {
            let (_, _, fingerprint) =
                import_key(case.private_key, case.passphrase).expect(case.label);

            assert_eq!(fingerprint, case.fingerprint, "{}", case.label);
        }
    }

    #[test]
    fn public_key_matches_the_ssh_keygen_public_key() {
        for case in cases() {
            let (_, public, _) = import_key(case.private_key, case.passphrase).expect(case.label);

            assert_eq!(
                key_type_and_blob(&public),
                key_type_and_blob(case.public_key),
                "{}",
                case.label
            );
        }
    }

    #[test]
    fn openssh_keys_keep_their_comment_in_the_public_key() {
        let (_, public, _) = import_key(fixture!("ed25519"), None).expect("import");
        assert_eq!(public, fixture!("ed25519.pub").trim_end());

        let (_, public, _) = import_key(fixture!("ed25519_enc"), Some(PASSPHRASE)).expect("import");
        assert_eq!(public, fixture!("ed25519_enc.pub").trim_end());
    }

    #[test]
    fn converted_keys_have_no_comment() {
        let (_, public, _) = import_key(fixture!("rsa_pkcs8"), None).expect("import");

        assert_eq!(public.split_whitespace().count(), 2);
    }

    #[test]
    fn output_is_unencrypted_openssh_the_agent_can_serve() {
        for case in cases() {
            let (pem, _, fingerprint) =
                import_key(case.private_key, case.passphrase).expect(case.label);

            assert!(
                pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
                "{}",
                case.label
            );
            let reparsed = PrivateKey::from_openssh(&*pem).expect(case.label);
            assert!(!reparsed.is_encrypted(), "{}", case.label);
            assert_eq!(
                reparsed.fingerprint(HashAlg::Sha256).to_string(),
                fingerprint,
                "{}",
                case.label
            );
            SSHKeyData::from_private_key_pem(&pem, "k".to_owned(), "id".to_owned())
                .expect(case.label);
        }
    }

    #[test]
    fn surrounding_whitespace_and_crlf_are_tolerated() {
        let crlf = fixture!("ed25519").replace('\n', "\r\n");
        let padded = format!("\n  \r\n{crlf}\r\n\r\n");

        let (_, _, fingerprint) = import_key(&padded, None).expect("import");

        assert_eq!(fingerprint, ED25519_FP);
    }

    #[test]
    fn passphrase_is_ignored_for_unencrypted_keys() {
        let (_, _, fingerprint) =
            import_key(fixture!("rsa_pkcs8"), Some("unused")).expect("import");

        assert_eq!(fingerprint, RSA_FP);
    }

    #[test]
    fn wrong_passphrase_is_reported() {
        let error = import_error(fixture!("ed25519_enc"), Some("battery staple"));

        assert!(matches!(error, ImportError::WrongPassphrase), "{error}");
    }

    #[test]
    fn empty_passphrase_is_a_wrong_passphrase() {
        let error = import_error(fixture!("ed25519_enc"), Some(""));

        assert!(matches!(error, ImportError::WrongPassphrase), "{error}");
    }

    #[test]
    fn missing_passphrase_is_reported() {
        let error = import_error(fixture!("ed25519_enc"), None);

        assert!(matches!(error, ImportError::PassphraseRequired), "{error}");
    }

    #[test]
    fn encrypted_pem_and_pkcs8_are_refused_with_a_hint() {
        for input in [fixture!("rsa_pkcs8_enc"), fixture!("rsa_traditional_enc")] {
            let error = import_error(input, Some(PASSPHRASE));

            assert!(
                matches!(error, ImportError::EncryptedPemUnsupported),
                "{error}"
            );
            assert!(error.to_string().contains("ssh-keygen -p"), "{error}");
        }
    }

    #[test]
    fn garbage_is_not_a_private_key() {
        for input in [
            "",
            "   \n",
            "hunter2",
            "not a key at all\nreally",
            "-----BEGIN",
        ] {
            let error = import_error(input, None);

            assert!(
                matches!(error, ImportError::NotAPrivateKey),
                "{input:?}: {error}"
            );
        }
    }

    #[test]
    fn public_key_line_is_not_a_private_key() {
        let error = import_error(fixture!("ed25519.pub"), None);

        assert!(matches!(error, ImportError::NotAPrivateKey), "{error}");
    }

    #[test]
    fn other_pem_documents_are_unsupported_formats() {
        let error = import_error(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----",
            None,
        );

        assert!(
            matches!(&error, ImportError::UnsupportedFormat(label) if label == "PUBLIC KEY"),
            "{error}"
        );
    }

    #[test]
    fn corrupted_bodies_are_malformed_per_format() {
        let corrupt = |input: &str| {
            let mut lines: Vec<&str> = input.lines().collect();
            lines.truncate(lines.len() / 2);
            lines.push(lines[lines.len() - 1]);
            let end = input.lines().last().expect("footer");
            format!("{}\n{end}", lines.join("\n"))
        };
        for (input, format) in [
            (fixture!("ed25519"), "OpenSSH"),
            (fixture!("rsa_pkcs8"), "PKCS#8"),
            (fixture!("rsa_traditional"), "RSA"),
            (fixture!("ecdsa_p256_sec1"), "EC"),
        ] {
            let error = import_error(&corrupt(input), None);

            assert!(
                matches!(&error, ImportError::Malformed(found) if *found == format),
                "{format}: {error}"
            );
        }
    }

    #[test]
    fn unsupported_ec_curves_are_refused() {
        let secp256k1 = import_error(fixture!("ec_secp256k1_pkcs8"), None);
        let p521 = import_error(fixture!("ec_p521_pkcs8"), None);

        assert!(
            matches!(&secp256k1, ImportError::UnsupportedAlgorithm(what) if what.contains("EC curve")),
            "{secp256k1}"
        );
        assert!(
            matches!(&p521, ImportError::UnsupportedAlgorithm(what) if what.contains("66-byte")),
            "{p521}"
        );
    }

    #[test]
    fn import_output_never_contains_the_passphrase() {
        let (pem, public, fingerprint) =
            import_key(fixture!("ed25519_enc"), Some(PASSPHRASE)).expect("import");

        for text in [pem.as_str(), &public, &fingerprint] {
            assert!(!text.contains(PASSPHRASE));
        }
    }

    #[test]
    fn generated_ed25519_is_a_fresh_valid_key() {
        let (pem, public, fingerprint) = generate_ed25519().expect("generate");
        let (other_pem, _, other_fingerprint) = generate_ed25519().expect("generate");

        let key = PrivateKey::from_openssh(&*pem).expect("OpenSSH PEM");
        assert!(!key.is_encrypted());
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert!(public.starts_with("ssh-ed25519 "), "{public}");
        assert_eq!(fingerprint, key.fingerprint(HashAlg::Sha256).to_string());
        assert!(fingerprint.starts_with("SHA256:"));
        assert_eq!(fingerprint.len(), "SHA256:".len() + 43);
        assert_ne!(*pem, *other_pem);
        assert_ne!(fingerprint, other_fingerprint);
    }

    #[test]
    fn generated_key_survives_an_import_round_trip() {
        let (pem, public, fingerprint) = generate_ed25519().expect("generate");

        let (reimported, reimported_public, reimported_fingerprint) =
            import_key(&pem, None).expect("import");

        assert_eq!(*pem, *reimported);
        assert_eq!(public, reimported_public);
        assert_eq!(fingerprint, reimported_fingerprint);
    }
}
