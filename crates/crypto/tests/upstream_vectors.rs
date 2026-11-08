//! Fixed vectors from Bitwarden's own test suites (sdk-internal and clients), exercised through
//! the public API only. Expected values are copied from upstream, never computed here.

use std::io::Cursor;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bwl_crypto::{EncString, Error, Kdf, MasterKey, PrivateKey, SymmetricKey, enc_buffer};

// sdk-internal keys/device_key.rs `test_decrypt_user_key` (keys from the desktop app).
const DEVICE_PROTECTED_PRIVATE_KEY: &str = "2.GyQfUYWW6Byy4UV5icFLxg==|EMiU7OTF79N6tfv3+YUs5zJhBAgqv6sa5YCoPl6yAETh7Tfk+JmbeizxXFPj5Q1X/tcVpDZl/3fGcxtnIxg1YtvDFn7j8uPnoApOWhCKmwcvJSIkt+qvX3lELNBwZXozSiy7PbQ0JbCMe2d4MkimR5k8+lE9FB3208yYK7nOJhlrsUCnOekCYEU9/4NCMA8tz8SpITx/MN4JJ1TQ/KjPJYLt+3JNUxK47QlgREWQvyVzCRt7ZGtcgIJ/U1qycAWMpEg9NkuV8j5QRA1S7VBsA6qliJwys5+dmTuIOmOMwdKFZDc4ZvWoRkPp2TSJBu7L8sSAgU6mmDWac8iQ+9Ka/drdfwYLrH8GAZvURk79tSpRrT7+PAFe2QdUtliUIyiqkh8iJVjZube4hRnEsRuX9V9b+UdtAr6zAj7mugO/VAu5T9J38V79V2ohG3NtXysDeKLXpAlkhjllWXeq/wret2fD4WiwqEDj0G2A/PY3F3OziIgp0UKc00AfqrPq8OVK3A+aowwVqdYadgxyoVCKWJ8unJeAXG7MrMQ9tHpzF6COoaEy7Wwoc17qko33zazwLZbfAjB4oc8Ea26jRKnJZP56sVZAjOSQQMziAsA08MRaa/DQhgRea1+Ygba0gMft8Dww8anN2gQBveTZRBWyqXYgN3U0Ity5gNauT8RnFk9faqVFt2Qxnp0JgJ+PsqEt5Hn4avBRZQQ7o8VvPnxYLDKFe3I2m6HFYFWRhOGeDYxexIuaiF2iIAYFVUmnDuWpgnUiL4XJ3KHDsjkPzcV3z4D2Knr/El2VVXve8jhDjETfovmmN28+i2e29PXvKIymTskMFpFCQPc7wBY/Id7pmgb3SujKYNpkAS2sByDoRir0my49DDGfta0dENssJhFd3x+87fZbEj3cMiikg2pBwpTLgmfIUa5cVZU2s8JZ9wu7gaioYzvX+elHa3EHLcnEUoJTtSf9kjb+Nbq4ktMgYAO2wIC96t1LvmqK4Qn2cOdw5QNlRqALhqe5V31kyIcwRMK0AyIoOPhnSqtpYdFiR3LDTvZA8dU0vSsuchCwHNMeRUtKvdzN/tk+oeznyY/mpakUESN501lEKd/QFLtJZsDZTtNlcA8fU3kDtws4ZIMR0O5+PFmgQFSU8OMobf9ClUzy/wHTvYGyDuSwbOoPeS955QKkUKXCNMj33yrPr+ioHQ1BNwLX3VmMF4bNRBY/vr+CG0/EZi0Gwl0kyHGl0yWEtpQuu+/PaROJeOraWy5D1UoZZhY4n0zJZBt1eg3FZ2rhKv4gdUc50nZpeNWE8pIqZ6RQ7qPJuqfF1Z+G73iOSnLYCHDiiFmhD5ivf9IGkTAcWcBsQ/2wcSj9bFJr4DrKfsbQ4CkSWICWVn/W+InKkO6BTsBbYmvte5SvbaN+UOtiUSkHLBCCr8273VNgcB/hgtbUires3noxYZJxoczr+i7vdlEgQnWEKrpo0CifsFxGwYS3Yy2K79iwvDMaLPDf73zLSbuoUl6602F2Mzcjnals67f+gSpaDvWt7Kg9c/ZfGjq8oNxVaXJnX3gSDsO+fhwVAtnDApL+tL8cFfxGerW4KGi9/74woH+C3MMIViBtNnrpEuvxUW97Dg5nd40oGDeyi/q+8HdcxkneyFY=|JYdol19Yi+n1r7M+06EwK5JCi2s/CWqKui2Cy6hEb3k=";

// Same test: user key wrapped by the device RSA key.
const DEVICE_PROTECTED_USER_KEY: &str = "4.f+VbbacRhO2q4MOUSdt1AIjQ2FuLAvg4aDxJMXAh3VxvbmUADj8Ct/R7XEpPUqApmbRS566jS0eRVy8Sk08ogoCdj1IFN9VsIky2i2X1WHK1fUnr3UBmXE3tl2NPBbx56U+h73S2jNTSyet2W18Jg2q7/w8KIhR3J41QrG9aGoOTN93to3hb5W4z6rdrSI0e7GkizbwcIA0NH7Z1JyAhrjPm9+tjRjg060YbEbGaWTAOkZWfgbLjr8bY455DteO2xxG139cOx7EBo66N+YhjsLi0ozkeUyPQkoWBdKMcQllS7jCfB4fDyJA05ALTbk74syKkvqFxqwmQbg+aVn+dcw==";

// sdk-internal bitwarden-vault cipher/attachment.rs `test_attachment_key` / `test_attachment_without_key`.
const ATTACHMENT_USER_KEY: &str =
    "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";

// `test_attachment_key`: cipher key wrapped by the user key.
const ATTACHMENT_CIPHER_KEY: &str = "2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=";

// `test_attachment_key`: attachment key wrapped by the cipher key.
const ATTACHMENT_KEY: &str = "2.r288/AOSPiaLFkW07EBGBw==|SAmnnCbOLFjX5lnURvoualOetQwuyPc54PAmHDTRrhT0gwO9ailna9U09q9bmBfI5XrjNNEsuXssgzNygRkezoVQvZQggZddOwHB6KQW5EQ=|erIMUJp8j+aTcmhdE50zEX+ipv/eR1sZ7EwULJm/6DY=";

// `test_attachment_key`: file encrypted with the attachment key.
const ATTACHMENT_FILE_WITH_KEY: &str = "Ao00qr1xLsV+ZNQpYZ/UwEwOWo3hheKwCYcOGIbsorZ6JIG2vLWfWEXCVqP0hDuzRvmx8otApNZr8pJYLNwCe1aQ+ySHQYGkdubFjoMojulMbQ959Y4SJ6Its/EnVvpbDnxpXTDpbutDxyhxfq1P3lstL2G9rObJRrxiwdGlRGu1h94UA1fCCkIUQux5LcqUee6W4MyQmRnsUziH8gGzmtI=";

// Plaintext of both attachment files.
const ATTACHMENT_PLAINTEXT: &str = "rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==";

// `test_attachment_without_key`: file encrypted directly with the user key.
const ATTACHMENT_FILE_WITHOUT_KEY: &str = "AsQLXOBHrJ8porroTUlPxeJOm9XID7LL9D2+KwYATXEpR1EFjLBpcCvMmnqcnYLXIEefe9TCeY4Us50ux43kRSpvdB7YkjxDKV0O1/y6tB7qC4vvv9J9+O/uDEnMx/9yXuEhAW/LA/TsU/WAgxkOM0uTvm8JdD9LUR1z9Ql7zOWycMVzkvGsk2KBNcqAdrotS5FlDftZOXyU8pWecNeyA/w=";

// bitwarden/clients libs/legacy-crypto web-crypto-function.service.spec.ts `RsaPrivateKey` (PKCS#8 DER).
const CLIENTS_RSA_PRIVATE_KEY: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXRVrCX+2hfOQS8HzYUS2oc/jGVTZpv+/Ryuoh9d8ihYX9dd0cYh2tl6KWdFc88lPUH11Oxqy20Rk2e5r/RF6T9yM0Me3NPnaKt+hlhLtfoc0h86LnhD56A9FDUfuI0dVnPcrwNv0YJIo94LwxtbqBULNvXl6wJ7WAbODrCQy5ZgMVg+iH+gGpwiqsZqHt+KuoHWcN53MSPDfaF4/YMB99U3TziJMOOJask1TEEnakMPln11PczNDazT17DXIxYrbPfutPdh6sLs6AQOajdZijfEvepgnOe7cQ7aeatiOJFrjTApKPGxOVRzEMX4XS4xbyhH0QxQeB6l16l8C0uxIBAgMBAAECggEASaWfeVDA3cVzOPFSpvJm20OTE+R6uGOU+7vh36TX/POq92qBuwbd0h0oMD32FxsXywd2IxtBDUSiFM9699qufTVuM0Q3tZw6lHDTOVG08+tPdr8qSbMtw7PGFxN79fHLBxejjO4IrM9lapjWpxEF+11x7r+wM+0xRZQ8sNFYG46aPfIaty4BGbL0I2DQ2y8I57iBCAy69eht59NLMm27fRWGJIWCuBIjlpfzET1j2HLXUIh5bTBNzqaN039WH49HczGE3mQKVEJZc/efk3HaVd0a1Sjzyn0QY+N1jtZN3jTRbuDWA1AknkX1LX/0tUhuS3/7C3ejHxjw4Dk1ZLo5/QKBgQDIWvqFn0+IKRSu6Ua2hDsufIHHUNLelbfLUMmFthxabcUn4zlvIscJO00Tq/ezopSRRvbGiqnxjv/mYxucvOUBeZtlus0Q9RTACBtw9TGoNTmQbEunJ2FOSlqbQxkBBAjgGEppRPt30iGj/VjAhCATq2MYOa/X4dVR51BqQAFIEwKBgQDBSIfTFKC/hDk6FKZlgwvupWYJyU9RkyfstPErZFmzoKhPkQ3YORo2oeAYmVUbS9I2iIYpYpYQJHX8jMuCbCz4ONxTCuSIXYQYUcUq4PglCKp31xBAE6TN8SvhfME9/MvuDssnQinAHuF0GDAhF646T3LLS1not6Vszv7brwSoGwKBgQC88v/8cGfi80ssQZeMnVvq1UTXIeQcQnoY5lGHJl3K8mbS3TnXE6c9j417Fdz+rj8KWzBzwWXQB5pSPflWcdZO886Xu/mVGmy9RWgLuVFhXwCwsVEPjNX5ramRb0/vY0yzenUCninBsIxFSbIfrPtLUYCc4hpxr+sr2Mg/y6jpvQKBgBezMRRs3xkcuXepuI2R+BCXL1/b02IJTUf1F+1eLLGd7YV0H+J3fgNc7gGWK51hOrF9JBZHBGeOUPlaukmPwiPdtQZpu4QNE3l37VlIpKTF30E6mb+BqR+nht3rUjarnMXgAoEZ18y6/KIjpSMpqC92Nnk/EBM9EYe6Cf4eA9ApAoGAeqEUg46UTlJySkBKURGpIs3v1kkf5I0X8DnOhwb+HPxNaiEdmO7ckm8+tPVgppLcG0+tMdLjigFQiDUQk2y3WjyxP5ZvXu7U96jaJRI8PFMoE06WeVYcdIzrID2HvqH+w0UQJFrLJ/0Mn4stFAEzXKZBokBGnjFnTnKcs7nv/O8=";

// Same spec, `rsaDecrypt`: RSA-OAEP-SHA1 ciphertext of "EncryptMe!", given
// the type-4 header here.
const CLIENTS_RSA_CIPHERTEXT: &str = "4.A1/p8BQzN9UrbdYxUY2Va5+kPLyfZXF9JsZrjeEXcaclsnHurdxVAJcnbEqYMP3UXV4YAS/mpf+Rxe6/X0WS1boQdA0MAHSgx95hIlAraZYpiMLLiJRKeo2u8YivCdTM9V5vuAEJwf9Tof/qFsFci3sApdbATkorCTzFOIEPF2S1zgperEP23M01mr4dWVdYN18B32YF67xdJHMbFhp5dkQwv9CmscoWq7OE5HIfOb+JAh7BEZb+CmKhM3yWJvoR/D/5jcercUtK2o+XrzNrL4UQ7yLZcFz6Bfwb/j6ICYvqd/YJwXNE6dwlL57OfwJyCdw2rRYf0/qI00t9u8Iitw==";

// sdk-internal keys/master_key.rs `test_decrypt_user_key_aes_cbc256_b64`.
const LEGACY_PROTECTED_USER_KEY: &str = "0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=";

// sdk-internal stream/aes256_cbc_hmac_legacy_stream.rs `STREAM_TEST_VECTOR`, which omits the
// leading type byte.
const STREAM_TEST_VECTOR: [u8; 160] = [
    202, 35, 233, 113, 188, 138, 45, 92, 122, 28, 38, 85, 31, 242, 192, 113, 213, 46, 222, 105,
    210, 189, 251, 90, 162, 190, 27, 47, 139, 54, 146, 233, 233, 246, 27, 201, 172, 13, 180, 105,
    69, 177, 113, 72, 154, 138, 43, 75, 53, 193, 235, 62, 28, 217, 137, 81, 167, 40, 33, 95, 241,
    1, 154, 92, 69, 252, 151, 218, 106, 46, 189, 208, 154, 123, 192, 207, 253, 155, 22, 17, 158,
    142, 88, 91, 177, 117, 227, 45, 58, 16, 150, 180, 193, 32, 144, 95, 227, 233, 60, 7, 98, 197,
    200, 144, 179, 213, 220, 95, 242, 17, 112, 115, 211, 97, 90, 250, 210, 141, 200, 157, 156, 71,
    133, 165, 246, 161, 110, 127, 232, 225, 121, 190, 235, 121, 228, 4, 31, 123, 67, 140, 84, 64,
    41, 198, 227, 221, 20, 188, 252, 70, 20, 81, 138, 210, 247, 230, 16, 233, 229, 154,
];

const STREAM_PLAINTEXT: &[u8] = b"This is a test vector text for streaming encryption. It is long enough to require multiple CBC blocks.";

// `test_decrypt_user_key`: the device key and the user key it ultimately unwraps.
const DEVICE_KEY: [u8; 64] = [
    114, 235, 60, 115, 172, 156, 203, 145, 195, 130, 215, 250, 88, 146, 215, 230, 12, 109, 245,
    222, 54, 217, 255, 211, 221, 105, 230, 236, 65, 52, 209, 133, 76, 208, 113, 254, 194, 216, 156,
    19, 230, 62, 32, 93, 87, 7, 144, 156, 117, 142, 250, 32, 182, 118, 187, 8, 247, 7, 203, 201,
    65, 147, 206, 247,
];
const DEVICE_USER_KEY: [u8; 64] = [
    109, 128, 172, 147, 206, 123, 134, 95, 16, 36, 155, 113, 201, 18, 186, 230, 216, 212, 173, 188,
    74, 11, 134, 131, 137, 242, 105, 178, 105, 126, 52, 139, 248, 91, 215, 21, 128, 91, 226, 222,
    165, 67, 251, 34, 83, 81, 77, 147, 225, 76, 13, 41, 102, 45, 183, 218, 106, 89, 254, 208, 251,
    101, 130, 10,
];

// `test_decrypt_user_key_aes_cbc256_b64`: the user key behind LEGACY_PROTECTED_USER_KEY.
const LEGACY_USER_KEY: [u8; 64] = [
    12, 95, 151, 203, 37, 4, 236, 67, 137, 97, 90, 58, 6, 127, 242, 28, 209, 168, 125, 29, 118, 24,
    213, 44, 117, 202, 2, 115, 132, 165, 125, 148, 186, 215, 234, 137, 24, 169, 227, 29, 218, 57,
    180, 237, 73, 91, 189, 51, 253, 26, 17, 52, 226, 4, 134, 75, 194, 208, 178, 133, 128, 224, 140,
    167,
];

fn b64(text: &str) -> Vec<u8> {
    STANDARD.decode(text).expect("test vector is valid base64")
}

fn enc(text: &str) -> EncString {
    text.parse().expect("test vector is a valid EncString")
}

fn key(bytes: &[u8]) -> SymmetricKey {
    SymmetricKey::from_bytes(bytes).expect("test vector is a valid key")
}

fn device_private_key() -> PrivateKey {
    let der = enc(DEVICE_PROTECTED_PRIVATE_KEY)
        .decrypt(&key(&DEVICE_KEY))
        .expect("type-2 vector decrypts with the device key");
    PrivateKey::from_pkcs8_der(&der).expect("plaintext is a PKCS#8 RSA key")
}

#[test]
fn type2_then_type4_unwrap_the_device_user_key() {
    let user_key = enc(DEVICE_PROTECTED_USER_KEY)
        .decrypt_with_private_key(&device_private_key())
        .expect("type-4 vector decrypts with the device RSA key");
    assert_eq!(user_key.as_slice(), DEVICE_USER_KEY.as_slice());
}

#[test]
fn type2_vector_round_trips_through_display() {
    assert_eq!(
        enc(DEVICE_PROTECTED_PRIVATE_KEY).to_string(),
        DEVICE_PROTECTED_PRIVATE_KEY
    );
    assert_eq!(
        enc(DEVICE_PROTECTED_USER_KEY).to_string(),
        DEVICE_PROTECTED_USER_KEY
    );
}

fn tampered(part: usize) -> EncString {
    let mut parts: Vec<Vec<u8>> = DEVICE_PROTECTED_PRIVATE_KEY[2..]
        .split('|')
        .map(b64)
        .collect();
    parts[part][0] ^= 0x01;
    let [iv, data, mac] = <[Vec<u8>; 3]>::try_from(parts).expect("three parts");
    EncString::AesCbc256HmacSha256 {
        iv: iv.try_into().expect("16-byte IV"),
        data,
        mac: mac.try_into().expect("32-byte MAC"),
    }
}

#[test]
fn tampered_type2_vector_fails_the_mac() {
    for part in 0..3 {
        let result = tampered(part).decrypt(&key(&DEVICE_KEY));
        assert!(
            matches!(result, Err(Error::MacMismatch)),
            "part {part} gave {result:?}"
        );
    }
}

#[test]
fn type2_vector_with_wrong_key_fails_the_mac() {
    let result = enc(DEVICE_PROTECTED_PRIVATE_KEY).decrypt(&key(&DEVICE_USER_KEY));
    assert!(matches!(result, Err(Error::MacMismatch)));
}

#[test]
fn type4_decrypts_known_plaintext() {
    let private_key =
        PrivateKey::from_pkcs8_der(&b64(CLIENTS_RSA_PRIVATE_KEY)).expect("valid PKCS#8 key");
    let plaintext = enc(CLIENTS_RSA_CIPHERTEXT)
        .decrypt_with_private_key(&private_key)
        .expect("decrypts");
    assert_eq!(plaintext.as_slice(), b"EncryptMe!");
}

#[test]
fn type4_with_wrong_private_key_fails() {
    let result = enc(CLIENTS_RSA_CIPHERTEXT).decrypt_with_private_key(&device_private_key());
    assert!(matches!(result, Err(Error::Decrypt)));
}

#[test]
fn private_key_rejects_symmetric_enc_strings() {
    let result = enc(DEVICE_PROTECTED_PRIVATE_KEY).decrypt_with_private_key(&device_private_key());
    assert!(matches!(result, Err(Error::UnsupportedEncType(2))));
    let type0 = enc(LEGACY_PROTECTED_USER_KEY);
    let result = type0.decrypt_with_private_key(&device_private_key());
    assert!(matches!(result, Err(Error::UnsupportedEncType(0))));
}

#[test]
fn legacy_account_unlocks_from_password() {
    let kdf = Kdf::from_wire(0, 600_000, None, None).expect("valid prelogin settings");
    let master_key =
        MasterKey::derive(b"asdfasdfasdf", "legacy@bitwarden.com", &kdf).expect("derives");
    let protected = enc(LEGACY_PROTECTED_USER_KEY);

    let user_key = master_key
        .decrypt_user_key(&protected)
        .expect("type-0 user key decrypts with the raw master key");
    assert_eq!(user_key.to_bytes().as_slice(), LEGACY_USER_KEY.as_slice());

    let via_stretched = protected.decrypt(&master_key.stretch());
    assert!(
        matches!(via_stretched, Err(Error::MacRequired)),
        "type 0 must not be accepted under a key with a MAC: {via_stretched:?}"
    );
}

// sdk-internal keys/master_key.rs `test_decrypt_cbc256`: a type-0 user key under a 32-byte key.
const TYPE0_KEY: &str = "hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe08=";
const TYPE0_USER_KEY: &str = "0.tn/heK4HLbbEe+yEkC+kvw==|8QM94f7aVTtjm/bmvRdVxOxiLiiZtHYYO7+oBdjFCkilncesx0iVrXPl+tMKqW+Jo7+FtZdPNsTrL6RdoG7i5QbCRVwK+9010+xm7MTQY8s=";
const TYPE0_PLAINTEXT: [u8; 64] = [
    116, 170, 187, 43, 80, 212, 193, 202, 234, 181, 57, 66, 151, 249, 59, 47, 70, 16, 57, 4, 170,
    78, 85, 241, 152, 232, 91, 57, 9, 87, 209, 245, 40, 245, 106, 140, 2, 225, 138, 213, 98, 223,
    92, 168, 135, 208, 22, 194, 31, 21, 178, 252, 203, 198, 35, 174, 53, 218, 254, 151, 235, 57, 7,
    98,
];

#[test]
fn type0_decrypts_with_and_without_header() {
    let legacy_key = key(&b64(TYPE0_KEY));
    for text in [TYPE0_USER_KEY, &TYPE0_USER_KEY[2..]] {
        let plaintext = enc(text).decrypt(&legacy_key).expect("decrypts");
        assert_eq!(plaintext.as_slice(), TYPE0_PLAINTEXT.as_slice(), "{text}");
    }
}

// sdk-internal enc_string/symmetric.rs `test_decrypt_downgrade_encstring_prevention`: a type-2
// string with its MAC removed, offered to a key that has a MAC key.
const DOWNGRADE_KEY: &str =
    "hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==";
const DOWNGRADED_ENC_STRING: &str = "0.NQfjHLr6za7VQVAbrpL81w==|wfrjmyJ0bfwkQlySrhw8dA==";

#[test]
fn downgraded_type0_is_rejected_for_a_mac_key() {
    let result = enc(DOWNGRADED_ENC_STRING).decrypt(&key(&b64(DOWNGRADE_KEY)));
    assert!(matches!(result, Err(Error::MacRequired)), "{result:?}");
}

#[test]
fn device_vector_with_mac_stripped_is_rejected() {
    let (iv_and_data, _mac) = DEVICE_PROTECTED_PRIVATE_KEY[2..]
        .rsplit_once('|')
        .expect("type 2 has three parts");
    let result = enc(&format!("0.{iv_and_data}")).decrypt(&key(&DEVICE_KEY));
    assert!(matches!(result, Err(Error::MacRequired)), "{result:?}");
}

#[test]
fn type0_with_wrong_key_fails_padding() {
    let result = enc(TYPE0_USER_KEY).decrypt(&key(&[0u8; 32]));
    assert!(matches!(result, Err(Error::Decrypt)), "{result:?}");
}

#[test]
fn attachment_without_key_decrypts_with_user_key() {
    let file = b64(ATTACHMENT_FILE_WITHOUT_KEY);
    let user_key = key(&b64(ATTACHMENT_USER_KEY));
    let expected = b64(ATTACHMENT_PLAINTEXT);

    enc_buffer::verify_stream(&user_key, file.as_slice()).expect("valid MAC");
    let mut streamed = Vec::new();
    let written =
        enc_buffer::decrypt_stream(&user_key, file.as_slice(), &mut streamed).expect("decrypts");
    assert_eq!(streamed, expected);
    assert_eq!(written, u64::try_from(expected.len()).expect("small"));
    let in_memory = enc_buffer::decrypt_bytes(&user_key, &file).expect("decrypts");
    assert_eq!(in_memory.as_slice(), expected.as_slice());
}

#[test]
fn attachment_key_chain_decrypts_file() {
    let user_key = key(&b64(ATTACHMENT_USER_KEY));
    let cipher_key = key(&enc(ATTACHMENT_CIPHER_KEY)
        .decrypt(&user_key)
        .expect("cipher key decrypts"));
    let attachment_key = key(&enc(ATTACHMENT_KEY)
        .decrypt(&cipher_key)
        .expect("attachment key decrypts"));
    let file = b64(ATTACHMENT_FILE_WITH_KEY);

    let plaintext = enc_buffer::decrypt_bytes(&attachment_key, &file).expect("file decrypts");
    assert_eq!(plaintext.as_slice(), b64(ATTACHMENT_PLAINTEXT).as_slice());

    let result = enc_buffer::decrypt_bytes(&user_key, &file);
    assert!(
        matches!(result, Err(Error::MacMismatch)),
        "the user key must not open it"
    );
}

#[test]
fn sdk_stream_vector_decrypts_with_type_header() {
    let mut keys = [0u8; 64];
    keys[32..].fill(1);
    let stream_key = key(&keys);
    let mut file = vec![2u8];
    file.extend_from_slice(&STREAM_TEST_VECTOR);

    let mut out = Cursor::new(Vec::new());
    enc_buffer::decrypt_stream(&stream_key, file.as_slice(), &mut out).expect("decrypts");
    assert_eq!(out.into_inner(), STREAM_PLAINTEXT);

    let mut tampered = file.clone();
    tampered[51] ^= 0x01;
    let result = enc_buffer::verify_stream(&stream_key, tampered.as_slice());
    assert!(matches!(result, Err(Error::MacMismatch)));
}
