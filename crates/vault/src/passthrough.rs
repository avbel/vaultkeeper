//! Server data this client doesn't model, carried from the stored cipher into an update.
//!
//! The update request starts from the stored cipher's `extra` maps (passkeys, `archivedDate`,
//! whatever a newer server adds). When the item key changes, every EncString in them is
//! re-encrypted under the new key; one that can't be decrypted aborts the edit, because sending
//! it on would leave the item readable only in part.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use vk_api::models::Extra;
use vk_crypto::{EncString, SymmetricKey};

use crate::{Error, Result, keys::encrypt_text};

pub(crate) const UNDECRYPTABLE_PASSTHROUGH: &str = "This item holds data that can't be decrypted, \
     so saving it here would damage it. Edit it in another Bitwarden client.";

/// Every symmetric EncString body starts with the 24-character base64 of its 16-byte IV, and RSA
/// or COSE bodies are longer, so shorter `<digits>.<...>` strings (`"3.14"`) are plain values.
const MIN_ENCRYPTED_BODY: usize = 24;

/// The key the stored ciphertext uses and the one the update writes.
#[derive(Clone, Copy)]
pub(crate) struct Rekey<'a> {
    pub old: &'a SymmetricKey,
    pub new: &'a SymmetricKey,
}

/// A copy of `extra` for the request, re-encrypted when `rekey` is set.
pub(crate) fn carry(extra: Option<&Extra>, rekey: Option<Rekey<'_>>) -> Result<Extra> {
    let Some(extra) = extra else {
        return Ok(Extra::new());
    };
    match rekey {
        None => Ok(extra.clone()),
        Some(rekey) => extra
            .iter()
            .map(|(name, value)| Ok((name.clone(), reencrypt(value, rekey)?)))
            .collect(),
    }
}

fn reencrypt(value: &Value, rekey: Rekey<'_>) -> Result<Value> {
    match value {
        Value::String(text) if looks_encrypted(text) => {
            reencrypt_text(text, rekey).map(Value::String)
        }
        Value::Array(items) => items
            .iter()
            .map(|item| reencrypt(item, rekey))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(map) => map
            .iter()
            .map(|(name, child)| Ok((name.clone(), reencrypt(child, rekey)?)))
            .collect::<Result<Extra>>()
            .map(Value::Object),
        other => Ok(other.clone()),
    }
}

fn reencrypt_text(text: &str, rekey: Rekey<'_>) -> Result<String> {
    let plain = text
        .parse::<EncString>()
        .and_then(|enc| enc.decrypt(rekey.old))
        .map_err(|error| {
            tracing::warn!(%error, "an unmodelled cipher property does not decrypt");
            Error::unsupported(UNDECRYPTABLE_PASSTHROUGH)
        })?;
    Ok(EncString::encrypt(&plain, rekey.new)?.to_string())
}

/// Fail-closed: a `<digits>.<base64|...>` string is ciphertext even when it doesn't parse (an
/// EncString type this client can't read), so it is never sent on under the old key. Dates and
/// version numbers have a non-base64 body. Header-less strings are ciphertext only if they parse
/// as the legacy type-0 form.
fn looks_encrypted(text: &str) -> bool {
    match text.split_once('.') {
        Some((header, body)) => {
            !header.is_empty()
                && header.bytes().all(|byte| byte.is_ascii_digit())
                && body.len() >= MIN_ENCRYPTED_BODY
                && body
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+/=|".contains(&byte))
        }
        None => text.contains('|') && text.parse::<EncString>().is_ok(),
    }
}

/// `uriChecksum`: base64 of SHA-256 over the URI exactly as encrypted, encrypted with the item
/// key. Official clients drop a keyed cipher's URIs whose checksum is missing or doesn't match.
pub(crate) fn uri_checksum(uri: &str, key: &SymmetricKey) -> Result<String> {
    let digest = Sha256::digest(uri.as_bytes());
    encrypt_text(&STANDARD.encode(digest), key)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vk_api::models::{Cipher, CipherRequest};

    use super::*;
    use crate::{
        encrypt::prepare,
        keys::{KeyRing, decrypt_text, parse},
        reveal,
        testutil::{self, card, identity, login, note, ring, ssh},
    };

    fn enc(plain: &str, key: &SymmetricKey) -> String {
        testutil::enc(plain, key).unwrap()
    }

    /// Type 7 (COSE), which this client can't decrypt.
    const UNREADABLE_TYPE: &str = "7.0oRDoQEFoQVQMTIzNDU2Nzg5MGFiY2RlZvZYIA==";
    /// A type-2 string without its MAC.
    const MALFORMED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|Y2lwaGVydGV4dA==";

    const PASSKEY_CREATED: &str = "2026-11-08T17:00:59.321Z";
    /// Every EncString of a `fido2Credentials` entry, with its plaintext.
    const PASSKEY: [(&str, &str); 12] = [
        ("credentialId", "a3e4b0c2-credential"),
        ("keyType", "public-key"),
        ("keyAlgorithm", "ECDSA"),
        ("keyCurve", "P-256"),
        (
            "keyValue",
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",
        ),
        ("rpId", "passkeys.example"),
        ("userHandle", "dXNlci1oYW5kbGU="),
        ("userName", "ada"),
        ("counter", "0"),
        ("rpName", "Passkeys Example"),
        ("userDisplayName", "Ada Lovelace"),
        ("discoverable", "true"),
    ];
    /// Unmodelled EncStrings at the other levels: (JSON pointer, plaintext).
    const HIDDEN: [(&str, &str); 4] = [
        ("/futureSecret", "top secret"),
        ("/login/uris/0/futureUriSecret", "uri secret"),
        ("/fields/0/futureFieldSecret", "field secret"),
        ("/passwordHistory/0/futureHistorySecret", "history secret"),
    ];

    fn passkey(key: &SymmetricKey) -> Value {
        let mut credential: Extra = PASSKEY
            .iter()
            .map(|(name, plain)| ((*name).to_owned(), json!(enc(plain, key))))
            .collect();
        credential.insert("creationDate".to_owned(), json!(PASSKEY_CREATED));
        Value::Object(credential)
    }

    /// A login as Vaultwarden's `Cipher::to_json` sends it, with a passkey and properties no model
    /// names at every level, all encrypted with `key`; `wrapped` is its item key, if it has one.
    fn raw_login(key: &SymmetricKey, wrapped: Option<&str>) -> Value {
        json!({
            "object": "cipherDetails",
            "id": "l1",
            "type": 1,
            "creationDate": "2026-11-08T17:00:59.311257Z",
            "revisionDate": "2026-11-08T17:00:59.323234Z",
            "deletedDate": null,
            "archivedDate": "2026-11-08T18:00:00.000000Z",
            "reprompt": 0,
            "organizationId": null,
            "folderId": null,
            "key": wrapped,
            "attachments": null,
            "organizationUseTotp": true,
            "collectionIds": [],
            "name": enc("Passkey login", key),
            "notes": enc("some notes", key),
            "favorite": false,
            "edit": true,
            "viewPassword": true,
            "permissions": { "delete": true, "restore": true },
            "futureTopLevel": { "nested": [1, "two", null] },
            "futureSecret": enc("top secret", key),
            "fields": [{
                "type": 0, "name": enc("pin", key), "value": enc("1234", key), "linkedId": null,
                "futureField": 7, "futureFieldSecret": enc("field secret", key)
            }],
            "passwordHistory": [{
                "password": enc("older", key), "lastUsedDate": "2026-01-01T00:00:00.000Z",
                "futureHistorySecret": enc("history secret", key)
            }],
            "login": {
                "username": enc("ada", key),
                "password": enc("current", key),
                "passwordRevisionDate": null,
                "totp": null,
                "uri": enc("https://passkeys.example", key),
                "uris": [
                    {
                        "uri": enc("https://passkeys.example", key), "match": 3,
                        "futureUri": "x", "futureUriSecret": enc("uri secret", key)
                    },
                    { "uri": enc("https://second.example", key), "match": null }
                ],
                "autofillOnPageLoad": false,
                "futureLogin": [true],
                "fido2Credentials": [passkey(key)]
            },
            "secureNote": null, "card": null, "identity": null, "sshKey": null,
            "bankAccount": null, "driversLicense": null, "passport": null
        })
    }

    fn wrap(item: &SymmetricKey, keys: &KeyRing) -> String {
        EncString::encrypt(&item.to_bytes(), keys.user())
            .unwrap()
            .to_string()
    }

    fn renamed(base: &Cipher, keys: &KeyRing) -> Result<CipherRequest> {
        let mut draft = reveal::draft(base, keys).unwrap();
        draft.name = "Renamed".into();
        prepare(&draft, Some(base), keys).map(|prepared| prepared.request)
    }

    /// `value` without the `skip` properties, serialized (sorted keys) for a byte comparison.
    fn without(value: &Value, skip: &[&str]) -> String {
        let mut map = value.as_object().unwrap().clone();
        for name in skip {
            map.remove(*name);
        }
        serde_json::to_string(&map).unwrap()
    }

    #[test]
    fn an_edit_sends_everything_it_did_not_edit_byte_for_byte() {
        let keys = ring();
        let item = SymmetricKey::generate();
        let raw = raw_login(&item, Some(&wrap(&item, &keys)));
        let base: Cipher = serde_json::from_value(raw.clone()).unwrap();
        let request = renamed(&base, &keys).unwrap();
        let body = serde_json::to_value(&request).unwrap();
        assert_eq!(
            &*decrypt_text(body["name"].as_str(), &item).unwrap(),
            "Renamed"
        );

        // Server-side metadata is typed on `Cipher` and never sent back.
        let response_only = [
            "id",
            "edit",
            "viewPassword",
            "attachments",
            "collectionIds",
            "revisionDate",
            "creationDate",
            "deletedDate",
        ];
        let edited = [
            "name",
            "notes",
            "folderId",
            "favorite",
            "reprompt",
            "login",
            "fields",
            "passwordHistory",
            "lastKnownRevisionDate",
        ];
        let skip: Vec<&str> = response_only.iter().chain(&edited).copied().collect();
        assert_eq!(without(&body, &edited), without(&raw, &skip));
        assert_eq!(body["lastKnownRevisionDate"], raw["revisionDate"]);
        assert_eq!(
            body["archivedDate"], raw["archivedDate"],
            "an edit must not unarchive"
        );

        let login_edited = [
            "username",
            "password",
            "passwordRevisionDate",
            "totp",
            "uris",
            "uri",
        ];
        assert_eq!(
            without(&body["login"], &login_edited),
            without(&raw["login"], &login_edited)
        );
        assert!(
            body["login"].get("uri").is_none(),
            "the legacy mirror is not sent"
        );
        for index in 0..2 {
            let uri = &body["login"]["uris"][index];
            assert_eq!(
                without(uri, &["uri", "uriChecksum"]),
                without(&raw["login"]["uris"][index], &["uri", "uriChecksum"])
            );
        }
        assert_eq!(
            without(&body["fields"][0], &["name", "value"]),
            without(&raw["fields"][0], &["name", "value"])
        );
        assert_eq!(
            serde_json::to_string(&body["passwordHistory"]).unwrap(),
            serde_json::to_string(&raw["passwordHistory"]).unwrap(),
            "same key and password: the history goes back as stored"
        );
    }

    #[test]
    fn an_upgraded_legacy_item_re_encrypts_every_passkey_string() {
        let keys = ring();
        let raw = raw_login(keys.user(), None);
        let base: Cipher = serde_json::from_value(raw.clone()).unwrap();
        let body = serde_json::to_value(renamed(&base, &keys).unwrap()).unwrap();
        let wrapped = body["key"]
            .as_str()
            .expect("a legacy item gets its own key");
        let item = SymmetricKey::from_bytes(&parse(wrapped).unwrap().decrypt(keys.user()).unwrap())
            .unwrap();

        let credential = &body["login"]["fido2Credentials"][0];
        for (name, plain) in PASSKEY {
            let text = credential[name].as_str().unwrap();
            assert_eq!(&*decrypt_text(Some(text), &item).unwrap(), plain, "{name}");
            assert!(
                decrypt_text(Some(text), keys.user()).is_err(),
                "{name} is still under the user key"
            );
        }
        assert_eq!(credential["creationDate"], PASSKEY_CREATED);
        for (pointer, plain) in HIDDEN {
            let text = body.pointer(pointer).and_then(Value::as_str).unwrap();
            assert_eq!(
                &*decrypt_text(Some(text), &item).unwrap(),
                plain,
                "{pointer}"
            );
        }
        let history = body["passwordHistory"][0]["password"].as_str();
        assert_eq!(&*decrypt_text(history, &item).unwrap(), "older");
        assert_eq!(body["futureTopLevel"], raw["futureTopLevel"]);
        assert_eq!(body["login"]["futureLogin"], raw["login"]["futureLogin"]);
        assert_eq!(body["archivedDate"], raw["archivedDate"]);
    }

    fn refused_as_undecryptable(result: Result<CipherRequest>) -> bool {
        matches!(
            result,
            Err(Error::Api(vk_api::Error::Server { message, .. }))
                if message == UNDECRYPTABLE_PASSTHROUGH
        )
    }

    #[test]
    fn passthrough_that_does_not_decrypt_aborts_an_upgrade_but_not_a_plain_edit() {
        let keys = ring();
        let foreign = json!(enc("x", &SymmetricKey::generate()));

        let mut legacy = raw_login(keys.user(), None);
        legacy["login"]["fido2Credentials"][0]["keyValue"] = foreign.clone();
        let base: Cipher = serde_json::from_value(legacy).unwrap();
        assert!(refused_as_undecryptable(renamed(&base, &keys)));

        let mut unreadable_type = raw_login(keys.user(), None);
        unreadable_type["futureSecret"] = json!(UNREADABLE_TYPE);
        let base: Cipher = serde_json::from_value(unreadable_type).unwrap();
        assert!(refused_as_undecryptable(renamed(&base, &keys)));

        // With its own key the item is not re-encrypted, so the data goes back as it came.
        let item = SymmetricKey::generate();
        let mut keyed = raw_login(&item, Some(&wrap(&item, &keys)));
        keyed["login"]["fido2Credentials"][0]["keyValue"] = foreign.clone();
        let base: Cipher = serde_json::from_value(keyed).unwrap();
        let body = serde_json::to_value(renamed(&base, &keys).unwrap()).unwrap();
        assert_eq!(body["login"]["fido2Credentials"][0]["keyValue"], foreign);
    }

    #[test]
    fn every_kind_carries_its_unknown_properties() {
        let keys = ring();
        let future = || Extra::from_iter([("future".to_owned(), json!({ "keep": [1, 2] }))]);
        let mut items = [
            note("n1", "Note", &keys),
            card("c1", "Card", &keys),
            identity("i1", "Me", "a@b.c", &keys),
            ssh("s1", "Key", &keys),
            login("l1", "Login", "u", "p", &keys),
        ];
        for cipher in &mut items {
            cipher.extra = future();
            if let Some(part) = &mut cipher.secure_note {
                part.r#type = 0;
                part.extra = future();
            }
            if let Some(part) = &mut cipher.card {
                part.extra = future();
            }
            if let Some(part) = &mut cipher.identity {
                part.extra = future();
            }
            if let Some(part) = &mut cipher.ssh_key {
                part.extra = future();
            }
            if let Some(part) = &mut cipher.login {
                part.extra = future();
            }
        }
        for (cipher, part) in
            items
                .iter()
                .zip(["secureNote", "card", "identity", "sshKey", "login"])
        {
            let body = serde_json::to_value(renamed(cipher, &keys).unwrap()).unwrap();
            assert_eq!(body["future"], json!({ "keep": [1, 2] }), "{part}");
            assert_eq!(body[part]["future"], json!({ "keep": [1, 2] }), "{part}");
        }
    }

    #[test]
    fn saved_uris_carry_the_checksum_official_clients_verify() {
        let keys = ring();
        let base = login("l1", "GitHub", "octocat", "pw", &keys);
        let item = keys.cipher_key(&base).unwrap();
        let request = renamed(&base, &keys).unwrap();
        let checksums: Vec<String> = request
            .login
            .unwrap()
            .uris
            .unwrap()
            .iter()
            .map(|uri| {
                decrypt_text(uri.uri_checksum.as_deref(), &item)
                    .unwrap()
                    .to_string()
            })
            .collect();
        // printf '%s' <uri> | openssl dgst -sha256 -binary | base64
        assert_eq!(
            checksums,
            [
                "RzWKAVwehm8kNlGZqCNb9jkcDKVCOpdFfotsh1D3rWE=",
                "Pl6ZJmCexA5jyKh6pNYHftghr0IAO49SUHCw0ysU5bs="
            ]
        );
    }

    #[test]
    fn ciphertext_is_recognised_by_its_header_and_alphabet() {
        let key = SymmetricKey::generate();
        assert!(looks_encrypted(&enc("x", &key)));
        assert!(looks_encrypted("4.cmVhbGx5LWFuLW9yZy1rZXk="));
        assert!(
            looks_encrypted(UNREADABLE_TYPE),
            "unreadable types still count"
        );
        assert!(looks_encrypted(MALFORMED));
        for plain in [
            "2026-11-08T17:00:59.321Z",
            "2025.12.0",
            "3.14",
            "2.AAAA|BBBB",
            "public-key",
            "true",
            "a|b",
            "",
            ".",
            "2.",
        ] {
            assert!(!looks_encrypted(plain), "{plain}");
        }
    }

    #[test]
    fn without_a_new_key_passthrough_is_copied_as_is() {
        let extra = Extra::from_iter([("opaque".to_owned(), json!("2.not|real|ciphertext"))]);
        assert_eq!(carry(Some(&extra), None).unwrap(), extra);
        assert!(carry(None, None).unwrap().is_empty());
    }

    #[test]
    fn rekeying_reaches_nested_strings_and_keeps_everything_else() {
        let old = SymmetricKey::generate();
        let new = SymmetricKey::generate();
        let extra = Extra::from_iter([
            (
                "fido2Credentials".to_owned(),
                json!([{ "keyValue": enc("secret", &old), "creationDate": "2026-11-08T17:00:59.321Z" }]),
            ),
            ("autofillOnPageLoad".to_owned(), json!(false)),
            ("count".to_owned(), json!(3)),
            ("nothing".to_owned(), Value::Null),
        ]);
        let rekey = Rekey {
            old: &old,
            new: &new,
        };
        let out = carry(Some(&extra), Some(rekey)).unwrap();
        let value = out["fido2Credentials"][0]["keyValue"].as_str().unwrap();
        assert_eq!(&*decrypt_text(Some(value), &new).unwrap(), "secret");
        assert!(decrypt_text(Some(value), &old).is_err());
        assert_eq!(
            out["fido2Credentials"][0]["creationDate"],
            "2026-11-08T17:00:59.321Z"
        );
        assert_eq!(out["autofillOnPageLoad"], false);
        assert_eq!(out["count"], 3);
        assert_eq!(out["nothing"], Value::Null);
    }

    #[test]
    fn rekeying_refuses_ciphertext_it_cannot_decrypt() {
        let old = SymmetricKey::generate();
        let new = SymmetricKey::generate();
        let rekey = Rekey {
            old: &old,
            new: &new,
        };
        let foreign = enc("x", &SymmetricKey::generate());
        for value in [
            json!(foreign),
            json!([UNREADABLE_TYPE]),
            json!({ "a": MALFORMED }),
        ] {
            let extra = Extra::from_iter([("v".to_owned(), value)]);
            let error = carry(Some(&extra), Some(rekey)).unwrap_err();
            assert!(
                matches!(&error, Error::Api(vk_api::Error::Server { message, .. }) if message == UNDECRYPTABLE_PASSTHROUGH),
                "{error:?}"
            );
        }
    }

    #[test]
    fn uri_checksum_is_the_encrypted_base64_sha256_of_the_uri() {
        let key = SymmetricKey::generate();
        let checksum = uri_checksum("https://a.example", &key).unwrap();
        // printf 'https://a.example' | openssl dgst -sha256 -binary | base64
        assert_eq!(
            &*decrypt_text(Some(&checksum), &key).unwrap(),
            "OGEsllqcTDXXE0OZGYBK2WDrVNCtQbQ2L/2FND1Lu08="
        );
    }
}
