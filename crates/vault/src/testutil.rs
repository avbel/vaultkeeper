//! Builders for encrypted server data in unit tests. Ciphertext comes straight from vk-crypto,
//! never from this crate's encrypt module, so decrypt paths are checked independently.

use vk_api::models::{
    Attachment, Card, Cipher, Field, Folder, Identity, Login, LoginUri, PasswordHistory, Profile,
    SecureNote, SshKey, SyncResponse,
};
use vk_crypto::{EncString, SymmetricKey};

use crate::keys::KeyRing;

pub(crate) const USER_ID: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";

pub(crate) fn ring() -> KeyRing {
    KeyRing::build(SymmetricKey::generate(), None, &[], None).unwrap()
}

// Every encrypted field of the wire models is an `Option<String>`.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn enc(plain: &str, key: &SymmetricKey) -> Option<String> {
    Some(
        EncString::encrypt(plain.as_bytes(), key)
            .unwrap()
            .to_string(),
    )
}

/// A cipher with its own item key wrapped by the ring's user key; returns it with the item key.
pub(crate) fn keyed(id: &str, kind: u8, name: &str, ring: &KeyRing) -> (Cipher, SymmetricKey) {
    let item = SymmetricKey::generate();
    let cipher = Cipher {
        id: id.into(),
        r#type: kind,
        name: enc(name, &item),
        key: Some(
            EncString::encrypt(&item.to_bytes(), ring.user())
                .unwrap()
                .to_string(),
        ),
        edit: true,
        view_password: true,
        revision_date: "2026-11-08T17:00:59.321Z".into(),
        ..Cipher::default()
    };
    (cipher, item)
}

pub(crate) fn login(
    id: &str,
    name: &str,
    username: &str,
    password: &str,
    ring: &KeyRing,
) -> Cipher {
    let (mut cipher, item) = keyed(id, 1, name, ring);
    cipher.notes = enc("login notes", &item);
    cipher.login = Some(Login {
        username: enc(username, &item),
        password: enc(password, &item),
        password_revision_date: None,
        totp: enc("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", &item),
        uris: Some(vec![
            LoginUri {
                uri: enc("https://Example.com/login", &item),
                r#match: Some(3),
                ..LoginUri::default()
            },
            LoginUri {
                uri: enc("https://second.example.org", &item),
                r#match: None,
                ..LoginUri::default()
            },
        ]),
        ..Login::default()
    });
    cipher.fields = Some(vec![
        Field {
            r#type: 1,
            name: enc("pin", &item),
            value: enc("4321", &item),
            linked_id: None,
            ..Field::default()
        },
        Field {
            r#type: 2,
            name: enc("flag", &item),
            value: enc("true", &item),
            linked_id: None,
            ..Field::default()
        },
    ]);
    cipher.password_history = Some(vec![PasswordHistory {
        password: enc("older", &item).unwrap(),
        last_used_date: "2026-01-01T00:00:00.000Z".into(),
        ..PasswordHistory::default()
    }]);
    cipher
}

/// Encrypted directly with the user key, the way items made before per-item keys are.
pub(crate) fn legacy_login(id: &str, name: &str, password: &str, ring: &KeyRing) -> Cipher {
    let user = ring.user();
    Cipher {
        id: id.into(),
        r#type: 1,
        name: enc(name, user),
        login: Some(Login {
            username: enc("legacy-user", user),
            password: enc(password, user),
            ..Login::default()
        }),
        edit: true,
        view_password: true,
        revision_date: "2026-11-08T17:00:59.321Z".into(),
        ..Cipher::default()
    }
}

pub(crate) fn note(id: &str, name: &str, ring: &KeyRing) -> Cipher {
    let (mut cipher, item) = keyed(id, 2, name, ring);
    cipher.notes = enc("note body", &item);
    cipher.secure_note = Some(SecureNote::default());
    cipher
}

pub(crate) fn card(id: &str, name: &str, ring: &KeyRing) -> Cipher {
    let (mut cipher, item) = keyed(id, 3, name, ring);
    cipher.card = Some(Card {
        cardholder_name: enc("Ada Lovelace", &item),
        brand: enc("Visa", &item),
        number: enc("4111111111114242", &item),
        exp_month: enc("12", &item),
        exp_year: enc("2031", &item),
        code: enc("123", &item),
        ..Card::default()
    });
    cipher
}

pub(crate) fn identity(id: &str, name: &str, email: &str, ring: &KeyRing) -> Cipher {
    let (mut cipher, item) = keyed(id, 4, name, ring);
    cipher.identity = Some(Identity {
        first_name: enc("Ada", &item),
        last_name: enc("Lovelace", &item),
        email: if email.is_empty() {
            None
        } else {
            enc(email, &item)
        },
        phone: enc("+44 20 7946 0000", &item),
        username: enc("ada.l", &item),
        ssn: enc("078-05-1120", &item),
        ..Identity::default()
    });
    cipher
}

pub(crate) fn ssh(id: &str, name: &str, ring: &KeyRing) -> Cipher {
    let (mut cipher, item) = keyed(id, 5, name, ring);
    cipher.ssh_key = Some(SshKey {
        private_key: enc(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            &item,
        ),
        public_key: enc("ssh-ed25519 AAAAC3Nza test@example", &item),
        key_fingerprint: enc("SHA256:fingerprint", &item),
        ..SshKey::default()
    });
    cipher
}

pub(crate) fn attachment(id: &str, file_name: &str, key: &SymmetricKey) -> Attachment {
    Attachment {
        id: id.into(),
        url: None,
        file_name: enc(file_name, key),
        key: Some(
            EncString::encrypt(&SymmetricKey::generate().to_bytes(), key)
                .unwrap()
                .to_string(),
        ),
        size: Some("1234".into()),
        size_name: Some("1.21 KB".into()),
    }
}

pub(crate) fn folder(id: &str, name: &str, ring: &KeyRing) -> Folder {
    Folder {
        id: id.into(),
        name: enc(name, ring.user()).unwrap(),
        revision_date: "2026-11-08T17:00:59.321Z".into(),
    }
}

pub(crate) fn profile() -> Profile {
    Profile {
        id: USER_ID.into(),
        email: "user@example.com".into(),
        name: None,
        key: None,
        private_key: None,
        organizations: Vec::new(),
    }
}

pub(crate) fn sync(ciphers: Vec<Cipher>, folders: Vec<Folder>) -> SyncResponse {
    SyncResponse {
        profile: profile(),
        folders,
        collections: Vec::new(),
        ciphers,
        sends: Vec::new(),
    }
}
