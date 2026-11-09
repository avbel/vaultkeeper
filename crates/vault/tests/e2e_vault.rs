//! Items, folders and organizations against the e2e Vaultwarden (scripts/e2e.sh). The harness
//! decrypts what reached the server with the user key it registered, independently of the vault.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

mod support;

use std::time::Duration;

use bwl_api::models::{Cipher, CipherRequest, Login, LoginUri};
use bwl_crypto::{EncString, SymmetricKey};
use bwl_vault::{
    Error, VaultService,
    model::{CopyField, Filter, ItemData, ItemDraft, ItemId, ItemKind},
};
use serde_json::{Value, json};
use support::{
    KdfChoice, TestVault, create_org, decrypt, drafts, enc, env, org_key, raw_session, register,
    server_cipher_key,
};
use zeroize::Zeroizing;

/// `saved` is `expected` as stored by a later revision: every field but the revision matches.
fn assert_saved_as(saved: &ItemDraft, expected: &ItemDraft, what: &str) {
    assert!(
        saved.revision_date.is_some(),
        "{what}: stored items carry a revision"
    );
    assert_ne!(
        saved.revision_date, expected.revision_date,
        "{what}: the revision moved on"
    );
    let unrevised = |draft: &ItemDraft| ItemDraft {
        revision_date: None,
        ..draft.clone()
    };
    assert!(
        unrevised(saved) == unrevised(expected),
        "{what}: round trip"
    );
}

/// Changes one field per kind and returns its new plaintext.
fn edit_kind_field(draft: &mut ItemDraft) -> String {
    let value = match &mut draft.data {
        ItemData::SecureNote => {
            draft.notes = Zeroizing::new("edited note".into());
            "edited note"
        }
        ItemData::Card { code, .. } => {
            *code = Zeroizing::new("999".into());
            "999"
        }
        ItemData::Identity(identity) => {
            identity.phone = "+1 555 0100".into();
            "+1 555 0100"
        }
        ItemData::SshKey { public_key, .. } => {
            *public_key = "ssh-ed25519 AAAAedited e2e@example".into();
            "ssh-ed25519 AAAAedited e2e@example"
        }
        ItemData::Login { username, .. } => {
            *username = "edited-user".into();
            "edited-user"
        }
    };
    value.to_owned()
}

/// The encrypted field [`edit_kind_field`] changed, as stored on the server.
fn kind_field(cipher: &Cipher) -> Option<&str> {
    match cipher.r#type {
        2 => cipher.notes.as_deref(),
        3 => cipher.card.as_ref().and_then(|card| card.code.as_deref()),
        4 => cipher
            .identity
            .as_ref()
            .and_then(|identity| identity.phone.as_deref()),
        5 => cipher
            .ssh_key
            .as_ref()
            .and_then(|ssh| ssh.public_key.as_deref()),
        _ => cipher
            .login
            .as_ref()
            .and_then(|login| login.username.as_deref()),
    }
}

fn trash_filter() -> Filter {
    Filter {
        trash: true,
        ..Filter::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_item_kind_round_trips_through_the_server() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let server = raw_session(&env, &account).await;

    let login = drafts::login("Bank", "ada", "first-password");
    let samples = [
        (login.clone(), ItemKind::Login, "ada"),
        (drafts::note("Diary"), ItemKind::SecureNote, ""),
        (drafts::card("Travel card"), ItemKind::Card, "Visa *4242"),
        (
            drafts::identity("Passport"),
            ItemKind::Identity,
            "ada@example.com",
        ),
        (
            drafts::ssh("Deploy key"),
            ItemKind::SshKey,
            "SHA256:e2eFingerprintValue",
        ),
    ];
    let mut ids = Vec::new();
    for (draft, kind, subtitle) in &samples {
        let id = vault.save(None, draft.clone()).await.unwrap();
        let found = vault
            .search(&draft.name.to_lowercase(), &Filter::default())
            .unwrap();
        assert_eq!(found.len(), 1, "{}", draft.name);
        assert_eq!(found[0].id, id);
        assert_eq!(found[0].kind, *kind);
        assert_eq!(&*found[0].subtitle, *subtitle);
        assert_saved_as(
            &vault.draft(&id).unwrap(),
            draft,
            &format!("{} draft round trip", draft.name),
        );

        // New items carry their own key, wrapped by the user key; the name decrypts with it.
        let stored = server.cipher(&id.0).await;
        assert!(stored.key.is_some(), "{} has an item key", draft.name);
        let item_key = server_cipher_key(&stored, &account.user_key);
        assert_eq!(decrypt(stored.name.as_deref(), &item_key), draft.name);
        ids.push(id);
    }

    let bank = &ids[0];
    let summary = vault.search("bank", &Filter::default()).unwrap()[0].clone();
    assert!(summary.has_password && summary.has_totp);
    assert_eq!(
        summary.primary_uri.as_deref(),
        Some("https://login.example.com/")
    );
    assert_eq!(
        &*vault.reveal(bank, CopyField::Password).unwrap(),
        "first-password"
    );
    assert_eq!(&*vault.reveal(bank, CopyField::Username).unwrap(), "ada");
    assert_eq!(&*vault.reveal(bank, CopyField::Custom(0)).unwrap(), "4321");
    // RFC 6238 appendix B: T = 59 s, SHA-1, truncated to 6 digits.
    assert_eq!(&*vault.totp(bank, 59).unwrap().code, "287082");
    assert_eq!(
        &*vault.reveal(&ids[2], CopyField::CardNumber).unwrap(),
        "4111111111114242"
    );
    assert_eq!(
        &*vault.reveal(&ids[3], CopyField::Email).unwrap(),
        "ada@example.com"
    );
    assert_eq!(
        &*vault.reveal(&ids[4], CopyField::SshPrivateKey).unwrap(),
        drafts::SSH_PRIVATE
    );
    assert!(matches!(
        vault.reveal(&ids[1], CopyField::Password),
        Err(Error::NoSuchField)
    ));
    assert_eq!(
        vault.search("", &Filter::default()).unwrap()[0].id,
        ids[4],
        "MRU first"
    );

    let ssh = vault.ssh_keys().unwrap();
    assert_eq!(ssh.len(), 1);
    assert_eq!(ssh[0].name, "Deploy key");
    assert_eq!(&*ssh[0].private_key, drafts::SSH_PRIVATE);

    // Every other kind takes an edit (name + one kind-specific field) and a trash/restore
    // cycle; the server's copy decrypts to the edited values.
    for id in &ids[1..] {
        let mut changed = vault.draft(id).unwrap();
        changed.name = format!("{} v2", changed.name);
        let expected = edit_kind_field(&mut changed);
        vault.save(Some(id.clone()), changed.clone()).await.unwrap();
        assert_saved_as(
            &vault.draft(id).unwrap(),
            &changed,
            &format!("{} edit round trip", changed.name),
        );
        let stored = server.cipher(&id.0).await;
        let key = server_cipher_key(&stored, &account.user_key);
        assert_eq!(decrypt(stored.name.as_deref(), &key), changed.name);
        assert_eq!(
            decrypt(kind_field(&stored), &key),
            expected,
            "{}",
            changed.name
        );

        vault.trash(id).await.unwrap();
        assert!(server.cipher(&id.0).await.deleted_date.is_some());
        let trashed = vault
            .search(&changed.name.to_lowercase(), &trash_filter())
            .unwrap();
        assert_eq!(trashed.len(), 1, "{} in the trash", changed.name);
        vault.restore(id).await.unwrap();
        assert!(server.cipher(&id.0).await.deleted_date.is_none());
        assert_eq!(
            vault
                .search(&changed.name.to_lowercase(), &Filter::default())
                .unwrap()
                .len(),
            1
        );
    }

    // Edit: the old password moves to the history, encrypted under the same item key.
    let mut edited = vault.draft(bank).unwrap();
    if let ItemData::Login { password, .. } = &mut edited.data {
        *password = Zeroizing::new("second-password".into());
    }
    edited.favorite = true;
    let before = server.cipher(&bank.0).await;
    vault
        .save(Some(bank.clone()), edited.clone())
        .await
        .unwrap();
    assert_saved_as(&vault.draft(bank).unwrap(), &edited, "bank edit");
    let after = server.cipher(&bank.0).await;
    assert_eq!(after.key, before.key, "an existing item key is kept");
    let item_key = server_cipher_key(&after, &account.user_key);
    let history = after.password_history.as_deref().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(
        decrypt(Some(&history[0].password), &item_key),
        "first-password"
    );
    assert_eq!(
        decrypt(after.login.as_ref().unwrap().password.as_deref(), &item_key),
        "second-password"
    );
    assert!(after.favorite);

    // Optimistic concurrency: another device edits the item while this one has not synced
    // (sleeping, so the websocket can't deliver the change). The vault's save carries the old
    // lastKnownRevisionDate and the server's refusal is reported as a conflict; after a sync a
    // fresh draft goes through. The server only refuses when its copy is more than one whole
    // second newer.
    vault.on_sleep();
    let mut late = vault.draft(bank).unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let other_device = CipherRequest {
        r#type: 1,
        name: enc("Bank (other device)", &item_key),
        key: after.key.clone(),
        login: Some(Login::default()),
        last_known_revision_date: Some(after.revision_date.clone()),
        ..CipherRequest::default()
    };
    server
        .client
        .update_cipher(&server.token, &bank.0, &other_device)
        .await
        .unwrap();
    late.name = "Bank (this device)".into();
    let refused = vault
        .save(Some(bank.clone()), late.clone())
        .await
        .unwrap_err();
    assert!(matches!(&refused, Error::Conflict), "{refused:?}");
    vault.on_wake();
    vault.sync().await.unwrap();
    assert_eq!(
        &*vault.search("bank", &Filter::default()).unwrap()[0].name,
        "Bank (other device)"
    );
    let mut fresh = vault.draft(bank).unwrap();
    fresh.name = "Bank".into();
    vault.save(Some(bank.clone()), fresh).await.unwrap();

    // The same race after a sync already brought the other device's edit: the draft opened
    // before it is refused locally, nothing is sent, and the other device's edit stays.
    let mut opened = vault.draft(bank).unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let current = server.cipher(&bank.0).await;
    let phone = CipherRequest {
        name: enc("Bank (phone)", &item_key),
        last_known_revision_date: Some(current.revision_date.clone()),
        ..other_device.clone()
    };
    server
        .client
        .update_cipher(&server.token, &bank.0, &phone)
        .await
        .unwrap();
    vault.sync().await.unwrap();
    opened.name = "Bank (desktop)".into();
    let before = server.cipher(&bank.0).await.revision_date;
    let refused = vault.save(Some(bank.clone()), opened).await.unwrap_err();
    assert!(matches!(&refused, Error::Conflict), "{refused:?}");
    let kept = server.cipher(&bank.0).await;
    assert_eq!(kept.revision_date, before, "nothing was written");
    assert_eq!(decrypt(kept.name.as_deref(), &item_key), "Bank (phone)");
    let mut reopened = vault.draft(bank).unwrap();
    assert_eq!(reopened.name, "Bank (phone)");
    reopened.name = "Bank".into();
    vault.save(Some(bank.clone()), reopened).await.unwrap();

    // Trash, restore and permanent delete.
    vault.trash(&ids[1]).await.unwrap();
    assert!(
        vault
            .search("diary", &Filter::default())
            .unwrap()
            .is_empty()
    );
    let trashed = vault.search("diary", &trash_filter()).unwrap();
    assert_eq!(trashed.len(), 1);
    assert!(trashed[0].deleted);
    assert!(server.cipher(&ids[1].0).await.deleted_date.is_some());

    vault.restore(&ids[1]).await.unwrap();
    assert_eq!(vault.search("diary", &Filter::default()).unwrap().len(), 1);
    assert!(server.cipher(&ids[1].0).await.deleted_date.is_none());

    vault.delete_permanently(&ids[1]).await.unwrap();
    assert!(
        vault
            .search("diary", &Filter::default())
            .unwrap()
            .is_empty()
    );
    assert!(vault.search("diary", &trash_filter()).unwrap().is_empty());
    assert!(
        server
            .ciphers()
            .await
            .iter()
            .all(|cipher| *cipher.id != *ids[1].0)
    );
    assert!(matches!(vault.draft(&ids[1]), Err(Error::NotFound)));

    // The cached vault survives a full sync unchanged.
    vault.sync().await.unwrap();
    assert_eq!(vault.search("", &Filter::default()).unwrap().len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_items_without_an_item_key_decrypt_and_upgrade_on_edit() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let server = raw_session(&env, &account).await;
    let legacy = CipherRequest {
        r#type: 1,
        name: enc("Legacy login", &account.user_key),
        login: Some(Login {
            username: Some(enc("old-user", &account.user_key)),
            password: Some(enc("old-pass", &account.user_key)),
            ..Login::default()
        }),
        ..CipherRequest::default()
    };
    let created = server
        .client
        .create_cipher(&server.token, &legacy, &[])
        .await
        .unwrap();
    assert!(created.key.is_none());

    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let id = ItemId(created.id.as_str().into());
    let found = vault.search("legacy", &Filter::default()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(&*found[0].subtitle, "old-user");
    assert_eq!(
        &*vault.reveal(&id, CopyField::Password).unwrap(),
        "old-pass"
    );

    let mut draft = vault.draft(&id).unwrap();
    draft.name = "Legacy login (edited)".into();
    vault.save(Some(id.clone()), draft).await.unwrap();

    let stored = server.cipher(&id.0).await;
    assert!(
        stored.key.is_some(),
        "an edited legacy item gets its own key"
    );
    let item_key = server_cipher_key(&stored, &account.user_key);
    assert_ne!(item_key.to_bytes(), account.user_key.to_bytes());
    assert_eq!(
        decrypt(stored.name.as_deref(), &item_key),
        "Legacy login (edited)"
    );
    let login = stored.login.as_ref().unwrap();
    assert_eq!(decrypt(login.password.as_deref(), &item_key), "old-pass");
    assert_eq!(decrypt(login.username.as_deref(), &item_key), "old-user");
    assert_eq!(
        &*vault.reveal(&id, CopyField::Password).unwrap(),
        "old-pass"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn folders_crud_and_filtering() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let server = raw_session(&env, &account).await;

    let work = vault.create_folder("Work").await.unwrap();
    let home = vault.create_folder("Home").await.unwrap();
    let names: Vec<_> = vault
        .folders()
        .unwrap()
        .iter()
        .map(|f| f.name.to_string())
        .collect();
    assert_eq!(names, ["Home", "Work"]);

    let mut draft = drafts::login("VPN", "ada", "pw");
    draft.folder_id = Some(work.id.clone());
    let vpn = vault.save(None, draft).await.unwrap();
    vault.save(None, drafts::note("Loose note")).await.unwrap();

    let in_work = Filter {
        folder: Some(Some(work.id.clone())),
        ..Filter::default()
    };
    let no_folder = Filter {
        folder: Some(None),
        ..Filter::default()
    };
    assert_eq!(vault.search("", &in_work).unwrap().len(), 1);
    assert_eq!(
        &*vault.search("", &no_folder).unwrap()[0].name,
        "Loose note"
    );

    vault.rename_folder(&work.id, "Office").await.unwrap();
    let sync = server.client.sync(&server.token).await.unwrap();
    let stored = sync
        .folders
        .iter()
        .find(|folder| *folder.id == *work.id)
        .unwrap();
    assert_eq!(decrypt(Some(&stored.name), &account.user_key), "Office");
    assert!(
        vault
            .folders()
            .unwrap()
            .iter()
            .any(|f| &*f.name == "Office")
    );

    vault.delete_folder(&work.id).await.unwrap();
    assert_eq!(vault.folders().unwrap().len(), 1);
    assert_eq!(
        vault.search("vpn", &Filter::default()).unwrap()[0].folder_id,
        None
    );
    vault.sync().await.unwrap();
    assert_eq!(vault.search("", &no_folder).unwrap().len(), 2);
    assert!(
        server
            .client
            .sync(&server.token)
            .await
            .unwrap()
            .folders
            .iter()
            .all(|f| *f.id != *work.id)
    );
    assert!(matches!(
        vault.rename_folder(&work.id, "x").await,
        Err(Error::NotFound)
    ));
    assert_eq!(vault.draft(&vpn).unwrap().folder_id, None);
    let _ = home;
}

#[tokio::test(flavor = "multi_thread")]
async fn organization_items_decrypt_with_the_org_key() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let server = raw_session(&env, &account).await;
    let (org_id, collection_id) = create_org(&env, &server, &account.email).await;

    let org = org_key();
    let item_key = SymmetricKey::generate();
    let shared = CipherRequest {
        r#type: 1,
        organization_id: Some(org_id.clone()),
        name: enc("Shared router", &item_key),
        key: Some(
            EncString::encrypt(&item_key.to_bytes(), &org)
                .unwrap()
                .to_string(),
        ),
        login: Some(Login {
            username: Some(enc("admin", &item_key)),
            password: Some(enc("router-pass", &item_key)),
            ..Login::default()
        }),
        ..CipherRequest::default()
    };
    let created = server
        .client
        .create_cipher(&server.token, &shared, std::slice::from_ref(&collection_id))
        .await
        .unwrap();

    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let orgs = vault.organizations().unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(&*orgs[0].name, "E2E Org");
    let collections = vault.collections().unwrap();
    assert_eq!(collections.len(), 1);
    assert_eq!(&*collections[0].name, "Shared");
    assert_eq!(&*collections[0].organization_id, org_id);

    let found = vault.search("router", &Filter::default()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].organization_id.as_deref(), Some(org_id.as_str()));
    let id = ItemId(created.id.as_str().into());
    assert_eq!(
        &*vault.reveal(&id, CopyField::Password).unwrap(),
        "router-pass"
    );
    let only_org = Filter {
        organization: Some(Some(org_id.as_str().into())),
        ..Filter::default()
    };
    let personal = Filter {
        organization: Some(None),
        ..Filter::default()
    };
    assert_eq!(vault.search("", &only_org).unwrap().len(), 1);
    assert!(vault.search("", &personal).unwrap().is_empty());

    // A new org item written by the vault decrypts with the org key on the server side.
    let mut draft = drafts::login("Team wiki", "team", "wiki-pass");
    draft.organization_id = Some(org_id.as_str().into());
    draft.collection_ids = vec![collection_id.as_str().into()];
    let wiki = vault.save(None, draft).await.unwrap();
    let stored = server.cipher(&wiki.0).await;
    assert_eq!(stored.organization_id.as_deref(), Some(org_id.as_str()));
    assert_eq!(stored.collection_ids, vec![collection_id.clone()]);
    let stored_key = server_cipher_key(&stored, &org);
    assert_eq!(decrypt(stored.name.as_deref(), &stored_key), "Team wiki");

    let mut moved = vault.draft(&wiki).unwrap();
    moved.organization_id = None;
    assert!(
        vault.save(Some(wiki), moved).await.is_err(),
        "moving out of an org is refused"
    );
}

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
const PASSKEY_CREATED: &str = "2026-11-08T17:00:59.321Z";
const PASSKEY_URI: &str = "https://passkeys.example/login";
/// `printf '%s' https://passkeys.example/login | openssl dgst -sha256 -binary | base64`
const PASSKEY_URI_CHECKSUM: &str = "w6TH6D1hefTIETTNu68+SOtz754v24TtDleuMxGNEK4=";

/// A passkey login as an official client would write it, encrypted with `key`.
fn passkey_login(key: &SymmetricKey, wrapped: Option<String>) -> CipherRequest {
    let mut credential: serde_json::Map<String, Value> = PASSKEY
        .iter()
        .map(|(name, plain)| ((*name).to_owned(), json!(enc(plain, key))))
        .collect();
    credential.insert("creationDate".into(), json!(PASSKEY_CREATED));
    CipherRequest {
        r#type: 1,
        name: enc("Passkey site", key),
        key: wrapped,
        login: Some(Login {
            username: Some(enc("ada", key)),
            password: Some(enc("site-password", key)),
            uris: Some(vec![LoginUri {
                uri: Some(enc(PASSKEY_URI, key)),
                uri_checksum: Some(enc(PASSKEY_URI_CHECKSUM, key)),
                ..LoginUri::default()
            }]),
            extra: serde_json::Map::from_iter([
                ("fido2Credentials".to_owned(), json!([credential])),
                ("autofillOnPageLoad".to_owned(), json!(false)),
            ]),
            ..Login::default()
        }),
        ..CipherRequest::default()
    }
}

fn stored_passkey(cipher: &Cipher) -> &Value {
    &cipher.login.as_ref().unwrap().extra["fido2Credentials"][0]
}

/// The stored passkey and the URI checksum decrypt to what was written, under `key`.
fn assert_passkey_under(cipher: &Cipher, key: &SymmetricKey) {
    let credential = stored_passkey(cipher);
    for (name, plain) in PASSKEY {
        assert_eq!(decrypt(credential[name].as_str(), key), plain, "{name}");
    }
    assert_eq!(credential["creationDate"], PASSKEY_CREATED);
    let login = cipher.login.as_ref().unwrap();
    assert_eq!(login.extra["autofillOnPageLoad"], false);
    let uri = &login.uris.as_ref().unwrap()[0];
    assert_eq!(decrypt(uri.uri.as_deref(), key), PASSKEY_URI);
    assert_eq!(
        decrypt(uri.uri_checksum.as_deref(), key),
        PASSKEY_URI_CHECKSUM
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_and_the_archive_date_survive_an_edit_in_this_client() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let server = raw_session(&env, &account).await;
    let item_key = SymmetricKey::generate();
    let wrapped = EncString::encrypt(&item_key.to_bytes(), &account.user_key)
        .unwrap()
        .to_string();
    let created = server
        .client
        .create_cipher(&server.token, &passkey_login(&item_key, Some(wrapped)), &[])
        .await
        .unwrap();
    server
        .api(
            &env,
            reqwest::Method::PUT,
            &format!("api/ciphers/{}/archive", created.id),
            Value::Null,
        )
        .await;
    let before = server.cipher(&created.id).await;
    let archived_at = before.extra["archivedDate"].clone();
    assert!(archived_at.is_string(), "{archived_at}");

    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let id = ItemId(created.id.as_str().into());
    let mut draft = test.vault.draft(&id).unwrap();
    draft.name = "Passkey site (renamed)".into();
    test.vault.save(Some(id), draft).await.unwrap();

    let after = server.cipher(&created.id).await;
    assert_eq!(after.key, before.key);
    assert_eq!(
        decrypt(after.name.as_deref(), &item_key),
        "Passkey site (renamed)"
    );
    assert_eq!(
        stored_passkey(&after),
        stored_passkey(&before),
        "the passkey goes back byte for byte"
    );
    assert_passkey_under(&after, &item_key);
    assert_eq!(after.extra["archivedDate"], archived_at, "still archived");
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrading_a_legacy_login_re_encrypts_its_passkey_under_the_new_item_key() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let server = raw_session(&env, &account).await;
    let created = server
        .client
        .create_cipher(&server.token, &passkey_login(&account.user_key, None), &[])
        .await
        .unwrap();
    assert!(created.key.is_none());
    assert_passkey_under(&created, &account.user_key);

    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let id = ItemId(created.id.as_str().into());
    let mut draft = test.vault.draft(&id).unwrap();
    draft.name = "Passkey site (upgraded)".into();
    test.vault.save(Some(id), draft).await.unwrap();

    let after = server.cipher(&created.id).await;
    assert!(
        after.key.is_some(),
        "an edited legacy item gets its own key"
    );
    let item_key = server_cipher_key(&after, &account.user_key);
    assert_ne!(item_key.to_bytes(), account.user_key.to_bytes());
    assert_eq!(
        decrypt(after.name.as_deref(), &item_key),
        "Passkey site (upgraded)"
    );
    assert_passkey_under(&after, &item_key);
    let key_value = stored_passkey(&after)["keyValue"].as_str().unwrap();
    assert!(
        key_value
            .parse::<EncString>()
            .unwrap()
            .decrypt(&account.user_key)
            .is_err(),
        "nothing stays under the user key"
    );
}
