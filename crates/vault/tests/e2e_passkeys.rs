//! Vault passkeys against the e2e Vaultwarden (scripts/e2e.sh): what the server keeps of the
//! `fido2Credentials` written here, and reading them back after a sync.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used)]

mod support;

use support::{KdfChoice, TestVault, decrypt, env, raw_session, register, server_cipher_key};
use vk_vault::{
    NewPasskey, PasskeyTarget, VaultService, credential_id_text,
    model::{ItemData, ItemId},
};
use zeroize::Zeroizing;

const CREDENTIAL: [u8; 16] = [0xa1; 16];
const KEY: &[u8] = b"pkcs8 bytes stand-in";

fn passkey(user: &str) -> NewPasskey {
    NewPasskey {
        credential_id: CREDENTIAL.to_vec(),
        key_pkcs8: Zeroizing::new(KEY.to_vec()),
        rp_id: "example.com".to_owned(),
        rp_name: "Example".to_owned(),
        user_handle: b"handle".to_vec(),
        user_name: user.to_owned(),
        user_display_name: "Anne".to_owned(),
        discoverable: true,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saved_passkey_survives_the_server_and_a_sync() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;

    let id = vault
        .save_passkey(
            PasskeyTarget::New {
                name: "Example".to_owned(),
                username: "anne".to_owned(),
                uri: "https://example.com".to_owned(),
            },
            passkey("anne"),
        )
        .await
        .unwrap();

    // The server's copy, read by another device.
    let other = raw_session(&env, &account).await;
    let cipher = other.cipher(&id.0).await;
    let key = server_cipher_key(&cipher, &account.user_key);
    let login = cipher.login.as_ref().unwrap();
    assert_eq!(decrypt(login.username.as_deref(), &key), "anne");
    let stored = &login.extra["fido2Credentials"][0];
    let field = |name: &str| decrypt(stored[name].as_str(), &key);
    assert_eq!(field("credentialId"), credential_id_text(&CREDENTIAL));
    assert_eq!(field("rpId"), "example.com");
    assert_eq!(field("userName"), "anne");
    assert_eq!(field("counter"), "0");
    assert_eq!(field("discoverable"), "true");
    assert_eq!(field("keyAlgorithm"), "ECDSA");
    assert!(stored["creationDate"].as_str().unwrap().starts_with("20"));

    // Back from a full sync, with the key intact.
    vault.sync().await.unwrap();
    let found = vault.passkeys_for("example.com").unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].summary.id, id);
    assert_eq!(found[0].credential_id, CREDENTIAL);
    assert!(found[0].discoverable);
    assert!(vault.passkeys_for("other.example").unwrap().is_empty());
    let snapshot = vault.browser_snapshot().unwrap();
    let secret = vault
        .passkey_secret(snapshot, &id, &CREDENTIAL, "example.com")
        .unwrap();
    assert_eq!(secret.key_pkcs8.as_slice(), KEY);
    assert_eq!(secret.user_handle.as_deref(), Some(&b"handle"[..]));
    assert_eq!(secret.counter, 0);

    // An imported passkey that counts keeps its count on the server.
    vault
        .set_passkey_counter(&id, &CREDENTIAL, 7)
        .await
        .unwrap();
    let cipher = other.cipher(&id.0).await;
    let stored = &cipher.login.as_ref().unwrap().extra["fido2Credentials"][0];
    assert_eq!(decrypt(stored["counter"].as_str(), &key), "7");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_saved_into_a_login_replaces_its_passkey_and_keeps_the_rest() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let id = vault
        .save(None, support::drafts::login("Example", "anne", "s3cret"))
        .await
        .unwrap();

    vault
        .save_passkey(PasskeyTarget::Existing(id.clone()), passkey("first"))
        .await
        .unwrap();
    vault
        .save_passkey(PasskeyTarget::Existing(id.clone()), passkey("second"))
        .await
        .unwrap();

    let draft = vault.draft(&ItemId(id.0.clone())).unwrap();
    let ItemData::Login { password, .. } = &draft.data else {
        panic!("a login");
    };
    assert_eq!(password.as_str(), "s3cret");
    let found = vault.passkeys_for("example.com").unwrap();
    assert_eq!(found.len(), 1, "one passkey per login");
    assert_eq!(found[0].user_name, "second");
}
