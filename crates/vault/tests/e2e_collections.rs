//! Moving items into an organization and between its collections, against the e2e Vaultwarden
//! (scripts/e2e.sh). The harness decrypts what reached the server with the org key itself.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

mod support;

use std::sync::Arc;

use serde_json::json;
use support::{
    KdfChoice, TestVault, create_org, decrypt, drafts, enc, env, org_key, raw_session, register,
    server_cipher_key,
};
use vk_api::models::{CipherRequest, Login};
use vk_vault::{
    VaultService,
    model::{CopyField, ItemId},
};

#[tokio::test(flavor = "multi_thread")]
async fn personal_items_move_into_an_organization_and_between_its_collections() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let server = raw_session(&env, &account).await;
    let (org_id, shared) = create_org(&env, &server, &account.email).await;
    let org = org_key();
    let second = server
        .api(
            &env,
            reqwest::Method::POST,
            &format!("api/organizations/{org_id}/collections"),
            json!({ "name": enc("Second", &org), "groups": [], "users": [] }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // An item from before per-item keys: every field under the user key.
    let legacy = server
        .client
        .create_cipher(
            &server.token,
            &CipherRequest {
                r#type: 1,
                name: enc("Legacy router", &account.user_key),
                login: Some(Login {
                    username: Some(enc("admin", &account.user_key)),
                    password: Some(enc("legacy-pass", &account.user_key)),
                    ..Login::default()
                }),
                ..CipherRequest::default()
            },
            &[],
        )
        .await
        .unwrap();

    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let keyed = vault
        .save(None, drafts::login("Team wiki", "team", "wiki-pass"))
        .await
        .unwrap();
    let legacy = ItemId(legacy.id.as_str().into());
    let org_ref: Arc<str> = org_id.as_str().into();

    assert!(
        vault
            .assign_collections(&keyed, &org_id, Vec::new())
            .await
            .is_err(),
        "a move needs a collection"
    );
    assert!(
        vault
            .assign_collections(&keyed, "not-an-org", vec![shared.as_str().into()])
            .await
            .is_err(),
        "only organizations the user is in"
    );

    for (id, name, password) in [
        (&keyed, "Team wiki", "wiki-pass"),
        (&legacy, "Legacy router", "legacy-pass"),
    ] {
        vault
            .assign_collections(id, &org_id, vec![shared.as_str().into()])
            .await
            .unwrap();
        let stored = server.cipher(&id.0).await;
        assert_eq!(stored.organization_id.as_deref(), Some(org_id.as_str()));
        assert_eq!(stored.collection_ids, vec![shared.clone()]);
        let key = server_cipher_key(&stored, &org);
        assert_eq!(decrypt(stored.name.as_deref(), &key), name, "{name}");
        assert_eq!(
            decrypt(stored.login.as_ref().unwrap().password.as_deref(), &key),
            password,
            "{name}"
        );
        let draft = vault.draft(id).unwrap();
        assert_eq!(draft.organization_id.as_ref(), Some(&org_ref));
        assert_eq!(
            draft.collection_ids,
            vec![Arc::<str>::from(shared.as_str())]
        );
        assert_eq!(&*vault.reveal(id, CopyField::Password).unwrap(), password);
    }

    vault.sync().await.unwrap();
    vault
        .assign_collections(
            &keyed,
            &org_id,
            vec![second.as_str().into(), shared.as_str().into()],
        )
        .await
        .unwrap();
    let mut both = server.cipher(&keyed.0).await.collection_ids;
    both.sort();
    let mut expected = vec![shared.clone(), second.clone()];
    expected.sort();
    assert_eq!(both, expected);

    vault
        .assign_collections(&keyed, &org_id, vec![second.as_str().into()])
        .await
        .unwrap();
    assert_eq!(
        server.cipher(&keyed.0).await.collection_ids,
        vec![second.clone()]
    );
    assert_eq!(
        vault.draft(&keyed).unwrap().collection_ids,
        vec![Arc::<str>::from(second.as_str())]
    );
}
