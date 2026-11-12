//! Text Sends against the e2e Vaultwarden (scripts/e2e.sh). What reached the server is read
//! back through a second session and opened from the link alone, as a recipient would.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use support::{KdfChoice, TestVault, env, raw_session, register, unix_now};
use vk_api::models::SendItem;
use vk_crypto::{EncString, SendKey};
use vk_vault::{VaultService, model::SendDraft};
use zeroize::Zeroizing;

fn draft(text: &str) -> SendDraft {
    let now = i64::try_from(unix_now()).unwrap();
    SendDraft {
        name: "Door code".into(),
        text: Zeroizing::new(text.into()),
        hidden: true,
        notes: Zeroizing::new("for the plumber".into()),
        deletion_date: now + 3 * 86_400,
        expiration_date: None,
        max_access_count: Some(2),
        hide_email: true,
        disabled: false,
        password: Some(Zeroizing::new("open sesame".into())),
        has_password: false,
    }
}

/// The recipient's side: only the link's fragment and the server's copy.
fn open(link: &str, send: &SendItem) -> String {
    let fragment_key = URL_SAFE_NO_PAD
        .decode(link.rsplit('/').next().unwrap())
        .unwrap();
    let key = SendKey::from_seed(&fragment_key).unwrap();
    let text: EncString = send
        .text
        .as_ref()
        .and_then(|text| text.text.as_deref())
        .unwrap()
        .parse()
        .unwrap();
    text.decrypt_string(key.key()).unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_text_send_round_trips_and_its_link_opens_it() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    let server = raw_session(&env, &account).await;
    let stored = |id: Arc<str>| {
        let server = &server;
        async move {
            server
                .client
                .sync(&server.token)
                .await
                .unwrap()
                .sends
                .into_iter()
                .find(|send| send.id == *id)
        }
    };

    let created = vault.save_send(None, draft("4711")).await.unwrap();
    assert!(created.has_password && created.hide_email);
    assert_eq!(created.max_access_count, Some(2));
    let link = vault.send_link(&created.id).unwrap();
    let on_server = stored(Arc::clone(&created.id))
        .await
        .expect("on the server");
    assert!(link.starts_with(env.vw.as_str().trim_end_matches('/')));
    assert!(link.contains(&format!("/#/send/{}/", on_server.access_id)));
    assert_eq!(open(&link, &on_server), "4711");

    let mut edit = vault.send_draft(&created.id).unwrap();
    assert_eq!(edit.notes.as_str(), "for the plumber");
    assert!(edit.has_password);
    edit.text = Zeroizing::new("0815".into());
    vault
        .save_send(Some(Arc::clone(&created.id)), edit)
        .await
        .unwrap();
    let edited = stored(Arc::clone(&created.id)).await.unwrap();
    assert_eq!(
        edited.key, on_server.key,
        "the seed, and so the link, stays"
    );
    assert!(
        edited.password.is_some(),
        "a null password keeps the old one"
    );
    assert_eq!(open(&link, &edited), "0815");

    vault.remove_send_password(&created.id).await.unwrap();
    assert!(
        stored(Arc::clone(&created.id))
            .await
            .unwrap()
            .password
            .is_none()
    );
    vault.sync().await.unwrap();
    assert!(!vault.sends().unwrap()[0].has_password);

    vault.delete_send(&created.id).await.unwrap();
    assert!(stored(Arc::clone(&created.id)).await.is_none());
    vault.sync().await.unwrap();
    assert_eq!(vault.sends().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deletion_date_beyond_31_days_is_refused_and_nothing_is_stored() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let mut far = draft("x");
    far.deletion_date += 40 * 86_400;
    assert!(test.vault.save_send(None, far).await.is_err());
    assert_eq!(test.vault.sends().unwrap().len(), 0);
}
