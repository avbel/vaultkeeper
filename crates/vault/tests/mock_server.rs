//! Vault logic against a wiremock server: login rounds, token refresh, offline mode and its
//! recovery, debounce, sleep and the log-out error collection. Server data is encrypted with
//! vk-crypto directly; the vault decrypts it independently.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

mod common;

use std::{sync::Arc, time::Duration};

use common::{
    ACCESS_1, ACCESS_2, EMAIL, Fake, PASSWORD, USER_ID, WAIT, harness, harness_with, logged_in,
    names, timings, wait_until,
};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use vk_api::{DeviceInfo, TwoFactorProvider};
use vk_crypto::{EncString, SymmetricKey};
use vk_vault::{
    BackgroundStatus, Error, LogoutErrors, MemorySecretStore, SecretStore, SecretStoreError,
    Timings, Vault, VaultConfig, VaultService,
    model::{Filter, ItemData, ItemDraft, LoginRequest, LoginStep, SessionState, TwoFactorAnswer},
};
use wiremock::{
    Mock, Request, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};
use zeroize::Zeroizing;

fn note_draft(name: &str) -> ItemDraft {
    ItemDraft {
        name: name.into(),
        notes: Zeroizing::new("body".into()),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data: ItemData::SecureNote,
        revision_date: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broken_ssh_item_is_skipped_and_the_other_keys_are_still_served() {
    let fake = Fake::start().await;
    let good = "-----BEGIN OPENSSH PRIVATE KEY-----\ngood\n-----END OPENSSH PRIVATE KEY-----\n";
    let harness = logged_in(
        &fake,
        vec![
            fake.ssh_key("broken", None),
            fake.ssh_key("good", Some(good)),
        ],
    )
    .await;
    let keys = harness.vault.ssh_keys().unwrap();
    let served: Vec<_> = keys.iter().map(|key| &*key.cipher_id.0).collect();
    assert_eq!(served, ["good"]);
    assert_eq!(keys[0].private_key.as_str(), good);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_syncs_and_decrypts_the_vault() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "GitHub", "pw")]).await;
    let vault = &harness.vault;
    assert_eq!(names(vault), ["GitHub"]);
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
    assert_eq!(
        vault.sync_count(),
        0,
        "the login's own sync is not a background sync"
    );
    let stored = harness.memory.as_ref().unwrap();
    assert_eq!(
        stored
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-1"[..])
    );
    let token_request = &fake.requests_to("/identity/connect/token").await[0];
    let form = String::from_utf8_lossy(&token_request.body);
    assert!(
        form.contains("client_id=desktop") && form.contains("scope=api+offline_access"),
        "{form}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_factor_rounds_reuse_the_derived_key_and_store_the_remember_token() {
    let fake = Fake::start().await;
    fake.server.reset().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })),
        )
        .mount(&fake.server)
        .await;
    let mut success = fake.token_body(ACCESS_1, "refresh-1");
    success["TwoFactorToken"] = json!("remember-me");
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=123456"))
        .and(body_string_contains("twoFactorProvider=1"))
        .and(body_string_contains("twoFactorRemember=1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=remember-me"))
        .and(body_string_contains("twoFactorProvider=5"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(fake.token_body(ACCESS_1, "refresh-2")),
        )
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders2": { "1": { "Email": "us***@example.com" }, "0": null }
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/two-factor/send-email-login"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&fake.server)
        .await;
    fake.mount_sync(vec![]).await;

    let harness = harness();
    let vault = &harness.vault;
    assert!(
        matches!(vault.send_email_code().await, Err(Error::LoggedOut)),
        "no login started"
    );
    let step = vault.login(fake.request(), None, None).await.unwrap();
    assert_eq!(
        step,
        LoginStep::TwoFactorRequired {
            providers: vec![TwoFactorProvider::Authenticator, TwoFactorProvider::Email],
            webauthn: None,
        }
    );
    vault.send_email_code().await.unwrap();
    let answer = TwoFactorAnswer {
        provider: TwoFactorProvider::Email,
        code: " 123456 ".into(),
        remember: true,
    };
    assert_eq!(
        vault
            .login(fake.request(), Some(answer), None)
            .await
            .unwrap(),
        LoginStep::Done
    );
    assert_eq!(
        fake.requests_to("/identity/accounts/prelogin").await.len(),
        1,
        "one KDF run for both rounds"
    );
    let memory = harness.memory.as_ref().unwrap();
    assert_eq!(
        memory.keys(),
        vec![
            format!("{USER_ID}.refresh_token"),
            format!("{USER_ID}.two_factor_remember")
        ]
    );

    // Next login on this device sends the remembered token instead of asking again.
    vault.begin_add_account();
    assert_eq!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::Done
    );
    assert_eq!(
        memory
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-2"[..])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_or_abandoned_login_keeps_no_typed_password_or_derived_key() {
    let fake = Fake::start().await;
    fake.server.reset().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })),
        )
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken="))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders2": { "1": { "Email": "us***@example.com" } }
        })))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("username=typo%40example.com"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password",
            "ErrorModel": { "Message": "Username or password is incorrect. Try again" }
        })))
        .with_priority(2)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders2": { "1": { "Email": "us***@example.com" } }
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/two-factor/send-email-login"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&fake.server)
        .await;

    let harness = harness();
    let vault = &harness.vault;
    let typo = LoginRequest {
        email: "typo@example.com".into(),
        ..fake.request()
    };
    assert!(vault.login(typo, None, None).await.is_err());
    assert!(
        matches!(vault.send_email_code().await, Err(Error::LoggedOut)),
        "a rejected password leaves no pending login"
    );

    assert!(matches!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::TwoFactorRequired { .. }
    ));
    vault.send_email_code().await.unwrap();
    vault.lock();
    assert!(
        matches!(vault.send_email_code().await, Err(Error::LoggedOut)),
        "locking abandons the second round"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn new_device_verification_round() {
    let fake = Fake::start().await;
    fake.server.reset().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })),
        )
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("newDeviceOtp=654321"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fake.token_body(ACCESS_1, "r")))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "New device verification required"
        })))
        .mount(&fake.server)
        .await;
    fake.mount_sync(vec![]).await;

    let harness = harness();
    let vault = &harness.vault;
    assert_eq!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::NewDeviceOtpRequired
    );
    let step = vault
        .login(fake.request(), None, Some("654321".into()))
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_server_switches_to_offline_and_the_probe_recovers_without_the_timer() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "Cached", "pw")]).await;
    let vault = &harness.vault;
    let mut offline = vault.offline_changes();

    fake.go_down().await;
    let error = vault.sync().await.unwrap_err();
    assert!(error.is_offline(), "{error:?}");
    assert!(vault.is_offline());
    assert!(*offline.borrow_and_update());
    assert!(vault.background().offline_probe);
    assert_eq!(names(vault), ["Cached"], "the cached vault stays readable");

    let refused = vault.save(None, note_draft("later")).await.unwrap_err();
    assert!(matches!(refused, Error::Offline), "{refused:?}");
    assert!(refused.is_offline());
    assert!(
        fake.requests_to("/api/ciphers").await.is_empty(),
        "nothing was sent"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(vault.is_offline());
    assert!(
        !fake.requests_to("/alive").await.is_empty(),
        "the probe asks /alive"
    );

    fake.come_back(vec![
        fake.login("c1", "Cached", "pw"),
        fake.login("c2", "Fresh", "pw"),
    ])
    .await;
    wait_until(|| !vault.is_offline()).await;
    wait_until(|| names(vault).contains(&"Fresh".to_owned())).await;
    assert!(!*offline.borrow_and_update());
    wait_until(|| !vault.background().offline_probe).await;
    assert_eq!(vault.sync_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_network_change_probes_at_once() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![]).await;
    let harness = harness_with(
        Timings {
            probe_initial: Duration::from_secs(3600),
            probe_max: Duration::from_secs(3600),
            ..timings()
        },
        None,
    );
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    fake.go_down().await;
    assert!(vault.sync().await.is_err());
    fake.come_back(vec![fake.login("c9", "Back", "pw")]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(vault.is_offline(), "the probe still sleeps");
    assert!(fake.requests_to("/alive").await.is_empty());

    vault.on_network_change();
    wait_until(|| !vault.is_offline()).await;
    assert_eq!(names(vault), ["Back"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_sync_requests_runs_one_sync() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = fake.requests_to("/api/sync").await.len();

    for _ in 0..20 {
        vault.request_sync();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    wait_until(|| vault.sync_count() == 1).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(fake.requests_to("/api/sync").await.len(), before + 1);
    assert_eq!(vault.sync_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_access_token_is_refreshed_once_and_the_call_retried() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&fake.server)
        .await;
    fake.mount_sync(vec![fake.login("c1", "After refresh", "pw")])
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-rotated"
        })))
        .expect(1)
        .mount(&fake.server)
        .await;

    vault.sync().await.unwrap();
    assert_eq!(names(vault), ["After refresh"]);
    let syncs = fake.requests_to("/api/sync").await;
    assert_eq!(syncs.len(), 2);
    assert_eq!(
        syncs[1]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {ACCESS_2}")
    );
    let memory = harness.memory.as_ref().unwrap();
    assert_eq!(
        memory
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-rotated"[..])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_refresh_token_means_logging_in_again() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })))
        .expect(1)
        .mount(&fake.server)
        .await;

    let error = vault.sync().await.unwrap_err();
    assert!(
        matches!(error, Error::Api(vk_api::Error::Unauthorized)),
        "{error:?}"
    );
    assert!(!vault.is_offline());
    assert!(
        harness.memory.as_ref().unwrap().keys().is_empty(),
        "the dead refresh token is gone"
    );
    let again = vault.sync().await.unwrap_err();
    assert!(
        matches!(again, Error::Api(vk_api::Error::Unauthorized)),
        "{again:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sleep_stops_syncing_until_wake() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    assert!(vault.background().sync_worker);
    vault.on_sleep();
    assert_eq!(vault.background(), BackgroundStatus::default());
    let before = fake.requests_to("/api/sync").await.len();
    vault.request_sync();
    vault.sync().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fake.requests_to("/api/sync").await.len(), before);

    vault.on_wake();
    assert!(vault.background().sync_worker && vault.background().websocket);
    wait_until(|| vault.sync_count() == 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_that_finishes_after_lock_is_discarded() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "Before", "pw")]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fake.sync_body(vec![fake.login("c2", "Late", "pw")]))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&fake.server)
        .await;

    let (result, ()) = tokio::join!(vault.sync(), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        vault.lock();
    });
    result.unwrap();
    assert!(matches!(vault.state(), SessionState::Locked { .. }));
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::Locked)
    ));
    fake.server.reset().await;
    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    assert_eq!(
        names(vault),
        ["Before"],
        "the late answer neither unlocked nor reached the cache"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_refresh_that_finishes_after_lock_is_not_kept() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&fake.server)
        .await;
    fake.mount_sync(vec![]).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-1"
                }))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&fake.server)
        .await;

    let (result, ()) = tokio::join!(vault.sync(), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        vault.lock();
    });
    result.unwrap();
    assert_eq!(fake.requests_to("/identity/connect/token").await.len(), 1);

    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    vault.sync().await.unwrap();
    assert_eq!(
        fake.requests_to("/identity/connect/token").await.len(),
        2,
        "the token that arrived after the lock was dropped, so the unlocked session refreshes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_unlock_and_user_key_unlock_use_only_the_cache() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "Cached", "pw")]).await;
    let vault = &harness.vault;
    let user_key = vault.user_key().unwrap();
    assert_eq!(*user_key, *fake.user_key.to_bytes());
    vault.lock();
    drop(fake);

    assert!(
        vault
            .verify_master_password(Zeroizing::new(PASSWORD.into()))
            .await
            .unwrap()
    );
    assert!(
        !vault
            .verify_master_password(Zeroizing::new("wrong".into()))
            .await
            .unwrap()
    );
    assert!(matches!(
        vault
            .unlock_with_password(Zeroizing::new("wrong".into()))
            .await,
        Err(Error::InvalidPassword)
    ));
    assert!(matches!(
        vault.unlock_with_user_key(Zeroizing::new(vec![1; 7])),
        Err(Error::InvalidPassword)
    ));
    vault.unlock_with_user_key(user_key).unwrap();
    assert_eq!(names(vault), ["Cached"]);
    let error = vault.sync().await.unwrap_err();
    assert!(error.is_offline(), "{error:?}");
}

struct FailingDeletes(MemorySecretStore);

impl SecretStore for FailingDeletes {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        self.0.get(key)
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        self.0.set(key, secret)
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        self.0.delete(key)
    }

    fn delete_all_for(&self, _prefix: &str) -> Result<usize, SecretStoreError> {
        Err(SecretStoreError::other("keychain locked"))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_keeps_wiping_after_a_failed_step_and_reports_it() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![fake.login("c1", "Secret", "pw")])
        .await;
    let harness = harness_with(
        timings(),
        Some(Arc::new(FailingDeletes(MemorySecretStore::new()))),
    );
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    let account_dir = harness.dir.join("accounts").join(USER_ID);
    assert!(account_dir.is_dir());

    let error = vault.logout().await.unwrap_err();
    let Error::Logout(LogoutErrors(collected)) = &error else {
        panic!("expected the collected errors, got {error:?}");
    };
    assert_eq!(collected.len(), 1);
    assert!(collected[0].to_string().contains("keychain locked"));
    assert!(!account_dir.exists(), "later steps still ran");
    assert_eq!(vault.state(), SessionState::LoggedOut);
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::LoggedOut)
    ));
    assert!(
        harness
            .secrets
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edit_from_a_cache_written_before_lossless_ciphers_syncs_first() {
    let fake = Fake::start().await;
    let mut cipher = fake.login("c1", "Passkey site", "pw");
    let passkey_key = SymmetricKey::generate();
    let passkey = json!([{
        "credentialId": EncString::encrypt(b"credential", &passkey_key).unwrap().to_string(),
        "creationDate": "2026-11-08T17:00:59.321Z",
    }]);
    cipher
        .login
        .as_mut()
        .unwrap()
        .extra
        .insert("fido2Credentials".into(), passkey.clone());
    fake.mount_sync(vec![cipher.clone()]).await;
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/c1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&cipher))
        .mount(&fake.server)
        .await;
    // Locking drops the access token; the writes after the unlock refresh it.
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-1"
        })))
        .mount(&fake.server)
        .await;
    // Only the explicit syncs run, so the count below shows which one the edit caused.
    let mut slow = timings();
    slow.sync_debounce = Duration::from_secs(600);
    let harness = harness_with(slow, None);
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    vault.lock();

    let file = harness
        .dir
        .join("accounts")
        .join(USER_ID)
        .join("vault.json");
    let mut cache: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(cache["ciphers"][0]["login"]["fido2Credentials"], passkey);
    // What an earlier version wrote: no format marker and nothing the models didn't name.
    cache.as_object_mut().unwrap().remove("cacheFormat");
    cache["ciphers"][0]["login"]
        .as_object_mut()
        .unwrap()
        .remove("fido2Credentials");
    std::fs::write(&file, serde_json::to_vec(&cache).unwrap()).unwrap();
    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();

    let syncs = fake.requests_to("/api/sync").await.len();
    let id = vk_vault::model::ItemId("c1".into());
    let mut draft = vault.draft(&id).unwrap();
    draft.name = "Renamed".into();
    vault.save(Some(id.clone()), draft.clone()).await.unwrap();
    assert_eq!(fake.requests_to("/api/sync").await.len(), syncs + 1);
    let put = &fake.requests_to("/api/ciphers/c1").await[0];
    let body: Value = serde_json::from_slice(&put.body).unwrap();
    assert_eq!(
        body["login"]["fido2Credentials"], passkey,
        "the passkey is kept"
    );

    vault.save(Some(id), draft).await.unwrap();
    assert_eq!(
        fake.requests_to("/api/sync").await.len(),
        syncs + 1,
        "a synced vault edits without another sync"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_restores_the_most_recent_account_locked() {
    let fake = Fake::start().await;
    let first = logged_in(&fake, vec![fake.login("c1", "Kept", "pw")]).await;
    let dir = first.dir.clone();
    let device = DeviceInfo {
        identifier: Uuid::new_v4(),
        name: "test".into(),
        device_type: 7,
    };
    let config = VaultConfig::new(
        dir.clone(),
        device.clone(),
        tokio::runtime::Handle::current(),
    );
    let reopened = Vault::open(config, Arc::clone(&first.secrets)).unwrap();
    assert_eq!(
        reopened.state(),
        SessionState::Locked {
            server: fake.url(),
            email: EMAIL.into()
        }
    );
    reopened
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    assert_eq!(names(&reopened), ["Kept"]);
    drop(reopened);

    // An index entry whose account files vanished is skipped instead of failing the start.
    std::fs::remove_dir_all(dir.join("accounts").join(USER_ID)).unwrap();
    let config = VaultConfig::new(dir, device, tokio::runtime::Handle::current());
    let empty = Vault::open(config, Arc::clone(&first.secrets)).unwrap();
    assert_eq!(empty.state(), SessionState::LoggedOut);
    assert_eq!(empty.accounts(), Vec::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_and_logged_out_calls_report_their_state() {
    let harness = harness();
    let vault = &harness.vault;
    assert_eq!(vault.state(), SessionState::LoggedOut);
    let id = vk_vault::model::ItemId("x".into());
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::LoggedOut)
    ));
    assert!(matches!(vault.counts(), Err(Error::LoggedOut)));
    assert!(matches!(vault.sync().await, Err(Error::LoggedOut)));
    assert!(matches!(
        vault.save(None, note_draft("n")).await,
        Err(Error::LoggedOut)
    ));
    assert!(matches!(
        vault.unlock_with_password(Zeroizing::new("p".into())).await,
        Err(Error::LoggedOut)
    ));
    assert!(matches!(vault.draft(&id), Err(Error::LoggedOut)));
    assert!(matches!(vault.logout().await, Err(Error::LoggedOut)));
    assert!(vault.ssh_keys().unwrap().is_empty());
    assert_eq!(vault.accounts(), Vec::new());
    vault.lock();
    vault.on_sleep();
    vault.on_wake();
    vault.on_network_change();
    assert_eq!(vault.background(), BackgroundStatus::default());

    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "One", "pw")]).await;
    let vault = &harness.vault;
    let id = vk_vault::model::ItemId("c1".into());
    vault.lock();
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::Locked)
    ));
    assert!(matches!(
        vault.reveal(&id, vk_vault::model::CopyField::Password),
        Err(Error::Locked)
    ));
    assert!(matches!(vault.trash(&id).await, Err(Error::Locked)));
    assert!(matches!(vault.create_folder("f").await, Err(Error::Locked)));
    assert!(matches!(vault.user_key(), Err(Error::Locked)));
    assert!(matches!(vault.folders(), Err(Error::Locked)));
    assert!(matches!(vault.counts(), Err(Error::Locked)));
    assert!(vault.ssh_keys().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_reports_the_version_and_needs_no_session() {
    let fake = Fake::start().await;
    fake.mount_status("GET", "/alive", 200).await;
    Mock::given(method("GET"))
        .and(path("/api/version"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#""1.37.5""#))
        .mount(&fake.server)
        .await;
    let harness = harness();
    assert_eq!(harness.vault.state(), SessionState::LoggedOut);

    let probe = harness.vault.probe_server(&fake.url()).await.unwrap();
    assert_eq!(probe.version.as_deref(), Some("1.37.5"));
    assert_eq!(harness.vault.state(), SessionState::LoggedOut);
    assert!(
        !harness.vault.is_offline(),
        "a probe never flips offline mode"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_keeps_a_path_prefix_and_tolerates_a_missing_version() {
    let fake = Fake::start().await;
    fake.mount_status("GET", "/vw/alive", 200).await;
    let harness = harness();
    let prefixed = fake.url().join("vw").unwrap();

    let probe = harness.vault.probe_server(&prefixed).await.unwrap();
    assert_eq!(probe.version, None, "404 on /vw/api/version");
    assert_eq!(fake.requests_to("/vw/api/version").await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_of_a_dead_or_failing_server_is_an_error() {
    let fake = Fake::start().await;
    fake.mount_status("GET", "/alive", 503).await;
    let harness = harness();
    let gateway = harness.vault.probe_server(&fake.url()).await.unwrap_err();
    assert!(gateway.is_offline(), "{gateway:?}");

    let not_vaultwarden = Fake::start().await;
    let error = harness
        .vault
        .probe_server(&not_vaultwarden.url())
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Api(vk_api::Error::Server { status: 404, .. })),
        "{error:?}"
    );
    assert!(!error.is_offline());

    let dead = Url::parse("http://127.0.0.1:9/").unwrap();
    let refused = harness.vault.probe_server(&dead).await.unwrap_err();
    assert!(refused.is_offline(), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_snapshot_does_not_survive_lock_and_unlock() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "GitHub", "pw")]).await;
    let vault = &harness.vault;
    let snapshot = vault.browser_snapshot().unwrap();
    vault.lock();
    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    let page = vk_vault::uri_match::PageUrl::new("https://example.com", "/").unwrap();
    let result = vault.browser_reveal(
        snapshot,
        &vk_vault::model::ItemId("c1".into()),
        &page,
        vk_vault::uri_match::DefaultMatch::Domain,
        true,
        vk_vault::BrowserFields {
            username: true,
            password: true,
        },
    );
    assert!(matches!(result, Err(Error::Conflict)));
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_a_draft_after_a_sync_brought_a_remote_edit_is_a_conflict() {
    let fake = Fake::start().await;
    let original = fake.login("c1", "GitHub", "pw");
    let harness = logged_in(&fake, vec![original.clone()]).await;
    let vault = &harness.vault;
    let id = vk_vault::model::ItemId("c1".into());
    let mut draft = vault.draft(&id).unwrap();
    let browser_snapshot = vault.browser_snapshot().unwrap();
    assert_eq!(
        draft.revision_date.as_deref(),
        Some(original.revision_date.as_str())
    );

    let mut remote = fake.login("c1", "GitHub (phone)", "pw");
    remote.revision_date = "2026-11-08T17:05:00.000Z".into();
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fake.sync_body(vec![remote])))
        .with_priority(1)
        .mount(&fake.server)
        .await;
    vault.sync().await.unwrap();
    assert_eq!(names(vault), ["GitHub (phone)"]);
    let page = vk_vault::uri_match::PageUrl::new("https://example.com", "/").unwrap();
    assert!(matches!(
        vault.browser_reveal(
            browser_snapshot,
            &id,
            &page,
            vk_vault::uri_match::DefaultMatch::Domain,
            true,
            vk_vault::BrowserFields {
                username: true,
                password: true
            }
        ),
        Err(Error::Conflict)
    ));

    draft.name = "GitHub (desktop)".into();
    let refused = vault.save(Some(id.clone()), draft).await.unwrap_err();
    assert!(matches!(refused, Error::Conflict), "{refused:?}");
    assert_eq!(refused.to_string(), vk_vault::CONFLICT_MESSAGE);
    assert!(
        fake.requests_to("/api/ciphers/c1").await.is_empty(),
        "nothing was sent"
    );
    assert_eq!(names(vault), ["GitHub (phone)"]);

    let fresh = vault.draft(&id).unwrap();
    assert_eq!(fresh.name, "GitHub (phone)");
    assert_eq!(
        fresh.revision_date.as_deref(),
        Some("2026-11-08T17:05:00.000Z")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_servers_out_of_date_refusal_is_a_conflict_and_asks_for_a_sync() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![fake.login("c1", "GitHub", "pw")]).await;
    let vault = &harness.vault;
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/c1"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "The client copy of this cipher is out of date. Resync the client and try again.",
            "errorModel": { "message": "The client copy of this cipher is out of date. Resync the client and try again." },
        })))
        .mount(&fake.server)
        .await;
    let syncs = fake.requests_to("/api/sync").await.len();
    let id = vk_vault::model::ItemId("c1".into());
    let mut draft = vault.draft(&id).unwrap();
    draft.name = "Renamed".into();
    let refused = vault.save(Some(id), draft).await.unwrap_err();
    assert!(matches!(refused, Error::Conflict), "{refused:?}");
    let sent = fake.requests_to("/api/ciphers/c1").await;
    let body: Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert_eq!(body["lastKnownRevisionDate"], "2026-11-08T17:00:59.321Z");
    let deadline = tokio::time::Instant::now() + WAIT;
    while fake.requests_to("/api/sync").await.len() == syncs {
        assert!(tokio::time::Instant::now() < deadline, "no sync requested");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_known_account_refuses_a_weaker_kdf_before_sending_the_hash() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    // Same KDF as cached: logging in again is fine.
    assert_eq!(
        vault.login(fake.request(), None, None).await.unwrap(),
        LoginStep::Done
    );

    // The account was created at Bitwarden's default of 600 000 PBKDF2 iterations; the server now
    // claims 5 000.
    let account = harness
        .dir
        .join("accounts")
        .join(USER_ID)
        .join("account.json");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&account).unwrap()).unwrap();
    record["kdf"]["iterations"] = json!(600_000);
    std::fs::write(&account, serde_json::to_vec(&record).unwrap()).unwrap();
    fake.server.reset().await;
    fake.mount_login().await;

    let error = vault.login(fake.request(), None, None).await.unwrap_err();
    assert!(matches!(error, Error::KdfDowngrade), "{error:?}");
    assert!(fake.requests_to("/identity/connect/token").await.is_empty());
    assert_eq!(
        fake.requests_to("/identity/accounts/prelogin").await.len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_in_flight_during_log_out_does_not_store_its_rotated_token() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-rotated"
                }))
                .set_delay(Duration::from_millis(500)),
        )
        .mount(&fake.server)
        .await;

    let sync = vault.sync();
    let log_out = async {
        let deadline = tokio::time::Instant::now() + WAIT;
        while fake.requests_to("/identity/connect/token").await.is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "no refresh started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        vault.logout().await
    };
    let (_, logged_out) = tokio::join!(sync, log_out);
    logged_out.unwrap();

    assert!(
        harness.memory.as_ref().unwrap().keys().is_empty(),
        "the rotated refresh token outlived the log out"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_attachment_upload_does_not_hold_back_a_sync() {
    let fake = Fake::start().await;
    let item = fake.login("c1", "Item", "pw");
    let harness = logged_in(&fake, vec![item.clone()]).await;
    let vault = &harness.vault;
    // Vaultwarden saves the attachment row before its data arrives, so the sync below sees it.
    let mut with_row = item;
    with_row.attachments = Some(vec![vk_api::models::Attachment {
        id: "att1".into(),
        size: Some("15".into()),
        ..vk_api::models::Attachment::default()
    }]);
    fake.server.reset().await;
    fake.mount_sync(vec![with_row]).await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/v2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachmentId": "att1",
            "url": "/ciphers/c1/attachment/att1",
            "fileUploadType": 0,
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/att1"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&fake.server)
        .await;
    let source = harness.dir.join("report.txt");
    std::fs::write(&source, b"attachment body").unwrap();

    let id = vk_vault::model::ItemId(Arc::from("c1"));
    let upload = vault.upload_attachment(&id, source);
    let sync_meanwhile = async {
        let deadline = tokio::time::Instant::now() + WAIT;
        while fake
            .requests_to("/api/ciphers/c1/attachment/v2")
            .await
            .is_empty()
        {
            assert!(tokio::time::Instant::now() < deadline, "no upload started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::timeout(Duration::from_secs(1), vault.sync()).await
    };
    let (uploaded, synced) = tokio::join!(upload, sync_meanwhile);
    synced.expect("the sync waited for the upload").unwrap();
    assert_eq!(&*uploaded.unwrap().file_name, "report.txt");
    let views = vault.attachments(&id).unwrap();
    assert_eq!(
        views.len(),
        1,
        "the synced row and the upload are one attachment"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_401_from_a_proxy_during_refresh_keeps_the_refresh_token() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, vec![]).await;
    let vault = &harness.vault;
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    fake.mount_status("POST", "/identity/connect/token", 401)
        .await;

    let error = vault.sync().await.unwrap_err();
    assert!(
        matches!(error, Error::Api(vk_api::Error::Server { status: 401, .. })),
        "{error:?}"
    );
    assert!(
        harness
            .secrets
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .is_some(),
        "only invalid_grant from the identity server deletes the refresh token"
    );
}

/// The ordinary endpoints answer within `read`; a sync or an attachment upload may take far
/// longer and must not be cut off by it.
#[tokio::test(flavor = "multi_thread")]
async fn syncs_and_uploads_outlast_the_read_timeout_of_ordinary_requests() {
    let fake = Fake::start().await;
    let mut timings = timings();
    timings.http.read = Duration::from_millis(300);
    timings.http.request = Duration::from_millis(300);
    let harness = harness_with(timings, None);
    fake.mount_sync(vec![fake.login("c1", "Item", "pw")]).await;
    harness
        .vault
        .login(fake.request(), None, None)
        .await
        .unwrap();
    let vault = &harness.vault;

    fake.server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(fake.sync_body(vec![fake.login("c1", "Item", "pw")]))
                .set_delay(Duration::from_secs(1)),
        )
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/v2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attachmentId": "att1",
            "url": "/ciphers/c1/attachment/att1",
            "fileUploadType": 0,
        })))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/ciphers/c1/attachment/att1"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(1)))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(
                    json!({ "id": "f1", "name": "x", "revisionDate": "2026-11-08T17:00:59.321Z" }),
                )
                .set_delay(Duration::from_secs(1)),
        )
        .mount(&fake.server)
        .await;

    vault.sync().await.unwrap();
    let source = harness.dir.join("slow.bin");
    std::fs::write(&source, b"attachment body").unwrap();
    let id = vk_vault::model::ItemId(Arc::from("c1"));
    vault.upload_attachment(&id, source).await.unwrap();
    // The short limits are in force for everything else.
    let error = vault.create_folder("Slow").await.unwrap_err();
    assert!(error.is_offline(), "{error:?}");
}

/// A keychain whose writes take a second once `slow` is set, like one waiting on an access prompt.
#[derive(Default)]
struct SlowSets {
    memory: MemorySecretStore,
    slow: std::sync::atomic::AtomicBool,
}

impl SecretStore for SlowSets {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        self.memory.get(key)
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        if self.slow.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
        }
        self.memory.set(key, secret)
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        self.memory.delete(key)
    }

    fn delete_all_for(&self, prefix: &str) -> Result<usize, SecretStoreError> {
        self.memory.delete_all_for(prefix)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_keychain_write_during_refresh_does_not_block_state_reads() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![]).await;
    let secrets = Arc::new(SlowSets::default());
    let harness = harness_with(timings(), Some(secrets.clone() as Arc<dyn SecretStore>));
    let vault = &harness.vault;
    vault.login(fake.request(), None, None).await.unwrap();
    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": "refresh-rotated"
        })))
        .mount(&fake.server)
        .await;
    secrets
        .slow
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // The keychain write blocks its thread, so the sync runs on its own; on this task's thread
    // the read would only run after it.
    let runtime = tokio::runtime::Handle::current();
    let (waited, state) = tokio::task::block_in_place(|| {
        std::thread::scope(|scope| {
            let sync = scope.spawn(|| runtime.block_on(vault.sync()));
            runtime.block_on(async {
                let deadline = tokio::time::Instant::now() + WAIT;
                while fake.requests_to("/identity/connect/token").await.is_empty() {
                    assert!(tokio::time::Instant::now() < deadline, "no refresh started");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                // The refresh is now inside its one-second keychain write.
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
            let started = std::time::Instant::now();
            let state = vault.state();
            let waited = started.elapsed();
            sync.join().unwrap().unwrap_err();
            (waited, state)
        })
    });

    assert!(
        waited < Duration::from_millis(300),
        "a state read waited {waited:?} for the keychain"
    );
    assert!(matches!(state, SessionState::Unlocked { .. }), "{state:?}");
    assert_eq!(
        secrets
            .get(&format!("{USER_ID}.refresh_token"))
            .unwrap()
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"refresh-rotated"[..])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_the_hub_rejects_is_refreshed_before_reconnecting() {
    let fake = Fake::start().await;
    fake.mount_sync(vec![]).await;
    Mock::given(method("GET"))
        .and(path("/notifications/hub"))
        .and(wiremock::matchers::header(
            "authorization",
            format!("Bearer {ACCESS_1}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(401))
        .mount(&fake.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600
        })))
        .mount(&fake.server)
        .await;
    let mut timings = timings();
    timings.notifications.backoff_initial = Duration::from_millis(50);
    timings.notifications.backoff_max = Duration::from_millis(200);
    let harness = harness_with(timings, None);
    harness
        .vault
        .login(fake.request(), None, None)
        .await
        .unwrap();

    let bearer = |request: &Request| {
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let seen: Vec<_> = fake
            .requests_to("/notifications/hub")
            .await
            .iter()
            .filter_map(bearer)
            .collect();
        if seen.contains(&format!("Bearer {ACCESS_2}")) {
            assert_eq!(seen[0], format!("Bearer {ACCESS_1}"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the hub only ever saw {seen:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        fake.requests_to("/identity/connect/token").await.len(),
        2,
        "the password login and one refresh"
    );
}

/// Vaultwarden's Send routes, enough for the vault: `POST /api/sends` and `PUT /api/sends/{id}`
/// store the request as the server would, and `/api/sync` lists what is stored, so the
/// confirming sync after a write keeps the Send.
struct SendServer {
    stored: Arc<std::sync::Mutex<Vec<Value>>>,
}

impl SendServer {
    async fn mount(fake: &Fake) -> Self {
        let stored = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let create = Arc::clone(&stored);
        Mock::given(method("POST"))
            .and(path("/api/sends"))
            .respond_with(move |request: &Request| {
                let mut list = create.lock().unwrap();
                let id = format!("send-{}", list.len() + 1);
                let send = stored_send(&id, request, None);
                list.push(send.clone());
                ResponseTemplate::new(200).set_body_json(send)
            })
            .mount(&fake.server)
            .await;
        let update = Arc::clone(&stored);
        Mock::given(method("PUT"))
            .and(wiremock::matchers::path_regex("^/api/sends/[^/]+$"))
            .respond_with(move |request: &Request| {
                let id = request.url.path().rsplit('/').next().unwrap().to_owned();
                let mut list = update.lock().unwrap();
                let position = list.iter().position(|send| send["id"] == id.as_str());
                let Some(position) = position else {
                    return ResponseTemplate::new(404);
                };
                let send = stored_send(&id, request, Some(&list[position]));
                list[position] = send.clone();
                ResponseTemplate::new(200).set_body_json(send)
            })
            .mount(&fake.server)
            .await;
        let sync = Arc::clone(&stored);
        let body = fake.sync_body(Vec::new());
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(move |_: &Request| {
                let mut body = body.clone();
                body["sends"] = Value::Array(sync.lock().unwrap().clone());
                ResponseTemplate::new(200).set_body_json(body)
            })
            .with_priority(1)
            .mount(&fake.server)
            .await;
        Self { stored }
    }

    fn get(&self, id: &str) -> Value {
        let list = self.stored.lock().unwrap();
        list.iter().find(|send| send["id"] == id).unwrap().clone()
    }
}

/// What Vaultwarden's `Send::to_json` returns for a create or update request.
fn stored_send(id: &str, request: &Request, before: Option<&Value>) -> Value {
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert!(body.get("emails").is_none(), "Vaultwarden refuses emails");
    let password = match (&body["password"], before) {
        (Value::Null, Some(before)) => before["password"].clone(),
        (Value::Null, None) => Value::Null,
        (Value::String(_), _) => json!("c2VydmVyLWhhc2g"),
        (other, _) => panic!("password must be a string or null, got {other}"),
    };
    json!({
        "id": id,
        "accessId": format!("access-{id}"),
        "type": body["type"],
        "name": body["name"],
        "notes": body["notes"],
        "text": body["text"],
        "file": null,
        "key": body["key"],
        "maxAccessCount": body["maxAccessCount"],
        "accessCount": before.map_or(json!(0), |before| before["accessCount"].clone()),
        "password": password,
        "disabled": body["disabled"],
        "hideEmail": body["hideEmail"],
        "revisionDate": "2026-11-08T17:00:59.321Z",
        "expirationDate": body["expirationDate"],
        "deletionDate": body["deletionDate"],
        "object": "send",
    })
}

fn send_draft(text: &str, password: Option<&str>) -> vk_vault::model::SendDraft {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    vk_vault::model::SendDraft {
        name: "Wi-Fi".into(),
        text: Zeroizing::new(text.into()),
        hidden: true,
        notes: Zeroizing::new("guests only".into()),
        deletion_date: now + 7 * 86_400,
        expiration_date: None,
        max_access_count: Some(3),
        hide_email: false,
        disabled: false,
        password: password.map(|password| Zeroizing::new(password.into())),
        has_password: false,
    }
}

/// Opens a link as a recipient's client does: the seed from the fragment, then the text.
fn open_link(link: &str, send: &Value) -> String {
    use base64::Engine as _;
    let fragment = link.rsplit('/').next().unwrap();
    let fragment_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(fragment)
        .unwrap();
    let key = vk_crypto::SendKey::from_seed(&fragment_key).unwrap();
    let text: EncString = send["text"]["text"].as_str().unwrap().parse().unwrap();
    text.decrypt_string(key.key()).unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_text_send_opens_from_its_link_and_survives_the_confirming_sync() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, Vec::new()).await;
    let server = SendServer::mount(&fake).await;
    let vault = &harness.vault;

    let summary = vault
        .save_send(None, send_draft("hunter2", Some("open sesame")))
        .await
        .unwrap();
    assert_eq!(&*summary.name, "Wi-Fi");
    assert!(summary.has_password && summary.hidden);
    let stored = server.get(&summary.id);

    let link = vault.send_link(&summary.id).unwrap();
    let prefix = format!("{}#/send/access-{}/", fake.url(), summary.id);
    assert!(link.starts_with(&prefix), "{}", link.as_str());
    assert_eq!(open_link(&link, &stored), "hunter2");

    // The owner keeps the seed wrapped by the user key; the password proof is salted with it.
    let wrapped: EncString = stored["key"].as_str().unwrap().parse().unwrap();
    let seed = wrapped.decrypt(&fake.user_key).unwrap();
    let key = vk_crypto::SendKey::from_seed(&seed).unwrap();
    let requests = fake.requests_to("/api/sends").await;
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["password"], key.password_hash("open sesame"));

    vault.sync().await.unwrap();
    let listed = vault.sends().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, summary.id);
    assert_eq!(
        vault.send_draft(&summary.id).unwrap().text.as_str(),
        "hunter2"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn editing_a_send_keeps_its_seed_so_the_shared_link_still_opens() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, Vec::new()).await;
    let server = SendServer::mount(&fake).await;
    let vault = &harness.vault;
    let summary = vault
        .save_send(None, send_draft("first", Some("pw")))
        .await
        .unwrap();
    let link = vault.send_link(&summary.id).unwrap();
    let key_before = server.get(&summary.id)["key"].clone();

    let mut draft = vault.send_draft(&summary.id).unwrap();
    assert!(draft.has_password && draft.password.is_none());
    draft.text = Zeroizing::new("second".into());
    vault
        .save_send(Some(Arc::clone(&summary.id)), draft)
        .await
        .unwrap();

    let stored = server.get(&summary.id);
    assert_eq!(stored["key"], key_before);
    assert_eq!(open_link(&link, &stored), "second");
    assert_eq!(vault.send_link(&summary.id).unwrap(), link);
    assert!(
        vault.sends().unwrap()[0].has_password,
        "a null password keeps the old one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_are_cached_for_offline_use_and_writes_wait_for_the_server() {
    let fake = Fake::start().await;
    let harness = logged_in(&fake, Vec::new()).await;
    let _server = SendServer::mount(&fake).await;
    let vault = &harness.vault;
    let summary = vault
        .save_send(None, send_draft("cached", None))
        .await
        .unwrap();
    let link = vault.send_link(&summary.id).unwrap();
    vault.lock();
    assert!(matches!(vault.sends(), Err(Error::Locked)));
    drop(fake);

    vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    assert_eq!(vault.sends().unwrap()[0].name, summary.name);
    assert_eq!(vault.send_link(&summary.id).unwrap(), link);
    assert!(vault.sync().await.unwrap_err().is_offline());
    let refused = vault.delete_send(&summary.id).await.unwrap_err();
    assert!(matches!(refused, Error::Offline), "{refused:?}");
    assert_eq!(vault.sends().unwrap().len(), 1);
}
