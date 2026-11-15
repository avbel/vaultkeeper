//! The sealed token store driven through the real vault: login, lock, unlock, sync, logout and
//! account switching, with the refresh token living in a file under the account directory instead
//! of a keychain.

#![allow(clippy::unwrap_used)]

mod common;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use common::{ACCESS_2, EMAIL, Fake, Harness, PASSWORD, USER_ID, harness_in, timings};
use serde_json::json;
use vk_vault::{
    BlobWrapper, Error, SealedFileStore, SecretStore, SecretStoreError, VaultService,
    model::{LoginStep, SessionState},
};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};
use zeroize::Zeroizing;

const OTHER_ID: &str = "9d1c3e2a-0000-4000-8000-000000000001";

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!("vk-sealed-life-{}", uuid::Uuid::new_v4().simple()))
}

fn sealed_harness(dir: &Path) -> (Harness, Arc<SealedFileStore>) {
    let store = Arc::new(SealedFileStore::new(dir.to_path_buf(), |path, bytes| {
        std::fs::write(path, bytes)
    }));
    let harness = harness_in(
        dir.to_path_buf(),
        slow_timings(),
        Some(Arc::clone(&store) as Arc<dyn SecretStore>),
    );
    (harness, store)
}

/// Only the test's own `sync()` calls run: an unlock schedules a debounced sync that would race
/// the mocks this test mounts afterwards.
fn slow_timings() -> vk_vault::Timings {
    let mut timings = timings();
    timings.sync_debounce = Duration::from_secs(600);
    timings
}

fn token_key(user_id: &str) -> String {
    format!("{user_id}.refresh_token")
}

fn token_path(dir: &Path, user_id: &str) -> PathBuf {
    dir.join("accounts").join(user_id).join("refresh_token.enc")
}

async fn login(harness: &Harness, fake: &Fake) {
    fake.mount_sync(Vec::new()).await;
    let step = harness
        .vault
        .login(fake.request(), None, None)
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
}

/// Replaces the server with one that accepts exactly one refresh with `refresh` and answers the
/// retried sync.
async fn expect_one_refresh(fake: &Fake, refresh: &str, rotated: &str) {
    fake.server.reset().await;
    fake.mount_sync(Vec::new()).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains(format!("refresh_token={refresh}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_2, "expires_in": 3600, "refresh_token": rotated
        })))
        .expect(1)
        .mount(&fake.server)
        .await;
}

fn stored(store: &SealedFileStore, user_id: &str) -> Option<Vec<u8>> {
    store
        .get(&token_key(user_id))
        .unwrap()
        .map(|secret| secret.to_vec())
}

#[tokio::test(flavor = "multi_thread")]
async fn login_lock_unlock_and_sync_read_the_sealed_refresh_token() {
    let fake = Fake::start().await;
    let dir = temp_dir();
    let (harness, store) = sealed_harness(&dir);
    login(&harness, &fake).await;
    let path = token_path(&dir, USER_ID);
    assert!(path.is_file(), "login writes the sealed token");
    assert_eq!(stored(&store, USER_ID).as_deref(), Some(&b"refresh-1"[..]));

    harness.vault.lock();
    assert_eq!(
        harness.vault.state(),
        SessionState::Locked {
            server: fake.url(),
            email: EMAIL.into()
        }
    );
    let locked = store
        .get(&token_key(USER_ID))
        .expect_err("key forgotten on lock");
    assert!(locked.is_locked(), "{locked:?}");

    harness
        .vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    // The lock dropped the access token, so this sync must refresh with the sealed token.
    expect_one_refresh(&fake, "refresh-1", "refresh-2").await;
    harness.vault.sync().await.unwrap();

    assert!(matches!(
        harness.vault.state(),
        SessionState::Unlocked { .. }
    ));
    assert_eq!(stored(&store, USER_ID).as_deref(), Some(&b"refresh-2"[..]));
    assert!(
        path.is_file(),
        "the rotated token is sealed back to the same file"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_removes_the_sealed_files_without_a_key() {
    let fake = Fake::start().await;
    let dir = temp_dir();
    let (harness, store) = sealed_harness(&dir);
    login(&harness, &fake).await;
    let account_dir = dir.join("accounts").join(USER_ID);
    assert!(token_path(&dir, USER_ID).is_file());

    harness.vault.logout().await.unwrap();
    assert_eq!(harness.vault.state(), SessionState::LoggedOut);
    assert!(!account_dir.exists(), "the account directory is gone");
    let forgotten = store
        .get(&token_key(USER_ID))
        .expect_err("key forgotten on log out");
    assert!(forgotten.is_locked(), "{forgotten:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn switching_accounts_keeps_each_accounts_sealed_token() {
    let first = Fake::start_as(USER_ID).await;
    let second = Fake::start_as(OTHER_ID).await;
    let dir = temp_dir();
    let (harness, store) = sealed_harness(&dir);

    login(&harness, &first).await;
    harness.vault.begin_add_account();
    login(&harness, &second).await;
    assert!(token_path(&dir, USER_ID).is_file());
    assert!(token_path(&dir, OTHER_ID).is_file());
    // Switching away forgot the first key; the file stays for the switch back.
    let forgotten = store
        .get(&token_key(USER_ID))
        .expect_err("key forgotten on switch");
    assert!(forgotten.is_locked(), "{forgotten:?}");

    harness.vault.switch_account(USER_ID).unwrap();
    harness
        .vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    expect_one_refresh(&first, "refresh-1", "refresh-first").await;
    harness.vault.sync().await.unwrap();
    assert_eq!(
        stored(&store, USER_ID).as_deref(),
        Some(&b"refresh-first"[..])
    );
    assert!(
        token_path(&dir, OTHER_ID).is_file(),
        "the other account's file is untouched"
    );

    harness.vault.switch_account(OTHER_ID).unwrap();
    harness
        .vault
        .unlock_with_password(Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    expect_one_refresh(&second, "refresh-1", "refresh-second").await;
    harness.vault.sync().await.unwrap();
    assert_eq!(
        stored(&store, OTHER_ID).as_deref(),
        Some(&b"refresh-second"[..])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_sealed_under_another_user_key_is_deleted_and_sync_asks_to_log_in_again() {
    let fake = Fake::start().await;
    let dir = temp_dir();
    let (harness, _store) = sealed_harness(&dir);
    login(&harness, &fake).await;

    // What a user key rotated on another machine leaves behind: the file opens with that key only.
    let other_key = SealedFileStore::new(dir.clone(), |path, bytes| std::fs::write(path, bytes));
    other_key.provide_key(USER_ID, &[0x99; 64]).unwrap();
    other_key
        .set(&token_key(USER_ID), b"sealed-elsewhere")
        .unwrap();

    fake.server.reset().await;
    fake.mount_status("GET", "/api/sync", 401).await;

    let error = harness.vault.sync().await.unwrap_err();
    assert!(
        matches!(error, Error::Api(vk_api::Error::Unauthorized)),
        "{error:?}"
    );
    assert!(!harness.vault.is_offline());
    assert!(
        !token_path(&dir, USER_ID).exists(),
        "the undecryptable token is deleted"
    );
}

/// Wraps like the identity but can never unwrap, like a DPAPI blob from another profile.
struct UnwrapFails;

impl BlobWrapper for UnwrapFails {
    fn wrap(&self, _user_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        Ok(plaintext.to_vec())
    }

    fn unwrap(&self, _user_id: &str, _blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
        Err(SecretStoreError::undecryptable())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_undecryptable_remember_token_is_deleted_and_login_proceeds_without_it() {
    let fake = Fake::start().await;
    let dir = temp_dir();
    let store = Arc::new(
        SealedFileStore::new(dir.clone(), |path, bytes| std::fs::write(path, bytes))
            .with_wrapper(Arc::new(UnwrapFails)),
    );
    let harness = harness_in(
        dir.clone(),
        slow_timings(),
        Some(Arc::clone(&store) as Arc<dyn SecretStore>),
    );
    login(&harness, &fake).await;

    let remember_key = format!("{USER_ID}.two_factor_remember");
    store.set(&remember_key, b"remembered").unwrap();
    let remember_path = dir
        .join("accounts")
        .join(USER_ID)
        .join("two_factor_remember.enc");
    assert!(remember_path.is_file());

    harness.vault.begin_add_account();
    fake.mount_sync(Vec::new()).await;
    let step = harness
        .vault
        .login(fake.request(), None, None)
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
    assert!(
        !remember_path.exists(),
        "the undecryptable remember token is deleted"
    );
}
