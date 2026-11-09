//! Live sync, offline mode and sleep against the e2e Vaultwarden (scripts/e2e.sh). Scenarios
//! that take the server away use their own TCP proxy, so parallel scenarios are unaffected.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used)]

mod support;

use std::time::Duration;

use support::{
    KdfChoice, TestVault, drafts, env, names, proxy::Proxy, raw_session, register, wait_until,
};
use vk_vault::{
    BackgroundStatus, OFFLINE_MESSAGE, Timings, VaultService,
    model::{CopyField, ItemId, SessionState},
};
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread")]
async fn a_change_from_another_device_arrives_over_the_websocket() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    wait_until(|| vault.background().websocket_connected).await;
    let mut changes = vault.changes();
    changes.borrow_and_update();

    let other = raw_session(&env, &account).await;
    assert_ne!(other.device.identifier, test.device.identifier);
    let created = other.create_login(&account, "From the phone").await;

    wait_until(|| names(vault).contains(&"From the phone".to_owned())).await;
    assert!(changes.has_changed().unwrap());
    let id = ItemId(created.id.as_str().into());
    assert_eq!(
        &*vault.reveal(&id, CopyField::Password).unwrap(),
        "from-elsewhere"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_unlock_from_cache_then_recovery_without_waiting_for_the_timer() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let proxy = Proxy::start(&env.vw).await;
    let mut test = TestVault::new();
    test.login(&proxy.url(), &account).await;
    let cached = test
        .vault
        .save(None, drafts::login("Cached", "user", "cached-pass"))
        .await
        .unwrap();

    // The server goes away and the app restarts: unlock works from the cache alone.
    proxy.stop();
    test.restart();
    let vault = &test.vault;
    assert!(matches!(vault.state(), SessionState::Locked { .. }));
    vault
        .unlock_with_password(Zeroizing::new(account.password.clone()))
        .await
        .unwrap();
    assert_eq!(names(vault), ["Cached"]);
    assert_eq!(
        &*vault.reveal(&cached, CopyField::Password).unwrap(),
        "cached-pass"
    );

    wait_until(|| vault.is_offline()).await;
    assert!(*vault.offline_changes().borrow());
    let failed = vault.sync().await.unwrap_err();
    assert!(failed.is_offline(), "{failed:?}");
    let refused = vault.save(None, drafts::note("not now")).await.unwrap_err();
    assert!(refused.is_offline());
    assert!(refused.to_string().contains(OFFLINE_MESSAGE));
    assert!(vault.background().offline_probe);
    assert_eq!(
        names(vault),
        ["Cached"],
        "the cached vault stays usable read-only"
    );

    let other = raw_session(&env, &account).await;
    other.create_login(&account, "Added while offline").await;
    let syncs = vault.sync_count();

    // The probe notices the server within seconds; the 30-minute timer plays no part.
    proxy.resume().await;
    wait_until(|| !vault.is_offline()).await;
    wait_until(|| names(vault).contains(&"Added while offline".to_owned())).await;
    assert!(vault.sync_count() > syncs);
    wait_until(|| vault.background().websocket_connected).await;
    wait_until(|| !vault.background().offline_probe).await;
    vault
        .save(None, drafts::note("writes work again"))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_network_change_skips_the_probe_backoff() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let proxy = Proxy::start(&env.vw).await;
    // Nothing would retry for ten minutes on its own.
    let mut timings = Timings {
        probe_initial: Duration::from_secs(600),
        probe_max: Duration::from_secs(600),
        ..Timings::default()
    };
    timings.notifications.backoff_initial = Duration::from_secs(600);
    timings.notifications.backoff_max = Duration::from_secs(600);
    let test = TestVault::with_timings(timings);
    test.login(&proxy.url(), &account).await;
    let vault = &test.vault;
    // The websocket's first connect asks for a (debounced) sync; let it finish so no pending
    // request can bring the vault back online on its own.
    wait_until(|| vault.background().websocket_connected).await;
    wait_until(|| vault.sync_count() >= 1).await;

    proxy.stop();
    assert!(vault.sync().await.unwrap_err().is_offline());
    assert!(vault.is_offline());
    proxy.resume().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        vault.is_offline(),
        "without a trigger the probe still waits"
    );

    vault.on_network_change();
    wait_until(|| !vault.is_offline()).await;
    wait_until(|| vault.background().websocket_connected).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sleep_stops_background_work_and_wake_restores_it() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    let vault = &test.vault;
    wait_until(|| vault.background().websocket_connected).await;

    vault.on_sleep();
    assert_eq!(vault.background(), BackgroundStatus::default());
    let other = raw_session(&env, &account).await;
    other.create_login(&account, "Made during sleep").await;
    let syncs = vault.sync_count();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    vault.sync().await.unwrap();
    assert!(!names(vault).contains(&"Made during sleep".to_owned()));
    assert_eq!(vault.sync_count(), syncs, "no sync runs while asleep");

    vault.on_wake();
    let status = vault.background();
    assert!(status.sync_worker && status.websocket, "{status:?}");
    wait_until(|| names(vault).contains(&"Made during sleep".to_owned())).await;
    wait_until(|| vault.background().websocket_connected).await;
    assert!(vault.sync_count() > syncs);
}
