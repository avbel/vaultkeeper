//! Several accounts, switching and the log-out wipe against the e2e Vaultwarden.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used)]

mod support;

use support::{KdfChoice, TestVault, drafts, env, names, register};
use vk_vault::{
    Error, SecretStore, VaultService,
    model::{CopyField, Filter, SessionState},
};
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread")]
async fn switching_accounts_locks_and_shows_only_the_target_account() {
    let env = env();
    let alice = register(&env, KdfChoice::Pbkdf2).await;
    let bob = register(&env, KdfChoice::Argon2id).await;
    let test = TestVault::new();
    let vault = &test.vault;

    test.login(&env.vw, &alice).await;
    vault
        .save(None, drafts::login("Alice mail", "alice", "a-pass"))
        .await
        .unwrap();
    let alice_id = vault.active_account_id().unwrap();

    vault.begin_add_account();
    assert_eq!(vault.state(), SessionState::LoggedOut);
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::LoggedOut)
    ));
    test.login(&env.vw, &bob).await;
    vault.save(None, drafts::note("Bob note")).await.unwrap();
    assert_eq!(names(vault), ["Bob note"]);

    let accounts = vault.accounts();
    let emails: Vec<_> = accounts.iter().map(|a| a.email.to_string()).collect();
    assert_eq!(
        emails,
        [bob.email.clone(), alice.email.clone()],
        "most recent first"
    );
    assert!(accounts[0].active && !accounts[1].active);

    let bob_synced = vault.last_sync().expect("bob synced on login");

    vault.switch_account(&alice_id).unwrap();
    let alice_synced = vault.last_sync().expect("alice synced at her login");
    assert!(
        alice_synced < bob_synced,
        "the time shown after a switch is the active account's own"
    );
    assert_eq!(
        vault.state(),
        SessionState::Locked {
            server: env.vw.clone(),
            email: alice.email.clone()
        }
    );
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::Locked)
    ));
    assert!(vault.ssh_keys().unwrap().is_empty());
    vault
        .unlock_with_password(Zeroizing::new(alice.password.clone()))
        .await
        .unwrap();
    assert_eq!(names(vault), ["Alice mail"]);
    assert_eq!(vault.accounts()[0].id, alice_id);

    // The most recent account is the active one after a restart.
    let mut test = test;
    test.restart();
    assert_eq!(test.vault.active_account_id().as_deref(), Some(&*alice_id));
    assert!(matches!(
        test.vault.switch_account("not-an-account"),
        Err(Error::NotFound)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_wipes_everything_of_the_account() {
    let env = env();
    let alice = register(&env, KdfChoice::Pbkdf2).await;
    let bob = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    let vault = &test.vault;

    test.login(&env.vw, &alice).await;
    let login = vault
        .save(None, drafts::login("Alice bank", "alice", "a-secret"))
        .await
        .unwrap();
    vault
        .save(None, drafts::ssh("Alice deploy key"))
        .await
        .unwrap();
    vault.sync().await.unwrap();
    assert_eq!(
        &*vault.reveal(&login, CopyField::Password).unwrap(),
        "a-secret"
    );
    assert_eq!(vault.ssh_keys().unwrap().len(), 1);
    let alice_id = vault.active_account_id().unwrap();
    let alice_dir = test.account_dir(&alice_id);
    assert!(alice_dir.join("vault.json").is_file());
    // Something the app stores under the same prefix, like the Touch ID key.
    test.secrets
        .set(&format!("{alice_id}.touch_id"), b"blob")
        .unwrap();
    let mut ssh_changes = vault.ssh_key_changes();
    ssh_changes.borrow_and_update();

    vault.logout().await.unwrap();

    assert!(!alice_dir.exists(), "the account directory is gone");
    assert!(
        test.secrets
            .keys()
            .iter()
            .all(|key| !key.starts_with(&*alice_id)),
        "{:?}",
        test.secrets.keys()
    );
    assert_eq!(vault.state(), SessionState::LoggedOut);
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::LoggedOut)
    ));
    assert!(matches!(
        vault.reveal(&login, CopyField::Password),
        Err(Error::LoggedOut)
    ));
    assert!(vault.ssh_keys().unwrap().is_empty());
    assert!(
        ssh_changes.has_changed().unwrap(),
        "the agent is told to drop the keys"
    );
    assert_eq!(vault.accounts(), Vec::new());
    assert_eq!(vault.background(), vk_vault::BackgroundStatus::default());
    assert!(matches!(vault.logout().await, Err(Error::LoggedOut)));

    test.login(&env.vw, &bob).await;
    vault.save(None, drafts::note("Bob only")).await.unwrap();
    assert_eq!(names(vault), ["Bob only"]);
    assert!(
        vault
            .search("alice", &Filter::default())
            .unwrap()
            .is_empty()
    );
    assert_eq!(vault.accounts().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_activates_the_most_recent_remaining_account() {
    let env = env();
    let alice = register(&env, KdfChoice::Pbkdf2).await;
    let bob = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    let vault = &test.vault;
    test.login(&env.vw, &alice).await;
    vault.begin_add_account();
    test.login(&env.vw, &bob).await;

    vault.logout().await.unwrap();
    assert_eq!(
        vault.state(),
        SessionState::Locked {
            server: env.vw.clone(),
            email: alice.email.clone()
        }
    );
    assert_eq!(vault.accounts().len(), 1);
    vault
        .unlock_with_password(Zeroizing::new(alice.password.clone()))
        .await
        .unwrap();
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
}
