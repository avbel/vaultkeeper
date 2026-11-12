//! Login scenarios against the e2e Vaultwarden + Mailpit (scripts/e2e.sh).

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used)]

mod support;

use support::{
    KdfChoice, TestVault, email_factor, enable_authenticator, enable_email_two_factor,
    enable_webauthn, env, mail_count, raw_session, register, totp, unix_now, wait_for_code,
};
use vk_api::TwoFactorProvider;
use vk_vault::{
    Error, VaultService,
    model::{Filter, LoginStep, SessionState, TwoFactorAnswer},
};
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread")]
async fn login_without_two_factor_unlocks_and_caches_the_account() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    let vault = &test.vault;
    assert_eq!(vault.state(), SessionState::LoggedOut);

    test.login(&env.vw, &account).await;

    assert_eq!(
        vault.state(),
        SessionState::Unlocked {
            server: env.vw.clone(),
            email: account.email.clone()
        }
    );
    let accounts = vault.accounts();
    assert_eq!(accounts.len(), 1);
    assert!(accounts[0].active);
    assert_eq!(&*accounts[0].email, account.email);
    assert!(vault.search("", &Filter::default()).unwrap().is_empty());
    assert_eq!(vault.user_key().unwrap(), account.user_key.to_bytes());

    let user_id = vault.active_account_id().unwrap();
    let dir = test.account_dir(&user_id);
    assert!(dir.join("account.json").is_file());
    assert!(dir.join("vault.json").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("vault.json")), 0o600);
        assert_eq!(mode(&test.data_dir.join("accounts.json")), 0o600);
    }
    assert_eq!(
        test.secrets.keys(),
        vec![format!("{user_id}.refresh_token")],
        "only the refresh token is kept; the access token stays in memory"
    );

    vault.lock();
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::Locked)
    ));
    assert!(matches!(vault.user_key(), Err(Error::Locked)));
    vault
        .unlock_with_password(Zeroizing::new(account.password.clone()))
        .await
        .unwrap();
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
    vault.sync().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn argon2id_account_logs_in_and_unlocks() {
    let env = env();
    let account = register(&env, KdfChoice::Argon2id).await;
    let test = TestVault::new();
    test.login(&env.vw, &account).await;
    test.vault.lock();
    assert!(
        test.vault
            .verify_master_password(Zeroizing::new(account.password.clone()))
            .await
            .unwrap()
    );
    assert!(
        !test
            .vault
            .verify_master_password(Zeroizing::new("nope".into()))
            .await
            .unwrap()
    );
    test.vault
        .unlock_with_password(Zeroizing::new(account.password.clone()))
        .await
        .unwrap();
    assert!(matches!(test.vault.state(), SessionState::Unlocked { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_is_reported_for_login_and_unlock() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let test = TestVault::new();
    let mut request = account.login_request(&env.vw);
    request.password = Zeroizing::new("definitely wrong".into());
    let error = test.vault.login(request, None, None).await.unwrap_err();
    assert!(matches!(error, Error::InvalidPassword), "{error:?}");
    assert_eq!(test.vault.state(), SessionState::LoggedOut);
    assert_eq!(test.vault.accounts(), Vec::new());

    test.login(&env.vw, &account).await;
    test.vault.lock();
    let error = test
        .vault
        .unlock_with_password(Zeroizing::new("definitely wrong".into()))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidPassword), "{error:?}");
    assert!(matches!(test.vault.state(), SessionState::Locked { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn email_two_factor_with_a_mailed_code_and_remember_device() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let setup = raw_session(&env, &account).await;
    enable_email_two_factor(&env, &setup, &account).await;

    let test = TestVault::new();
    let vault = &test.vault;
    let step = vault
        .login(account.login_request(&env.vw), None, None)
        .await
        .unwrap();
    assert_eq!(
        step,
        LoginStep::TwoFactorRequired {
            providers: vec![TwoFactorProvider::Email],
            webauthn: None,
        }
    );

    let before = mail_count(&env, &account.email).await;
    vault.send_email_code().await.unwrap();
    let code = wait_for_code(&env, &account.email, before).await;

    let wrong = vault
        .login(
            account.login_request(&env.vw),
            Some(email_factor("000000", false)),
            None,
        )
        .await;
    assert!(wrong.is_err(), "a wrong code must not log in");

    let step = vault
        .login(
            account.login_request(&env.vw),
            Some(email_factor(&code, true)),
            None,
        )
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
    let user_id = vault.active_account_id().unwrap();
    assert!(
        test.secrets
            .keys()
            .contains(&format!("{user_id}.two_factor_remember")),
        "{:?}",
        test.secrets.keys()
    );

    // A later login on this device (e.g. after the session expired) needs no new code.
    vault.begin_add_account();
    let mails_before = mail_count(&env, &account.email).await;
    let step = vault
        .login(account.login_request(&env.vw), None, None)
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
    assert!(matches!(vault.state(), SessionState::Unlocked { .. }));
    assert_eq!(
        vault.accounts().len(),
        1,
        "the same account is reused, not duplicated"
    );
    assert_eq!(
        mail_count(&env, &account.email).await,
        mails_before,
        "no code was mailed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticator_two_factor_smoke_test() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let setup = raw_session(&env, &account).await;
    let secret = enable_authenticator(&env, &setup, &account).await;

    let test = TestVault::new();
    let step = test
        .vault
        .login(account.login_request(&env.vw), None, None)
        .await
        .unwrap();
    assert_eq!(
        step,
        LoginStep::TwoFactorRequired {
            providers: vec![TwoFactorProvider::Authenticator],
            webauthn: None,
        }
    );
    // The activation used the current step and the server rejects replays; the next step is
    // within its allowed drift.
    let answer = TwoFactorAnswer {
        provider: TwoFactorProvider::Authenticator,
        code: totp(&secret, unix_now() + 30),
        remember: false,
    };
    let step = test
        .vault
        .login(account.login_request(&env.vw), Some(answer), None)
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
    assert!(matches!(test.vault.state(), SessionState::Unlocked { .. }));
}

/// The token is built exactly as the login window builds it from a USB key's answer, so this
/// pins the wire contract with Vaultwarden's webauthn-rs: client data origin, rpId and the
/// connector's field names.
#[tokio::test(flavor = "multi_thread")]
async fn security_key_two_factor_logs_in_and_a_challenge_is_single_use() {
    let env = env();
    let account = register(&env, KdfChoice::Pbkdf2).await;
    let setup = raw_session(&env, &account).await;
    let key = enable_webauthn(&env, &setup, &account).await;

    let test = TestVault::new();
    let LoginStep::TwoFactorRequired {
        providers,
        webauthn: Some(first),
    } = test
        .vault
        .login(account.login_request(&env.vw), None, None)
        .await
        .unwrap()
    else {
        panic!("expected a security-key challenge");
    };
    assert_eq!(providers, vec![TwoFactorProvider::WebAuthn]);
    let challenge = || async {
        match test
            .vault
            .login(account.login_request(&env.vw), None, None)
            .await
            .unwrap()
        {
            LoginStep::TwoFactorRequired {
                webauthn: Some(challenge),
                ..
            } => challenge,
            other => panic!("expected a security-key challenge, got {other:?}"),
        }
    };
    let answer = |challenge: &str| TwoFactorAnswer {
        provider: TwoFactorProvider::WebAuthn,
        code: key.answer(challenge, &env.vw),
        remember: false,
    };

    // Asking again replaces the first challenge on the server.
    challenge().await;
    assert!(
        test.vault
            .login(account.login_request(&env.vw), Some(answer(&first)), None)
            .await
            .is_err(),
        "an answer to a replaced challenge is refused"
    );

    let fresh = challenge().await;
    let step = test
        .vault
        .login(account.login_request(&env.vw), Some(answer(&fresh)), None)
        .await
        .unwrap();
    assert_eq!(step, LoginStep::Done);
    assert!(matches!(test.vault.state(), SessionState::Unlocked { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_names_the_vaultwarden_release_before_any_login() {
    let env = env();
    let expected: String = env
        .http
        .get(env.vw.join("api/version").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let test = TestVault::new();
    let probe = test.vault.probe_server(&env.vw).await.unwrap();
    assert_eq!(probe.version.as_deref(), Some(expected.as_str()));
    assert_eq!(test.vault.state(), SessionState::LoggedOut);
}
