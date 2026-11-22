use super::*;

fn test_vault() -> (super::super::Vault, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("vk-pending-{}", uuid::Uuid::new_v4()));
    let config = crate::VaultConfig::new(
        dir.clone(),
        vk_api::DeviceInfo {
            identifier: uuid::Uuid::new_v4(),
            name: "test".into(),
            device_type: 7,
        },
        tokio::runtime::Handle::current(),
    );
    let vault =
        super::super::Vault::open(config, Arc::new(crate::MemorySecretStore::new())).unwrap();
    (vault, dir)
}

fn pending_login() -> Arc<PendingLogin> {
    let kdf = KdfRecord {
        kind: 0,
        iterations: 5000,
        memory_mib: None,
        parallelism: None,
    };
    let server = Url::parse("https://example.com").unwrap();
    let client = Client::with_timeouts(
        server.clone(),
        vk_api::DeviceInfo {
            identifier: uuid::Uuid::new_v4(),
            name: "test".into(),
            device_type: 7,
        },
        vk_api::HttpTimeouts::default(),
    )
    .unwrap();
    Arc::new(PendingLogin {
        server,
        email: "a@example.com".into(),
        password: Zeroizing::new("password".into()),
        hash: Zeroizing::new("hash".into()),
        master_key: MasterKey::derive(b"password", "a@example.com", &kdf.to_kdf().unwrap())
            .unwrap(),
        kdf,
        client: Arc::new(client),
        created: Instant::now(),
    })
}

#[tokio::test]
async fn an_abandoned_second_round_is_wiped_when_its_ttl_runs_out() {
    let ttl = Duration::from_millis(50);
    let (vault, dir) = test_vault();
    let inner = &vault.inner;
    let abandoned = pending_login();
    let watch = Arc::downgrade(&abandoned);
    inner.remember_pending(abandoned, ttl);
    tokio::time::sleep(ttl * 4).await;
    assert!(lock(&inner.pending).is_none());
    assert!(
        watch.upgrade().is_none(),
        "nothing else keeps the key alive"
    );

    let older = pending_login();
    inner.remember_pending(older, ttl);
    tokio::time::sleep(ttl / 2).await;
    let newer = pending_login();
    let newer_ptr = Arc::as_ptr(&newer);
    inner.remember_pending(newer, ttl * 20);
    tokio::time::sleep(ttl * 2).await;
    assert!(
        lock(&inner.pending)
            .as_ref()
            .is_some_and(|login| std::ptr::eq(Arc::as_ptr(login), newer_ptr)),
        "the older timer leaves a newer login alone"
    );
    drop(vault);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn hostile_expires_in_is_clamped_instead_of_overflowing() {
    let now = Instant::now();
    for expires_in in [u64::MAX, u64::MAX / 2, 1 << 40] {
        let at = token_expiry(expires_in);
        assert!(at <= now + MAX_TOKEN_LIFETIME + Duration::from_secs(1));
        assert!(at > now);
    }
    let short = token_expiry(60);
    assert!(short < now + Duration::from_secs(61));
}

#[test]
fn wrong_password_message_maps_to_invalid_password() {
    let wrong = vk_api::Error::Server {
        status: 400,
        message: "Username or password is incorrect. Try again".into(),
    };
    assert!(matches!(login_error(wrong), Error::InvalidPassword));
    let other = vk_api::Error::Server {
        status: 400,
        message: "Invalid TOTP code!".into(),
    };
    assert!(matches!(login_error(other), Error::Api(_)));
    assert!(matches!(
        login_error(vk_api::Error::Unauthorized),
        Error::Api(vk_api::Error::Unauthorized)
    ));
}
