//! Every `VaultService` method through `RemoteVault` against the fake, and every `Call` variant
//! that `RemoteVault` serves from its cache, sent by hand.

mod common;

use std::{path::PathBuf, sync::Arc};

use bwl_ipc::{
    ServeOptions, TouchIdBackend, TouchIdFailure,
    dto::{AccountDto, FolderDto, SessionStateDto, WireError},
    protocol::{Call, DaemonMessage, Event, Reply, UiMessage},
};
use bwl_vault::{
    Error, TotpCode, TwoFactorProvider, VaultService,
    model::{
        CopyField, Filter, ItemData, ItemId, LoginRequest, LoginStep, SessionState, TwoFactorAnswer,
    },
};
use common::{
    Daemon, EMAIL, FakeTouchId, FakeVault, OTHER_EMAIL, OTHER_SERVER, PASSWORD, RawClient, SERVER,
    USER_KEY, accounts, attachment, collections, draft, folders, locked, organizations, secret,
    unlocked, url,
};
use zeroize::Zeroizing;

fn id(text: &str) -> ItemId {
    ItemId(text.into())
}

async fn unlocked_pair() -> (Daemon, bwl_ipc::RemoteVault) {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 20)).await;
    let (vault, _events) = daemon.connect().await;
    (daemon, vault)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_rounds_carry_every_argument_and_step() {
    let daemon = Daemon::start(FakeVault::new(SessionState::LoggedOut, 0)).await;
    let (vault, _events) = daemon.connect().await;
    let request = || LoginRequest {
        server: url(SERVER),
        email: EMAIL.to_owned(),
        password: secret(PASSWORD),
    };
    let step = vault
        .login(request(), None, None)
        .await
        .expect("first round");
    assert_eq!(
        step,
        LoginStep::TwoFactorRequired(vec![
            TwoFactorProvider::Authenticator,
            TwoFactorProvider::Email
        ])
    );
    let answer = TwoFactorAnswer {
        provider: TwoFactorProvider::Email,
        code: "123456".to_owned(),
        remember: true,
    };
    let step = vault
        .login(request(), Some(answer), None)
        .await
        .expect("2fa");
    assert_eq!(step, LoginStep::NewDeviceOtpRequired);
    let step = vault
        .login(request(), None, Some("987654".to_owned()))
        .await
        .expect("otp");
    assert_eq!(step, LoginStep::Done);
    assert_eq!(vault.state(), unlocked());
    assert_eq!(
        daemon.fake.log(),
        [
            format!("login {SERVER} {EMAIL} {PASSWORD} 2fa=none otp=none"),
            format!("login {SERVER} {EMAIL} {PASSWORD} 2fa=1:123456:true otp=none"),
            format!("login {SERVER} {EMAIL} {PASSWORD} 2fa=none otp=987654"),
        ]
    );
    vault.send_email_code().await.expect("email code");
    assert_eq!(
        daemon.fake.log().last().map(String::as_str),
        Some("send_email_code")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlock_lock_and_account_calls_update_the_cache_before_returning() {
    let touch_id = Arc::new(FakeTouchId::default());
    let options = ServeOptions::new()
        .expect("options")
        .with_touch_id(Arc::clone(&touch_id) as Arc<dyn TouchIdBackend>);
    let daemon = Daemon::start_with(FakeVault::new(locked(), 0), options).await;
    let (vault, _events) = daemon.connect().await;
    assert_eq!(vault.state(), locked());
    assert!(matches!(vault.folders(), Err(Error::Locked)));

    let wrong = vault.unlock_with_password(secret("nope")).await;
    assert!(matches!(wrong, Err(Error::InvalidPassword)), "{wrong:?}");
    vault
        .unlock_with_password(secret(PASSWORD))
        .await
        .expect("unlock");
    assert_eq!(vault.state(), unlocked());
    assert_eq!(vault.folders().expect("folders"), folders());
    assert_eq!(vault.organizations().expect("orgs"), organizations());
    assert_eq!(vault.collections().expect("collections"), collections());

    vault.lock();
    assert_eq!(vault.state(), locked());
    assert!(matches!(vault.collections(), Err(Error::Locked)));

    // Key material never crosses the socket: these fail in the client and reach no daemon.
    let refused = vault.unlock_with_user_key(Zeroizing::new(USER_KEY.to_vec()));
    assert!(bwl_ipc::ipc_error(&refused.expect_err("no key unlock")).is_some());
    assert!(bwl_ipc::ipc_error(&vault.user_key().expect_err("no user key")).is_some());

    // Touch ID runs in the daemon: it reads the key from its own vault and seals it.
    assert!(matches!(
        vault.enroll_touch_id("user-1"),
        Err(Error::Locked)
    ));
    assert_eq!(
        vault.unlock_with_touch_id("user-1").expect("call"),
        Err(TouchIdFailure::Unavailable),
        "nothing enrolled yet"
    );
    vault
        .unlock_with_password(secret(PASSWORD))
        .await
        .expect("unlock");
    assert_eq!(
        vault.enroll_touch_id("user-2").expect("call"),
        Err(TouchIdFailure::AccountChanged),
        "only the active account can be enrolled"
    );
    assert_eq!(vault.enroll_touch_id("user-1").expect("call"), Ok(()));
    assert_eq!(
        touch_id.sealed(),
        Some(("user-1".to_owned(), USER_KEY.to_vec()))
    );
    vault.lock();
    touch_id.refuse(Some(TouchIdFailure::Cancelled));
    assert_eq!(
        vault.unlock_with_touch_id("user-1").expect("call"),
        Err(TouchIdFailure::Cancelled)
    );
    assert_eq!(vault.state(), locked());
    touch_id.refuse(None);
    assert_eq!(vault.unlock_with_touch_id("user-1").expect("call"), Ok(()));
    assert_eq!(
        vault.state(),
        unlocked(),
        "cache refreshed before the answer"
    );
    assert_eq!(touch_id.unlocks(), ["user-1", "user-1", "user-1"]);

    assert_eq!(vault.accounts(), accounts());
    assert!(matches!(
        vault.switch_account("nobody"),
        Err(Error::NotFound)
    ));
    vault.switch_account("user-2").expect("switch");
    assert_eq!(
        vault.state(),
        SessionState::Locked {
            server: url(OTHER_SERVER),
            email: OTHER_EMAIL.to_owned(),
        }
    );
    assert!(matches!(
        vault.enroll_touch_id("user-1"),
        Err(Error::Locked)
    ));

    // The fake does not bump its counter here; the cache must still follow.
    vault.begin_add_account();
    assert_eq!(vault.state(), SessionState::LoggedOut);

    daemon.fake.set_state(unlocked());
    vault.logout().await.expect("logout");
    assert_eq!(vault.state(), SessionState::LoggedOut);
    assert_eq!(
        daemon.fake.log(),
        [
            "unlock_with_password nope",
            format!("unlock_with_password {PASSWORD}").as_str(),
            "lock",
            format!("unlock_with_password {PASSWORD}").as_str(),
            "lock",
            "unlock_with_user_key 64 bytes",
            "switch_account nobody",
            "switch_account user-2",
            "begin_add_account",
            "logout",
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn master_password_check_and_sync() {
    let (daemon, vault) = unlocked_pair().await;
    assert!(
        vault
            .verify_master_password(secret(PASSWORD))
            .await
            .expect("verify")
    );
    assert!(
        !vault
            .verify_master_password(secret("x"))
            .await
            .expect("verify")
    );
    vault.sync().await.expect("sync");
    assert_eq!(
        vault.last_sync(),
        Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(common::LAST_SYNC_UNIX))
    );
    daemon.fake.set_offline(true);
    // The fake fails with a real reqwest transport error, which cannot cross the socket as is.
    let error = vault.sync().await.expect_err("offline");
    assert!(matches!(error, bwl_vault::Error::Offline), "{error:?}");
    assert!(error.is_offline());
    assert!(vault.is_offline());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_probe_round_trips_in_any_state() {
    let daemon = Daemon::start(FakeVault::new(bwl_vault::model::SessionState::LoggedOut, 0)).await;
    let (vault, _events) = daemon.connect().await;
    let server = common::url("https://vw.lan:8443/vw");
    let probe = vault.probe_server(&server).await.expect("probe");
    assert_eq!(probe.version.as_deref(), Some(common::PROBE_VERSION));
    assert!(
        daemon
            .fake
            .log()
            .contains(&"probe_server https://vw.lan:8443/vw".to_owned()),
        "{:?}",
        daemon.fake.log()
    );
    daemon.fake.set_offline(true);
    let error = vault.probe_server(&server).await.expect_err("unreachable");
    assert!(error.is_offline(), "{error:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_reveal_totp_and_draft_round_trip() {
    let (daemon, vault) = unlocked_pair().await;
    let all = vault.search("", &Filter::default()).expect("search");
    assert_eq!(all.len(), 20);
    assert_eq!(all[0], common::items(20)[0]);
    let one = vault
        .search("ITEM 013", &Filter::default())
        .expect("search");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].id, id("item-013"));
    assert_eq!(one[0].kind, bwl_vault::model::ItemKind::Login);
    let favorites = Filter {
        favorites_only: true,
        ..Filter::default()
    };
    let ids: Vec<_> = vault
        .search("", &favorites)
        .expect("search")
        .iter()
        .map(|item| item.id.0.to_string())
        .collect();
    assert_eq!(ids, ["item-000", "item-010"]);

    let password = vault
        .reveal(&id("item-001"), CopyField::Password)
        .expect("reveal");
    assert_eq!(password.as_str(), "item-001/Password");
    let custom = vault
        .reveal(&id("item-001"), CopyField::Custom(2))
        .expect("reveal");
    assert_eq!(custom.as_str(), "item-001/Custom(2)");
    assert!(matches!(
        vault.reveal(&id("missing"), CopyField::Username),
        Err(Error::NotFound)
    ));

    // 1_700_000_005 = 56_666_666 * 30 + 25, so 5 s of the 30 s step are left.
    let code = vault.totp(&id("item-003"), 1_700_000_005).expect("totp");
    assert_eq!(
        code,
        TotpCode {
            code: secret("287082"),
            period: 30,
            remaining: 5,
        }
    );
    let error = vault.totp(&id("bad-totp"), 0).expect_err("bad secret");
    assert_eq!(
        error.to_string(),
        "invalid TOTP secret or URI: secret is not valid base32"
    );

    assert!(vault.draft(&id("item-001")).expect("draft") == draft());
    assert_eq!(daemon.fake.log(), ["draft item-001"]);

    daemon.fake.set_state(locked());
    assert!(matches!(
        vault.search("", &Filter::default()),
        Err(Error::Locked)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writes_attachments_folders_and_ssh_keys_round_trip() {
    let (daemon, vault) = unlocked_pair().await;
    let saved = vault
        .save(Some(id("item-001")), draft())
        .await
        .expect("save");
    assert_eq!(saved, id("item-001"));
    let created = vault.save(None, draft()).await.expect("create");
    assert_eq!(created, id("item-new"));

    assert_eq!(
        vault.attachments(&id("item-001")).expect("list"),
        [attachment()]
    );
    vault
        .download_attachment(&id("item-001"), "a1", PathBuf::from("/tmp/out/ré port.pdf"))
        .await
        .expect("download");
    let uploaded = vault
        .upload_attachment(&id("item-001"), PathBuf::from("/tmp/in/scan.png"))
        .await
        .expect("upload");
    assert_eq!(uploaded.id.as_ref(), "a2");
    assert_eq!(uploaded.file_name.as_ref(), "scan.png");
    assert_eq!(uploaded.size_bytes, 42);
    vault
        .delete_attachment(&id("item-001"), "a1")
        .await
        .expect("delete attachment");

    vault
        .assign_collections(&id("item-002"), "org-1", vec!["c1".into(), "c2".into()])
        .await
        .expect("assign collections");
    vault.trash(&id("item-002")).await.expect("trash");
    vault.restore(&id("item-002")).await.expect("restore");
    let refused = vault.delete_permanently(&id("item-002")).await;
    assert!(matches!(refused, Err(Error::ReadOnly)), "{refused:?}");

    let folder = vault.create_folder("Taxes").await.expect("create folder");
    assert_eq!((folder.id.as_ref(), folder.name.as_ref()), ("f3", "Taxes"));
    vault.rename_folder("f3", "Tax 2026").await.expect("rename");
    vault.delete_folder("f3").await.expect("delete folder");

    let Err(refused) = vault.ssh_keys() else {
        panic!("SSH keys stay in the daemon");
    };
    assert!(
        bwl_ipc::ipc_error(&refused).is_some(),
        "the client never asks the daemon for private keys"
    );

    assert_eq!(
        daemon.fake.log(),
        [
            "save item-001 Bank hunter2 fields=1",
            "save new Bank hunter2 fields=1",
            "attachments item-001",
            "download item-001 a1 /tmp/out/ré port.pdf",
            "upload item-001 /tmp/in/scan.png",
            "delete_attachment item-001 a1",
            "assign_collections item-002 org-1 c1,c2",
            "trash item-002",
            "restore item-002",
            "delete_permanently item-002",
            "create_folder Taxes",
            "rename_folder f3 Tax 2026",
            "delete_folder f3",
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_watch_starts_at_the_daemon_revision_and_follows_it() {
    let fake = FakeVault::new(locked(), 0);
    fake.set_state(locked());
    fake.set_state(locked());
    let daemon = Daemon::start(Arc::clone(&fake)).await;
    let (vault, _events) = daemon.connect().await;
    let mut changes = vault.changes();
    assert_eq!(*changes.borrow(), 2);
    fake.set_state(unlocked());
    changes.changed().await.expect("changed");
    assert_eq!(*changes.borrow_and_update(), 3);
    assert_eq!(vault.state(), unlocked(), "cache refreshed before the bump");
}

/// `RemoteVault` answers these from its cache; check the daemon still serves each `Call`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_backed_calls_are_served_by_the_daemon() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), 0)).await;
    let mut raw = RawClient::connect(&daemon.socket());
    let welcome = raw.hello();
    assert_eq!(welcome.snapshot.state, SessionStateDto::from(unlocked()));
    let calls = [
        Call::State,
        Call::Changes,
        Call::Accounts,
        Call::IsOffline,
        Call::Folders,
        Call::Organizations,
        Call::Collections,
    ];
    for (id, call) in (1..).zip(calls) {
        raw.send(&UiMessage::Request { id, call });
    }
    let mut replies = Vec::new();
    while replies.len() < 7 {
        match raw.recv().expect("reply") {
            DaemonMessage::Response { id, result } => replies.push((id, result)),
            DaemonMessage::Event(Event::Snapshot(_) | Event::Changed(_)) => {}
            _ => panic!("unexpected message"),
        }
    }
    replies.sort_by_key(|(id, _)| *id);
    let mut replies = replies.into_iter().map(|(_, result)| result);
    let mut next = || replies.next().expect("reply").expect("success");
    assert!(matches!(next(), Reply::State(state) if state == SessionStateDto::from(unlocked())));
    assert!(matches!(next(), Reply::Revision(0)));
    let expected_accounts: Vec<AccountDto> = accounts().into_iter().map(Into::into).collect();
    assert!(matches!(next(), Reply::Accounts(list) if list == expected_accounts));
    assert!(matches!(next(), Reply::Bool(false)));
    let expected_folders: Vec<FolderDto> = folders().into_iter().map(Into::into).collect();
    assert!(matches!(next(), Reply::Folders(list) if list == expected_folders));
    assert!(matches!(next(), Reply::Organizations(list) if list.len() == 1));
    assert!(matches!(next(), Reply::Collections(list) if list.len() == 1 && list[0].read_only));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_that_do_not_map_onto_the_model_get_an_error_reply() {
    let daemon = Daemon::start(FakeVault::new(SessionState::LoggedOut, 0)).await;
    let mut raw = RawClient::connect(&daemon.socket());
    raw.hello();
    raw.send(&UiMessage::Request {
        id: 5,
        call: Call::Login {
            request: bwl_ipc::dto::LoginRequestDto {
                server: "vault.example.com".to_owned(),
                email: EMAIL.to_owned(),
                password: secret(PASSWORD),
            },
            two_factor: None,
            new_device_otp: None,
        },
    });
    loop {
        match raw.recv().expect("reply") {
            DaemonMessage::Response { id: 5, result } => {
                let Err(WireError::Api(api)) = result else {
                    panic!("expected an API error");
                };
                let error = Error::Api(api.into());
                assert!(matches!(error, Error::Api(bwl_api::Error::Url(_))));
                break;
            }
            DaemonMessage::Event(_) => {}
            _ => panic!("unexpected message"),
        }
    }
    assert_eq!(
        daemon.fake.log(),
        Vec::<String>::new(),
        "the service was not called"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secure_note_save_crosses_the_socket() {
    let (daemon, vault) = unlocked_pair().await;
    let mut note = draft();
    note.data = ItemData::SecureNote;
    vault.save(None, note).await.expect("save note");
    assert_eq!(daemon.fake.log(), ["save new Bank  fields=1"]);
}

#[derive(Default)]
struct FakeClipboard {
    log: std::sync::Mutex<Vec<String>>,
}

impl FakeClipboard {
    fn log(&self) -> Vec<String> {
        self.log.lock().expect("log").clone()
    }
}

impl bwl_ipc::ClipboardHost for FakeClipboard {
    fn copy(
        &self,
        text: &str,
        clear_after: Option<std::time::Duration>,
    ) -> std::result::Result<(), String> {
        if text == "refused" {
            return Err("pasteboard refused".to_owned());
        }
        self.log
            .lock()
            .expect("log")
            .push(format!("copy {text} {clear_after:?}"));
        Ok(())
    }

    fn clear_if_ours(&self) {
        self.log.lock().expect("log").push("clear".to_owned());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copies_and_clears_run_in_the_daemon_clipboard() {
    let clipboard = Arc::new(FakeClipboard::default());
    let options = ServeOptions::new()
        .expect("options")
        .with_clipboard(Arc::clone(&clipboard) as Arc<dyn bwl_ipc::ClipboardHost>);
    let daemon = Daemon::start_with(FakeVault::new(locked(), 0), options).await;
    let (vault, _events) = daemon.connect().await;
    vault
        .copy_to_clipboard("hunter2", Some(std::time::Duration::from_secs(30)))
        .expect("copy");
    vault.copy_to_clipboard("kept", None).expect("copy");
    vault.clear_clipboard().expect("clear");
    assert_eq!(
        clipboard.log(),
        ["copy hunter2 Some(30s)", "copy kept None", "clear"]
    );
    let refused = vault
        .copy_to_clipboard("refused", None)
        .expect_err("the daemon's error comes back");
    assert!(
        refused.to_string().contains("pasteboard refused"),
        "{refused}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_without_a_clipboard_refuses_copies() {
    let (_daemon, vault) = unlocked_pair().await;
    assert!(vault.copy_to_clipboard("hunter2", None).is_err());
}
