//! The browser integration against a real `Daemon` (BROWSERS.md sections 3, 8.3, 8.4 and 9): the
//! test process plays the `--ui` process and the native host, and a wiremock server plays the
//! vault. Expected values come from the spec, not from running the code.
//!
//! `vw-it` lets the listener start without a hardened runtime and moves the browsers' manifest
//! directory under the test data dir, so nothing here touches `~/Library`.

#![cfg(feature = "vw-it")]
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    clippy::format_collect
)]

#[path = "browser_daemon/harness.rs"]
mod harness;

use std::{os::unix::fs::PermissionsExt as _, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use harness::{
    ALICE, BANK, BOB, Extension, Rig, eventually, integration_on, items, paired, run, stored,
    write_settings,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use vaultkeeper::{
    daemon::browser::{ids, manifests::MANIFEST_FILE, pairing::PairingStore},
    settings::Settings,
};
use vk_ipc::{BrowserPrompt, BrowserReply, UiCommand, UiNotice};
use vk_vault::{VaultService, model::Filter};

const GITHUB: &str = "https://github.com";

fn assert_failure(reply: &Value, error: &str) {
    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(reply["error"], error, "{reply}");
}

fn credentials(reply: &Value) -> (Option<&str>, Option<&str>) {
    assert_eq!(reply["ok"], true, "{reply}");
    (
        reply["result"]["username"].as_str(),
        reply["result"]["password"].as_str(),
    )
}

#[test]
fn a_request_before_pairing_is_refused() {
    run(async {
        let mut rig = Rig::start().await;
        let extension = Extension::chrome(1);

        let mut host = rig.connect(&extension).await;
        let reply = host.request(json!({ "type": "status" })).await;
        assert_eq!(reply, json!({ "id": 1, "ok": false, "error": "unpaired" }));
        host.assert_closed().await;

        let mut host = rig.connect(&extension).await;
        host.hello(&extension).await;
        let id = host.submit_fill(GITHUB, false).await;
        assert_failure(&host.response(id).await, "unpaired");
        host.assert_closed().await;
        rig.ui.no_prompt().await;
        assert!(paired(&rig.dir).is_empty());
        rig.shutdown().await;
    });
}

#[test]
fn a_new_key_is_paired_once_the_user_approves_it() {
    run(async {
        let mut rig = Rig::start().await;
        let extension = Extension::chrome(2);
        let mut host = rig.connect(&extension).await;
        let hello = host.hello(&extension).await;
        assert_eq!(hello["result"]["known"], false);
        let challenge = STANDARD
            .decode(hello["result"]["challenge"].as_str().unwrap())
            .unwrap();
        assert_eq!(challenge.len(), 32);

        let id = host.prove(&extension, &hello).await;
        let asked = rig.ui.prompt().await;
        match &asked.prompt {
            BrowserPrompt::Pair {
                browser,
                fingerprint,
            } => {
                assert_eq!(browser, "Google Chrome");
                assert_eq!(*fingerprint, extension.fingerprint());
            }
            other => panic!("expected the pair prompt, got {other:?}"),
        }
        assert!(
            paired(&rig.dir).is_empty(),
            "nothing is stored before the user answers"
        );
        asked.answer(BrowserReply::PairApproved);
        let proved = host.response(id).await;
        assert_eq!(proved["ok"], true, "{proved}");
        assert_eq!(proved["result"]["state"], "unlocked");
        assert_eq!(proved["result"]["fingerprint"], extension.fingerprint());

        let entries = paired(&rig.dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["public_key"], extension.public_key_b64());
        assert_eq!(entries[0]["browser"], "chrome");
        assert_eq!(entries[0]["caller"], extension.caller);
        let mode = std::fs::metadata(rig.dir.pairings())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let status = host.request(json!({ "type": "status" })).await;
        assert_eq!(status["ok"], true);
        assert_eq!(status["result"]["state"], "unlocked");

        let mut again = rig.connect(&extension).await;
        let hello = again.hello(&extension).await;
        assert_eq!(hello["result"]["known"], true);
        let id = again.prove(&extension, &hello).await;
        assert_eq!(again.response(id).await["ok"], true);
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}

#[test]
fn a_denied_pairing_stores_nothing_and_closes() {
    run(async {
        let mut rig = Rig::start().await;
        let extension = Extension::chrome(3);
        let mut host = rig.connect(&extension).await;
        let hello = host.hello(&extension).await;
        let id = host.prove(&extension, &hello).await;
        rig.ui.prompt().await.answer(BrowserReply::Dismissed);
        assert_failure(&host.response(id).await, "denied");
        host.assert_closed().await;
        assert!(paired(&rig.dir).is_empty());
        rig.shutdown().await;
    });
}

#[test]
fn a_bad_signature_is_denied_without_asking_the_user() {
    run(async {
        let mut rig = Rig::start().await;
        let extension = Extension::chrome(4);
        let impostor = Extension::chrome(5);

        let mut host = rig.connect(&extension).await;
        let hello = host.hello(&extension).await;
        let challenge = hello["result"]["challenge"].as_str().unwrap();
        let id = host
            .submit(json!({
                "type": "prove", "signature": impostor.sign(challenge, &extension.caller),
            }))
            .await;
        assert_failure(&host.response(id).await, "denied");
        host.assert_closed().await;

        // The right key, but signed for another caller string.
        let mut host = rig.connect(&extension).await;
        let hello = host.hello(&extension).await;
        let challenge = hello["result"]["challenge"].as_str().unwrap();
        let id = host
            .submit(json!({
                "type": "prove", "signature": extension.sign(challenge, "chrome-extension://other/"),
            }))
            .await;
        assert_failure(&host.response(id).await, "denied");
        host.assert_closed().await;

        rig.ui.no_prompt().await;
        assert!(paired(&rig.dir).is_empty());
        rig.shutdown().await;
    });
}

#[test]
fn a_fill_releases_only_the_item_the_user_picked() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(6)).await;

        let id = host.submit_fill(GITHUB, false).await;
        let asked = rig.ui.prompt().await;
        let BrowserPrompt::Fill {
            browser,
            host: shown,
            insecure,
            matches,
            touch_id,
            ..
        } = &asked.prompt
        else {
            panic!("expected the fill prompt, got {:?}", asked.prompt);
        };
        assert_eq!(browser, "Google Chrome");
        assert_eq!(shown, "github.com");
        assert!(!insecure && !touch_id);
        let mut offered: Vec<&str> = matches.iter().map(|item| &*item.id).collect();
        offered.sort_unstable();
        assert_eq!(offered, [ALICE, BOB], "the bank login is not offered");
        asked.fill_with(BOB, false);
        assert_eq!(
            host.response(id).await,
            json!({ "id": id, "ok": true, "result": { "username": "bob", "password": "bob-pw" } })
        );

        // `choose` shows the picker again, and a field the page does not need stays null.
        let id = host
            .submit(json!({
                "type": "fill", "origin": GITHUB, "path": "/login", "choose": true,
                "fields": { "username": false, "password": true },
            }))
            .await;
        rig.ui.prompt().await.fill_with(ALICE, false);
        let reply = host.response(id).await;
        assert_eq!(credentials(&reply), (None, Some("alice-pw")));
        assert!(reply["result"]["username"].is_null());
        rig.shutdown().await;
    });
}

#[test]
fn a_confirmed_item_of_another_site_is_released_but_not_remembered() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(7)).await;

        let id = host.submit_fill(GITHUB, false).await;
        rig.ui.prompt().await.answer(BrowserReply::Dismissed);
        assert_failure(&host.response(id).await, "cancelled");

        let id = host.submit_fill(GITHUB, false).await;
        rig.ui.prompt().await.fill_with(BANK, true);
        assert_eq!(
            credentials(&host.response(id).await),
            (Some("carol"), Some("carol-pw"))
        );

        let reply = host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        assert_eq!(credentials(&reply), (Some("alice"), Some("alice-pw")));
        rig.shutdown().await;
    });
}

/// BROWSERS.md 8.3 step 7 and 8.4: `login_matches` false without `confirmed_other_site` is `denied`.
#[test]
fn an_item_of_another_site_without_the_confirmation_is_denied() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(23)).await;
        let id = host.submit_fill(GITHUB, false).await;
        rig.ui.prompt().await.fill_with(BANK, false);
        let reply = host.response(id).await;
        assert!(
            reply["result"]["password"].is_null(),
            "nothing was released"
        );
        assert_failure(&reply, "denied");
        rig.shutdown().await;
    });
}

#[test]
fn a_remembered_approval_belongs_to_one_connection_and_origin() {
    run(async {
        let mut rig = Rig::start().await;
        let extension = Extension::chrome(8);
        let mut first = rig.open(&extension).await;
        let reply = first.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        assert_eq!(credentials(&reply), (Some("alice"), Some("alice-pw")));

        let id = first.submit_fill(GITHUB, false).await;
        let reply = first.response(id).await;
        assert_eq!(credentials(&reply), (Some("alice"), Some("alice-pw")));
        rig.ui.no_prompt().await;

        let id = first.submit_fill(GITHUB, true).await;
        rig.ui.prompt().await.fill_with(ALICE, false);
        assert_eq!(first.response(id).await["ok"], true);

        let reply = first
            .picked_fill(&mut rig.ui, "https://bank.example.org", BANK)
            .await;
        assert_eq!(credentials(&reply), (Some("carol"), Some("carol-pw")));

        let mut second = rig.open(&extension).await;
        let id = second.submit_fill(GITHUB, false).await;
        let asked = rig.ui.prompt().await;
        assert!(matches!(asked.prompt, BrowserPrompt::Fill { .. }));
        asked.fill_with(ALICE, false);
        assert_eq!(second.response(id).await["ok"], true);
        rig.shutdown().await;
    });
}

#[test]
fn locking_forgets_remembered_approvals() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(9)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;

        // The daemon clears its copy when it sees the lock, in the same step that forgets approvals.
        rig.ui.remote.copy_to_clipboard("marker", None).unwrap();
        eventually(|| rig.clipboard.content().is_some()).await;
        rig.daemon.vault().lock();
        eventually(|| rig.clipboard.content().is_none()).await;
        let event = host.event().await;
        assert_eq!(event["event"], "state");
        assert_eq!(event["state"], "locked");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let id = host.submit_fill(GITHUB, false).await;
        rig.ui
            .command(|command| matches!(command, UiCommand::UnlockInTray))
            .await;
        rig.unlock().await;
        let asked = rig.ui.prompt().await;
        assert!(
            matches!(asked.prompt, BrowserPrompt::Fill { .. }),
            "the first fill after an unlock asks again"
        );
        asked.fill_with(ALICE, false);
        assert_eq!(host.response(id).await["ok"], true);
        rig.shutdown().await;
    });
}

#[test]
fn twenty_fills_a_minute_and_then_rate_limited() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(10)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        for _ in 1..20 {
            let id = host.submit_fill(GITHUB, false).await;
            assert_eq!(host.response(id).await["ok"], true);
        }
        let id = host.submit_fill(GITHUB, false).await;
        assert_failure(&host.response(id).await, "rate_limited");
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}

#[test]
fn three_cancelled_fills_cool_an_origin_down() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(11)).await;
        for _ in 0..3 {
            let id = host.submit_fill(GITHUB, false).await;
            rig.ui.prompt().await.answer(BrowserReply::Dismissed);
            assert_failure(&host.response(id).await, "cancelled");
        }
        let id = host.submit_fill(GITHUB, false).await;
        assert_failure(&host.response(id).await, "rate_limited");
        rig.ui.no_prompt().await;

        let reply = host
            .picked_fill(&mut rig.ui, "https://bank.example.org", BANK)
            .await;
        assert_eq!(credentials(&reply), (Some("carol"), Some("carol-pw")));
        rig.shutdown().await;
    });
}

#[test]
fn malformed_requests_get_an_error_and_never_a_prompt() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(12)).await;

        let id = host.submit_fill("http://example.com", false).await;
        assert_failure(&host.response(id).await, "insecure_page");
        let id = host.submit_fill("https://github.com/path", false).await;
        assert_failure(&host.response(id).await, "bad_request");
        let reply = host.request(json!({ "type": "fill" })).await;
        assert_failure(&reply, "bad_request");
        let reply = host.request(json!({ "type": "bogus" })).await;
        assert_failure(&reply, "unknown_type");
        let reply = host.save_candidate(GITHUB, "alice", "", "login").await;
        assert_failure(&reply, "bad_request");

        let status = host.request(json!({ "type": "status" })).await;
        assert_eq!(status["ok"], true, "the connection survives bad requests");
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}

#[test]
fn a_candidate_with_the_stored_password_asks_nothing() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(13)).await;
        let ack = host
            .save_candidate(GITHUB, "alice", "alice-pw", "login")
            .await;
        assert_eq!(ack["ok"], true, "{ack}");
        assert_eq!(ack["result"], json!({}));
        let ack = host
            .save_candidate(GITHUB, "ALICE", "alice-pw", "login")
            .await;
        assert_eq!(ack["ok"], true);
        rig.ui.no_prompt().await;
        assert_eq!(rig.fake.writes().await, 0);
        rig.shutdown().await;
    });
}

#[test]
fn a_changed_password_offers_an_update_and_writes_it() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(14)).await;
        let ack = host
            .save_candidate(GITHUB, "alice", "alice-new", "change")
            .await;
        assert_eq!(
            ack["result"],
            json!({}),
            "the answer never depends on the vault"
        );

        let asked = rig.ui.prompt().await;
        let BrowserPrompt::Save {
            browser,
            host: shown,
            username,
            update_of,
            choices,
            ..
        } = &asked.prompt
        else {
            panic!("expected the save prompt, got {:?}", asked.prompt);
        };
        assert_eq!(browser, "Google Chrome");
        assert_eq!(shown, "github.com");
        assert_eq!(username, "alice");
        assert_eq!(update_of.as_ref().map(|item| &*item.id), Some(ALICE));
        assert!(choices.is_empty());
        assert_eq!(
            rig.password_of(ALICE),
            "alice-pw",
            "nothing changes before the answer"
        );
        asked.answer(BrowserReply::Save {
            target: Some(ALICE.into()),
        });

        eventually(|| rig.password_of(ALICE) == "alice-new").await;
        assert_eq!(rig.password_of(BOB), "bob-pw");
        assert_eq!(rig.password_of(BANK), "carol-pw");
        assert_eq!(rig.fake.writes().await, 1);
        rig.shutdown().await;
    });
}

#[test]
fn an_answer_for_an_item_that_was_not_offered_writes_nothing() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(15)).await;
        host.save_candidate(GITHUB, "alice", "alice-new", "change")
            .await;
        rig.ui.prompt().await.answer(BrowserReply::Save {
            target: Some(BANK.into()),
        });
        tokio::time::sleep(harness::QUIET).await;
        assert_eq!(rig.fake.writes().await, 0);
        assert_eq!(rig.password_of(BANK), "carol-pw");
        assert_eq!(rig.password_of(ALICE), "alice-pw");
        rig.shutdown().await;
    });
}

#[test]
fn a_new_username_is_offered_as_a_new_login_and_never_for_site_sticks() {
    run(async {
        let mut rig = Rig::start().await;
        let mut host = rig.open(&Extension::chrome(16)).await;
        host.save_candidate(GITHUB, "dave", "dave-pw", "login")
            .await;
        let asked = rig.ui.prompt().await;
        let BrowserPrompt::Save {
            username,
            update_of,
            choices,
            ..
        } = &asked.prompt
        else {
            panic!("expected the save prompt, got {:?}", asked.prompt);
        };
        assert_eq!(username, "dave");
        assert!(update_of.is_none() && choices.is_empty());
        asked.answer(BrowserReply::Save { target: None });

        let find = || {
            rig.daemon
                .vault()
                .search("", &Filter::default())
                .unwrap()
                .iter()
                .find(|item| &*item.subtitle == "dave")
                .cloned()
        };
        eventually(|| find().is_some()).await;
        let created = find().unwrap();
        assert_eq!(&*created.name, "github.com");
        assert_eq!(rig.password_of(&created.id.0), "dave-pw");

        host.save_candidate(GITHUB, "erin", "erin-pw", "login")
            .await;
        rig.ui.prompt().await.answer(BrowserReply::NeverForSite);
        eventually(|| {
            stored(&rig.dir)["never_save"]
                .as_array()
                .is_some_and(|list| list.len() == 1)
        })
        .await;
        let store = stored(&rig.dir);
        let mut hasher = Sha256::new();
        hasher.update(
            STANDARD
                .decode(store["never_save_salt"].as_str().unwrap())
                .unwrap(),
        );
        hasher.update(b"github.com");
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(store["never_save"][0], expected);

        host.save_candidate("https://gist.github.com", "frank", "frank-pw", "login")
            .await;
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}

#[test]
fn removing_a_pairing_closes_its_sessions_and_only_those() {
    run(async {
        let mut rig = Rig::start().await;
        let removed = Extension::chrome(17);
        let kept = Extension::chrome(18);
        let mut removed_host = rig.open(&removed).await;
        let mut kept_host = rig.open(&kept).await;
        assert_eq!(paired(&rig.dir).len(), 2);

        assert!(PairingStore::remove_key(&rig.dir.pairings(), &removed.public_key_b64()).unwrap());
        rig.ui.remote.notify(UiNotice::SettingsChanged).unwrap();
        removed_host.assert_closed().await;

        let status = kept_host.request(json!({ "type": "status" })).await;
        assert_eq!(status["ok"], true, "{status}");
        assert_eq!(paired(&rig.dir).len(), 1);

        let mut again = rig.connect(&removed).await;
        let hello = again.hello(&removed).await;
        assert_eq!(hello["result"]["known"], false);
        rig.shutdown().await;
    });
}

#[test]
fn a_caller_that_does_not_fit_its_parent_browser_is_dropped() {
    run(async {
        let mut rig = Rig::start().await;
        let mut mismatched = Extension::firefox(19);
        mismatched.parent = "chrome";
        let mut host = rig.connect(&mismatched).await;
        host.assert_closed().await;

        let firefox = Extension::firefox(20);
        let mut host = rig.connect(&firefox).await;
        let hello = host.hello(&firefox).await;
        let id = host.prove(&firefox, &hello).await;
        let asked = rig.ui.prompt().await;
        assert!(matches!(
            &asked.prompt,
            BrowserPrompt::Pair { browser, .. } if browser == "Firefox"
        ));
        asked.answer(BrowserReply::PairApproved);
        assert_eq!(host.response(id).await["ok"], true);
        let entries = paired(&rig.dir);
        assert_eq!(entries[0]["browser"], "firefox");
        assert_eq!(entries[0]["caller"], ids::FIREFOX_EXTENSION_ID);
        rig.shutdown().await;
    });
}

#[test]
fn the_listener_follows_the_integration_setting() {
    run(async {
        let mut rig = Rig::start_with(&Settings::default(), &items()).await;
        assert!(!rig.dir.socket().exists(), "off by default");
        assert!(!rig.dir.app_support().exists());

        write_settings(&rig.dir, &integration_on());
        rig.ui.remote.notify(UiNotice::SettingsChanged).unwrap();
        let socket = rig.dir.socket();
        eventually(|| socket.exists()).await;
        let mut host = rig.open(&Extension::chrome(21)).await;
        assert_eq!(host.request(json!({ "type": "status" })).await["ok"], true);

        write_settings(&rig.dir, &Settings::default());
        rig.ui.remote.notify(UiNotice::SettingsChanged).unwrap();
        eventually(|| !socket.exists()).await;
        host.assert_closed().await;
        rig.shutdown().await;
    });
}

#[test]
fn manifests_are_written_for_installed_browsers_only_and_restored_when_changed() {
    run(async {
        let mut rig = Rig::start_with(&Settings::default(), &items()).await;
        let support = rig.dir.app_support();
        std::fs::create_dir_all(support.join("Google/Chrome")).unwrap();
        write_settings(&rig.dir, &integration_on());
        rig.ui.remote.notify(UiNotice::SettingsChanged).unwrap();

        let chrome = support
            .join("Google/Chrome/NativeMessagingHosts")
            .join(MANIFEST_FILE);
        eventually(|| chrome.exists()).await;
        let written = std::fs::read(&chrome).unwrap();
        let manifest: Value = serde_json::from_slice(&written).unwrap();
        assert_eq!(manifest["name"], "org.vaultkeeper.browser");
        assert_eq!(manifest["type"], "stdio");
        assert_eq!(
            manifest["path"],
            std::fs::canonicalize(std::env::current_exe().unwrap())
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            manifest["allowed_origins"],
            json!([format!("chrome-extension://{}/", ids::CHROME_EXTENSION_ID)])
        );
        assert!(manifest.get("allowed_extensions").is_none());
        assert_eq!(
            std::fs::metadata(&chrome).unwrap().permissions().mode() & 0o777,
            0o644
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        let created: Vec<_> = std::fs::read_dir(&support)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            created,
            ["Google"],
            "no directory for a browser that is not installed"
        );

        std::fs::write(&chrome, br#"{"name":"evil"}"#).unwrap();
        let firefox_dir = support.join("Mozilla");
        std::fs::create_dir_all(&firefox_dir).unwrap();
        let socket = rig.dir.socket();
        eventually(|| socket.exists()).await;
        let _connection = rig.connect(&Extension::chrome(22)).await;
        eventually(|| std::fs::read(&chrome).is_ok_and(|bytes| bytes == written)).await;
        let toast = rig
            .ui
            .command(|command| matches!(command, UiCommand::Toast { .. }))
            .await;
        assert_eq!(
            toast,
            UiCommand::Toast {
                text: "The browser connection file for Chrome was changed and has been restored"
                    .to_owned(),
                error: true,
            }
        );
        let firefox = firefox_dir.join("NativeMessagingHosts").join(MANIFEST_FILE);
        eventually(|| firefox.exists()).await;
        let manifest: Value = serde_json::from_slice(&std::fs::read(&firefox).unwrap()).unwrap();
        assert_eq!(
            manifest["allowed_extensions"],
            json!([ids::FIREFOX_EXTENSION_ID])
        );
        assert!(manifest.get("allowed_origins").is_none());

        write_settings(&rig.dir, &Settings::default());
        rig.ui.remote.notify(UiNotice::SettingsChanged).unwrap();
        eventually(|| !chrome.exists() && !firefox.exists()).await;
        rig.shutdown().await;
    });
}
