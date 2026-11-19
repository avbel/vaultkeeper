//! Fill on page load (BROWSERS.md, "fill"): released only from a remembered pick, with the setting
//! on, the vault unlocked and Touch ID off, and never with a window.

use std::sync::atomic::Ordering;

use serde_json::Value;
use vaultkeeper::settings::Settings;
use vk_ipc::UiCommand;
use vk_vault::VaultService as _;

use super::{
    GITHUB,
    harness::{ALICE, Extension, Rig, integration_on, items, run},
};

const BANK_ORIGIN: &str = "https://bank.example.org";

fn on() -> Settings {
    Settings {
        browser_autofill: true,
        ..integration_on()
    }
}

fn quiet(reply: &Value) {
    super::assert_failure(reply, "no_auto");
}

#[test]
fn a_remembered_login_is_filled_on_load_without_a_window() {
    run(async {
        let mut rig = Rig::start_with(&on(), &items()).await;
        let mut host = rig.open(&Extension::chrome(30)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;

        let id = host.submit_auto_fill(GITHUB).await;
        let reply = host.response(id).await;
        assert_eq!(
            super::credentials(&reply),
            (Some("alice"), Some("alice-pw"))
        );
        rig.ui.no_prompt().await;

        // A new connection of the same browser gets it too: the pick outlives connections.
        let mut again = rig.open(&Extension::chrome(30)).await;
        let id = again.submit_auto_fill(GITHUB).await;
        let reply = again.response(id).await;
        assert_eq!(
            super::credentials(&reply),
            (Some("alice"), Some("alice-pw"))
        );
        rig.shutdown().await;
    });
}

#[test]
fn nothing_is_filled_on_load_unless_the_setting_is_on() {
    run(async {
        let mut rig = Rig::start_with(&integration_on(), &items()).await;
        let mut host = rig.open(&Extension::chrome(31)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        let id = host.submit_auto_fill(GITHUB).await;
        quiet(&host.response(id).await);
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}

#[test]
fn a_site_without_a_remembered_pick_is_never_filled_or_asked_about_on_load() {
    run(async {
        let mut rig = Rig::start_with(&on(), &items()).await;
        let mut host = rig.open(&Extension::chrome(32)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        // One login matches the bank, which would fill at once on a click, but never on load.
        let id = host.submit_auto_fill(BANK_ORIGIN).await;
        quiet(&host.response(id).await);
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}

#[test]
fn a_locked_vault_is_not_unlocked_for_a_page_load() {
    run(async {
        let mut rig = Rig::start_with(&on(), &items()).await;
        let mut host = rig.open(&Extension::chrome(33)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        rig.daemon.vault().lock();
        let event = host.event().await;
        assert_eq!(event["state"], "locked");

        let id = host.submit_auto_fill(GITHUB).await;
        quiet(&host.response(id).await);
        rig.ui.no_prompt().await;
        assert!(
            !rig.ui
                .commands
                .iter()
                .any(|command| matches!(command, UiCommand::UnlockInTray)),
            "the lock screen stays down"
        );
        rig.shutdown().await;
    });
}

#[test]
fn touch_id_turns_page_load_fills_off_without_asking_for_it() {
    run(async {
        let settings = Settings {
            browser_touch_id: true,
            ..on()
        };
        let mut rig = Rig::start_with(&settings, &items()).await;
        let mut host = rig.open(&Extension::chrome(34)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        assert_eq!(rig.touch_id.checks.load(Ordering::SeqCst), 1);

        let id = host.submit_auto_fill(GITHUB).await;
        quiet(&host.response(id).await);
        assert_eq!(rig.touch_id.checks.load(Ordering::SeqCst), 1);
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}

#[test]
fn a_page_cannot_ask_for_more_than_three_fills_a_minute() {
    run(async {
        let mut rig = Rig::start_with(&on(), &items()).await;
        let mut host = rig.open(&Extension::chrome(36)).await;
        host.picked_fill(&mut rig.ui, GITHUB, ALICE).await;
        for _ in 0..3 {
            let id = host.submit_auto_fill(GITHUB).await;
            assert_eq!(host.response(id).await["ok"], true);
        }
        let id = host.submit_auto_fill(GITHUB).await;
        quiet(&host.response(id).await);
        rig.ui.no_prompt().await;
        rig.shutdown().await;
    });
}
