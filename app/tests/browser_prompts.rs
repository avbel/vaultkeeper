mod common;

use std::time::Duration;

use common::{Mods, Setup, click, elapse, harness, key, pump, special, type_into};
use slint::{ComponentHandle, platform::Key};
use tokio::sync::oneshot;
use vaultkeeper::{
    UiCommand,
    app::BrowserPromptRequest,
    mock::MOCK_MASTER_PASSWORD,
    settings::{Settings, ThemeChoice},
    ui::{Theme, ThemeMode},
};
use vk_ipc::{BrowserPrompt, BrowserReply, dto::ItemSummaryDto};
use vk_vault::{
    VaultService,
    model::{Filter, SessionState},
};

fn request(code: &str) -> (BrowserPromptRequest, oneshot::Receiver<BrowserReply>) {
    let (reply, receiver) = oneshot::channel();
    (
        BrowserPromptRequest {
            prompt: BrowserPrompt::Pair {
                browser: "Firefox".into(),
                fingerprint: code.into(),
            },
            reply,
        },
        receiver,
    )
}

#[test]
fn pair_requires_click_and_return_does_not_approve() {
    let h = harness(Setup::default());
    let (request, mut answer) = request("A1B2-C3D4-E5F6-0718");
    h.app.request_browser_prompt(request);
    let prompt = h.app.browser_pair_prompt().expect("pair prompt");
    assert_eq!(prompt.get_fingerprint(), "A1B2-C3D4-E5F6-0718");
    key(&prompt, &special(Key::Return), Mods::default());
    assert!(answer.try_recv().is_err());
    click(&prompt, "Connect");
    assert_eq!(answer.try_recv(), Ok(BrowserReply::PairApproved));
    assert!(h.app.browser_pair_prompt().is_none());
}

#[test]
fn pair_escape_and_timeout_dismiss() {
    let h = harness(Setup::default());
    let (first, mut answer) = request("first");
    h.app.request_browser_prompt(first);
    key(
        &h.app.browser_pair_prompt().expect("prompt"),
        &special(Key::Escape),
        Mods::default(),
    );
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    let (second, mut answer) = request("second");
    h.app.request_browser_prompt(second);
    elapse(Duration::from_secs(61));
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
}

#[test]
fn picker_releases_only_the_selected_match() {
    let h = harness(Setup::default());
    let items = h
        .vault
        .search("github", &Filter::default())
        .expect("search");
    let item = items.first().expect("GitHub");
    let (reply, mut answer) = oneshot::channel();
    h.app.request_browser_prompt(BrowserPromptRequest {
        prompt: BrowserPrompt::Fill {
            browser: "Firefox".into(),
            host: "github.com".into(),
            insecure: false,
            matches: vec![ItemSummaryDto::from(item)],
            touch_id: false,
            return_to: None,
        },
        reply,
    });
    let picker = h.app.browser_picker().expect("picker");
    key(&picker, &special(Key::Return), Mods::default());
    assert_eq!(
        answer.try_recv(),
        Ok(BrowserReply::Fill {
            item_id: item.id.0.clone(),
            confirmed_other_site: false
        })
    );
}

#[test]
fn picker_reprompt_requires_master_password() {
    let h = harness(Setup::default());
    let items = h
        .vault
        .search("paypal", &Filter::default())
        .expect("search");
    let item = items.first().expect("PayPal");
    assert!(item.reprompt);
    let (reply, mut answer) = oneshot::channel();
    h.app.request_browser_prompt(BrowserPromptRequest {
        prompt: BrowserPrompt::Fill {
            browser: "Firefox".into(),
            host: "paypal.com".into(),
            insecure: false,
            matches: vec![ItemSummaryDto::from(item)],
            touch_id: false,
            return_to: None,
        },
        reply,
    });
    let picker = h.app.browser_picker().expect("picker");
    key(&picker, &special(Key::Return), Mods::default());
    assert!(picker.get_reprompt());
    type_into(&picker, "Master password", "wrong");
    click(&picker, "Confirm password");
    assert!(answer.try_recv().is_err());
    assert!(!picker.get_password_error().is_empty());
    type_into(
        &picker,
        "Master password",
        vaultkeeper::mock::MOCK_MASTER_PASSWORD,
    );
    click(&picker, "Confirm password");
    assert_eq!(
        answer.try_recv(),
        Ok(BrowserReply::Fill {
            item_id: item.id.0.clone(),
            confirmed_other_site: false
        })
    );
}

#[test]
fn picker_requires_confirmation_for_another_site() {
    let h = harness(Setup::default());
    let (reply, mut answer) = oneshot::channel();
    h.app.request_browser_prompt(BrowserPromptRequest {
        prompt: BrowserPrompt::Fill {
            browser: "Firefox".into(),
            host: "other.example".into(),
            insecure: false,
            matches: vec![],
            touch_id: false,
            return_to: None,
        },
        reply,
    });
    let picker = h.app.browser_picker().expect("picker");
    type_into(&picker, "Search vault", "GitHub");
    key(&picker, &special(Key::Return), Mods::default());
    assert!(picker.get_confirm_other());
    assert!(answer.try_recv().is_err());
    key(&picker, &special(Key::Return), Mods::default());
    assert!(!picker.get_confirm_other());
    assert!(answer.try_recv().is_err());
    key(&picker, &special(Key::Return), Mods::default());
    click(&picker, "Fill anyway");
    assert!(matches!(
        answer.try_recv(),
        Ok(BrowserReply::Fill {
            confirmed_other_site: true,
            ..
        })
    ));
}

#[test]
fn save_prompt_returns_action_without_exposing_a_password() {
    let h = harness(Setup::default());
    let (reply, mut answer) = oneshot::channel();
    h.app.request_browser_prompt(BrowserPromptRequest {
        prompt: BrowserPrompt::Save {
            browser: "Firefox".into(),
            host: "example.com".into(),
            username: "a".repeat(70),
            update_of: None,
            choices: vec![],
            return_to: None,
        },
        reply,
    });
    let prompt = h.app.browser_save_prompt().expect("save prompt");
    assert_eq!(prompt.get_username().len(), 64);
    click(&prompt, "Save");
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Save { target: None }));
}

#[test]
fn pair_prompts_queue_and_lock_dismisses_pending() {
    let h = harness(Setup::default());
    let (first, mut answer1) = request("first");
    let (second, mut answer2) = request("second");
    h.app.request_browser_prompt(first);
    h.app.request_browser_prompt(second);
    click(&h.app.browser_pair_prompt().expect("first"), "Connect");
    assert_eq!(answer1.try_recv(), Ok(BrowserReply::PairApproved));
    assert_eq!(
        h.app
            .browser_pair_prompt()
            .expect("second")
            .get_fingerprint(),
        "second"
    );
    h.app.lock();
    assert_eq!(answer2.try_recv(), Ok(BrowserReply::Dismissed));
}

fn fill_request(host: &str) -> (BrowserPromptRequest, oneshot::Receiver<BrowserReply>) {
    let (reply, receiver) = oneshot::channel();
    (
        BrowserPromptRequest {
            prompt: BrowserPrompt::Fill {
                browser: "Firefox".into(),
                host: host.into(),
                insecure: false,
                matches: vec![],
                touch_id: false,
                return_to: None,
            },
            reply,
        },
        receiver,
    )
}

fn save_request() -> (BrowserPromptRequest, oneshot::Receiver<BrowserReply>) {
    let (reply, receiver) = oneshot::channel();
    (
        BrowserPromptRequest {
            prompt: BrowserPrompt::Save {
                browser: "Firefox".into(),
                host: "example.com".into(),
                username: "user".into(),
                update_of: None,
                choices: vec![],
                return_to: None,
            },
            reply,
        },
        receiver,
    )
}

#[test]
fn picker_escape_dismisses() {
    let h = harness(Setup::default());
    let (request, mut answer) = fill_request("example.com");
    h.app.request_browser_prompt(request);
    key(
        &h.app.browser_picker().expect("picker"),
        &special(Key::Escape),
        Mods::default(),
    );
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    assert!(h.app.browser_picker().is_none());
}

#[test]
fn picker_times_out_after_sixty_seconds() {
    let h = harness(Setup::default());
    let (request, mut answer) = fill_request("example.com");
    h.app.request_browser_prompt(request);
    elapse(Duration::from_secs(59));
    assert!(answer.try_recv().is_err(), "still waiting at 59 s");
    elapse(Duration::from_secs(2));
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    assert!(h.app.browser_picker().is_none());
}

#[test]
fn save_prompt_times_out_after_thirty_seconds_as_not_now() {
    let h = harness(Setup::default());
    let (request, mut answer) = save_request();
    h.app.request_browser_prompt(request);
    elapse(Duration::from_secs(29));
    assert!(answer.try_recv().is_err(), "still waiting at 29 s");
    elapse(Duration::from_secs(2));
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    assert!(h.app.browser_save_prompt().is_none());
}

#[test]
fn save_prompt_escape_and_never_answer() {
    let h = harness(Setup::default());
    let (request, mut answer) = save_request();
    h.app.request_browser_prompt(request);
    click(
        &h.app.browser_save_prompt().expect("prompt"),
        "Never for this site",
    );
    assert_eq!(answer.try_recv(), Ok(BrowserReply::NeverForSite));
    let (request, mut answer) = save_request();
    h.app.request_browser_prompt(request);
    click(&h.app.browser_save_prompt().expect("prompt"), "Not now");
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
}

#[test]
fn a_fill_while_locked_waits_behind_the_lock_screen() {
    let h = harness(Setup {
        unlocked: false,
        ..Setup::default()
    });
    let (request, mut answer) = fill_request("example.com");
    h.app.request_browser_prompt(request);
    assert!(
        h.app.browser_picker().is_none(),
        "no picker before the unlock"
    );
    let lock = h.app.lock_window().expect("lock screen");
    type_into(&lock, "Master password", MOCK_MASTER_PASSWORD);
    click(&lock, "Unlock");
    pump();
    assert!(matches!(h.vault.state(), SessionState::Unlocked { .. }));
    assert!(
        h.app.browser_picker().is_some(),
        "the unlock shows the picker"
    );
    assert!(answer.try_recv().is_err());
}

#[test]
fn closing_the_lock_screen_dismisses_a_waiting_fill() {
    let h = harness(Setup {
        unlocked: false,
        ..Setup::default()
    });
    let (request, mut answer) = fill_request("example.com");
    h.app.request_browser_prompt(request);
    let lock = h.app.lock_window().expect("lock screen");
    lock.window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    assert!(h.app.browser_picker().is_none());
}

#[test]
fn locking_closes_an_open_picker_and_a_save_prompt() {
    let h = harness(Setup::default());
    let (fill, mut fill_answer) = fill_request("example.com");
    h.app.request_browser_prompt(fill);
    assert!(h.app.browser_picker().is_some());
    h.app.lock();
    assert_eq!(fill_answer.try_recv(), Ok(BrowserReply::Dismissed));
    assert!(h.app.browser_picker().is_none());
    let h = harness(Setup::default());
    let (save, mut save_answer) = save_request();
    h.app.request_browser_prompt(save);
    h.app.lock();
    assert_eq!(save_answer.try_recv(), Ok(BrowserReply::Dismissed));
    assert!(h.app.browser_save_prompt().is_none());
}

fn activations(h: &common::Harness) -> usize {
    h.dock.activations.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn only_a_save_prompt_leaves_the_app_in_the_background() {
    let h = harness(Setup::default());
    let (save, _answer) = save_request();
    h.app.handle(UiCommand::ShowBrowserPrompt(save));
    assert!(h.app.browser_save_prompt().is_some());
    assert_eq!(activations(&h), 0, "a save prompt must not take focus");
    let (pair, _answer) = request("fingerprint");
    h.app.handle(UiCommand::ShowBrowserPrompt(pair));
    assert!(activations(&h) > 0, "a pairing prompt needs the keyboard");
    let h = harness(Setup::default());
    let (fill, _answer) = fill_request("example.com");
    h.app.handle(UiCommand::ShowBrowserPrompt(fill));
    assert!(activations(&h) > 0, "the picker needs the keyboard");
}

#[test]
fn every_prompt_window_follows_a_theme_change() {
    let h = harness(Setup {
        settings: Settings {
            theme: ThemeChoice::Light,
            ..Settings::default()
        },
        ..Setup::default()
    });
    let (fill, _fill_answer) = fill_request("example.com");
    h.app.request_browser_prompt(fill);
    let picker = h.app.browser_picker().expect("picker");
    assert_eq!(picker.global::<Theme>().get_mode(), ThemeMode::Light);
    h.app.set_theme(ThemeChoice::Dark);
    assert_eq!(picker.global::<Theme>().get_mode(), ThemeMode::Dark);
    h.app.lock();
    let (pair, _pair_answer) = request("fingerprint");
    h.app.request_browser_prompt(pair);
    let pair_prompt = h.app.browser_pair_prompt().expect("pair prompt");
    h.app.set_theme(ThemeChoice::Light);
    assert_eq!(pair_prompt.global::<Theme>().get_mode(), ThemeMode::Light);
    click(&pair_prompt, "Deny");
    let (save, _save_answer) = save_request();
    h.app.request_browser_prompt(save);
    let save_prompt = h.app.browser_save_prompt().expect("save prompt");
    h.app.set_theme(ThemeChoice::Dark);
    assert_eq!(save_prompt.global::<Theme>().get_mode(), ThemeMode::Dark);
}
