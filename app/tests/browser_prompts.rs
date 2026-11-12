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
fn a_site_without_a_saved_address_suggests_logins_named_after_it() {
    let h = harness(Setup::default());
    let (reply, mut answer) = oneshot::channel();
    h.app.request_browser_prompt(BrowserPromptRequest {
        prompt: BrowserPrompt::Fill {
            browser: "Firefox".into(),
            host: "login.github.com".into(),
            insecure: false,
            matches: vec![],
            touch_id: false,
            return_to: None,
        },
        reply,
    });
    let picker = h.app.browser_picker().expect("picker");
    // No typing: the GitHub login is already listed, but it is another site's saved address, so
    // picking it asks for the confirmation first.
    key(&picker, &special(Key::Return), Mods::default());
    assert!(picker.get_confirm_other());
    assert!(answer.try_recv().is_err());
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

fn address_item(h: &common::Harness) -> ItemSummaryDto {
    let items = h
        .vault
        .search("github", &Filter::default())
        .expect("search");
    ItemSummaryDto::from(items.first().expect("GitHub"))
}

fn address_request(
    item: &ItemSummaryDto,
) -> (BrowserPromptRequest, oneshot::Receiver<BrowserReply>) {
    let (reply, receiver) = oneshot::channel();
    (
        BrowserPromptRequest {
            prompt: BrowserPrompt::AddAddress {
                browser: "Firefox".into(),
                host: "gist.github.com".into(),
                item: item.clone(),
            },
            reply,
        },
        receiver,
    )
}

#[test]
fn address_offer_adds_to_the_named_item() {
    let h = harness(Setup::default());
    let item = address_item(&h);
    let (request, mut answer) = address_request(&item);
    h.app.request_browser_prompt(request);
    let prompt = h.app.browser_save_prompt().expect("address prompt");
    assert!(prompt.get_address());
    assert_eq!(prompt.get_item_name(), item.name.as_ref());
    assert_eq!(prompt.get_host(), "gist.github.com");
    assert!(!common::control_exists(&prompt, "Never for this site"));
    click(&prompt, "Add");
    assert_eq!(
        answer.try_recv(),
        Ok(BrowserReply::Save {
            target: Some(item.id.clone())
        })
    );
    assert!(h.app.browser_save_prompt().is_none());
}

#[test]
fn address_offer_not_now_escape_and_timeout_dismiss() {
    let h = harness(Setup::default());
    let item = address_item(&h);
    let (request, mut answer) = address_request(&item);
    h.app.request_browser_prompt(request);
    click(&h.app.browser_save_prompt().expect("prompt"), "Not now");
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    let (request, mut answer) = address_request(&item);
    h.app.request_browser_prompt(request);
    key(
        &h.app.browser_save_prompt().expect("prompt"),
        &special(Key::Escape),
        Mods::default(),
    );
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    let (request, mut answer) = address_request(&item);
    h.app.request_browser_prompt(request);
    elapse(Duration::from_secs(29));
    assert!(answer.try_recv().is_err(), "still waiting at 29 s");
    elapse(Duration::from_secs(2));
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
}

#[test]
fn address_offer_stays_in_the_background_and_follows_the_theme() {
    let h = harness(Setup {
        settings: Settings {
            theme: ThemeChoice::Light,
            ..Settings::default()
        },
        ..Setup::default()
    });
    let item = address_item(&h);
    let (request, mut answer) = address_request(&item);
    h.app.handle(UiCommand::ShowBrowserPrompt(request));
    let prompt = h.app.browser_save_prompt().expect("address prompt");
    assert_eq!(activations(&h), 0, "the offer must not take focus");
    h.app.set_theme(ThemeChoice::Dark);
    assert_eq!(prompt.global::<Theme>().get_mode(), ThemeMode::Dark);
    h.app.lock();
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
    assert!(h.app.browser_save_prompt().is_none());
}

fn passkey_request(
    save: bool,
    choices: Vec<ItemSummaryDto>,
) -> (BrowserPromptRequest, oneshot::Receiver<BrowserReply>) {
    passkey_request_for("octocat", save, choices)
}

fn passkey_request_for(
    user_name: &str,
    save: bool,
    choices: Vec<ItemSummaryDto>,
) -> (BrowserPromptRequest, oneshot::Receiver<BrowserReply>) {
    let (reply, receiver) = oneshot::channel();
    (
        BrowserPromptRequest {
            prompt: BrowserPrompt::Passkey {
                browser: "Google Chrome".into(),
                host: "github.com".into(),
                save,
                user_name: user_name.into(),
                choices,
                return_to: None,
            },
            reply,
        },
        receiver,
    )
}

#[test]
fn passkey_save_offers_the_site_logins_then_a_new_one() {
    let h = harness(Setup::default());
    let item = address_item(&h);
    let (request, mut answer) = passkey_request_for("someone-else", true, vec![item.clone()]);
    h.app.handle(UiCommand::ShowBrowserPrompt(request));
    assert_eq!(
        activations(&h),
        0,
        "like a save prompt, it leaves the browser in front"
    );
    let prompt = h.app.browser_save_prompt().expect("passkey prompt");
    assert!(prompt.get_passkey_save());
    assert_eq!(prompt.get_username(), "someone-else");
    let choices: Vec<String> = slint::Model::iter(&prompt.get_choices())
        .map(|choice| choice.to_string())
        .collect();
    assert_eq!(choices.len(), 2);
    assert!(choices[0].starts_with(item.name.as_ref()));
    assert_eq!(choices[1], "New login");
    assert!(!common::control_exists(&prompt, "Never for this site"));
    assert_eq!(
        prompt.get_choice_index(),
        1,
        "another account's login is not the default"
    );
    click(&prompt, "Save");
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Save { target: None }));

    let (request, mut answer) = passkey_request_for(&item.subtitle, true, vec![item.clone()]);
    h.app.request_browser_prompt(request);
    let prompt = h.app.browser_save_prompt().expect("passkey prompt");
    assert_eq!(prompt.get_choice_index(), 0, "the same account's login is");
    click(&prompt, "Save");
    assert_eq!(
        answer.try_recv(),
        Ok(BrowserReply::Save {
            target: Some(item.id.clone())
        })
    );
}

#[test]
fn passkey_sign_in_answers_with_the_chosen_login_or_not_now() {
    let h = harness(Setup::default());
    let item = address_item(&h);
    let (request, mut answer) = passkey_request(false, vec![item.clone()]);
    h.app.request_browser_prompt(request);
    let prompt = h.app.browser_save_prompt().expect("passkey prompt");
    assert!(prompt.get_passkey_sign_in());
    click(&prompt, "Sign in");
    assert_eq!(
        answer.try_recv(),
        Ok(BrowserReply::Save {
            target: Some(item.id.clone())
        })
    );

    let (request, mut answer) = passkey_request(false, vec![item]);
    h.app.request_browser_prompt(request);
    click(
        &h.app.browser_save_prompt().expect("passkey prompt"),
        "Not now",
    );
    assert_eq!(answer.try_recv(), Ok(BrowserReply::Dismissed));
}
