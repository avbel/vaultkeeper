//! Native browser prompt queue.

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use tokio::sync::oneshot;
use vk_ipc::{BrowserPrompt, BrowserReply};
use vk_vault::{
    VaultService,
    model::{Filter, ItemKind, ItemSummary, SessionState},
};
use zeroize::Zeroizing;

use super::{App, handler, hide, retire, show};
use crate::ui::{BrowserPairPrompt, BrowserPicker, BrowserPickerRow, BrowserSavePrompt};

#[derive(Debug)]
pub struct BrowserPromptRequest {
    pub prompt: BrowserPrompt,
    pub reply: oneshot::Sender<BrowserReply>,
}

struct Queued {
    id: u64,
    request: BrowserPromptRequest,
}

#[derive(Default)]
pub(super) struct BrowserQueue {
    next_id: u64,
    pending: VecDeque<Queued>,
    current: Option<Queued>,
    timer: Option<Timer>,
    rows: Vec<ItemSummary>,
    matched: HashSet<Arc<str>>,
    selected: Option<(ItemSummary, bool)>,
}

impl<S: VaultService> App<S> {
    pub fn request_browser_prompt(&self, request: BrowserPromptRequest) {
        let mut queue = self.browser.borrow_mut();
        queue.next_id += 1;
        let id = queue.next_id;
        let needs_unlock = matches!(request.prompt, BrowserPrompt::Fill { .. })
            && matches!(self.vault.state(), SessionState::Locked { .. });
        queue.pending.push_back(Queued { id, request });
        drop(queue);
        if needs_unlock {
            self.target.set(super::Target::None);
            self.request_unlock(super::unlock::UnlockView::LockWindow);
        } else {
            self.show_next_browser_prompt();
        }
    }

    pub(super) fn show_next_browser_prompt(&self) {
        if self.browser.borrow().current.is_some() {
            return;
        }
        if self
            .browser
            .borrow()
            .pending
            .front()
            .is_some_and(|queued| matches!(queued.request.prompt, BrowserPrompt::Fill { .. }))
            && !matches!(self.vault.state(), SessionState::Unlocked { .. })
        {
            if matches!(self.vault.state(), SessionState::LoggedOut) {
                self.deny_all_browser();
            }
            return;
        }
        let Some(queued) = self.browser.borrow_mut().pending.pop_front() else {
            return;
        };
        if matches!(&queued.request.prompt, BrowserPrompt::Fill { .. }) {
            self.show_browser_picker(queued);
            return;
        }
        if matches!(&queued.request.prompt, BrowserPrompt::Save { .. }) {
            self.show_browser_save(queued);
            return;
        }
        let BrowserPrompt::Pair {
            browser,
            fingerprint,
        } = &queued.request.prompt
        else {
            // No password or login data is released for prompt kinds without a window.
            let _ = queued.request.reply.send(BrowserReply::Dismissed);
            self.show_next_browser_prompt();
            return;
        };
        let window = match BrowserPairPrompt::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create browser pairing prompt");
                let _ = queued.request.reply.send(BrowserReply::Dismissed);
                self.show_next_browser_prompt();
                return;
            }
        };
        self.apply_theme(&window);
        window.set_browser(browser.as_str().into());
        window.set_fingerprint(fingerprint.as_str().into());
        let id = queued.id;
        window.on_approve(handler!(self, |app| app
            .finish_browser(id, BrowserReply::PairApproved)));
        window.on_deny(handler!(self, |app| app.finish_browser(id, BrowserReply::Dismissed)));
        let timer = Timer::default();
        timer.start(
            TimerMode::SingleShot,
            Duration::from_secs(60),
            handler!(self, |app| app.finish_browser(id, BrowserReply::Dismissed)),
        );
        {
            let mut queue = self.browser.borrow_mut();
            queue.current = Some(queued);
            queue.timer = Some(timer);
        }
        show(&window, "browser pairing prompt");
        *self.browser_pair_prompt.borrow_mut() = Some(window);
    }

    fn show_browser_picker(&self, queued: Queued) {
        let BrowserPrompt::Fill {
            browser,
            host,
            insecure,
            matches,
            touch_id,
            ..
        } = &queued.request.prompt
        else {
            return;
        };
        let window = match BrowserPicker::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create browser picker");
                let _ = queued.request.reply.send(BrowserReply::Dismissed);
                self.show_next_browser_prompt();
                return;
            }
        };
        self.apply_theme(&window);
        window.set_browser(browser.as_str().into());
        window.set_host(host.as_str().into());
        window.set_insecure(*insecure);
        window.set_touch_id(*touch_id);
        let rows: Vec<ItemSummary> = matches.iter().cloned().map(Into::into).collect();
        let matched = rows.iter().map(|item| Arc::clone(&item.id.0)).collect();
        let id = queued.id;
        window.on_search_edited(handler!(self, |app, text| app.search_browser(id, &text)));
        window.on_pick(handler!(self, |app, index| app.pick_browser(id, index)));
        window.on_confirm(handler!(self, |app| app.confirm_browser(id)));
        window.on_cancel_confirm(handler!(self, |app| app.cancel_browser_selection(id)));
        window.on_submit_password(handler!(self, |app, password| app
            .verify_browser_password(id, Zeroizing::new(password.to_string()))));
        window.on_dismiss(handler!(self, |app| app.finish_browser(id, BrowserReply::Dismissed)));
        let timer = Timer::default();
        timer.start(
            TimerMode::SingleShot,
            Duration::from_secs(60),
            handler!(self, |app| app.finish_browser(id, BrowserReply::Dismissed)),
        );
        if let Some(origin) = self
            .hooks
            .placement
            .quick_panel_origin(window.get_panel_width(), window.get_panel_height())
        {
            window.window().set_position(origin);
        }
        {
            let mut queue = self.browser.borrow_mut();
            queue.rows = rows;
            queue.matched = matched;
            queue.selected = None;
            queue.current = Some(queued);
            queue.timer = Some(timer);
        }
        *self.browser_picker.borrow_mut() = Some(window.clone_strong());
        self.render_browser_rows(&window);
        show(&window, "browser picker");
    }

    fn render_browser_rows(&self, window: &BrowserPicker) {
        let queue = self.browser.borrow();
        let rows: Vec<_> = queue
            .rows
            .iter()
            .map(|item| BrowserPickerRow {
                name: item.name.as_ref().into(),
                username: item.subtitle.as_ref().into(),
                other_site: !queue.matched.contains(&item.id.0),
            })
            .collect();
        window.set_rows(ModelRc::new(VecModel::from(rows)));
        window.set_selected(0);
    }

    fn search_browser(&self, id: u64, query: &str) {
        let initial = {
            let queue = self.browser.borrow();
            let Some(Queued {
                id: current,
                request:
                    BrowserPromptRequest {
                        prompt: BrowserPrompt::Fill { matches, .. },
                        ..
                    },
            }) = queue.current.as_ref()
            else {
                return;
            };
            if *current != id {
                return;
            }
            matches
                .iter()
                .cloned()
                .map(Into::into)
                .collect::<Vec<ItemSummary>>()
        };
        let rows = if query.is_empty() {
            initial
        } else {
            match self.vault.search(
                query,
                &Filter {
                    kind: Some(ItemKind::Login),
                    ..Filter::default()
                },
            ) {
                Ok(items) => items.iter().filter(|item| !item.deleted).cloned().collect(),
                Err(_) => Vec::new(),
            }
        };
        self.browser.borrow_mut().rows = rows;
        if let Some(window) = self.browser_picker.borrow().as_ref() {
            self.render_browser_rows(window);
        }
    }

    fn pick_browser(&self, id: u64, index: i32) {
        let (item, other) = {
            let queue = self.browser.borrow();
            if queue
                .current
                .as_ref()
                .is_none_or(|current| current.id != id)
            {
                return;
            }
            let Some(item) = usize::try_from(index)
                .ok()
                .and_then(|index| queue.rows.get(index))
                .cloned()
            else {
                return;
            };
            let other = !queue.matched.contains(&item.id.0);
            (item, other)
        };
        let confirmation = if other {
            let host = item
                .primary_uri
                .as_deref()
                .and_then(|uri| url::Url::parse(uri).ok())
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_else(|| "another site".into());
            Some(format!(
                "{} is saved for {}, not {}. Fill it here anyway?",
                item.name,
                host,
                self.browser_picker
                    .borrow()
                    .as_ref()
                    .map_or_else(String::new, |window| window.get_host().to_string())
            ))
        } else {
            None
        };
        self.browser.borrow_mut().selected = Some((item, other));
        if let Some(text) = confirmation {
            if let Some(window) = self.browser_picker.borrow().as_ref() {
                window.set_confirm_text(text.into());
                window.set_confirm_other(true);
            }
        } else {
            self.confirm_browser(id);
        }
    }

    fn cancel_browser_selection(&self, id: u64) {
        if self
            .browser
            .borrow()
            .current
            .as_ref()
            .is_none_or(|current| current.id != id)
        {
            return;
        }
        self.browser.borrow_mut().selected = None;
        if let Some(window) = self.browser_picker.borrow().as_ref() {
            window.set_confirm_other(false);
        }
    }

    fn confirm_browser(&self, id: u64) {
        let selected = {
            let queue = self.browser.borrow();
            if queue
                .current
                .as_ref()
                .is_none_or(|current| current.id != id)
            {
                return;
            }
            queue.selected.clone()
        };
        let Some((item, other)) = selected else {
            return;
        };
        if item.reprompt {
            if let Some(window) = self.browser_picker.borrow().as_ref() {
                window.set_confirm_other(false);
                window.set_reprompt(true);
            }
        } else {
            self.finish_browser(
                id,
                BrowserReply::Fill {
                    item_id: item.id.0,
                    confirmed_other_site: other,
                },
            );
        }
    }

    fn verify_browser_password(&self, id: u64, password: Zeroizing<String>) {
        if password.is_empty() {
            return;
        }
        let selected = {
            let queue = self.browser.borrow();
            if queue
                .current
                .as_ref()
                .is_none_or(|current| current.id != id)
            {
                return;
            }
            queue.selected.clone()
        };
        let Some((item, other)) = selected else {
            return;
        };
        if let Some(window) = self.browser_picker.borrow().as_ref() {
            window.set_password("".into());
        }
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.verify_master_password(password).await },
            handler!(self, |app, result| {
                let valid = {
                    let queue = app.browser.borrow();
                    queue
                        .current
                        .as_ref()
                        .is_some_and(|current| current.id == id)
                        && queue
                            .selected
                            .as_ref()
                            .is_some_and(|(selected, selected_other)| {
                                selected.id == item.id && *selected_other == other
                            })
                };
                if !valid {
                    return;
                }
                if matches!(result, Ok(true)) {
                    app.finish_browser(
                        id,
                        BrowserReply::Fill {
                            item_id: item.id.0,
                            confirmed_other_site: other,
                        },
                    );
                } else if let Some(window) = app.browser_picker.borrow().as_ref() {
                    window.set_password("".into());
                    window.set_password_error("Wrong master password · try again".into());
                }
            }),
        );
    }

    fn show_browser_save(&self, queued: Queued) {
        let BrowserPrompt::Save {
            browser,
            host,
            username,
            update_of,
            choices,
            ..
        } = &queued.request.prompt
        else {
            return;
        };
        let window = match BrowserSavePrompt::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create browser save prompt");
                let _ = queued.request.reply.send(BrowserReply::Dismissed);
                self.show_next_browser_prompt();
                return;
            }
        };
        self.apply_theme(&window);
        window.set_browser(browser.as_str().into());
        window.set_host(host.as_str().into());
        window.set_username(username.chars().take(64).collect::<String>().into());
        window.set_update(update_of.is_some() || !choices.is_empty());
        let labels: Vec<SharedString> = choices
            .iter()
            .map(|item| item.name.as_ref().into())
            .collect();
        window.set_choices(ModelRc::new(VecModel::from(labels)));
        let id = queued.id;
        window.on_save(handler!(self, |app, index| app.save_browser(id, index)));
        window.on_dismiss(handler!(self, |app| app.finish_browser(id, BrowserReply::Dismissed)));
        window.on_never(handler!(self, |app| app
            .finish_browser(id, BrowserReply::NeverForSite)));
        let timer = Timer::default();
        timer.start(
            TimerMode::SingleShot,
            Duration::from_secs(30),
            handler!(self, |app| app.finish_browser(id, BrowserReply::Dismissed)),
        );
        {
            let mut queue = self.browser.borrow_mut();
            queue.current = Some(queued);
            queue.timer = Some(timer);
        }
        show(&window, "browser save prompt");
        *self.browser_save_prompt.borrow_mut() = Some(window);
    }

    fn save_browser(&self, id: u64, index: i32) {
        let target = {
            let queue = self.browser.borrow();
            let Some(Queued {
                id: current,
                request:
                    BrowserPromptRequest {
                        prompt:
                            BrowserPrompt::Save {
                                update_of, choices, ..
                            },
                        ..
                    },
            }) = queue.current.as_ref()
            else {
                return;
            };
            if *current != id {
                return;
            }
            if choices.is_empty() {
                update_of.as_ref().map(|item| item.id.clone())
            } else {
                let Some(item) = usize::try_from(index)
                    .ok()
                    .and_then(|index| choices.get(index))
                else {
                    return;
                };
                Some(item.id.clone())
            }
        };
        self.finish_browser(id, BrowserReply::Save { target });
    }

    fn finish_browser(&self, id: u64, reply: BrowserReply) {
        let request = {
            let mut queue = self.browser.borrow_mut();
            if queue.current.as_ref().is_none_or(|item| item.id != id) {
                return;
            }
            if let Some(timer) = queue.timer.take() {
                timer.stop();
                retire(timer);
            }
            queue.rows.clear();
            queue.matched.clear();
            queue.selected = None;
            queue.current.take().map(|item| item.request)
        };
        let return_to = request.as_ref().and_then(|request| match &request.prompt {
            BrowserPrompt::Save { return_to, .. } | BrowserPrompt::Fill { return_to, .. } => {
                return_to.clone()
            }
            BrowserPrompt::Pair { .. } => None,
        });
        if let Some(request) = request {
            let _ = request.reply.send(reply);
        }
        if let Some(window) = self.browser_pair_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
        if let Some(window) = self.browser_save_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
        if let Some(window) = self.browser_picker.borrow_mut().take() {
            window.set_password("".into());
            hide(&window);
            retire(window);
            self.window_closed();
        }
        self.show_next_browser_prompt();
        if self.browser.borrow().current.is_none()
            && let Some(target) = return_to
        {
            self.hooks.autotype.give_focus_back(&target);
        }
    }

    pub(super) fn deny_all_browser(&self) {
        let requests: Vec<_> = {
            let mut queue = self.browser.borrow_mut();
            if let Some(timer) = queue.timer.take() {
                timer.stop();
                retire(timer);
            }
            queue.rows.clear();
            queue.matched.clear();
            queue.selected = None;
            queue
                .current
                .take()
                .into_iter()
                .chain(queue.pending.drain(..))
                .map(|item| item.request)
                .collect()
        };
        for request in requests {
            let _ = request.reply.send(BrowserReply::Dismissed);
        }
        if let Some(window) = self.browser_pair_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
        if let Some(window) = self.browser_save_prompt.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
        if let Some(window) = self.browser_picker.borrow_mut().take() {
            window.set_password("".into());
            hide(&window);
            retire(window);
            self.window_closed();
        }
    }

    pub(super) fn deny_browser_waiting_for_unlock(&self) {
        if !matches!(self.vault.state(), SessionState::Unlocked { .. }) {
            self.deny_all_browser();
        }
    }
}
