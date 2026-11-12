//! The single 1 s timer behind the detail pane's TOTP ring and code. It runs only while the
//! detail pane shows a code; list rows only offer a copy button and never compute codes.

use std::time::Duration;

use slint::{ComponentHandle, Timer, TimerMode};
use vk_vault::VaultService;

use super::{App, handler};
use crate::ui::Clock;

#[derive(Default)]
pub(super) struct Ticker {
    timer: Timer,
}

impl Ticker {
    pub(super) fn running(&self) -> bool {
        self.timer.running()
    }
}

impl<S: VaultService> App<S> {
    pub(super) fn update_ticker(&self) {
        let needed = self.detail_has_totp();
        if needed && !self.ticker.timer.running() {
            self.ticker.timer.start(
                TimerMode::Repeated,
                Duration::from_secs(1),
                handler!(self, |app| app.refresh_totp()),
            );
        } else if !needed && self.ticker.timer.running() {
            self.ticker.timer.stop();
        }
    }

    /// Advances `Clock.now` on the manager and refills the detail code once it expires.
    pub(super) fn refresh_totp(&self) {
        let now = self.ui_now();
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.global::<Clock>().set_now(now);
        }
        self.refresh_detail_totp();
        self.update_ticker();
    }
}
