//! The single 1 s timer behind TOTP rings and codes. It runs only while a window shows TOTP rows
//! (or the detail pane shows a code) and recomputes codes only for visible rows whose code expired.

use std::{ops::Range, time::Duration};

use bwl_vault::VaultService;
use slint::{ComponentHandle, Timer, TimerMode};

use super::{App, handler, quick::QUICK_ROWS};
use crate::{
    rows::RowsModel,
    ui::Clock,
    viewmodel::{TotpCell, group_code},
};

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
    fn manager_visible_range(&self) -> Option<Range<usize>> {
        self.manager.borrow().as_ref().map(|manager| {
            let first = usize::try_from(manager.window.get_first_visible()).unwrap_or(0);
            let count = usize::try_from(manager.window.get_visible_count()).unwrap_or(0);
            first..first + count
        })
    }

    fn totp_needed(&self) -> bool {
        let manager_rows = self.manager_visible_range().is_some_and(|range| {
            self.manager
                .borrow()
                .as_ref()
                .is_some_and(|manager| manager.rows.has_totp_in(range))
        });
        let quick_rows = self
            .quick
            .borrow()
            .as_ref()
            .is_some_and(|quick| quick.rows.has_totp_in(0..QUICK_ROWS));
        manager_rows || quick_rows || self.detail_has_totp()
    }

    pub(super) fn update_ticker(&self) {
        let needed = self.totp_needed();
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

    /// Advances `Clock.now` on windows showing codes and refills expired visible codes.
    pub(super) fn refresh_totp(&self) {
        let now = self.ui_now();
        let unix = self.hooks.clock.unix_now();
        if let Some(range) = self.manager_visible_range() {
            let rows = self.manager.borrow().as_ref().map(|manager| {
                manager.window.global::<Clock>().set_now(now);
                std::rc::Rc::clone(&manager.rows)
            });
            if let Some(rows) = rows {
                self.fill_codes(&rows, range, now, unix);
            }
        }
        let rows = self.quick.borrow().as_ref().map(|quick| {
            quick.window.global::<Clock>().set_now(now);
            std::rc::Rc::clone(&quick.rows)
        });
        if let Some(rows) = rows {
            self.fill_codes(&rows, 0..QUICK_ROWS, now, unix);
        }
        self.refresh_detail_totp();
        self.update_ticker();
    }

    fn fill_codes(&self, rows: &RowsModel, range: Range<usize>, now: i32, unix: u64) {
        for (row, id) in rows.stale_totp_rows(range, now) {
            if rows
                .item(row)
                .is_some_and(|item| !self.reprompt_cleared(&item))
            {
                continue;
            }
            match self.vault.totp(&id, unix) {
                Ok(code) => rows.set_totp(
                    row,
                    TotpCell {
                        code: group_code(&code.code).into(),
                        expires: now + i32::try_from(code.remaining).unwrap_or(30),
                        period: i32::try_from(code.period).unwrap_or(30),
                    },
                ),
                Err(error) => tracing::debug!(%error, "no TOTP for row"),
            }
        }
    }
}
