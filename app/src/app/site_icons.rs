//! Loads website icons for the rows on screen, after scrolling or typing has paused. Fetching
//! and decoding run off the UI thread; the UI thread only wraps finished pixels in an `Image` and
//! redraws the rows that show that host.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    ops::Range,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use slint::{ComponentHandle, Image, Rgba8Pixel, SharedPixelBuffer, Timer, TimerMode};
use vk_vault::VaultService;

use super::{App, handler, quick::QUICK_ROWS};
use crate::{
    hooks::SiteIcon,
    site_icon::{IconCache, Slot, decode},
};

/// Icons start loading once the list has been still this long, so a fast scroll or a burst of
/// keystrokes requests nothing for the rows it passes.
const SETTLE: Duration = Duration::from_millis(150);
/// The daemon runs 8 calls per UI connection, and searches and copies block the UI thread on
/// one; icons may take at most these, whatever the server's speed.
const MAX_IN_FLIGHT: usize = 2;
/// The row slot's side in logical pixels at the default text size.
const ICON_POINTS: f32 = 22.0;
/// Before a window reports its screen's scale factor: a Retina screen.
const DEFAULT_BACKING_SCALE: f32 = 2.0;

enum Loaded {
    Icon(SharedPixelBuffer<Rgba8Pixel>),
    /// No icon, or one that does not decode: the kind chip stays.
    Missing,
    /// Locked, offline or a server error: the host may be asked again at the next settle.
    Retry,
}

#[derive(Default)]
pub(super) struct SiteIcons {
    pub(super) cache: Rc<IconCache>,
    queue: RefCell<VecDeque<Arc<str>>>,
    in_flight: Cell<usize>,
    /// Moves when loaded icons must be forgotten (lock, account change, switched off), so loads
    /// started before it are dropped when they finish.
    generation: Cell<u64>,
    settle: Timer,
}

impl<S: VaultService> App<S> {
    fn site_icons_on(&self) -> bool {
        self.settings.borrow().show_site_icons
    }

    /// Restarts the settle timer; called whenever the rows on screen may have changed.
    pub(super) fn schedule_site_icons(&self) {
        if !self.site_icons_on() {
            return;
        }
        self.site_icons.settle.start(
            TimerMode::SingleShot,
            SETTLE,
            handler!(self, |app| app.load_site_icons()),
        );
    }

    /// Queues the icons of the rows on screen that are not loaded or loading yet.
    pub(super) fn load_site_icons(&self) {
        if !self.site_icons_on() {
            return;
        }
        let wanted = self.hosts_on_screen();
        let icons = &self.site_icons;
        icons.cache.show(&wanted);
        let mut queue = icons.queue.borrow_mut();
        queue.retain(|host| wanted.contains(host));
        for host in wanted {
            if !icons.cache.has(&host) {
                icons.cache.set(Arc::clone(&host), Slot::Queued);
                queue.push_back(host);
            }
        }
        drop(queue);
        self.pump_site_icons();
    }

    fn hosts_on_screen(&self) -> Vec<Arc<str>> {
        let mut hosts = self
            .manager_icon_range()
            .and_then(|range| {
                self.manager
                    .borrow()
                    .as_ref()
                    .map(|manager| manager.rows.icon_hosts(range))
            })
            .unwrap_or_default();
        if let Some(quick) = self.quick.borrow().as_ref() {
            for host in quick.rows.icon_hosts(0..QUICK_ROWS) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        for host in self.browser_icon_hosts() {
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts
    }

    fn manager_icon_range(&self) -> Option<Range<usize>> {
        self.manager.borrow().as_ref().map(|manager| {
            let first = usize::try_from(manager.window.get_first_visible()).unwrap_or(0);
            let count = usize::try_from(manager.window.get_visible_count()).unwrap_or(0);
            first..first + count
        })
    }

    fn pump_site_icons(&self) {
        let icons = &self.site_icons;
        let side = icon_side(
            self.settings.borrow().text_scale.factor(),
            self.backing_scale(),
        );
        while icons.in_flight.get() < MAX_IN_FLIGHT {
            let Some(host) = icons.queue.borrow_mut().pop_front() else {
                break;
            };
            icons.cache.set(Arc::clone(&host), Slot::Loading);
            icons.in_flight.set(icons.in_flight.get() + 1);
            let generation = icons.generation.get();
            let fetch = self.hooks.site_icons.fetch(&host);
            self.exec.spawn(
                async move {
                    match fetch.await {
                        SiteIcon::Found(bytes) => {
                            tokio::task::spawn_blocking(move || decode(&bytes, side))
                                .await
                                .ok()
                                .flatten()
                                .map_or(Loaded::Missing, Loaded::Icon)
                        }
                        SiteIcon::Missing => Loaded::Missing,
                        SiteIcon::Unavailable => Loaded::Retry,
                    }
                },
                handler!(self, |app, loaded| app
                    .site_icon_loaded(&host, generation, loaded)),
            );
        }
    }

    fn site_icon_loaded(&self, host: &str, generation: u64, loaded: Loaded) {
        let icons = &self.site_icons;
        icons.in_flight.set(icons.in_flight.get().saturating_sub(1));
        if generation == icons.generation.get() {
            match loaded {
                Loaded::Icon(pixels) => {
                    let image = Image::from_rgba8_premultiplied(pixels);
                    icons.cache.set(Arc::from(host), Slot::Ready(image));
                    self.redraw_icon_rows(host);
                }
                Loaded::Missing => icons.cache.set(Arc::from(host), Slot::Missing),
                Loaded::Retry => icons.cache.forget(host),
            }
        }
        self.pump_site_icons();
    }

    fn backing_scale(&self) -> f32 {
        let manager = self
            .manager
            .borrow()
            .as_ref()
            .map(|manager| manager.window.window().scale_factor());
        let quick = || {
            self.quick
                .borrow()
                .as_ref()
                .map(|quick| quick.window.window().scale_factor())
        };
        let picker = || {
            self.browser_picker
                .borrow()
                .as_ref()
                .map(|picker| picker.window().scale_factor())
        };
        manager
            .or_else(quick)
            .or_else(picker)
            .filter(|scale| (1.0..=4.0).contains(scale))
            .unwrap_or(DEFAULT_BACKING_SCALE)
    }

    fn redraw_icon_rows(&self, host: &str) {
        if let Some(range) = self.manager_icon_range()
            && let Some(manager) = self.manager.borrow().as_ref()
        {
            manager.rows.icon_loaded(host, range);
        }
        if let Some(quick) = self.quick.borrow().as_ref() {
            quick.rows.icon_loaded(host, 0..QUICK_ROWS);
        }
        self.browser_icon_loaded(host);
    }

    /// Drops every loaded and queued icon; loads in flight are ignored when they finish.
    pub(super) fn forget_site_icons(&self) {
        let icons = &self.site_icons;
        icons.settle.stop();
        icons.generation.set(icons.generation.get().wrapping_add(1));
        icons.queue.borrow_mut().clear();
        icons.cache.clear();
    }

    /// "Show site icons" changed: rows switch at once through `Theme.site-icons`.
    pub(super) fn site_icons_changed(&self) {
        if self.site_icons_on() {
            self.load_site_icons();
        } else {
            self.forget_site_icons();
        }
    }
}

/// Pixels per side for the row slot at `text_scale` on a screen of `backing_scale`, so the
/// renderer draws icons 1:1.
fn icon_side(text_scale: f32, backing_scale: f32) -> u32 {
    // At most 22 * 1.3 * 4 ≈ 115, so the cast cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let side = (ICON_POINTS * text_scale * backing_scale).ceil() as u32;
    side
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_side_follows_the_text_size() {
        assert_eq!(icon_side(1.0, 2.0), 44);
        assert_eq!(icon_side(1.15, 2.0), 51);
        assert_eq!(icon_side(1.3, 2.0), 58);
        assert_eq!(icon_side(1.0, 1.0), 22);
    }
}
