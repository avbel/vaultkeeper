//! Settings → Browsers: the master switch, per-browser installs, fill and save options and the
//! list of paired browsers.

use slint::{ModelRc, VecModel};
use vk_ipc::browser::protocol::KnownBrowser;
use vk_vault::VaultService;

use super::{App, handler};
use crate::{
    browser_status,
    daemon::browser::manifests::ManifestBrowser,
    settings::{BrowserMatch, Settings},
    ui::{PairedBrowserRow, SettingsWindow},
};

const fn browser_name(browser: KnownBrowser) -> &'static str {
    match browser {
        KnownBrowser::Chrome => "Google Chrome",
        KnownBrowser::Firefox => "Firefox",
    }
}

const fn match_index(mode: BrowserMatch) -> i32 {
    match mode {
        BrowserMatch::Domain => 0,
        BrowserMatch::Host => 1,
    }
}

const fn match_mode(index: i32) -> BrowserMatch {
    if index == 1 {
        BrowserMatch::Host
    } else {
        BrowserMatch::Domain
    }
}

fn show_state(window: &SettingsWindow, settings: &Settings) {
    window.set_browser_integration(settings.browser_integration);
    window.set_browser_state(
        browser_status::state_line(
            settings.browser_integration,
            browser_status::start_blocker(),
        )
        .into(),
    );
}

impl<S: VaultService> App<S> {
    pub(super) fn fill_browser_settings(&self, window: &SettingsWindow, settings: &Settings) {
        show_state(window, settings);
        let installed = self.hooks.browsers.installed();
        window.set_chrome_installed(installed.contains(&ManifestBrowser::Chrome));
        window.set_firefox_installed(installed.contains(&ManifestBrowser::Firefox));
        window.set_browser_chrome(settings.browser_chrome);
        window.set_browser_firefox(settings.browser_firefox);
        window.set_browser_touch_id(settings.browser_touch_id);
        window.set_browser_save_prompts(settings.browser_save_prompts);
        window.set_browser_copy_totp(settings.browser_copy_totp);
        window.set_browser_fill_single(settings.browser_fill_single);
        window.set_browser_passkeys(settings.browser_passkeys);
        window.set_browser_match_index(match_index(settings.browser_default_match));
        self.show_paired_browsers(window);
    }

    fn show_paired_browsers(&self, window: &SettingsWindow) {
        let rows: Vec<PairedBrowserRow> = self
            .hooks
            .browsers
            .paired()
            .into_iter()
            .map(|entry| PairedBrowserRow {
                name: browser_name(entry.browser).into(),
                fingerprint: entry.fingerprint.into(),
                key: entry.public_key.into(),
            })
            .collect();
        window.set_paired_browsers(ModelRc::new(VecModel::from(rows)));
    }

    pub(super) fn bind_browser_settings(&self, window: &SettingsWindow) {
        window.on_browser_integration_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_integration = enabled);
            if let Some(window) = app.settings_window.borrow().as_ref() {
                show_state(window, &app.settings.borrow());
            }
        }));
        window.on_browser_chrome_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_chrome = enabled);
        }));
        window.on_browser_firefox_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_firefox = enabled);
        }));
        window.on_browser_touch_id_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_touch_id = enabled);
        }));
        window.on_browser_save_prompts_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_save_prompts = enabled);
        }));
        window.on_browser_copy_totp_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_copy_totp = enabled);
        }));
        window.on_browser_fill_single_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_fill_single = enabled);
        }));
        window.on_browser_passkeys_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.browser_passkeys = enabled);
        }));
        window.on_browser_match_selected(handler!(self, |app, index| {
            app.update_settings(|settings| settings.browser_default_match = match_mode(index));
        }));
        window.on_paired_browser_removed(handler!(self, |app, key| {
            app.report(app.hooks.browsers.remove(&key));
            if let Some(window) = app.settings_window.borrow().as_ref() {
                app.show_paired_browsers(window);
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_choice_round_trips_through_the_segmented_index() {
        for mode in [BrowserMatch::Domain, BrowserMatch::Host] {
            assert_eq!(match_mode(match_index(mode)), mode);
        }
        assert_eq!(match_mode(7), BrowserMatch::Domain);
    }
}
