//! Password generator shared by the Manager slide-over and the standalone window.

use bwl_gen::generator::{PassphraseOptions, PasswordOptions};
use bwl_vault::VaultService;
use slint::{CloseRequestResponse, ComponentHandle, SharedString};
use zeroize::Zeroizing;

use super::{App, handler, hide, retire, show};
use crate::{
    settings::GeneratorPrefs,
    ui::{GeneratorState, GeneratorWindow},
};

#[derive(Default)]
pub(super) struct GeneratorCore {
    passphrase_mode: bool,
    password: PasswordOptions,
    passphrase: PassphraseOptions,
    /// Only the latest value is kept (no history): an earlier one is wiped when it is replaced.
    current: Zeroizing<String>,
}

impl GeneratorCore {
    pub(super) fn current(&self) -> &str {
        &self.current
    }

    /// Generated values are secrets of the account in use; logout and switch drop them.
    pub(super) fn clear(&mut self) {
        self.current = Zeroizing::new(String::new());
    }

    pub(super) fn strings(&self) -> Vec<String> {
        (!self.current.is_empty())
            .then(|| self.current.to_string())
            .into_iter()
            .collect()
    }

    fn push(&mut self, value: Zeroizing<String>) {
        self.current = value;
    }
}

impl GeneratorCore {
    /// Starts from the options saved last time, clamped like options read from the view.
    pub(super) fn from_prefs(prefs: &GeneratorPrefs) -> Self {
        Self {
            passphrase_mode: prefs.passphrase_mode,
            password: PasswordOptions {
                length: clamp_u8(i32::from(prefs.length), 5, 128),
                uppercase: prefs.uppercase,
                lowercase: prefs.lowercase,
                numbers: prefs.numbers,
                special: prefs.special,
                min_numbers: clamp_u8(i32::from(prefs.min_numbers), 0, 9),
                min_special: clamp_u8(i32::from(prefs.min_special), 0, 9),
                avoid_ambiguous: prefs.avoid_ambiguous,
            },
            passphrase: PassphraseOptions {
                words: clamp_u8(i32::from(prefs.words), 3, 20),
                separator: prefs.separator.clone(),
                capitalize: prefs.capitalize,
                include_number: prefs.include_number,
            },
            current: Zeroizing::new(String::new()),
        }
    }

    pub(super) fn prefs(&self) -> GeneratorPrefs {
        GeneratorPrefs {
            passphrase_mode: self.passphrase_mode,
            length: self.password.length,
            uppercase: self.password.uppercase,
            lowercase: self.password.lowercase,
            numbers: self.password.numbers,
            special: self.password.special,
            min_numbers: self.password.min_numbers,
            min_special: self.password.min_special,
            avoid_ambiguous: self.password.avoid_ambiguous,
            words: self.passphrase.words,
            separator: self.passphrase.separator.clone(),
            capitalize: self.passphrase.capitalize,
            include_number: self.passphrase.include_number,
        }
    }
}

fn clamp_u8(value: i32, min: u8, max: u8) -> u8 {
    u8::try_from(value.clamp(i32::from(min), i32::from(max))).unwrap_or(min)
}

/// Reads the options a generator view shows, clamped to the generator's valid ranges.
fn read_options(state: &GeneratorState<'_>) -> (bool, PasswordOptions, PassphraseOptions) {
    let password = PasswordOptions {
        length: clamp_u8(state.get_length(), 5, 128),
        uppercase: state.get_uppercase(),
        lowercase: state.get_lowercase(),
        numbers: state.get_numbers(),
        special: state.get_special(),
        min_numbers: clamp_u8(state.get_min_numbers(), 0, 9),
        min_special: clamp_u8(state.get_min_special(), 0, 9),
        avoid_ambiguous: state.get_avoid_ambiguous(),
    };
    let passphrase = PassphraseOptions {
        words: clamp_u8(state.get_words(), 3, 20),
        separator: state.get_separator().to_string(),
        capitalize: state.get_capitalize(),
        include_number: state.get_include_number(),
    };
    (state.get_mode() == 1, password, passphrase)
}

fn write_state(state: &GeneratorState<'_>, core: &GeneratorCore) {
    state.set_mode(i32::from(core.passphrase_mode));
    state.set_length(i32::from(core.password.length));
    state.set_uppercase(core.password.uppercase);
    state.set_lowercase(core.password.lowercase);
    state.set_numbers(core.password.numbers);
    state.set_special(core.password.special);
    state.set_min_numbers(i32::from(core.password.min_numbers));
    state.set_min_special(i32::from(core.password.min_special));
    state.set_avoid_ambiguous(core.password.avoid_ambiguous);
    state.set_words(i32::from(core.passphrase.words));
    state.set_separator(core.passphrase.separator.as_str().into());
    state.set_capitalize(core.passphrase.capitalize);
    state.set_include_number(core.passphrase.include_number);
    write_result(state, core);
}

fn write_result(state: &GeneratorState<'_>, core: &GeneratorCore) {
    state.set_result(core.current.as_str().into());
}

impl<S: VaultService> App<S> {
    pub(super) fn bind_generator(&self, state: &GeneratorState<'_>) {
        write_state(state, &self.generator.borrow());
        state.on_options_changed(handler!(self, |app| app.generator_options_changed()));
        state.on_regenerate(handler!(self, |app| app.regenerate()));
        state.on_copy_result(handler!(self, false, |app| {
            let value = Zeroizing::new(app.generator.borrow().current().to_owned());
            app.copy_text("generated password", &value)
        }));
        state.on_use_result(handler!(self, |app| {
            let value = Zeroizing::new(app.generator.borrow().current().to_owned());
            let target = app
                .manager
                .borrow()
                .as_ref()
                .map(|manager| manager.window.global::<GeneratorState>().get_use_target());
            if target.is_some_and(|target| app.use_generated(target, &value)) {
                app.close_detail_generator();
            }
        }));
    }

    /// Picks up option changes from whichever generator view sent them.
    fn generator_options_changed(&self) {
        let options = self
            .manager
            .borrow()
            .as_ref()
            .filter(|manager| manager.window.get_detail_mode() == 3)
            .map(|manager| read_options(&manager.window.global::<GeneratorState>()))
            .or_else(|| {
                self.generator_window
                    .borrow()
                    .as_ref()
                    .map(|window| read_options(&window.global::<GeneratorState>()))
            });
        if let Some((passphrase_mode, password, passphrase)) = options {
            let prefs = {
                let mut core = self.generator.borrow_mut();
                core.passphrase_mode = passphrase_mode;
                core.password = password;
                core.passphrase = passphrase;
                core.prefs()
            };
            // Kept for the next generator, also after this UI process has exited.
            if self.settings.borrow().generator != prefs {
                self.update_settings(|settings| settings.generator = prefs);
            }
        }
        self.regenerate();
    }

    pub(super) fn regenerate(&self) {
        let (passphrase_mode, password, passphrase) = {
            let core = self.generator.borrow();
            (
                core.passphrase_mode,
                core.password.clone(),
                core.passphrase.clone(),
            )
        };
        let result = if passphrase_mode {
            self.hooks.generator.passphrase(&passphrase)
        } else {
            self.hooks.generator.password(&password)
        };
        let error = match result {
            Ok(value) => {
                self.generator.borrow_mut().push(value);
                SharedString::new()
            }
            Err(error) => error.to_string().into(),
        };
        self.refresh_generator_views();
        self.for_each_generator(|state| state.set_error(error.clone()));
    }

    pub(super) fn refresh_generator_views(&self) {
        let core = self.generator.borrow();
        self.for_each_generator(|state| write_result(state, &core));
    }

    fn for_each_generator(&self, apply: impl Fn(&GeneratorState<'_>)) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            apply(&manager.window.global::<GeneratorState>());
        }
        if let Some(window) = self.generator_window.borrow().as_ref() {
            apply(&window.global::<GeneratorState>());
        }
    }

    pub fn open_generator_window(&self) {
        let existing = self
            .generator_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = existing {
            show(&window, "generator");
            return;
        }
        let window = match GeneratorWindow::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create the generator window");
                return;
            }
        };
        self.apply_theme(&window);
        self.bind_generator(&window.global::<GeneratorState>());
        window.window().on_close_requested(handler!(
            self,
            CloseRequestResponse::HideWindow,
            |app| {
                if let Some(window) = app.generator_window.borrow_mut().take() {
                    hide(&window);
                    retire(window);
                    app.window_closed();
                }
                CloseRequestResponse::HideWindow
            }
        ));
        show(&window, "generator");
        *self.generator_window.borrow_mut() = Some(window);
        if self.generator.borrow().current().is_empty() {
            self.regenerate();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_latest_value_is_kept() {
        let mut core = GeneratorCore::default();
        for index in 0..15 {
            core.push(Zeroizing::new(format!("v{index}")));
        }
        assert_eq!(core.current(), "v14");
        assert_eq!(core.strings(), ["v14"]);
        core.clear();
        assert_eq!(core.strings(), Vec::<String>::new());
    }

    #[test]
    fn saved_options_round_trip_and_are_clamped_on_load() {
        let prefs = GeneratorPrefs {
            passphrase_mode: true,
            length: 200,
            min_numbers: 42,
            words: 1,
            separator: "+".to_owned(),
            ..GeneratorPrefs::default()
        };
        let core = GeneratorCore::from_prefs(&prefs);
        assert!(core.passphrase_mode);
        assert_eq!(core.password.length, 128);
        assert_eq!(core.password.min_numbers, 9);
        assert_eq!(core.passphrase.words, 3);
        assert_eq!(core.passphrase.separator, "+");
        let back = core.prefs();
        assert_eq!(
            (back.length, back.min_numbers, back.words),
            (128, 9, 3),
            "the clamped values are what gets saved"
        );
        assert_eq!(GeneratorCore::from_prefs(&back).prefs(), back);
    }

    #[test]
    fn clamps_options() {
        assert_eq!(clamp_u8(3, 5, 128), 5);
        assert_eq!(clamp_u8(500, 5, 128), 128);
        assert_eq!(clamp_u8(-1, 0, 9), 0);
        assert_eq!(clamp_u8(7, 0, 9), 7);
    }
}
