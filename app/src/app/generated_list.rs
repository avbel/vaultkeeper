//! The Generator's list of passwords generated in the browser that no login holds yet.

use slint::{ModelRc, SharedString, VecModel};
use vk_vault::VaultService;

use super::{App, handler};
use crate::{
    hooks::{GeneratedDto, HookResult},
    ui::{GeneratorState, UnsavedRow},
};

const SAVED: &str = "Saved as a login. Add its username in the vault.";

impl<S: VaultService> App<S> {
    pub(super) fn bind_unsaved(&self, state: &GeneratorState<'_>) {
        state.on_copy_unsaved(handler!(self, |app, id| app.copy_unsaved(id)));
        state.on_save_unsaved(handler!(self, |app, id| app.save_unsaved(id)));
        state.on_forget_unsaved(handler!(self, |app, id| app.forget_unsaved(id)));
    }

    pub(super) fn refresh_unsaved(&self) {
        self.exec.spawn(
            self.hooks.generated.list(),
            handler!(self, |app, result| app.show_unsaved(result)),
        );
    }

    fn show_unsaved(&self, result: HookResult<Vec<GeneratedDto>>) {
        let entries = result.unwrap_or_else(|error| {
            tracing::warn!(%error, "cannot list the generated passwords");
            Vec::new()
        });
        let now = self.hooks.clock.unix_now();
        let rows: Vec<UnsavedRow> = entries
            .iter()
            .filter_map(|entry| {
                Some(UnsavedRow {
                    id: i32::try_from(entry.id).ok()?,
                    host: entry.host.as_str().into(),
                    age: age(now, entry.created_unix).into(),
                })
            })
            .collect();
        let model = ModelRc::new(VecModel::from(rows));
        self.for_each_generator(|state| state.set_unsaved(model.clone()));
    }

    fn unsaved_status(&self, text: &str) {
        let text = SharedString::from(text);
        self.for_each_generator(|state| state.set_unsaved_status(text.clone()));
    }

    fn copy_unsaved(&self, id: i32) {
        let Ok(id) = u64::try_from(id) else {
            return;
        };
        self.exec.spawn(
            self.hooks.generated.reveal(id),
            handler!(self, |app, result| match result {
                Ok(password) => {
                    if app.copy_text("generated password", &password) {
                        app.unsaved_status("Password copied");
                    }
                }
                Err(error) => app.unsaved_status(&format!("Could not copy: {error}")),
            }),
        );
    }

    fn save_unsaved(&self, id: i32) {
        let Ok(id) = u64::try_from(id) else {
            return;
        };
        self.exec.spawn(
            self.hooks.generated.save(id),
            handler!(self, |app, result| {
                match result {
                    Ok(()) => app.unsaved_status(SAVED),
                    Err(error) => app.unsaved_status(&format!("Could not save: {error}")),
                }
                app.refresh_unsaved();
            }),
        );
    }

    fn forget_unsaved(&self, id: i32) {
        let Ok(id) = u64::try_from(id) else {
            return;
        };
        self.exec.spawn(
            self.hooks.generated.forget(id),
            handler!(self, |app, result| {
                if let Err(error) = result {
                    app.unsaved_status(&format!("Could not remove: {error}"));
                }
                app.refresh_unsaved();
            }),
        );
    }
}

fn age(now: u64, created: u64) -> String {
    let minutes = now.saturating_sub(created) / 60;
    match minutes {
        0 => "Just now".to_owned(),
        1..60 => format!("{minutes} min ago"),
        _ => format!("{} h ago", minutes / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::age;

    #[test]
    fn ages_read_in_minutes_then_hours() {
        assert_eq!(age(1_000, 1_000), "Just now");
        assert_eq!(age(1_000 + 5 * 60, 1_000), "5 min ago");
        assert_eq!(age(1_000 + 3 * 3600 + 59, 1_000), "3 h ago");
        assert_eq!(age(0, 1_000), "Just now");
    }
}
