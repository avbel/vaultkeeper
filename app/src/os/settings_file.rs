//! `settings.json`: shared by the daemon (hotkey, lock timeout, SSH agent, theme of the tray) and
//! the UI process (everything else). Whoever writes it tells the other process to re-read it.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    hooks::{HookError, HookResult, SettingsStore},
    settings::Settings,
};

pub struct SettingsFile {
    path: PathBuf,
    after_save: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl SettingsFile {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            after_save: None,
        }
    }

    /// `after_save` runs after every successful write (the UI process notifies the daemon).
    #[must_use]
    pub fn with_after_save(path: PathBuf, after_save: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            path,
            after_save: Some(after_save),
        }
    }

    /// Defaults when the file is missing; a corrupt file is logged and also read as defaults.
    #[must_use]
    pub fn read(path: &Path) -> Settings {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Settings>(&bytes) {
                Ok(settings) => settings.sanitized(),
                Err(error) => {
                    tracing::warn!(%error, path = %path.display(), "unreadable settings; using defaults");
                    Settings::default()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Settings::default(),
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "cannot read settings; using defaults");
                Settings::default()
            }
        }
    }

    pub fn write(path: &Path, settings: &Settings) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(settings).map_err(io::Error::other)?;
        super::fs::write_private(path, &json)
    }
}

impl SettingsStore for SettingsFile {
    fn load(&self) -> Settings {
        Self::read(&self.path)
    }

    fn save(&self, settings: &Settings) -> HookResult<()> {
        Self::write(&self.path, settings)
            .map_err(|error| HookError::Failed(format!("Settings not saved: {error}")))?;
        if let Some(after_save) = &self.after_save {
            after_save();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::settings::{LockTimeout, ThemeChoice};

    #[test]
    fn a_saved_file_loads_back_and_notifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        let saves = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&saves);
        let store = SettingsFile::with_after_save(
            path.clone(),
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );
        assert_eq!(store.load(), Settings::default(), "missing file");
        let changed = Settings {
            theme: ThemeChoice::Dark,
            lock_timeout: LockTimeout::Minutes(5),
            ..Settings::default()
        };
        store.save(&changed).expect("save");
        assert_eq!(saves.load(Ordering::SeqCst), 1);
        assert_eq!(
            SettingsFile::new(path).load(),
            changed,
            "another process reads it"
        );
    }

    #[test]
    fn a_corrupt_file_reads_as_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"{not json").expect("write");
        assert_eq!(SettingsFile::read(&path), Settings::default());
    }

    #[test]
    fn a_failed_save_is_reported_and_does_not_notify() {
        let dir = tempfile::tempdir().expect("tempdir");
        let saves = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&saves);
        let store = SettingsFile::with_after_save(
            dir.path().join("missing/settings.json"),
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );
        assert!(matches!(
            store.save(&Settings::default()),
            Err(HookError::Failed(_))
        ));
        assert_eq!(saves.load(Ordering::SeqCst), 0);
    }
}
