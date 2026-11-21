//! Start-up permission checks on the data directory and the files that hold account secrets
//! (windows-support.md §4.4, linux-plan.md 2a). The checks live in vk-platform; on macOS they do
//! nothing, so it starts exactly as before.

use std::path::{Path, PathBuf};

use vk_platform::fs::{self, Refusal, Repair};

use crate::os::layout::{
    BROWSER_CHOICES_FILE, BROWSER_PAIRINGS_FILE, CLIPBOARD_PORTAL_TOKEN_FILE, DEVICE_FILE,
    SETTINGS_FILE,
};

const ACCOUNTS_FILE: &str = "accounts.json";
const ACCOUNTS_DIR: &str = "accounts";
const DATA_DIR_FILES: [&str; 6] = [
    ACCOUNTS_FILE,
    BROWSER_PAIRINGS_FILE,
    BROWSER_CHOICES_FILE,
    SETTINGS_FILE,
    DEVICE_FILE,
    CLIPBOARD_PORTAL_TOKEN_FILE,
];
/// The files of one account directory that carry secrets or the key to them: the cache header,
/// the sealed tokens and the Windows Hello enrolment.
const ACCOUNT_FILES: [&str; 5] = [
    "account.json",
    "vault.json",
    "refresh_token.enc",
    "two_factor_remember.enc",
    "touchid.bin",
];

/// Checks the data directory and its secret files, logging every repair. A refusal is logged,
/// shown to the user and returned, so the caller stops instead of using a directory that may not
/// be ours.
pub fn enforce(data_dir: &Path) -> anyhow::Result<()> {
    match verify(data_dir) {
        Ok(Repair::None) => Ok(()),
        Ok(repair) => {
            tracing::warn!(?repair, dir = %data_dir.display(), "repaired the permissions of the data directory");
            Ok(())
        }
        Err(refusal) => {
            tracing::error!(%refusal, "the data directory is not safe to use");
            show_refusal(&refusal);
            Err(anyhow::Error::new(refusal)
                .context("the Vaultkeeper data directory is not safe to use"))
        }
    }
}

fn verify(data_dir: &Path) -> Result<Repair, Refusal> {
    let dir = fs::verify_private_dir(data_dir)?;
    let mut repair = merge(dir, Repair::None);
    for account_dir in account_dirs(data_dir) {
        repair = merge(repair, fs::verify_private_dir(&account_dir)?);
    }
    let files = fs::verify_private_files(&secret_files(data_dir))?;
    Ok(merge(repair, files))
}

fn merge(first: Repair, second: Repair) -> Repair {
    match (first, second) {
        (Repair::None, other) | (other, Repair::None) => other,
        (
            Repair::Rewritten {
                dacl,
                label,
                attribute,
            },
            Repair::Rewritten {
                dacl: dacl2,
                label: label2,
                attribute: attribute2,
            },
        ) => Repair::Rewritten {
            dacl: dacl || dacl2,
            label: label || label2,
            attribute: attribute || attribute2,
        },
    }
}

/// Files that may exist; a missing one is skipped by the check. An unreadable accounts directory
/// is not an error here: the vault reports it when it opens the cache.
fn secret_files(data_dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = DATA_DIR_FILES
        .iter()
        .map(|name| data_dir.join(name))
        .collect();
    for dir in account_dirs(data_dir) {
        files.extend(ACCOUNT_FILES.iter().map(|name| dir.join(name)));
    }
    files
}

fn account_dirs(data_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(data_dir.join(ACCOUNTS_DIR)) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| !kind.is_file()))
        .map(|entry| entry.path())
        .collect()
}

#[cfg(windows)]
fn show_refusal(refusal: &Refusal) {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("Vaultkeeper cannot start")
        .set_description(format!(
            "The Vaultkeeper data directory is not safe to use, so Vaultkeeper will not start.\n\n\
             {refusal}\n\n\
             Remove the entry from its permissions or restore the folder from a trusted backup, \
             then start Vaultkeeper again."
        ))
        .show();
}

#[cfg(not(windows))]
fn show_refusal(_refusal: &Refusal) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_the_secret_files_of_every_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("accounts/a1")).expect("account dir");
        let files = secret_files(dir.path());
        assert!(files.contains(&dir.path().join("accounts.json")));
        assert!(files.contains(&dir.path().join("accounts/a1/refresh_token.enc")));
        assert!(files.contains(&dir.path().join("accounts/a1/touchid.bin")));
    }

    #[test]
    fn a_missing_accounts_directory_leaves_the_top_level_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let files = secret_files(dir.path());
        assert_eq!(files.len(), DATA_DIR_FILES.len());
        assert!(files.contains(&dir.path().join("accounts.json")));
        assert!(files.contains(&dir.path().join("browsers.json")));
        assert!(files.contains(&dir.path().join("settings.json")));
    }

    #[test]
    fn enforce_accepts_a_fresh_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        vk_platform::fs::ensure_private_dir(dir.path()).expect("private dir");
        enforce(dir.path()).expect("enforce");
    }

    #[test]
    fn repairs_merge_by_flag() {
        let one = Repair::Rewritten {
            dacl: true,
            label: false,
            attribute: false,
        };
        let two = Repair::Rewritten {
            dacl: false,
            label: false,
            attribute: true,
        };
        assert_eq!(
            merge(one, two),
            Repair::Rewritten {
                dacl: true,
                label: false,
                attribute: true
            }
        );
        assert_eq!(merge(Repair::None, one), one);
    }
}
