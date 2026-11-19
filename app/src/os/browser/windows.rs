//! Per-user native-messaging registration on Windows (§7.8): a manifest file under the data dir
//! plus the registry default value that points a browser at it.

use std::{fs, io, path::Path, ptr};

use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR},
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW,
    },
};

use crate::daemon::browser::manifests::{
    Existing, ExtensionIds, ManifestBrowser, Outcome, WINDOWS_MANIFESTS_DIR, existing_state,
    names_missing_host, render, write_atomic,
};

/// Owns a registry key so every early return still closes it exactly once.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from `RegCreateKeyExW` and nothing else owns it.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

const REGISTRY_BASE: &str = "Software";

pub fn install(
    root: &Path,
    browser: ManifestBrowser,
    exe_path: &Path,
    ids: &ExtensionIds<'_>,
) -> io::Result<Outcome> {
    install_under(REGISTRY_BASE, root, browser, exe_path, ids)
}

pub fn remove(root: &Path, browser: ManifestBrowser) -> io::Result<()> {
    remove_under(REGISTRY_BASE, root, browser)
}

#[must_use]
pub fn check_and_restore(
    root: &Path,
    enabled: &[ManifestBrowser],
    exe_path: &Path,
    ids: &ExtensionIds<'_>,
) -> Vec<(ManifestBrowser, io::Result<Outcome>)> {
    check_and_restore_under(REGISTRY_BASE, root, enabled, exe_path, ids)
}

fn install_under(
    base: &str,
    root: &Path,
    browser: ManifestBrowser,
    exe_path: &Path,
    ids: &ExtensionIds<'_>,
) -> io::Result<Outcome> {
    let wanted = render(browser, exe_path, ids);
    let dir = root.join(WINDOWS_MANIFESTS_DIR);
    let target = browser.windows_manifest_path(root);
    let outcome = match existing_state(&target, &wanted)? {
        Existing::Matches => Outcome::Unchanged,
        Existing::Missing => {
            fs::create_dir_all(&dir)?;
            write_atomic(&dir, &target, &wanted)?;
            Outcome::Written
        }
        Existing::Differs => {
            let relocated = names_missing_host(&target);
            fs::create_dir_all(&dir)?;
            write_atomic(&dir, &target, &wanted)?;
            if relocated {
                Outcome::Written
            } else {
                Outcome::Restored
            }
        }
    };
    // The registry value is written every time so a manually moved pointer is corrected silently.
    set_default_value(&browser.registry_key_under(base), &target)?;
    Ok(outcome)
}

fn remove_under(base: &str, root: &Path, browser: ManifestBrowser) -> io::Result<()> {
    delete_key(&browser.registry_key_under(base))?;
    match fs::remove_file(browser.windows_manifest_path(root)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn check_and_restore_under(
    base: &str,
    root: &Path,
    enabled: &[ManifestBrowser],
    exe_path: &Path,
    ids: &ExtensionIds<'_>,
) -> Vec<(ManifestBrowser, io::Result<Outcome>)> {
    enabled
        .iter()
        .map(|&browser| (browser, install_under(base, root, browser, exe_path, ids)))
        .collect()
}

fn set_default_value(subkey: &str, manifest: &Path) -> io::Result<()> {
    let key = create_key(subkey)?;
    let data = wide_bytes(&manifest.to_string_lossy());
    let len = u32::try_from(data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "manifest path is longer than 4 GiB",
        )
    })?;
    // SAFETY: the key is open with KEY_SET_VALUE, a null value name writes the default value and
    // `data` stays alive for `len` bytes across the call.
    let status = unsafe { RegSetValueExW(key.0, ptr::null(), 0, REG_SZ, data.as_ptr(), len) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(os_error(status))
    }
}

fn create_key(subkey: &str) -> io::Result<Key> {
    let subkey = wide(subkey);
    let mut handle = ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: `subkey` is NUL-terminated and outlives the call; the class and security attributes
    // are optional and passed as null, and both out-pointers are valid for the call.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &raw mut handle,
            &raw mut disposition,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(Key(handle))
    } else {
        Err(os_error(status))
    }
}

fn delete_key(subkey: &str) -> io::Result<()> {
    let subkey = wide(subkey);
    // SAFETY: `subkey` is NUL-terminated and outlives the call; deleting the `<name>` key removes
    // the default value with it.
    let status = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, subkey.as_ptr()) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(os_error(status))
    }
}

fn os_error(status: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(status.cast_signed())
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use windows_sys::Win32::System::Registry::{RRF_RT_REG_SZ, RegDeleteTreeW, RegGetValueW};

    use super::*;

    const ALL: [ManifestBrowser; 5] = [
        ManifestBrowser::Chrome,
        ManifestBrowser::Chromium,
        ManifestBrowser::Brave,
        ManifestBrowser::Edge,
        ManifestBrowser::Firefox,
    ];

    /// A throwaway `HKCU\Software\VaultkeeperTest-<pid>-<n>`, deleted even when a test panics.
    struct TestBase(String);

    impl TestBase {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            Self(format!(
                "Software\\VaultkeeperTest-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
        }

        fn value(&self, browser: ManifestBrowser) -> Option<String> {
            read_default(&browser.registry_key_under(&self.0))
        }
    }

    impl Drop for TestBase {
        fn drop(&mut self) {
            let base = wide(&self.0);
            // SAFETY: `base` is NUL-terminated and outlives the call.
            let _ = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, base.as_ptr()) };
            // SAFETY: as above; the tree is gone, this removes the now empty base key itself.
            let _ = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, base.as_ptr()) };
        }
    }

    fn read_default(subkey: &str) -> Option<String> {
        let subkey = wide(subkey);
        let mut buffer = [0u16; 1024];
        let mut size = u32::try_from(size_of_val(&buffer)).ok()?;
        // SAFETY: `subkey` is NUL-terminated, a null value name reads the default value and
        // `buffer` is valid for `size` bytes, which the call updates to the bytes written.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                ptr::null(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        let units = (size as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&buffer[..units]))
    }

    fn exe() -> std::path::PathBuf {
        std::path::PathBuf::from(r"C:\Program Files\Vaultkeeper\vaultkeeper.exe")
    }

    #[test]
    fn install_writes_every_browsers_key_and_manifest() {
        let base = TestBase::new();
        let root = tempfile::tempdir().expect("temp dir");
        for browser in ALL {
            let outcome = install_under(
                &base.0,
                root.path(),
                browser,
                &exe(),
                &ExtensionIds::DEFAULT,
            )
            .expect("install");
            assert_eq!(outcome, Outcome::Written);
            let manifest = browser.windows_manifest_path(root.path());
            assert!(manifest.is_file(), "{browser:?} manifest");
            assert_eq!(
                base.value(browser).as_deref(),
                Some(manifest.to_string_lossy().as_ref()),
                "{browser:?} registry value"
            );
        }
    }

    #[test]
    fn check_and_restore_repairs_a_changed_value_and_a_deleted_manifest() {
        let base = TestBase::new();
        let root = tempfile::tempdir().expect("temp dir");
        let ids = ExtensionIds::DEFAULT;
        let browser = ManifestBrowser::Chrome;
        install_under(&base.0, root.path(), browser, &exe(), &ids).expect("install");
        let manifest = browser.windows_manifest_path(root.path());

        set_default_value(
            &browser.registry_key_under(&base.0),
            Path::new(r"C:\elsewhere.json"),
        )
        .expect("tamper");
        fs::remove_file(&manifest).expect("delete manifest");

        let results = check_and_restore_under(&base.0, root.path(), &[browser], &exe(), &ids);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1.as_ref().expect("restored"), &Outcome::Written);
        assert!(manifest.is_file());
        assert_eq!(
            base.value(browser).as_deref(),
            Some(manifest.to_string_lossy().as_ref())
        );

        let again = check_and_restore_under(&base.0, root.path(), &[browser], &exe(), &ids);
        assert_eq!(again[0].1.as_ref().expect("unchanged"), &Outcome::Unchanged);
    }

    #[test]
    fn remove_deletes_only_our_keys_and_tolerates_absence() {
        let base = TestBase::new();
        let root = tempfile::tempdir().expect("temp dir");
        let ids = ExtensionIds::DEFAULT;
        for browser in ALL {
            install_under(&base.0, root.path(), browser, &exe(), &ids).expect("install");
        }
        remove_under(&base.0, root.path(), ManifestBrowser::Chrome).expect("remove");
        assert_eq!(base.value(ManifestBrowser::Chrome), None);
        assert!(
            !ManifestBrowser::Chrome
                .windows_manifest_path(root.path())
                .exists()
        );
        for browser in ALL.into_iter().filter(|b| *b != ManifestBrowser::Chrome) {
            assert!(base.value(browser).is_some(), "{browser:?} untouched");
            assert!(browser.windows_manifest_path(root.path()).is_file());
        }
        remove_under(&base.0, root.path(), ManifestBrowser::Chrome).expect("absent is fine");
    }
}
