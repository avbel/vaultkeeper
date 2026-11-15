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
    render, write_atomic,
};

/// Owns a registry key so every early return still closes it exactly once.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from `RegCreateKeyExW` and nothing else owns it.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

pub fn install(
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
            fs::create_dir_all(&dir)?;
            write_atomic(&dir, &target, &wanted)?;
            Outcome::Restored
        }
    };
    // The registry value is written every time so a manually moved pointer is corrected silently.
    set_default_value(&browser.registry_key(), &target)?;
    Ok(outcome)
}

pub fn remove(root: &Path, browser: ManifestBrowser) -> io::Result<()> {
    delete_key(&browser.registry_key())?;
    match fs::remove_file(browser.windows_manifest_path(root)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[must_use]
pub fn check_and_restore(
    root: &Path,
    enabled: &[ManifestBrowser],
    exe_path: &Path,
    ids: &ExtensionIds<'_>,
) -> Vec<(ManifestBrowser, io::Result<Outcome>)> {
    enabled
        .iter()
        .map(|&browser| (browser, install(root, browser, exe_path, ids)))
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
