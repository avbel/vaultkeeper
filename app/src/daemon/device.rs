//! The device id the server sees for this machine: created once, kept in `device.json`, so a new-device
//! email arrives only on the first login from this machine.

use std::{io, path::Path};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vk_vault::DeviceInfo;

use crate::os::{fs::write_private, layout::DEVICE_FILE};

/// Bitwarden's `DeviceType` values for the desktop apps: MacOsDesktop 7, WindowsDesktop 6,
/// LinuxDesktop 8.
#[cfg(target_os = "macos")]
const DEVICE: (&str, u8) = ("macos", 7);
#[cfg(target_os = "windows")]
const DEVICE: (&str, u8) = ("windows", 6);
#[cfg(target_os = "linux")]
const DEVICE: (&str, u8) = ("linux", 8);

#[derive(Serialize, Deserialize)]
struct DeviceFile {
    identifier: Uuid,
}

pub fn load_or_create(data_dir: &Path) -> io::Result<DeviceInfo> {
    let path = data_dir.join(DEVICE_FILE);
    let identifier = match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<DeviceFile>(&bytes) {
            Ok(file) => file.identifier,
            Err(error) => {
                tracing::warn!(%error, "device.json is unreadable; registering a new device id");
                create(&path)?
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => create(&path)?,
        Err(error) => return Err(error),
    };
    Ok(DeviceInfo {
        identifier,
        name: DEVICE.0.to_owned(),
        device_type: DEVICE.1,
    })
}

fn create(path: &Path) -> io::Result<Uuid> {
    let identifier = Uuid::new_v4();
    let json = serde_json::to_vec(&DeviceFile { identifier }).map_err(io::Error::other)?;
    write_private(path, &json)?;
    Ok(identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_id_is_created_once_and_then_reused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = load_or_create(dir.path()).expect("create");
        #[cfg(target_os = "macos")]
        let expected = ("macos", 7);
        #[cfg(target_os = "windows")]
        let expected = ("windows", 6);
        #[cfg(target_os = "linux")]
        let expected = ("linux", 8);
        assert_eq!((first.name.as_str(), first.device_type), expected);
        let again = load_or_create(dir.path()).expect("load");
        assert_eq!(again.identifier, first.identifier);
    }

    #[test]
    fn a_corrupt_file_is_replaced_with_a_new_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(DEVICE_FILE), b"[]").expect("write");
        let device = load_or_create(dir.path()).expect("recreate");
        assert_eq!(
            load_or_create(dir.path()).expect("load").identifier,
            device.identifier
        );
    }
}
