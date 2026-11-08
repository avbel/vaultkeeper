use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const SECONDS_PER_DAY: u64 = 86_400;

/// Current UTC time as RFC 3339 with millisecond precision, e.g. `2026-11-08T17:00:59.321Z`
/// (the format Bitwarden clients send for `lastUsedDate` and `deletedDate`).
pub(crate) fn now_rfc3339() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339(elapsed.as_secs(), elapsed.subsec_millis())
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn format_rfc3339(unix: u64, millis: u32) -> String {
    let days = unix / SECONDS_PER_DAY;
    let secs = unix % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Howard Hinnant's `civil_from_days` for days since 1970-01-01 (unsigned, so years >= 1970).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// A file removed when the guard drops, on success and on every error path alike.
pub(crate) struct TempFile(PathBuf);

impl TempFile {
    pub(crate) fn new_in(dir: &Path) -> Self {
        Self(dir.join(format!(".{}.part", uuid::Uuid::new_v4().simple())))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!(%error, "could not remove a temporary attachment file");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        // Reference values from `date -u -r <unix>`.
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(
            format_rfc3339(1_794_157_259, 321),
            "2026-11-08T17:00:59.321Z"
        );
        assert_eq!(
            format_rfc3339(4_102_444_799, 999),
            "2099-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn now_has_the_wire_shape() {
        let now = now_rfc3339();
        assert_eq!(now.len(), "2026-11-08T17:00:59.321Z".len());
        assert!(now.ends_with('Z'));
        assert!(unix_now() > 1_700_000_000);
    }

    #[test]
    fn temp_file_is_removed_on_drop() {
        let dir = std::env::temp_dir();
        let temp = TempFile::new_in(&dir);
        std::fs::write(temp.path(), b"x").unwrap();
        let path = temp.path().to_owned();
        drop(temp);
        assert!(!path.exists());
        // A guard whose file was never created drops quietly.
        drop(TempFile::new_in(&dir));
    }
}
