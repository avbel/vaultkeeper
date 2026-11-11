//! The bounded browser activity log: one line per fill, pairing change or refused connection.
//! Never a secret: only the time, the browser, the host and the item id.

use std::{
    io::Write as _,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::os::log_file::{BoundedLog, LOG_CAP, log_dir};

pub struct ActivityLog {
    file: Mutex<Option<BoundedLog>>,
}

impl ActivityLog {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            file: Mutex::new(None),
        }
    }

    pub fn record(&self, line: &str) {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if file.is_none() {
            let opened =
                log_dir().and_then(|dir| match BoundedLog::open(&dir, "browser", LOG_CAP) {
                    Ok(log) => Some(log),
                    Err(error) => {
                        tracing::warn!(%error, "cannot open the browser activity log");
                        None
                    }
                });
            *file = opened;
        }
        let Some(log) = file.as_mut() else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if let Err(error) = writeln!(log, "{now} {line}") {
            tracing::warn!(%error, "cannot write the browser activity log");
        }
    }
}

impl Default for ActivityLog {
    fn default() -> Self {
        Self::new()
    }
}
