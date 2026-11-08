//! `~/Library/Application Support/bw-lite` on macOS (platform data dir elsewhere).

use std::path::PathBuf;

use crate::Result;

/// Creates the directory (mode 0700) if missing.
pub fn data_dir() -> Result<PathBuf> {
    todo!("step 6")
}
