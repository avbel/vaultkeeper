//! The local transport under the IPC protocol: a Unix domain socket, or a named pipe on Windows.
//!
//! Callers deal in an [`Endpoint`] and a [`Listener`]; the peer's credentials are read as part of
//! [`Listener::accept`], so a connection is never handed out unverified.

use std::{
    fmt,
    path::{Path, PathBuf},
};

pub use crate::peer::PeerCredentials;

#[cfg(unix)]
pub(crate) mod unix;
#[cfg(unix)]
pub use unix::{Listener, ReadHalf, Stream, WriteHalf, connect};

#[cfg(windows)]
mod inherited;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use inherited::{UiPipe, adopt_ui_pipe};
#[cfg(windows)]
pub use windows::{Listener, ReadHalf, Stream, WriteHalf, connect};

/// The name of one UI channel's pipe. 128 random bits make it unguessable, but pipe names can be
/// listed, so the daemon still checks who connected (`docs/solutions/windows-support.md` §5.2).
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only the Windows UI channel uses it")
)]
pub(crate) fn ui_pipe_name(random: [u8; 16]) -> String {
    use std::fmt::Write as _;

    let mut name = String::from(r"\\.\pipe\vaultkeeper.ui.");
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

/// Where a local IPC server listens.
///
/// Both variants exist on every target so layout code can build the name it needs without knowing
/// which OS it runs on; a listener only supports the one its OS provides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A filesystem path for a Unix domain socket.
    Path(PathBuf),
    /// A named pipe name, such as `\\.\pipe\vaultkeeper.<sid>.cli`.
    Pipe(String),
}

impl Endpoint {
    #[must_use]
    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    #[must_use]
    pub fn pipe(name: impl Into<String>) -> Self {
        Self::Pipe(name.into())
    }

    #[must_use]
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Self::Path(path) => Some(path),
            Self::Pipe(_) => None,
        }
    }

    #[must_use]
    pub fn as_pipe(&self) -> Option<&str> {
        match self {
            Self::Pipe(name) => Some(name),
            Self::Path(_) => None,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => write!(f, "{}", path.display()),
            Self::Pipe(name) => f.write_str(name),
        }
    }
}

/// A path is an endpoint only where sockets are files; Windows callers build the pipe name from
/// the layout.
#[cfg(unix)]
impl From<PathBuf> for Endpoint {
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}

#[cfg(unix)]
impl From<&Path> for Endpoint {
    fn from(path: &Path) -> Self {
        Self::Path(path.to_path_buf())
    }
}

#[cfg(unix)]
impl From<&PathBuf> for Endpoint {
    fn from(path: &PathBuf) -> Self {
        Self::Path(path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ui_pipe_name_is_the_random_bytes_in_lowercase_hex() {
        let mut random = [0_u8; 16];
        random[0] = 0xab;
        random[15] = 0x0f;
        assert_eq!(
            ui_pipe_name(random),
            r"\\.\pipe\vaultkeeper.ui.ab00000000000000000000000000000f"
        );
    }

    #[test]
    fn endpoints_expose_only_their_own_kind() {
        let path = Endpoint::path("/tmp/vk.sock");
        assert_eq!(path.as_path(), Some(Path::new("/tmp/vk.sock")));
        assert_eq!(path.as_pipe(), None);
        assert_eq!(path.to_string(), "/tmp/vk.sock");

        let pipe = Endpoint::pipe(r"\\.\pipe\vaultkeeper.test");
        assert_eq!(pipe.as_pipe(), Some(r"\\.\pipe\vaultkeeper.test"));
        assert_eq!(pipe.as_path(), None);
        assert_eq!(pipe.to_string(), r"\\.\pipe\vaultkeeper.test");
    }
}
