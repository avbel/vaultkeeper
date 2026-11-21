//! Open and save dialogs through the FileChooser portal on ashpd's shared session connection.
//! rfd's portal backend opens a private connection per dialog, after hardening, so the portal
//! cannot identify the caller (`/proc/<pid>/root` is denied to a non-dumpable process) and refuses
//! it; its zenity fallback needs an exec that Landlock forbids ([`super::portal`]).
//!
//! No parent window identifier is passed: Wayland needs an xdg-foreign export the UI toolkit does
//! not expose, so the dialog is a top-level window of its own.
//!
//! Under Landlock (`VAULTKEEPER_LANDLOCK=1`) a chosen file is readable only inside the allowed
//! read set: the portal hands a non-sandboxed app the real path, which is typically in `$HOME`
//! and outside it. The caller's own read or write error is what the user then sees; the rule set
//! is deliberately not widened here.

use std::{future::Future, path::PathBuf, pin::pin, time::Duration};

use ashpd::{Error, desktop::file_chooser::SelectedFiles, zbus};
use futures_util::{StreamExt as _, future::Either};

use super::{open::run_unbounded, portal};

const PORTAL_BUS_NAME: &str = "org.freedesktop.portal.Desktop";

/// Registration normally takes milliseconds; the portal being stuck must not hang the UI thread.
const REGISTRATION_WAIT: Duration = Duration::from_secs(25);

#[derive(Debug)]
enum Outcome {
    Files(Result<SelectedFiles, Error>),
    NotRegistered,
    PortalLost,
}

#[must_use]
pub fn open_file() -> Option<PathBuf> {
    chosen(run_unbounded(dialog(async {
        SelectedFiles::open_file()
            .title("Choose a file")
            .modal(true)
            .send()
            .await?
            .response()
    })))
}

#[must_use]
pub fn save_file(suggested_name: &str) -> Option<PathBuf> {
    let name = suggested_name.to_owned();
    chosen(run_unbounded(dialog(async move {
        SelectedFiles::save_file()
            .title("Save file")
            .current_name(name.as_str())
            .modal(true)
            .send()
            .await?
            .response()
    })))
}

/// ashpd's `send` returns only once the Response signal arrived, so the wait for the user cannot
/// carry a timeout; a portal that dies mid-dialog never answers, and the bus name losing its owner
/// is what ends the wait instead.
async fn dialog(request: impl Future<Output = Result<SelectedFiles, Error>>) -> Outcome {
    let registered = tokio::time::timeout(REGISTRATION_WAIT, portal::ensure_registered()).await;
    if registered.is_err() {
        return Outcome::NotRegistered;
    }
    match futures_util::future::select(pin!(request), pin!(portal_lost())).await {
        Either::Left((result, _)) => Outcome::Files(result),
        Either::Right(((), _)) => Outcome::PortalLost,
    }
}

/// Resolves when the portal leaves the bus. If the bus cannot be watched it never resolves, which
/// leaves the dialog as unbounded as before. Bus-daemon signals only, like the restart watcher.
async fn portal_lost() {
    let watch = async {
        let connection = zbus::Connection::session().await?;
        let dbus = zbus::fdo::DBusProxy::new(&connection).await?;
        let mut changes = dbus
            .receive_name_owner_changed_with_args(&[(0, PORTAL_BUS_NAME)])
            .await?;
        while let Some(change) = changes.next().await {
            if change.args().is_ok_and(|args| args.new_owner().is_none()) {
                return zbus::Result::Ok(());
            }
        }
        Ok(())
    };
    match watch.await {
        Ok(()) => {}
        Err(error) => {
            tracing::warn!(%error, "cannot watch the portal during a file dialog");
            std::future::pending::<()>().await;
        }
    }
}

fn chosen(outcome: Option<Outcome>) -> Option<PathBuf> {
    match outcome {
        Some(Outcome::Files(Ok(files))) => first_path(files.uris().iter().map(ashpd::Uri::as_str)),
        Some(Outcome::Files(Err(Error::Response(ashpd::desktop::ResponseError::Cancelled)))) => {
            None
        }
        Some(Outcome::NotRegistered) => {
            tracing::warn!("portal registration did not finish; no file dialog");
            None
        }
        Some(Outcome::PortalLost) => {
            tracing::warn!("the desktop portal went away during the file dialog");
            None
        }
        Some(Outcome::Files(Err(error))) => {
            tracing::warn!(%error, "the FileChooser portal did not return a file");
            None
        }
        None => {
            tracing::warn!("the portal runtime is not running; no file dialog");
            None
        }
    }
}

fn first_path<'a>(uris: impl IntoIterator<Item = &'a str>) -> Option<PathBuf> {
    let uri = uris.into_iter().next()?;
    let path = uri_to_path(uri);
    if path.is_none() {
        tracing::warn!("the FileChooser portal returned a location that is not a local file");
    }
    path
}

/// Only `file://` locations name something this process can open; `Url` decodes the percent
/// escapes and rejects a host other than the local one. An escaped NUL decodes into the path, and
/// no real file has one, so it is refused here.
fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let path = url::Url::parse(uri).ok()?.to_file_path().ok()?;
    (!path.as_os_str().as_encoded_bytes().contains(&0)).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_uri_decodes_to_its_path() {
        assert_eq!(
            uri_to_path("file:///home/user/My%20Docs/caf%C3%A9%2B1.txt"),
            Some(PathBuf::from("/home/user/My Docs/café+1.txt"))
        );
    }

    #[test]
    fn other_schemes_and_remote_hosts_are_refused() {
        assert_eq!(uri_to_path("https://example.com/a.txt"), None);
        assert_eq!(uri_to_path("smb://server/share/a.txt"), None);
        assert_eq!(uri_to_path("file://otherhost/a.txt"), None);
        assert_eq!(uri_to_path("not a uri"), None);
    }

    #[test]
    fn localhost_is_the_local_host() {
        assert_eq!(uri_to_path("file://localhost/x"), Some(PathBuf::from("/x")));
    }

    #[test]
    fn non_utf8_bytes_survive_and_an_embedded_nul_is_refused() {
        use std::os::unix::ffi::OsStrExt as _;
        let path = uri_to_path("file:///a/%FF").expect("path");
        assert_eq!(path.as_os_str().as_bytes(), b"/a/\xff");
        assert_eq!(uri_to_path("file:///a/%00b"), None);
    }

    #[test]
    fn only_the_first_location_counts() {
        assert_eq!(
            first_path(["file:///a/one", "file:///a/two"]),
            Some(PathBuf::from("/a/one"))
        );
        assert_eq!(first_path([]), None);
    }

    /// Live check on a desktop session: opens the real dialog from a non-dumpable process, so it
    /// waits for the user; run by hand with `--ignored` and close the dialog.
    #[test]
    #[ignore = "needs a desktop session and a person at the dialog"]
    fn the_portal_accepts_an_open_file_request_after_hardening() {
        super::super::open::register_before_hardening(super::super::open::RegistrationWait::Daemon);
        // SAFETY: prctl with PR_SET_DUMPABLE takes plain integers and touches no memory.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
        let _ = open_file();
    }
}
