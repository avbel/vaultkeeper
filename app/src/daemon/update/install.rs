//! Unpacking, checking and swapping in a downloaded app bundle.
//!
//! Staging happens in the owner-only data directory, not next to the installed app: any admin
//! could replace a bundle staged in `/Applications` between the signature check and the swap.
//! The data directory and `/Applications` share the APFS Data volume, so the swap stays atomic.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Context as _;

use super::release::Version;

pub const BUNDLE_ID: &str = "org.vaultkeeper.desktop";
const APP_NAME: &str = "Vaultkeeper.app";
const PREVIOUS: &str = "previous.app";
/// The unpacked app is about 40 MB; the zip's own size claims are checked against this before
/// anything is written.
const MAX_UNPACKED: u64 = 512 * 1024 * 1024;

/// How a swap ended when it did not install the update.
#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    /// macOS refused to replace the app (App Management, permissions): retrying cannot help.
    #[error("macOS refused to replace the app: {0}")]
    Refused(std::io::Error),
    /// The update failed a check; the installed app is unchanged.
    #[error(transparent)]
    Rejected(anyhow::Error),
    /// The update was swapped in, failed its check, and the old app could not be put back: the
    /// old app is still in the work directory, which must not be cleaned.
    #[error("the previous app could not be restored: {0:#}")]
    Broken(anyhow::Error),
}

/// Why this copy cannot replace itself; the updater then only points at the release page.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Blocked {
    #[error("not running from an app bundle")]
    NotBundled,
    #[error("running from a read-only location ({0}); move Vaultkeeper to Applications")]
    ReadOnly(String),
    #[error("this build is not signed with a certificate")]
    Unsigned,
    #[error("no permission to replace {0}")]
    NotWritable(String),
    #[error("the app and its data are on different volumes")]
    OtherVolume,
}

pub struct Installer {
    bundle: PathBuf,
    requirement: String,
    work: PathBuf,
}

impl Installer {
    /// For the bundle this process runs from; `work` is an owner-only directory on its volume.
    pub fn for_running_app(work: PathBuf) -> Result<Self, Blocked> {
        let exe = std::env::current_exe()
            .and_then(|exe| exe.canonicalize())
            .map_err(|_| Blocked::NotBundled)?;
        let bundle = bundle_of(&exe).ok_or(Blocked::NotBundled)?;
        Self::new(bundle, work)
    }

    fn new(bundle: PathBuf, work: PathBuf) -> Result<Self, Blocked> {
        let text = bundle.to_string_lossy();
        let read_only = || Blocked::ReadOnly(text.clone().into_owned());
        if text.contains("/AppTranslocation/") || text.starts_with("/Volumes/") {
            return Err(read_only());
        }
        if vk_platform::fs::is_on_read_only_volume(&bundle).unwrap_or(true) {
            return Err(read_only());
        }
        let parent = bundle.parent().ok_or(Blocked::NotBundled)?;
        if !vk_platform::fs::is_writable_dir(parent) {
            return Err(Blocked::NotWritable(parent.display().to_string()));
        }
        vk_platform::fs::ensure_private_dir(&work)
            .map_err(|_| Blocked::NotWritable(work.display().to_string()))?;
        if !same_volume(parent, &work) {
            return Err(Blocked::OtherVolume);
        }
        let requirement = vk_platform::code_signature::own_designated_requirement()
            .map_err(|_| Blocked::Unsigned)?;
        Ok(Self {
            bundle,
            requirement,
            work,
        })
    }

    /// Skips the checks on where the app runs from; the requirement is given, not read from this
    /// (ad-hoc signed) test binary.
    #[cfg(test)]
    fn for_test(bundle: PathBuf, work: PathBuf, requirement: String) -> Self {
        vk_platform::fs::ensure_private_dir(&work).expect("work dir");
        Self {
            bundle,
            requirement,
            work,
        }
    }

    #[must_use]
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }

    #[must_use]
    pub fn zip_path(&self) -> PathBuf {
        self.work.join("update.zip")
    }

    /// Unpacks `zip` into a directory of its own for `version` and returns the app inside once
    /// it passes [`Installer::check`]. A staged app of another version is left alone.
    pub fn stage(&self, zip: &Path, version: Version) -> anyhow::Result<PathBuf> {
        let unpacked = self.work.join(format!("unpacked-{version}"));
        remove(&unpacked)?;
        let size = unpacked_size(zip)?;
        anyhow::ensure!(
            size <= MAX_UNPACKED,
            "the update would unpack to {size} bytes"
        );
        // No ACLs: the signature does not cover them, and one could open the app to other users.
        run(Command::new("/usr/bin/ditto")
            .args(["-x", "-k", "--noacl"])
            .arg(zip)
            .arg(&unpacked))
        .context("unpack the update")?;
        let app = unpacked.join(APP_NAME);
        let kind = std::fs::symlink_metadata(&app).context("the update has no Vaultkeeper.app")?;
        anyhow::ensure!(
            kind.is_dir(),
            "Vaultkeeper.app in the update is not a folder"
        );
        // File modes are not covered by the signature either: a group- or world-writable binary in
        // /Applications could be replaced by another user after the swap.
        check_modes(&app)?;
        self.check(&app, version)?;
        Ok(app)
    }

    /// The signature must satisfy the running app's designated requirement, and the bundle must
    /// say it is `version` of this app, newer than the one running.
    fn check(&self, app: &Path, version: Version) -> anyhow::Result<()> {
        vk_platform::code_signature::verify_app_bundle(app, &self.requirement, BUNDLE_ID)
            .context("the update is not signed like this app")?;
        let plist = app.join("Contents/Info.plist");
        let identifier = plist_value(&plist, "CFBundleIdentifier")?;
        anyhow::ensure!(identifier == BUNDLE_ID, "the update is {identifier}");
        let staged: Version = plist_value(&plist, "CFBundleShortVersionString")?.parse()?;
        anyhow::ensure!(
            staged == version,
            "the update is version {staged}, expected {version}"
        );
        anyhow::ensure!(
            staged > Version::current(),
            "the update {staged} is not newer than {}",
            Version::current()
        );
        Ok(())
    }

    /// Checks `staged` again (it may have sat in the work directory for days), swaps it into
    /// place and checks the result; if that fails the old app goes back. Once the swapped-in app
    /// passes, the update is installed: keeping the old one as `previous.app` is best-effort.
    pub fn swap_in(&self, staged: &Path, version: Version) -> Result<(), SwapError> {
        check_modes(staged)
            .and_then(|()| self.check(staged, version))
            .map_err(SwapError::Rejected)?;
        if let Err(error) = vk_platform::fs::swap(staged, &self.bundle) {
            return Err(
                if matches!(error.raw_os_error(), Some(errno::EPERM | errno::EACCES)) {
                    SwapError::Refused(error)
                } else {
                    SwapError::Rejected(anyhow::Error::new(error).context("swap in the update"))
                },
            );
        }
        if let Err(error) = self.check(&self.bundle, version) {
            return match vk_platform::fs::swap(staged, &self.bundle) {
                Ok(()) => Err(SwapError::Rejected(
                    error.context("the installed update failed its check"),
                )),
                Err(restore) => Err(SwapError::Broken(
                    anyhow::Error::new(restore).context(format!("{error:#}")),
                )),
            };
        }
        let previous = self.work.join(PREVIOUS);
        if let Err(error) = remove(&previous).and_then(|()| std::fs::rename(staged, &previous)) {
            tracing::warn!(%error, "cannot keep the previous app");
        }
        Ok(())
    }

    /// Removes leftovers of an update; `previous.app` too unless `keep_previous`.
    pub fn clean(&self, keep_previous: bool) {
        clean_work(&self.work, &self.bundle, keep_previous);
    }
}

/// Never deletes `running`, whatever the work directory contains.
fn clean_work(work: &Path, running: &Path, keep_previous: bool) {
    let Ok(entries) = std::fs::read_dir(work) else {
        return;
    };
    let running = running.canonicalize().ok();
    for entry in entries.flatten() {
        let path = entry.path();
        if keep_previous && path.file_name().is_some_and(|name| name == PREVIOUS) {
            continue;
        }
        if running.is_some() && path.canonicalize().ok() == running {
            continue;
        }
        if let Err(error) = remove(&path) {
            tracing::warn!(%error, path = %path.display(), "cannot remove update leftovers");
        }
    }
}

/// errno values for a refused rename (sys/errno.h); the app crate does not link libc itself.
mod errno {
    pub const EPERM: i32 = 1;
    pub const EACCES: i32 = 13;
}

/// The total uncompressed size the zip declares (`zipinfo -t`), so an oversized archive is
/// refused before it is unpacked.
fn unpacked_size(zip: &Path) -> anyhow::Result<u64> {
    let summary = run(Command::new("/usr/bin/zipinfo").arg("-t").arg(zip))
        .context("read the update archive")?;
    // "N files, X bytes uncompressed, Y bytes compressed:  Z%"
    summary
        .split(',')
        .find_map(|part| part.trim().strip_suffix(" bytes uncompressed"))
        .and_then(|bytes| bytes.trim().parse().ok())
        .with_context(|| format!("unexpected archive summary: {}", summary.trim()))
}

/// Refuses entries writable by group or others, and setuid/setgid files.
fn check_modes(root: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::symlink_metadata(root)?.permissions().mode();
    anyhow::ensure!(
        mode & 0o6022 == 0,
        "{} has unsafe permissions {:o}",
        root.display(),
        mode & 0o7777
    );
    if std::fs::symlink_metadata(root)?.is_dir() {
        for entry in std::fs::read_dir(root)? {
            check_modes(&entry?.path())?;
        }
    }
    Ok(())
}

/// `…/Vaultkeeper.app/Contents/MacOS/vaultkeeper` → `…/Vaultkeeper.app`.
fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    let is_bundle = macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app";
    is_bundle.then(|| bundle.to_path_buf())
}

fn same_volume(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev(),
        _ => false,
    }
}

fn plist_value(plist: &Path, key: &str) -> anyhow::Result<String> {
    let value = run(Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist))
    .with_context(|| format!("read {key}"))?;
    Ok(value.trim().to_owned())
}

fn run(command: &mut Command) -> anyhow::Result<String> {
    let output = command.output()?;
    anyhow::ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn remove(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_bundle_of_its_executable() {
        assert_eq!(
            bundle_of(Path::new(
                "/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper"
            )),
            Some(PathBuf::from("/Applications/Vaultkeeper.app"))
        );
        assert_eq!(bundle_of(Path::new("/usr/local/bin/vaultkeeper")), None);
        assert_eq!(
            bundle_of(Path::new("/x/Vaultkeeper/Contents/MacOS/vaultkeeper")),
            None
        );
    }

    #[test]
    fn copies_that_cannot_update_themselves_are_blocked() {
        let dir = tempfile::tempdir().expect("temp dir");
        let work = dir.path().join("work");
        for path in [
            "/Volumes/Vaultkeeper/Vaultkeeper.app",
            "/private/var/folders/x/AppTranslocation/1234/d/Vaultkeeper.app",
        ] {
            assert!(matches!(
                Installer::new(PathBuf::from(path), work.clone()),
                Err(Blocked::ReadOnly(_))
            ));
        }
        let bundle = dir.path().join("apps").join(APP_NAME);
        std::fs::create_dir_all(&bundle).expect("bundle");
        // A test binary is ad-hoc signed: there is no requirement a new build could satisfy.
        assert_eq!(
            Installer::new(bundle.clone(), work.clone()).err(),
            Some(Blocked::Unsigned)
        );
        let apps = bundle.parent().expect("parent");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(apps, std::fs::Permissions::from_mode(0o500)).expect("chmod");
            assert!(matches!(
                Installer::new(bundle.clone(), work),
                Err(Blocked::NotWritable(_))
            ));
            std::fs::set_permissions(apps, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
    }

    /// A bundle of `version` around a copy of `/usr/bin/true`, ad-hoc signed with the hardened
    /// runtime; `marker` makes each build's signature different.
    fn signed_app(dir: &Path, version: &str, marker: &str) -> PathBuf {
        let app = dir.join(APP_NAME);
        std::fs::create_dir_all(app.join("Contents/MacOS")).expect("dirs");
        std::fs::create_dir_all(app.join("Contents/Resources")).expect("dirs");
        std::fs::copy("/usr/bin/true", app.join("Contents/MacOS/vaultkeeper")).expect("binary");
        std::fs::write(app.join("Contents/Resources/marker"), marker).expect("marker");
        std::fs::write(
            app.join("Contents/Info.plist"),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
                 <key>CFBundleIdentifier</key><string>{BUNDLE_ID}</string>\
                 <key>CFBundleExecutable</key><string>vaultkeeper</string>\
                 <key>CFBundleShortVersionString</key><string>{version}</string>\
                 </dict></plist>\n"
            ),
        )
        .expect("plist");
        run(Command::new("codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--options",
                "runtime",
                "--identifier",
                BUNDLE_ID,
            ])
            .arg(&app))
        .expect("sign");
        app
    }

    fn requirement_of(app: &Path) -> String {
        let output = Command::new("codesign")
            .args(["-d", "-r-"])
            .arg(app)
            .output()
            .expect("codesign");
        let text = String::from_utf8_lossy(&output.stderr).into_owned()
            + &String::from_utf8_lossy(&output.stdout);
        text.lines()
            .find_map(|line| line.trim_start_matches("# ").strip_prefix("designated => "))
            .expect("requirement")
            .to_owned()
    }

    fn zip(app: &Path, dest: &Path) {
        run(Command::new("/usr/bin/ditto")
            .args(["-c", "-k", "--keepParent"])
            .arg(app)
            .arg(dest))
        .expect("zip");
    }

    #[test]
    fn stages_checks_and_swaps_in_a_signed_update() {
        let dir = tempfile::tempdir().expect("temp dir");
        let current_app = signed_app(&dir.path().join("apps"), "0.0.1", "old");
        let update = signed_app(&dir.path().join("build"), "99.0.0", "new");
        let installer = Installer::for_test(
            current_app.clone(),
            dir.path().join("work"),
            requirement_of(&update),
        );
        let version: Version = "99.0.0".parse().expect("version");
        zip(&update, &installer.zip_path());

        assert!(
            installer
                .stage(&installer.zip_path(), "99.0.1".parse().expect("v"))
                .is_err(),
            "the release and the bundle must agree on the version"
        );
        let staged = installer
            .stage(&installer.zip_path(), version)
            .expect("stage");
        let marker = staged.join("Contents/Resources/marker");
        std::fs::write(&marker, "changed while staged").expect("tamper");
        assert!(
            matches!(
                installer.swap_in(&staged, version),
                Err(SwapError::Rejected(_))
            ),
            "checked again before the swap"
        );
        assert_eq!(
            std::fs::read(current_app.join("Contents/Resources/marker")).expect("marker"),
            b"old",
            "the installed app is untouched"
        );
        std::fs::write(&marker, "new").expect("restore");
        installer.swap_in(&staged, version).expect("swap in");
        assert_eq!(
            std::fs::read(current_app.join("Contents/Resources/marker")).expect("marker"),
            b"new"
        );
        let previous = dir.path().join("work").join(PREVIOUS);
        assert_eq!(
            std::fs::read(previous.join("Contents/Resources/marker")).expect("marker"),
            b"old"
        );
        installer.clean(false);
        assert!(!previous.exists());
        assert!(current_app.exists());
    }

    #[test]
    fn refuses_updates_that_fail_the_checks() {
        let dir = tempfile::tempdir().expect("temp dir");
        let current_app = signed_app(&dir.path().join("apps"), "0.0.1", "old");
        let genuine = signed_app(&dir.path().join("genuine"), "99.0.0", "genuine");
        let installer = Installer::for_test(
            current_app,
            dir.path().join("work"),
            requirement_of(&genuine),
        );
        let version: Version = "99.0.0".parse().expect("version");

        let other = signed_app(&dir.path().join("other"), "99.0.0", "other build");
        zip(&other, &installer.zip_path());
        assert!(
            installer.stage(&installer.zip_path(), version).is_err(),
            "other signature"
        );

        std::fs::write(genuine.join("Contents/Resources/marker"), "tampered").expect("tamper");
        zip(&genuine, &installer.zip_path());
        assert!(
            installer.stage(&installer.zip_path(), version).is_err(),
            "tampered"
        );

        let loose = signed_app(&dir.path().join("loose"), "99.0.0", "genuine");
        {
            use std::os::unix::fs::PermissionsExt as _;
            // Modes are outside the signature: this bundle still verifies.
            std::fs::set_permissions(
                loose.join("Contents/MacOS/vaultkeeper"),
                std::fs::Permissions::from_mode(0o777),
            )
            .expect("chmod");
        }
        let loose_installer = Installer::for_test(
            dir.path().join("apps").join(APP_NAME),
            dir.path().join("work"),
            requirement_of(&loose),
        );
        zip(&loose, &loose_installer.zip_path());
        let err = loose_installer
            .stage(&loose_installer.zip_path(), version)
            .expect_err("world-writable binary");
        assert!(format!("{err:#}").contains("unsafe permissions"), "{err:#}");

        let old = signed_app(&dir.path().join("old"), "0.0.0", "old");
        let installer = Installer::for_test(
            dir.path().join("apps").join(APP_NAME),
            dir.path().join("work"),
            requirement_of(&old),
        );
        zip(&old, &installer.zip_path());
        assert!(
            installer
                .stage(&installer.zip_path(), "0.0.0".parse().expect("v"))
                .is_err(),
            "never a downgrade"
        );
    }

    #[test]
    fn cleaning_never_removes_the_running_app() {
        let dir = tempfile::tempdir().expect("temp dir");
        let work = dir.path().join("work");
        std::fs::create_dir_all(work.join(PREVIOUS)).expect("previous");
        std::fs::create_dir_all(work.join("unpacked/Vaultkeeper.app")).expect("unpacked");
        std::fs::write(work.join("update.zip"), b"zip").expect("zip");
        let running = work.join("unpacked/Vaultkeeper.app");

        clean_work(&work, &work.join(PREVIOUS), true);
        assert!(work.join(PREVIOUS).exists(), "kept on request");
        assert!(!work.join("update.zip").exists());
        assert!(!running.exists());

        clean_work(&work, &work.join(PREVIOUS), false);
        assert!(work.join(PREVIOUS).exists(), "never the running app");
        clean_work(&work, Path::new("/nonexistent"), false);
        assert!(!work.join(PREVIOUS).exists());
    }
}
