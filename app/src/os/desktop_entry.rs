//! The launcher entry and icon the daemon keeps in `$XDG_DATA_HOME` (linux-ideas.md §7.3). A
//! Homebrew formula cannot write outside its prefix, so the app writes its own entry; the portal
//! frontend resolves the app id to this file for names and permission prompts.

use std::{
    io,
    path::{Path, PathBuf},
};

use vk_platform::desktop_file::{APP_ID, exec_quote};

const ICON_SVG: &str = include_str!("../../../packaging/macos/icon.svg");
const ICON_SVG_SIZE: &str = r#"width="1024" height="1024""#;
/// The raster sizes of the hicolor theme the icon is also installed at: notifications and hosts
/// that do not read SVG look for these.
const PNG_SIZES: [u32; 7] = [16, 24, 32, 48, 64, 128, 256];

fn icon_png(px: u32) -> Option<Vec<u8>> {
    let svg = ICON_SVG.replacen(ICON_SVG_SIZE, &format!(r#"width="{px}" height="{px}""#), 1);
    let pixels = slint::Image::load_from_svg_data(svg.as_bytes())
        .ok()?
        .to_rgba8()?;
    let mut png = Vec::new();
    image::write_buffer_with_format(
        &mut std::io::Cursor::new(&mut png),
        pixels.as_bytes(),
        pixels.width(),
        pixels.height(),
        image::ExtendedColorType::Rgba8,
        image::ImageFormat::Png,
    )
    .ok()?;
    Some(png)
}

/// The `.desktop` text for `exe`, which must be the stable install path (Homebrew's `opt` path),
/// never a versioned Cellar path that the next upgrade deletes.
#[must_use]
pub fn render(exe: &Path) -> String {
    let exec = exec_quote(exe);
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Vaultkeeper\n\
         Comment=Bitwarden-compatible password manager\n\
         Exec={exec}\n\
         TryExec={exec}\n\
         Icon={APP_ID}\n\
         Terminal=false\n\
         Categories=Utility;Security;\n\
         Keywords=password;bitwarden;vault;\n\
         StartupNotify=true\n\
         SingleMainWindow=true\n\
         X-GNOME-UsesNotifications=true\n\
         Actions=Search;Generator;\n\
         \n\
         [Desktop Action Search]\n\
         Name=Search Vault\n\
         Exec={exec} --search\n\
         \n\
         [Desktop Action Generator]\n\
         Name=Password Generator\n\
         Exec={exec} --generator\n"
    )
}

/// The files the entry consists of, relative to `$XDG_DATA_HOME`.
fn files(exe: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = vec![
        (
            PathBuf::from(format!("applications/{APP_ID}.desktop")),
            render(exe).into_bytes(),
        ),
        (
            PathBuf::from(format!("icons/hicolor/scalable/apps/{APP_ID}.svg")),
            ICON_SVG.as_bytes().to_vec(),
        ),
    ];
    for px in PNG_SIZES {
        if let Some(png) = icon_png(px) {
            files.push((
                PathBuf::from(format!("icons/hicolor/{px}x{px}/apps/{APP_ID}.png")),
                png,
            ));
        } else {
            tracing::warn!(px, "cannot render the {px}px launcher icon");
        }
    }
    files
}

/// Writes whatever differs from what is on disk; `Ok(true)` when something changed. Idempotent,
/// so the daemon calls it on every start (an upgrade or a moved install rewrites the path).
pub fn ensure(data_home: &Path, exe: &Path) -> io::Result<bool> {
    let mut changed = false;
    for (relative, content) in files(exe) {
        let path = data_home.join(relative);
        if std::fs::read(&path).ok().as_deref() == Some(content.as_slice()) {
            continue;
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        vk_platform::fs::write_private_atomic(&path, &content)?;
        changed = true;
    }
    if changed {
        refresh_caches(data_home);
    }
    Ok(changed)
}

/// Launchers read the cache when there is one; a missing tool is fine (the file still works).
fn refresh_caches(data_home: &Path) {
    let applications = data_home.join("applications");
    match std::process::Command::new("update-desktop-database")
        .arg(&applications)
        .status()
    {
        Ok(status) if !status.success() => {
            tracing::debug!(%status, "update-desktop-database failed");
        }
        Err(error) => tracing::debug!(%error, "update-desktop-database is not installed"),
        Ok(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPT: &str = "/home/linuxbrew/.linuxbrew/opt/vaultkeeper/bin/vaultkeeper";

    #[test]
    fn the_entry_points_at_the_install_path_with_actions() {
        let entry = render(Path::new(OPT));
        assert!(entry.starts_with("[Desktop Entry]\n"));
        assert!(entry.contains(&format!("\nExec={OPT}\n")));
        assert!(entry.contains(&format!("\nTryExec={OPT}\n")));
        assert!(entry.contains(&format!("\nExec={OPT} --search\n")));
        assert!(entry.contains("\nIcon=io.github.avbel.Vaultkeeper\n"));
        assert!(!entry.contains("--skip-security-issues"));
    }

    #[test]
    fn ensure_writes_once_and_rewrites_a_moved_install() {
        let home = tempfile::tempdir().expect("tempdir");
        assert!(ensure(home.path(), Path::new(OPT)).expect("first"));
        assert!(!ensure(home.path(), Path::new(OPT)).expect("unchanged"));
        assert!(ensure(home.path(), Path::new("/opt/vk/bin/vaultkeeper")).expect("moved"));
        let entry = std::fs::read_to_string(
            home.path()
                .join("applications/io.github.avbel.Vaultkeeper.desktop"),
        )
        .expect("entry");
        assert!(entry.contains("Exec=/opt/vk/bin/vaultkeeper\n"));
        assert!(
            home.path()
                .join("icons/hicolor/scalable/apps/io.github.avbel.Vaultkeeper.svg")
                .exists()
        );
        for px in PNG_SIZES {
            let png = std::fs::read(home.path().join(format!(
                "icons/hicolor/{px}x{px}/apps/io.github.avbel.Vaultkeeper.png"
            )))
            .expect("png icon");
            let decoded = image::load_from_memory(&png).expect("decode");
            assert_eq!((decoded.width(), decoded.height()), (px, px));
        }
    }
}
