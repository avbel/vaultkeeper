//! Enables and disables the LaunchAgent under a throwaway HOME, so the real
//! `~/Library/LaunchAgents` is never touched. One test per binary: it changes `HOME`.
//! The plist is read back with `plutil`, Apple's own parser, so the values are launchd's view.

#![cfg(target_os = "macos")]

use std::{path::Path, process::Command};

use vk_platform::autostart;

fn plutil_value(plist: &Path, key_path: &str) -> String {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key_path, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .expect("plutil");
    assert!(output.status.success(), "{key_path}: {output:?}");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .trim()
        .to_owned()
}

#[test]
fn enable_writes_agent_for_current_exe_refresh_updates_it_and_disable_removes_it() {
    let home = tempfile::tempdir().expect("tempdir");
    // SAFETY: this binary runs exactly one test, so no other thread reads the environment.
    unsafe { std::env::set_var("HOME", home.path()) };
    std::fs::create_dir(home.path().join("Library")).expect("Library dir");
    let plist = home.path().join("Library/LaunchAgents/vaultkeeper.plist");

    assert!(!autostart::is_enabled().expect("is_enabled"));
    assert!(
        !autostart::refresh().expect("nothing to refresh"),
        "off stays off"
    );
    assert!(!plist.exists());
    autostart::set_enabled(true).expect("enable");
    assert!(autostart::is_enabled().expect("is_enabled after enable"));

    let lint = Command::new("/usr/bin/plutil")
        .arg("-lint")
        .arg(&plist)
        .output()
        .expect("plutil");
    assert!(lint.status.success(), "{lint:?}");
    let exe = std::env::current_exe()
        .expect("exe")
        .canonicalize()
        .expect("canonical exe");
    assert_eq!(plutil_value(&plist, "Label"), "vaultkeeper");
    assert_eq!(
        plutil_value(&plist, "ProgramArguments.0"),
        exe.to_str().expect("utf-8")
    );
    assert_eq!(plutil_value(&plist, "ProgramArguments.1"), "--tray");
    assert_eq!(plutil_value(&plist, "RunAtLoad"), "true");
    assert_eq!(
        plutil_value(&plist, "KeepAlive.SuccessfulExit"),
        "false",
        "restart after a crash, not after Quit"
    );
    assert!(!autostart::refresh().expect("refresh"), "already current");

    // An agent written by auto-launch (older versions): no KeepAlive. Brought up to date when it
    // starts this executable, left alone when it starts another one.
    let old_agent = |exe: &str| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST \
             1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n\
             <dict>\n  <key>Label</key>\n  <string>vaultkeeper</string>\n  <key>ProgramArguments</key>\n  \
             <array><string>{exe}</string><string>--tray</string></array>\n  <key>RunAtLoad</key>\n  \
             <true/>\n</dict>\n</plist>"
        )
    };
    let installed = old_agent("/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper");
    std::fs::write(&plist, &installed).expect("other agent");
    assert!(!autostart::refresh().expect("refresh"));
    assert_eq!(std::fs::read_to_string(&plist).expect("plist"), installed);
    std::fs::write(&plist, old_agent(exe.to_str().expect("utf-8"))).expect("old agent");
    assert!(autostart::refresh().expect("refresh"));
    assert_eq!(plutil_value(&plist, "KeepAlive.SuccessfulExit"), "false");

    autostart::set_enabled(true).expect("enable again");
    autostart::set_enabled(false).expect("disable");
    assert!(!autostart::is_enabled().expect("is_enabled after disable"));
    assert!(!plist.exists());
    autostart::set_enabled(false).expect("disable when already off");
}
