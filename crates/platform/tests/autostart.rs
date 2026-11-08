//! Enables and disables the LaunchAgent under a throwaway HOME, so the real
//! `~/Library/LaunchAgents` is never touched. One test per binary: it changes `HOME`.

#![cfg(target_os = "macos")]

use bwl_platform::autostart;

#[test]
fn enable_writes_agent_for_current_exe_and_disable_removes_it() {
    let home = tempfile::tempdir().expect("tempdir");
    // SAFETY: this binary runs exactly one test, so no other thread reads the environment.
    unsafe { std::env::set_var("HOME", home.path()) };
    // Every real home has ~/Library; auto-launch creates only the LaunchAgents level.
    std::fs::create_dir(home.path().join("Library")).expect("Library dir");
    let plist = home.path().join("Library/LaunchAgents/bw-lite.plist");

    assert!(!autostart::is_enabled().expect("is_enabled"));
    autostart::set_enabled(true).expect("enable");
    assert!(autostart::is_enabled().expect("is_enabled after enable"));

    let contents = std::fs::read_to_string(&plist).expect("plist");
    let exe = std::env::current_exe()
        .expect("exe")
        .canonicalize()
        .expect("canonical exe");
    let program = format!(
        "<key>ProgramArguments</key>\n  <array><string>{}</string><string>--tray</string></array>",
        exe.display()
    );
    assert!(
        contents.contains("<key>Label</key>\n  <string>bw-lite</string>"),
        "{contents}"
    );
    assert!(contents.contains(&program), "{contents}");
    assert!(
        contents.contains("<key>RunAtLoad</key>\n  <true/>"),
        "{contents}"
    );

    autostart::set_enabled(true).expect("enable again");
    autostart::set_enabled(false).expect("disable");
    assert!(!autostart::is_enabled().expect("is_enabled after disable"));
    assert!(!plist.exists());
    autostart::set_enabled(false).expect("disable when already off");
}
