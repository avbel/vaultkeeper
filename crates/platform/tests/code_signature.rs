//! `verify_app_bundle` against real signatures made with `codesign`: tiny bundles around a copy of
//! `/usr/bin/true`, ad-hoc signed or signed with a throwaway self-signed certificate (the way
//! release builds are signed).
#![cfg(target_os = "macos")]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use vk_platform::code_signature::{own_designated_requirement, verify_app_bundle};

const ID: &str = "org.vaultkeeper.test";

/// stdout and stderr together: `codesign -d` prints the requirement on stderr.
fn run(command: &mut Command) -> String {
    let output = command.output().expect("run tool");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{command:?}: {text}");
    text
}

fn bundle(dir: &Path, name: &str) -> PathBuf {
    let app = dir.join(format!("{name}.app"));
    std::fs::create_dir_all(app.join("Contents/MacOS")).expect("bundle dirs");
    std::fs::create_dir_all(app.join("Contents/Resources")).expect("bundle dirs");
    std::fs::copy("/usr/bin/true", app.join("Contents/MacOS/tool")).expect("copy binary");
    std::fs::write(
        app.join("Contents/Info.plist"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{ID}</string>
<key>CFBundleExecutable</key><string>tool</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
"#
        ),
    )
    .expect("Info.plist");
    app
}

fn sign(app: &Path, identity: &str, keychain: Option<&Path>, runtime: bool) {
    let mut command = Command::new("codesign");
    command.args(["--force", "--sign", identity, "--identifier", ID]);
    if runtime {
        command.args(["--options", "runtime"]);
    }
    if let Some(keychain) = keychain {
        command.arg("--keychain").arg(keychain);
    }
    run(command.arg(app));
}

fn designated(app: &Path) -> String {
    let text = run(Command::new("codesign").args(["-d", "-r-"]).arg(app));
    text.lines()
        .find_map(|line| line.trim_start_matches("# ").strip_prefix("designated => "))
        .expect("designated requirement")
        .to_owned()
}

#[test]
fn accepts_only_an_intact_hardened_bundle_matching_the_requirement() {
    let dir = tempfile::tempdir().expect("temp dir");
    let good = bundle(dir.path(), "Good");
    sign(&good, "-", None, true);
    let requirement = designated(&good);
    verify_app_bundle(&good, &requirement, ID).expect("own requirement");
    assert!(verify_app_bundle(&good, &requirement, "org.other").is_err());

    let other = bundle(dir.path(), "Other");
    std::fs::write(other.join("Contents/Resources/extra"), b"x").expect("change the bundle");
    sign(&other, "-", None, true);
    assert!(
        verify_app_bundle(&other, &requirement, ID).is_err(),
        "another build does not satisfy a cdhash requirement"
    );

    let soft = bundle(dir.path(), "Soft");
    sign(&soft, "-", None, false);
    let err = verify_app_bundle(&soft, &designated(&soft), ID).expect_err("no hardened runtime");
    assert!(err.to_string().contains("hardened runtime"), "{err}");

    std::fs::write(good.join("Contents/MacOS/tool"), b"tampered").expect("tamper");
    assert!(verify_app_bundle(&good, &requirement, ID).is_err());
}

#[test]
fn a_test_binary_has_no_certificate_requirement() {
    // Test binaries are linker-signed ad hoc: no requirement a new build could ever satisfy.
    let err = own_designated_requirement().expect_err("ad-hoc signed");
    assert!(err.to_string().contains("certificate"), "{err}");
}

/// A temporary keychain holding one self-signed code-signing identity named `name`.
fn identity(dir: &Path, name: &str) -> PathBuf {
    let keychain = dir.join(format!("{name}.keychain-db"));
    let config = dir.join(format!("{name}.cnf"));
    std::fs::write(
        &config,
        format!(
            "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n[dn]\nCN = {name}\n\
             [ext]\nbasicConstraints = critical, CA:false\nkeyUsage = critical, digitalSignature\n\
             extendedKeyUsage = critical, codeSigning\n"
        ),
    )
    .expect("openssl config");
    let key = dir.join(format!("{name}.key"));
    let cert = dir.join(format!("{name}.pem"));
    let p12 = dir.join(format!("{name}.p12"));
    run(Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        ])
        .arg("-config")
        .arg(&config)
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert));
    let export = |legacy: bool| {
        let mut command = Command::new("openssl");
        command.args(["pkcs12", "-export"]);
        if legacy {
            command.arg("-legacy");
        }
        command
            .arg("-inkey")
            .arg(&key)
            .arg("-in")
            .arg(&cert)
            .args(["-name", name, "-passout", "pass:test", "-out"])
            .arg(&p12)
            .status()
            .is_ok_and(|status| status.success())
    };
    assert!(export(true) || export(false), "export the identity");
    run(Command::new("security")
        .args(["create-keychain", "-p", "test"])
        .arg(&keychain));
    run(Command::new("security")
        .args(["unlock-keychain", "-p", "test"])
        .arg(&keychain));
    run(Command::new("security")
        .arg("import")
        .arg(&p12)
        .arg("-k")
        .arg(&keychain)
        .args(["-P", "test", "-T", "/usr/bin/codesign"]));
    run(Command::new("security")
        .args([
            "set-key-partition-list",
            "-S",
            "apple-tool:,apple:",
            "-s",
            "-k",
            "test",
        ])
        .arg(&keychain));
    keychain
}

#[test]
fn a_certificate_requirement_admits_every_build_signed_with_that_certificate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let ours = identity(dir.path(), "vk-test-ours");
    let theirs = identity(dir.path(), "vk-test-theirs");
    let first = bundle(dir.path(), "First");
    sign(&first, "vk-test-ours", Some(&ours), true);
    let requirement = designated(&first);
    assert!(requirement.contains("certificate leaf"), "{requirement}");

    let next = bundle(dir.path(), "Next");
    std::fs::write(next.join("Contents/Resources/extra"), b"new build").expect("change the bundle");
    sign(&next, "vk-test-ours", Some(&ours), true);
    verify_app_bundle(&next, &requirement, ID).expect("same certificate, new build");

    let forged = bundle(dir.path(), "Forged");
    sign(&forged, "vk-test-theirs", Some(&theirs), true);
    assert!(verify_app_bundle(&forged, &requirement, ID).is_err());

    for keychain in [ours, theirs] {
        let _ = Command::new("security")
            .arg("delete-keychain")
            .arg(keychain)
            .status();
    }
}
