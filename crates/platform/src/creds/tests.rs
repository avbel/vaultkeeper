use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

use super::*;

const SECRET: &[u8] = b"remember me please";

/// Stands in for systemd-creds: a letter-shift cipher that insists on the exact argv shape.
const FAKE: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "systemd 258 (258.1-1)"; exit 0; fi
[ "$1" = "--user" ] || exit 64
[ "$3" = "--name=vaultkeeper.2fa" ] || exit 65
case "$2" in
  encrypt) [ "$4 $5 $6" = "--with-key=auto - -" ] || exit 66; tr 'a-z' 'b-za' ;;
  decrypt) [ "$4 $5" = "- -" ] || exit 67; tr 'b-za' 'a-z' ;;
  *) exit 68 ;;
esac
"#;

fn fake(dir: &tempfile::TempDir, name: &str, script: &str) -> Creds {
    let path: PathBuf = dir.path().join(name);
    fs::write(&path, script).expect("write script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    Creds::with_program(path).with_timeout(Duration::from_secs(10))
}

fn good() -> (tempfile::TempDir, Creds) {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = fake(&dir, "systemd-creds", FAKE);
    (dir, creds)
}

#[test]
fn round_trips_through_the_command_with_the_exact_arguments() {
    let (_dir, creds) = good();
    let blob = creds.encrypt(SECRET).expect("encrypt");
    assert_ne!(blob, SECRET);
    assert_eq!(creds.decrypt(&blob).expect("decrypt").as_slice(), SECRET);
}

#[test]
fn secret_reaches_the_tool_over_stdin_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("seen");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{log}'\nenv >> '{log}'\ncat\n",
        log = log.display()
    );
    let creds = fake(&dir, "spy", &script);
    let out = creds.encrypt(SECRET).expect("encrypt");
    assert_eq!(out, SECRET);
    let seen = fs::read_to_string(&log).expect("log");
    assert!(!seen.contains("remember me"), "{seen}");
}

#[test]
fn failure_reports_the_status_and_never_the_secret() {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = fake(
        &dir,
        "bad",
        "#!/bin/sh\ncat >&2\necho remember me >&2\nexit 3\n",
    );
    let error = creds.encrypt(SECRET).expect_err("fails");
    assert!(matches!(error, CredsError::Failed(Some(3))), "{error:?}");
    assert!(!format!("{error} {error:?}").contains("remember"));
}

#[test]
fn output_over_the_limit_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = fake(&dir, "flood", "#!/bin/sh\nhead -c 200000 /dev/zero\n");
    let error = creds.encrypt(SECRET).expect_err("too large");
    assert!(matches!(error, CredsError::TooLarge(_)), "{error:?}");
}

#[test]
fn input_over_the_limit_is_rejected_without_spawning() {
    let creds = Creds::with_program("/nonexistent/systemd-creds");
    let error = creds
        .encrypt(&vec![0; MAX_INPUT + 1])
        .expect_err("too large");
    assert!(matches!(error, CredsError::TooLarge(_)), "{error:?}");
}

#[test]
fn a_hung_tool_times_out_and_is_killed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds =
        fake(&dir, "hang", "#!/bin/sh\nexec sleep 30\n").with_timeout(Duration::from_millis(200));
    let started = Instant::now();
    let error = creds.encrypt(SECRET).expect_err("times out");
    assert!(matches!(error, CredsError::Timeout), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_tool_that_ignores_stdin_still_reports_its_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = fake(&dir, "deaf", "#!/bin/sh\nexit 0\n");
    assert_eq!(creds.encrypt(&vec![b'a'; MAX_INPUT]).expect("ok").len(), 0);
}

#[test]
fn a_missing_program_is_a_spawn_error() {
    let error = Creds::with_program("/nonexistent/systemd-creds")
        .encrypt(SECRET)
        .expect_err("missing");
    assert!(matches!(error, CredsError::Spawn(_)), "{error:?}");
}

#[test]
fn version_is_parsed_from_the_first_line() {
    assert_eq!(parse_version(b"systemd 258 (258.1-1)\n+PAM"), Some(258));
    assert_eq!(parse_version(b"nonsense"), None);
    assert_eq!(parse_version(b""), None);
}

#[test]
fn codec_wraps_with_the_magic_and_unwraps() {
    let (_dir, creds) = good();
    let codec = BlobCodec::new(Some(creds));
    let blob = codec.wrap(SECRET).expect("wrap");
    assert!(blob.starts_with(MAGIC));
    assert_eq!(codec.unwrap(&blob).expect("unwrap").as_slice(), SECRET);
}

#[test]
fn a_blob_stored_without_the_tool_still_loads_with_it() {
    let (_dir, creds) = good();
    let legacy = BlobCodec::new(None).wrap(SECRET).expect("identity");
    assert_eq!(legacy, SECRET);
    let codec = BlobCodec::new(Some(creds));
    assert_eq!(codec.unwrap(&legacy).expect("legacy").as_slice(), SECRET);
}

#[test]
fn a_wrapped_blob_without_the_tool_is_an_error_not_a_loss() {
    let (_dir, creds) = good();
    let blob = BlobCodec::new(Some(creds.clone()))
        .wrap(SECRET)
        .expect("wrap");
    let error = BlobCodec::new(None).unwrap(&blob).expect_err("no tool");
    assert!(matches!(error, CredsError::Unavailable), "{error:?}");
    let back = BlobCodec::new(Some(creds))
        .unwrap(&blob)
        .expect("tool is back");
    assert_eq!(back.as_slice(), SECRET);
}

#[test]
fn a_wrapped_blob_the_tool_refuses_is_a_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = fake(&dir, "refuse", "#!/bin/sh\nexit 1\n");
    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(b"garbage");
    let error = BlobCodec::new(Some(creds))
        .unwrap(&blob)
        .expect_err("refused");
    assert!(matches!(error, CredsError::Failed(Some(1))), "{error:?}");
}

#[test]
fn detection_reports_the_key_binding() {
    let (dir, creds) = good();
    let with_tpm = Detection::probe_creds(creds.clone(), true);
    assert_eq!(with_tpm.backend(), &Backend::TpmAndHost);
    assert_eq!(with_tpm.backend().label(), "tpm2+host");
    assert_eq!(with_tpm.backend().probe(), Probe::Available);
    let host = Detection::probe_creds(creds, false);
    assert_eq!(host.backend(), &Backend::Host);
    assert!(matches!(host.backend().probe(), Probe::Degraded(_)));
    assert!(host.into_creds().is_some());
    drop(dir);
}

#[test]
fn detection_without_a_program_or_with_a_broken_one_is_unavailable_with_a_reason() {
    let none = Detection::probe(None, true);
    assert!(matches!(none.backend(), Backend::Unavailable(why) if !why.is_empty()));
    assert!(none.into_creds().is_none());

    let dir = tempfile::tempdir().expect("tempdir");
    let old = fake(&dir, "old", "#!/bin/sh\necho 'systemd 255 (255.1)'\n");
    let reason = match Detection::probe_creds(old, true).backend() {
        Backend::Unavailable(why) => why.clone(),
        other => panic!("{other:?}"),
    };
    assert!(reason.contains("255"), "{reason}");

    let broken = fake(
        &dir,
        "broken",
        "#!/bin/sh\n[ \"$1\" = --version ] && echo 'systemd 258' && exit 0\nexit 1\n",
    );
    let detection = Detection::probe_creds(broken, true);
    assert!(matches!(detection.backend(), Backend::Unavailable(why) if why.contains("encrypt")));
}

#[test]
fn the_chain_link_follows_the_backend() {
    let (_dir, creds) = good();
    let chain = |detection: &Detection| crate::security::Chain {
        id: "C1",
        name: "Secret files at rest",
        required: crate::security::Required::Status,
        minimum: 0,
        links: vec![detection.link()],
        fix: None,
    };
    let tpm = chain(&Detection::probe_creds(creds.clone(), true)).evaluate();
    assert_eq!(tpm.stacked, ["systemd-creds"]);
    let none = chain(&Detection::probe(None, false)).evaluate();
    assert_eq!(none.stacked.len(), 0);
    assert_eq!(none.skipped.len(), 1);
    assert_ne!(none.skipped[0].why, "");
}

#[test]
fn finds_the_program_on_the_given_path() {
    let (dir, _creds) = good();
    let found = find_program(Some(&dir.path().as_os_str().to_owned()));
    assert_eq!(found, Some(dir.path().join(PROGRAM)));
}

/// Where there is no systemd (Docker), the real probe must say so instead of failing.
#[test]
fn the_system_probe_never_panics_and_explains_unavailability() {
    if let Backend::Unavailable(why) = Detection::system().backend() {
        assert_ne!(why, "");
    }
}
