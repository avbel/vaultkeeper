use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

use super::*;

const SECRET: &[u8] = b"remember me please";

/// Stands in for systemd-creds: a letter-shift cipher behind a 24-character header, which
/// insists on the exact argv shape.
const FAKE: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "systemd 258 (258.1-1)"; exit 0; fi
[ "$1" = "--user" ] || exit 64
[ "$3" = "--name=vaultkeeper.2fa" ] || exit 65
case "$2" in
  encrypt) [ "$4 $5 $6" = "--with-key=auto - -" ] || exit 66; printf '%s' 'HEADER'; tr 'a-z' 'b-za' ;;
  decrypt) [ "$4 $5" = "- -" ] || exit 67; tail -c +25 | tr 'b-za' 'a-z' ;;
  *) exit 68 ;;
esac
"#;

/// `CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED_PINNED_SRK`: what `--user` yields with a TPM2.
const TPM_AND_HOST_HEADER: &str = "Kh+HekJ1Qxqz+e0fXY9mASAA";
/// `CRED_AES256_GCM_BY_HOST_SCOPED`: what `--user` yields without one, or when sealing fails.
const HOST_HEADER: &str = "VbntHThZTUOoMZ0uuzMqxiAA";
/// `CRED_AES256_GCM_BY_NULL`.
const NULL_HEADER: &str = "BYRp2vb1QySABUnaD46i+yAA";
/// `_CRED_AUTO_SCOPED`: an id systemd never writes to a blob.
const UNWRITTEN_HEADER: &str = "I4iWhW90SIqceG9qsOc7aiAA";

fn fake_with_header(dir: &tempfile::TempDir, name: &str, header: &str) -> Creds {
    assert_eq!(header.len(), 24);
    fake(dir, name, &FAKE.replace("HEADER", header))
}

fn fake(dir: &tempfile::TempDir, name: &str, script: &str) -> Creds {
    let path: PathBuf = dir.path().join(name);
    fs::write(&path, script).expect("write script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    Creds::with_program(path).with_timeout(Duration::from_secs(10))
}

fn good() -> (tempfile::TempDir, Creds) {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = fake_with_header(&dir, "systemd-creds", TPM_AND_HOST_HEADER);
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
fn detection_reports_the_key_the_probe_blob_was_sealed_with() {
    let dir = tempfile::tempdir().expect("tempdir");
    let with_tpm = Detection::probe_creds(fake_with_header(&dir, "tpm", TPM_AND_HOST_HEADER));
    assert_eq!(with_tpm.backend(), &Backend::TpmAndHost);
    assert_eq!(with_tpm.backend().label(), "tpm2+host");
    assert_eq!(with_tpm.backend().probe(), Probe::Available);

    let host = Detection::probe_creds(fake_with_header(&dir, "host", HOST_HEADER));
    assert_eq!(host.backend(), &Backend::Host);
    assert_eq!(host.backend().label(), "host");
    assert!(matches!(host.backend().probe(), Probe::Degraded(why) if why.contains("host key")));
    assert!(host.into_creds().is_some());
}

#[test]
fn an_unreadable_key_type_keeps_the_wrapper_but_never_counts_as_full() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, header) in [
        ("unwritten", UNWRITTEN_HEADER),
        ("junk", "not base64 at all !!!!!!"),
    ] {
        let detection = Detection::probe_creds(fake_with_header(&dir, name, header));
        assert!(matches!(detection.backend(), Backend::Unknown(_)), "{name}");
        assert_eq!(detection.backend().label(), "unknown");
        assert!(matches!(detection.backend().probe(), Probe::Degraded(why) if !why.is_empty()));
        assert!(detection.into_creds().is_some());
    }
}

#[test]
fn the_null_key_is_unavailable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let detection = Detection::probe_creds(fake_with_header(&dir, "null", NULL_HEADER));
    assert!(matches!(detection.backend(), Backend::Unavailable(why) if why.contains("null key")));
    assert!(detection.into_creds().is_none());
}

#[test]
fn the_status_follows_the_backend() {
    assert_eq!(Backend::TpmAndHost.probe(), Probe::Available);
    assert_eq!(Backend::Tpm.probe(), Probe::Available);
    assert_eq!(Backend::Tpm.label(), "tpm2");
    assert!(matches!(Backend::Host.probe(), Probe::Degraded(_)));
    assert_eq!(
        Backend::Unknown("why".to_owned()).probe(),
        Probe::Degraded("why".to_owned())
    );
    assert_eq!(
        Backend::Unavailable("gone".to_owned()).probe(),
        Probe::Unavailable("gone".to_owned())
    );
}

#[test]
fn detection_without_a_program_or_with_a_broken_one_is_unavailable_with_a_reason() {
    let none = Detection::probe(None);
    assert!(matches!(none.backend(), Backend::Unavailable(why) if !why.is_empty()));
    assert!(none.into_creds().is_none());

    let dir = tempfile::tempdir().expect("tempdir");
    let old = fake(&dir, "old", "#!/bin/sh\necho 'systemd 255 (255.1)'\n");
    let reason = match Detection::probe_creds(old).backend() {
        Backend::Unavailable(why) => why.clone(),
        other => panic!("{other:?}"),
    };
    assert!(reason.contains("255"), "{reason}");

    let broken = fake(
        &dir,
        "broken",
        "#!/bin/sh\n[ \"$1\" = --version ] && echo 'systemd 258' && exit 0\nexit 1\n",
    );
    let detection = Detection::probe_creds(broken);
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
    let tpm = chain(&Detection::probe_creds(creds)).evaluate();
    assert_eq!(tpm.stacked, ["systemd-creds (TPM2 + host key)"]);
    let none = chain(&Detection::probe(None)).evaluate();
    assert_eq!(none.stacked.len(), 0);
    assert_eq!(none.skipped.len(), 1);
    assert_ne!(none.skipped[0].why, "");
}

#[test]
fn finds_the_program_on_the_given_path() {
    let (dir, _creds) = good();
    let found = find_program(Some(&dir.path().as_os_str().to_owned()), &[]);
    assert_eq!(found, Some(dir.path().join(PROGRAM)));
}

/// Where there is no systemd (Docker), the real probe must say so instead of failing; where
/// there is one, the reported key is the one in a real blob's header.
#[test]
fn the_system_probe_explains_unavailability_or_matches_a_real_blob() {
    let detection = Detection::system();
    let Some(creds) = detection.creds() else {
        assert!(matches!(detection.backend(), Backend::Unavailable(why) if !why.is_empty()));
        return;
    };
    let blob = creds.encrypt(SECRET).expect("encrypt");
    let expected = match header::sealing(&blob).expect("a key type systemd documents") {
        Sealing::TpmAndHost => Backend::TpmAndHost,
        Sealing::Tpm => Backend::Tpm,
        Sealing::Host => Backend::Host,
        Sealing::Null => panic!("null key"),
    };
    assert_eq!(detection.backend(), &expected);
    // Asserted only where asked for, since the key depends on the machine's TPM2.
    if let Ok(wanted) = std::env::var("VK_TEST_CREDS_KEY") {
        assert_eq!(detection.backend().label(), wanted);
    }
}

#[test]
fn relative_path_entries_are_ignored() {
    let (dir, _creds) = good();
    let relative = OsString::from(format!(":relative:{}", dir.path().display()));
    assert_eq!(
        find_program(Some(&relative), &[]),
        Some(dir.path().join(PROGRAM))
    );
    assert_eq!(find_program(Some(&OsString::from("")), &[]), None);
}

#[test]
fn output_larger_than_the_cap_never_passes_as_valid_even_if_the_tool_exits_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let creds = fake(
        &dir,
        "burst",
        "#!/bin/sh\nhead -c 70000 /dev/zero\nexit 0\n",
    );
    for _ in 0..20 {
        let error = creds.encrypt(SECRET).expect_err("too large");
        assert!(matches!(error, CredsError::TooLarge(_)), "{error:?}");
    }
}

mod key_type;
