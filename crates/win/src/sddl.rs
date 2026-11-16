//! Security descriptor strings for the objects Vaultkeeper creates.
//!
//! Layouts come from docs/solutions/windows-support.md §4.3 and §5.1/§5.3. Kept free of Win32
//! calls so the exact bytes are unit-tested on macOS, where the Windows build cannot run.

use std::io;

/// Validates `sid` against `S-1-(\d+-)+\d+`. A malformed SID must never reach a DACL: a failed
/// substitution would widen the descriptor to the wrong principal.
fn checked(sid: &str) -> io::Result<&str> {
    if is_sid(sid) {
        Ok(sid)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("malformed user SID: {sid:?}"),
        ))
    }
}

fn is_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    let mut parts = 0;
    for part in rest.split('-') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        parts += 1;
    }
    parts >= 2
}

/// DACL for the private data directory: SYSTEM, Administrators and the user get full control, and
/// a medium-integrity "no read up" label keeps low-integrity and AppContainer processes out.
pub fn private_dir(sid: &str) -> io::Result<String> {
    let sid = checked(sid)?;
    Ok(format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})S:(ML;OICI;NRNWNX;;;ME)"
    ))
}

/// DACL for a named pipe: generic read and write to the user, minus FILE_CREATE_PIPE_INSTANCE
/// (0x4), so no same-user process can add an instance and steal the next client.
pub fn pipe(sid: &str) -> io::Result<String> {
    let sid = checked(sid)?;
    Ok(format!("D:P(A;;0x12019b;;;{sid})(A;;RC;;;OW)"))
}

/// DACL every pool instance is created with: [`pipe`] plus FILE_CREATE_PIPE_INSTANCE (0x4) and
/// WRITE_DAC (0x40000). Creating the next instance needs the former from the previous instance's
/// DACL, and replacing the DACL afterwards needs the latter. There is deliberately no owner ACE: it
/// would strip the owner's implicit WRITE_DAC. The caller applies [`pipe`] to every instance once
/// the pool exists.
pub fn pipe_setup(sid: &str) -> io::Result<String> {
    let sid = checked(sid)?;
    Ok(format!("D:P(A;;0x14019f;;;{sid})"))
}

/// DACL for a process: PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE (0x101000). Task Manager,
/// the pipe identity checks and wait_for_exit all keep working with only these rights.
pub fn process(sid: &str) -> io::Result<String> {
    let sid = checked(sid)?;
    Ok(format!("D:P(A;;0x101000;;;{sid})(A;;RC;;;OW)"))
}

/// DACL for a thread: THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE (0x100800). 0x1000 on a
/// thread is THREAD_RESUME, so the process mask must not be reused here.
pub fn thread(sid: &str) -> io::Result<String> {
    let sid = checked(sid)?;
    Ok(format!("D:P(A;;0x100800;;;{sid})(A;;RC;;;OW)"))
}

/// DACL for the single-instance named mutex.
pub fn mutex(sid: &str) -> io::Result<String> {
    let sid = checked(sid)?;
    Ok(format!("D:P(A;;0x1F0001;;;{sid})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    #[test]
    fn private_dir_grants_system_admins_and_the_user() {
        assert_eq!(
            private_dir(USER).expect("sid"),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1004336348-1177238915-682003330-1001)S:(ML;OICI;NRNWNX;;;ME)"
        );
    }

    #[test]
    fn pipe_grants_read_write_without_instance_creation() {
        assert_eq!(
            pipe(USER).expect("sid"),
            "D:P(A;;0x12019b;;;S-1-5-21-1004336348-1177238915-682003330-1001)(A;;RC;;;OW)"
        );
    }

    #[test]
    fn pipe_setup_adds_instance_creation_and_write_dac_without_an_owner_ace() {
        assert_eq!(
            pipe_setup(USER).expect("sid"),
            "D:P(A;;0x14019f;;;S-1-5-21-1004336348-1177238915-682003330-1001)"
        );
    }

    #[test]
    fn process_mask_allows_query_limited_and_synchronize() {
        assert_eq!(
            process(USER).expect("sid"),
            "D:P(A;;0x101000;;;S-1-5-21-1004336348-1177238915-682003330-1001)(A;;RC;;;OW)"
        );
    }

    #[test]
    fn thread_mask_uses_thread_rights_not_process_rights() {
        assert_eq!(
            thread(USER).expect("sid"),
            "D:P(A;;0x100800;;;S-1-5-21-1004336348-1177238915-682003330-1001)(A;;RC;;;OW)"
        );
    }

    #[test]
    fn mutex_grants_the_user_mutex_all_access() {
        assert_eq!(
            mutex(USER).expect("sid"),
            "D:P(A;;0x1F0001;;;S-1-5-21-1004336348-1177238915-682003330-1001)"
        );
    }

    #[test]
    fn well_known_and_short_sids_are_valid() {
        for sid in ["S-1-5-18", "S-1-5-21-1", USER] {
            assert!(is_sid(sid), "{sid}");
        }
    }

    #[test]
    fn malformed_sids_are_rejected_by_every_builder() {
        for sid in [
            "",
            "S-1-5",
            "S-1-",
            "S-2-5-1",
            "S-1-5-",
            "S-1--5-1",
            "S-1-5-x",
            "S-1-5-21-",
            " S-1-5-1",
            "S-1-5-1 ",
        ] {
            let err = private_dir(sid).expect_err("private_dir");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{sid}");
            assert!(pipe(sid).is_err(), "{sid}");
            assert!(pipe_setup(sid).is_err(), "{sid}");
            assert!(process(sid).is_err(), "{sid}");
            assert!(thread(sid).is_err(), "{sid}");
            assert!(mutex(sid).is_err(), "{sid}");
        }
    }
}
