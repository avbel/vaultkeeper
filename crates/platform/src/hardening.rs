//! Disables core dumps and debugger attach (`PT_DENY_ATTACH` on macOS) at startup.

/// Call once, first thing in `main`. Failures are logged, not fatal: the app still works,
/// just with a weaker posture.
pub fn harden_process() {
    #[cfg(unix)]
    disable_core_dumps();
    // Debug builds stay attachable so debuggers and profilers keep working.
    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    deny_debugger_attach();
}

#[cfg(unix)]
fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, initialised rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "could not disable core dumps");
    }
}

#[cfg(all(target_os = "macos", not(debug_assertions)))]
fn deny_debugger_attach() {
    // SAFETY: PT_DENY_ATTACH ignores pid, addr and data; a null addr is what Apple documents.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "could not deny debugger attach");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn core_dumps_are_disabled_soft_and_hard() {
        harden_process();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `limit` is a valid out pointer for the duration of the call.
        let status = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) };
        assert_eq!(status, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
    }

    #[test]
    fn hardening_twice_is_harmless() {
        harden_process();
        harden_process();
    }
}
