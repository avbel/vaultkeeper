//! Startup hardening: no core dumps and no debugger attach on macOS, and the process DACL,
//! loader search path and mitigation policies on Windows (docs/solutions/windows-support.md §5.1),
//! and umask, MDWE and non-dumpable processes on Linux (linux-plan.md 1d).

/// Which Vaultkeeper process is hardening. Windows applies a slightly different policy set to the
/// two; macOS ignores the role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Daemon,
    Ui,
}

/// Call once, first thing in `main`. Failures are logged, not fatal: the app still works,
/// just with a weaker posture.
pub fn harden_process(role: Role) {
    #[cfg(windows)]
    windows::harden(role);

    #[cfg(unix)]
    {
        // macOS has the same posture in both processes, so there is nothing to vary.
        let _ = role;
        disable_core_dumps();
        #[cfg(target_os = "linux")]
        linux::harden();
        // Debug builds stay attachable so debuggers and profilers keep working.
        #[cfg(all(target_os = "macos", not(debug_assertions)))]
        deny_debugger_attach();
    }
}

/// Why a process refuses to go on after hardening.
#[derive(Debug, thiserror::Error)]
pub enum HardeningError {
    /// A debugger or another program attached while the process was still dumpable.
    #[error(
        "process {tracer} is tracing Vaultkeeper and could read its memory; close that program \
         or debugger and start Vaultkeeper again"
    )]
    Traced { tracer: u32 },
    /// The protection could not be confirmed, so the process cannot know it is not readable.
    #[error("Vaultkeeper could not confirm that other programs cannot read its memory: {0}")]
    Unverified(String),
}

/// Linux: makes the process non-dumpable once the daemon has verified it, which needed its
/// `/proc/<pid>/exe` (linux-plan.md 1d, 2c). The daemon calls it at start. Elsewhere a no-op.
///
/// # Errors
/// On Linux, when dumpable does not read back 0, when the thread statuses cannot be read, or when
/// any thread is traced: a tracer that attached during the dumpable window stays attached after
/// dumpable is cleared. Debug builds let a tracer through with `VK_ALLOW_TRACER=1`, so developers
/// can run gdb; release builds never do.
pub fn harden_after_handshake() -> Result<(), HardeningError> {
    #[cfg(target_os = "linux")]
    {
        vk_linux::probes::drop_dumpable();
        match vk_linux::probes::dumpable() {
            Ok(false) => {}
            Ok(true) => {
                return Err(HardeningError::Unverified(
                    "the process is still dumpable".to_owned(),
                ));
            }
            Err(error) => return Err(HardeningError::Unverified(error)),
        }
        check_no_tracer()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_no_tracer() -> Result<(), HardeningError> {
    match vk_linux::probes::tracer_pid() {
        Ok(0) => Ok(()),
        Ok(tracer) if tracer_allowed() => {
            tracing::warn!(tracer, "a tracer is attached; allowed by VK_ALLOW_TRACER=1");
            Ok(())
        }
        Ok(tracer) => Err(HardeningError::Traced { tracer }),
        Err(error) => Err(HardeningError::Unverified(error)),
    }
}

#[cfg(target_os = "linux")]
fn tracer_allowed() -> bool {
    cfg!(debug_assertions) && std::env::var_os("VK_ALLOW_TRACER").is_some_and(|value| value == "1")
}

/// Whether `harden_process` replaced this process's DACL. The Windows stand-in for the macOS
/// hardened runtime: other same-user processes can no longer open it to write memory or start
/// threads. The process that created it keeps its handle, so this is weaker than CS_RUNTIME.
#[cfg(windows)]
#[must_use]
pub fn process_dacl_applied() -> bool {
    windows::DACL_APPLIED.load(std::sync::atomic::Ordering::Relaxed)
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

#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::is_hardened;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn core_dumps_are_disabled_soft_and_hard() {
        harden_process(Role::Daemon);
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `limit` is a valid out pointer for the duration of the call.
        let status = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) };
        assert_eq!(status, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_untraced_process_passes_the_tracer_check() {
        if vk_linux::probes::tracer_pid() != Ok(0) {
            // Run under a debugger or strace: the refusal is the expected outcome there.
            return;
        }
        assert!(harden_after_handshake().is_ok());
        assert_eq!(vk_linux::probes::dumpable(), Ok(false));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_thread_is_read_and_an_untraced_worker_passes() {
        if vk_linux::probes::tracer_pid() != Ok(0) {
            return;
        }
        let (started, ready) = std::sync::mpsc::channel();
        let (finish, done) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let _ = started.send(());
            let _ = done.recv();
        });
        ready.recv().expect("worker started");
        let threads = std::fs::read_dir("/proc/self/task")
            .expect("task dir")
            .count();
        assert!(threads >= 2, "the worker shows up in /proc/self/task");
        assert_eq!(vk_linux::probes::tracer_pid(), Ok(0));
        assert!(harden_after_handshake().is_ok());
        drop(finish);
        worker.join().expect("worker");
    }

    #[test]
    fn hardening_twice_is_harmless() {
        harden_process(Role::Daemon);
        harden_process(Role::Ui);
    }
}
