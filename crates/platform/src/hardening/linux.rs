//! Linux half of [`super::harden_process`], after Bitwarden's
//! `desktop_native/core/src/process_isolation/linux.rs` (dumpable and core limit).
//!
//! `PR_SET_DUMPABLE(0)` is not applied here: it hides `/proc/<pid>/exe` from same-user peers, and
//! the daemon reads a client's exe to verify it, so clients drop it only after the handshake and
//! the daemon only once clients stop reading its exe (linux-plan.md 1d, 2c).

/// Not fatal: Slint and the GPU driver may need writable-executable mappings, which MDWE refuses
/// after this call (decision 11 of the plan is taken from the VM runs).
pub(super) fn harden() {
    // SAFETY: umask only replaces the process file mode mask.
    unsafe { libc::umask(0o077) };
    let flags = vk_linux::consts::PR_MDWE_REFUSE_EXEC_GAIN | vk_linux::consts::PR_MDWE_NO_INHERIT;
    // SAFETY: PR_SET_MDWE takes the flag word and zeroed unused arguments.
    if unsafe { libc::prctl(vk_linux::consts::PR_SET_MDWE, flags, 0_u64, 0_u64, 0_u64) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "could not enable MDWE");
    }
}

/// Makes this process non-dumpable: no ptrace attach, no `/proc/<pid>/mem` or `exe` for
/// same-user processes, no core dumps.
pub fn drop_dumpable() {
    // SAFETY: PR_SET_DUMPABLE takes the value and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "could not drop dumpable");
    }
}

/// The Linux stand-in for the macOS hardened runtime: non-dumpable, and Yama stops same-user
/// attach on top of that. The BPF ptrace gate joins this as an alternative in step 4c.
#[must_use]
pub fn is_hardened() -> bool {
    vk_linux::probes::dumpable() == Ok(false)
        && vk_linux::probes::yama_scope().is_ok_and(|scope| scope >= 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umask_mdwe_and_dumpable_read_back() {
        harden();
        // SAFETY: umask is read by setting it and restoring the old value.
        let mask = unsafe {
            let old = libc::umask(0o077);
            libc::umask(old);
            old
        };
        assert_eq!(mask, 0o077);
        if vk_linux::probes::mdwe_supported().is_ok() {
            // SAFETY: PR_GET_MDWE takes no pointers.
            let flags = unsafe { libc::prctl(vk_linux::consts::PR_GET_MDWE, 0, 0, 0, 0) };
            assert_eq!(flags & 1, 1, "MDWE refuse-exec-gain is set");
        }
        drop_dumpable();
        assert_eq!(vk_linux::probes::dumpable(), Ok(false));
    }
}
