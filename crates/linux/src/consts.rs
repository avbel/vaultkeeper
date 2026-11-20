//! Kernel ABI values libc 0.2.191 does not have yet, checked against the v7.3 uapi headers.

/// `include/uapi/asm-generic/socket.h`; the same on x86_64 and aarch64.
pub const SO_PASSPIDFD: i32 = 76;
pub const SO_PEERPIDFD: i32 = 77;

/// `include/uapi/linux/prctl.h`.
pub const PR_SET_MDWE: i32 = 65;
pub const PR_GET_MDWE: i32 = 66;
pub const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1;
pub const PR_MDWE_NO_INHERIT: u64 = 2;

/// Generic syscall table numbers, shared by x86_64 and aarch64.
pub const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
pub const SYS_MEMFD_SECRET: i64 = 447;
pub const SYS_MSEAL: i64 = 462;
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

/// `include/uapi/linux/pidfd.h`.
pub const PIDFD_INFO_PID: u64 = 1 << 0;
pub const PIDFD_INFO_CREDS: u64 = 1 << 1;
pub const PIDFD_INFO_CGROUPID: u64 = 1 << 2;
pub const PIDFD_INFO_EXIT: u64 = 1 << 3;

/// `PIDFD_INFO_SIZE_VER0` layout. Later kernels append fields (exit code, coredump data), and
/// the ioctl copies only the size encoded in the request, so this first version is enough for
/// pid, credentials and cgroup id on every kernel that has the ioctl (6.13+).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct PidfdInfo {
    pub mask: u64,
    pub cgroupid: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub ruid: u32,
    pub rgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub spare0: u32,
}

/// `_IOWR(PIDFS_IOCTL_MAGIC = 0xFF, 11, struct pidfd_info)`.
pub const PIDFD_GET_INFO: u64 = ioc_read_write(0xFF, 11, size_of::<PidfdInfo>());

const fn ioc_read_write(kind: u64, number: u64, size: usize) -> u64 {
    const READ_WRITE: u64 = 3;
    (READ_WRITE << 30) | ((size as u64) << 16) | (kind << 8) | number
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfd_info_matches_the_ver0_size_and_request_number() {
        assert_eq!(size_of::<PidfdInfo>(), 64);
        assert_eq!(PIDFD_GET_INFO, 0xC040_FF0B);
    }
}
