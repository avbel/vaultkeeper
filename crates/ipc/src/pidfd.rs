//! Process file descriptors (Linux): taken with `SO_PEERPIDFD` at connect time or opened by pid,
//! they keep naming the same process even if its pid is reused.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use tokio::net::UnixStream;

pub(crate) fn of_peer(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|_| io::Error::other("c_int size does not fit socklen_t"))?;
    // SAFETY: the socket fd is borrowed from `stream` for the call; `fd` and `len` are live,
    // writable locals of the sizes passed.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            vk_linux::consts::SO_PEERPIDFD,
            (&raw mut fd).cast(),
            &raw mut len,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a new pidfd that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A pidfd polls readable once its process has exited; a poll error counts as exited too, so
/// the check fails closed.
/// Pins `pid` now; a check with [`exited`] afterwards shows whether what was read since still
/// belongs to it.
pub fn open(pid: i32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and has no memory preconditions.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = libc::c_int::try_from(fd).map_err(io::Error::other)?;
    // SAFETY: the kernel returned a new pidfd that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[must_use]
pub fn exited(pidfd: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pollfd, zero timeout.
    let ready = unsafe { libc::poll(&raw mut poll, 1, 0) };
    ready != 0
}

pub(crate) fn cgroup_id(pidfd: &OwnedFd) -> io::Result<u64> {
    let mut info = vk_linux::consts::PidfdInfo {
        mask: vk_linux::consts::PIDFD_INFO_CGROUPID,
        ..vk_linux::consts::PidfdInfo::default()
    };
    // SAFETY: `info` is a writable `pidfd_info` of the size encoded in the request.
    let status = unsafe {
        libc::ioctl(
            pidfd.as_raw_fd(),
            vk_linux::consts::PIDFD_GET_INFO as libc::Ioctl,
            &raw mut info,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if info.mask & vk_linux::consts::PIDFD_INFO_CGROUPID == 0 {
        return Err(io::Error::other("the kernel did not report the cgroup"));
    }
    Ok(info.cgroupid)
}
