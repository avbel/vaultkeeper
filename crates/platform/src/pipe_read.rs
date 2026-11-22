//! Size- and time-bounded reads of a subprocess's or clipboard owner's pipe on the calling
//! thread, so a writer that never closes its end cannot keep a thread or descriptor alive past
//! the deadline.

#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd};
use std::{io, time::Instant};

use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Bounded {
    Complete(Zeroizing<Vec<u8>>),
    TooLarge,
    #[cfg_attr(not(unix), allow(dead_code))]
    TimedOut,
}

/// Reads until end of file, more than `limit` bytes, or `deadline`, whichever comes first.
#[cfg(unix)]
pub fn read_bounded(source: impl AsFd, limit: usize, deadline: Instant) -> io::Result<Bounded> {
    let fd = source.as_fd();
    let capacity = limit + 1;
    // Preallocated so the buffer never reallocates and leaves unzeroed copies of a secret.
    let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
    loop {
        if buffer.len() > limit {
            return Ok(Bounded::TooLarge);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(Bounded::TimedOut);
        }
        if !wait_readable(fd, left)? {
            continue;
        }
        if read_some(fd, &mut buffer, capacity)? == Some(0) {
            return Ok(Bounded::Complete(buffer));
        }
    }
}

/// Elsewhere no caller has a pipe that can hang (systemd-creds exists only on Linux), so the
/// read blocks; it is still size-bounded.
#[cfg(not(unix))]
pub fn read_bounded(
    source: impl io::Read,
    limit: usize,
    _deadline: Instant,
) -> io::Result<Bounded> {
    use io::Read as _;

    let mut buffer = Zeroizing::new(Vec::with_capacity(limit + 1));
    source.take(limit as u64 + 1).read_to_end(&mut buffer)?;
    if buffer.len() > limit {
        return Ok(Bounded::TooLarge);
    }
    Ok(Bounded::Complete(buffer))
}

#[cfg(unix)]
fn wait_readable(fd: BorrowedFd<'_>, left: std::time::Duration) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Rounded up, so a sub-millisecond remainder waits instead of spinning.
    let millis =
        libc::c_int::try_from(left.as_millis().saturating_add(1)).unwrap_or(libc::c_int::MAX);
    // SAFETY: `pollfd` is one valid, initialised entry that lives for the whole call.
    let ready = unsafe { libc::poll(&raw mut pollfd, 1, millis) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(ready > 0)
}

/// `Some(0)` at end of file, `None` when nothing was ready after all.
#[cfg(unix)]
fn read_some(
    fd: BorrowedFd<'_>,
    buffer: &mut Vec<u8>,
    capacity: usize,
) -> io::Result<Option<usize>> {
    let start = buffer.len();
    buffer.resize(capacity, 0);
    let room = &mut buffer[start..];
    // SAFETY: `room` is initialised memory owned by `buffer`, valid for `room.len()` bytes for the
    // whole call; `capacity` never exceeds the preallocation, so the resize did not move it.
    let read = unsafe { libc::read(fd.as_raw_fd(), room.as_mut_ptr().cast(), room.len()) };
    let error = io::Error::last_os_error();
    let got = usize::try_from(read).ok();
    buffer.truncate(start + got.unwrap_or(0));
    if let Some(got) = got {
        return Ok(Some(got));
    }
    match error.kind() {
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => Ok(None),
        _ => Err(error),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        io::Write as _,
        os::{fd::OwnedFd, unix::net::UnixStream},
        time::Duration,
    };

    use super::*;

    const DEADLINE: Duration = Duration::from_millis(200);

    fn pipe() -> (OwnedFd, UnixStream) {
        let (reader, writer) = UnixStream::pair().expect("socket pair");
        (OwnedFd::from(reader), writer)
    }

    #[test]
    fn reads_everything_up_to_end_of_file() {
        let (reader, mut writer) = pipe();
        writer.write_all(b"hunter2").expect("write");
        drop(writer);
        let read = read_bounded(&reader, 16, Instant::now() + DEADLINE).expect("read");
        assert!(matches!(read, Bounded::Complete(bytes) if bytes.as_slice() == b"hunter2"));
    }

    #[test]
    fn more_than_the_limit_is_too_large() {
        let (reader, mut writer) = pipe();
        writer.write_all(&[b'x'; 17]).expect("write");
        let read = read_bounded(&reader, 16, Instant::now() + DEADLINE).expect("read");
        assert!(matches!(read, Bounded::TooLarge), "{read:?}");
    }

    #[test]
    fn exactly_the_limit_is_complete() {
        let (reader, mut writer) = pipe();
        writer.write_all(&[b'x'; 16]).expect("write");
        drop(writer);
        let read = read_bounded(&reader, 16, Instant::now() + DEADLINE).expect("read");
        assert!(matches!(read, Bounded::Complete(bytes) if bytes.len() == 16));
    }

    #[test]
    fn a_writer_that_never_closes_times_out_on_the_deadline() {
        let (reader, mut writer) = pipe();
        writer.write_all(b"partial").expect("write");
        let started = Instant::now();
        let read = read_bounded(&reader, 16, started + DEADLINE).expect("read");
        assert!(matches!(read, Bounded::TimedOut), "{read:?}");
        assert!(started.elapsed() < DEADLINE * 5, "{:?}", started.elapsed());
        drop(writer);
    }
}
