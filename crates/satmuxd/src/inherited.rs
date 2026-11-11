//! Descriptors the supervisor hands the daemon by number: the readiness pipe and, for the tunnel
//! front end, the utun device. A number is a claim, not a descriptor. It is checked and taken
//! here, before the runtime exists: the runtime's own descriptors (its kqueue first) take the
//! lowest free numbers, so a number that names nothing now would name one of those a moment
//! later, and the daemon would write its readiness byte into its own event queue and close it.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// Standard input, output and error: never what a supervisor means by "your descriptor".
const STANDARD: RawFd = 2;

/// Why a number was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NotAdopted {
    #[error("{variable}: descriptor {fd} is standard input, output or error")]
    Standard { variable: &'static str, fd: RawFd },
    #[error("{variable}: descriptor {fd} is not open in this process")]
    NotOpen { variable: &'static str, fd: RawFd },
    #[error("{variable} and {other} both name descriptor {fd}")]
    Shared { variable: &'static str, other: &'static str, fd: RawFd },
}

/// Takes ownership of the open descriptor `fd`, which `variable` named, and marks it
/// close-on-exec: it was inherited for this process and goes no further.
///
/// # Safety
///
/// Nothing else in this process may own `fd`: call it once per number, before anything that
/// opens descriptors of its own.
pub unsafe fn adopt(variable: &'static str, fd: RawFd) -> Result<OwnedFd, NotAdopted> {
    if fd <= STANDARD {
        return Err(NotAdopted::Standard { variable, fd });
    }
    // SAFETY: F_GETFD reads one descriptor's flags and touches nothing else; a number that is
    // not open answers -1 with EBADF.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(NotAdopted::NotOpen { variable, fd });
    }
    // SAFETY: `fd` is open (above) and F_SETFD only sets its own flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(NotAdopted::NotOpen { variable, fd });
    }
    // SAFETY: `fd` is open, and the caller vouches that nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Refuses two variables that name the same number: one descriptor cannot be both.
pub fn distinct(variable: &'static str, fd: RawFd, other: &'static str, other_fd: RawFd) -> Result<(), NotAdopted> {
    if fd == other_fd { Err(NotAdopted::Shared { variable, other, fd }) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, IntoRawFd};

    #[test]
    fn an_open_descriptor_is_taken_and_closes_on_exec() {
        let (read, _write) = std::io::pipe().expect("a pipe");
        let fd = read.into_raw_fd();
        // SAFETY: `into_raw_fd` gave up the only owner.
        let adopted = unsafe { adopt("TEST", fd) }.expect("an open descriptor");
        assert_eq!(adopted.as_raw_fd(), fd);
        // SAFETY: reads the flags of a descriptor this test owns.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }

    #[test]
    fn a_number_that_is_not_open_is_refused() {
        // Above any limit on open descriptors, so no test running beside this one can hold it.
        let fd = RawFd::MAX;
        // SAFETY: nothing owns a descriptor that is not open.
        assert_eq!(unsafe { adopt("TEST", fd) }.err(), Some(NotAdopted::NotOpen { variable: "TEST", fd }));
    }

    #[test]
    fn the_standard_three_are_refused() {
        for fd in 0..=STANDARD {
            // SAFETY: refused before the descriptor is touched.
            assert_eq!(unsafe { adopt("TEST", fd) }.err(), Some(NotAdopted::Standard { variable: "TEST", fd }));
        }
    }

    #[test]
    fn one_number_is_not_two_descriptors() {
        assert_eq!(distinct("A", 3, "B", 3), Err(NotAdopted::Shared { variable: "A", other: "B", fd: 3 }));
        assert_eq!(distinct("A", 3, "B", 4), Ok(()));
    }
}
