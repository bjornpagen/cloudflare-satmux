//! The packet device: whole IP packets in and out. [`Utun`] is the real one, a descriptor whose
//! every datagram is a 4-byte address-family header (a big-endian `u32`) and then the packet.

use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Bytes of the address-family header.
const FAMILY_HEADER: usize = 4;

/// Something that carries whole IP packets, one per call, with no framing of its own.
pub trait Device: Send + Sync + 'static {
    /// Waits for one packet and copies it into `packet`, cutting it to fit. The count is the
    /// packet's length. Dropping the future loses no packet.
    fn recv(&self, packet: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    /// Sends one packet.
    fn send(&self, packet: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

/// The address family of a packet, as its header names it.
fn family(packet: &[u8]) -> io::Result<[u8; FAMILY_HEADER]> {
    let family = match packet.first().map(|first| first >> 4) {
        Some(4) => libc::AF_INET,
        Some(6) => libc::AF_INET6,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "not an IP packet")),
    };
    Ok((family as u32).to_be_bytes())
}

/// A utun descriptor (or anything that frames packets the same way).
pub struct Utun {
    fd: AsyncFd<OwnedFd>,
}

impl Utun {
    /// Takes the descriptor, makes it non-blocking and registers it with the runtime.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: `fd` is an open descriptor this value owns; F_GETFL takes no pointer.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above; F_SETFL takes the integer flags and no pointer.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: an `OwnedFd` is an open descriptor, always reports that same descriptor, and
        // stays open until the `AsyncFd` that now owns it is dropped.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Self { fd })
    }
}

impl Device for Utun {
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        loop {
            let read = self
                .fd
                .async_io(Interest::READABLE, |fd| {
                    let mut header = [0u8; FAMILY_HEADER];
                    let mut parts = [
                        libc::iovec { iov_base: header.as_mut_ptr().cast(), iov_len: header.len() },
                        libc::iovec { iov_base: packet.as_mut_ptr().cast(), iov_len: packet.len() },
                    ];
                    // SAFETY: both parts point at live, writable buffers of the stated lengths,
                    // and the kernel writes no further than those lengths.
                    let read = unsafe { libc::readv(fd.as_raw_fd(), parts.as_mut_ptr(), parts.len() as libc::c_int) };
                    if read < 0 { Err(io::Error::last_os_error()) } else { Ok(read as usize) }
                })
                .await?;
            match read {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                runt if runt <= FAMILY_HEADER => continue,
                framed => return Ok(framed - FAMILY_HEADER),
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        let header = family(packet)?;
        let sent = self
            .fd
            .async_io(Interest::WRITABLE, |fd| {
                let parts = [
                    libc::iovec { iov_base: header.as_ptr().cast_mut().cast(), iov_len: header.len() },
                    libc::iovec { iov_base: packet.as_ptr().cast_mut().cast(), iov_len: packet.len() },
                ];
                // SAFETY: both parts point at live buffers of the stated lengths, which `writev`
                // only reads.
                let sent = unsafe { libc::writev(fd.as_raw_fd(), parts.as_ptr(), parts.len() as libc::c_int) };
                if sent < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
            })
            .await;
        match sent {
            // The interface's queue is full: the packet is lost, as on any link, and TCP repairs it.
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => Ok(()),
            other => other,
        }
    }
}
