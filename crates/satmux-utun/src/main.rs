//! `satmux-utun -d <fd> -e <var> prog...`: opens one utun interface, moves it to descriptor
//! `<fd>` without close-on-exec, puts the interface's name in the environment variable `<var>`
//! and executes `prog`. A chain loader: it does nothing else. macOS only.

use std::ffi::OsString;
use std::process::ExitCode;

/// Bad input: do not retry.
const EXIT_INPUT: u8 = 100;
/// The kernel refused (not root, no descriptors), or `prog` could not be executed.
#[cfg(target_os = "macos")]
const EXIT_TEMPORARY: u8 = 111;

const USAGE: &str = "usage: satmux-utun -d <fd> -e <var> prog...";

/// The whole input, parsed once.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct Chain {
    fd: i32,
    var: OsString,
    prog: OsString,
    args: Vec<OsString>,
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Chain, &'static str> {
    let mut fd: Option<i32> = None;
    let mut var: Option<OsString> = None;
    let prog = loop {
        let arg = args.next().ok_or(USAGE)?;
        match arg.to_str() {
            Some("-d") if fd.is_none() => {
                let value = args.next().ok_or(USAGE)?;
                let parsed: i32 = value.to_str().and_then(|text| text.parse().ok()).ok_or(USAGE)?;
                if parsed < 0 {
                    return Err(USAGE);
                }
                fd = Some(parsed);
            }
            Some("-e") if var.is_none() => {
                let value = args.next().ok_or(USAGE)?;
                let bytes = value.as_encoded_bytes();
                if bytes.is_empty() || bytes.contains(&b'=') || bytes.contains(&0) {
                    return Err(USAGE);
                }
                var = Some(value);
            }
            Some(option) if option.starts_with('-') => return Err(USAGE),
            _ => break arg,
        }
    };
    Ok(Chain { fd: fd.ok_or(USAGE)?, var: var.ok_or(USAGE)?, prog, args: args.collect() })
}

#[cfg(target_os = "macos")]
mod utun {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

    /// The kernel control that makes utun interfaces.
    const CONTROL: &[u8] = b"com.apple.net.utun_control";

    fn checked(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
    }

    /// Opens one utun interface, the kernel choosing its unit, and returns it with its name.
    pub fn open() -> io::Result<(OwnedFd, String)> {
        // SAFETY: `socket` takes no pointers; a non-negative result is a descriptor nothing else owns.
        let raw = checked(unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) })?;
        // SAFETY: `raw` was just returned by `socket` and is owned by nothing else.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: `ctl_info` is plain integers and a character array, for which all-zero is a value.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        for (slot, byte) in info.ctl_name.iter_mut().zip(CONTROL) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: CTLIOCGINFO reads and writes exactly one `ctl_info`, which `info` is, live for the call.
        checked(unsafe { libc::ioctl(socket.as_raw_fd(), libc::CTLIOCGINFO, &mut info) })?;

        let address = libc::sockaddr_ctl {
            sc_len: size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
            sc_family: libc::AF_SYSTEM as libc::c_uchar,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        // SAFETY: the pointer and length describe `address`, a whole `sockaddr_ctl` live for the call.
        checked(unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        })?;

        let mut name = [0u8; libc::IFNAMSIZ];
        let mut length = name.len() as libc::socklen_t;
        // SAFETY: the kernel writes at most `length` bytes into `name` and stores the count in `length`.
        checked(unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast::<libc::c_void>(),
                &mut length,
            )
        })?;
        let written = &name[..(length as usize).min(name.len())];
        let text = written.split(|byte| *byte == 0).next().unwrap_or(written);
        let name = std::str::from_utf8(text).map_err(io::Error::other)?.to_owned();
        Ok((socket, name))
    }

    /// Puts the interface on descriptor `target`, open across exec. The descriptor is
    /// deliberately left open: the executed program inherits it.
    pub fn place(socket: OwnedFd, target: RawFd) -> io::Result<()> {
        if socket.as_raw_fd() == target {
            let raw = socket.into_raw_fd();
            // SAFETY: `raw` is an open descriptor; F_SETFD with 0 only clears its close-on-exec flag.
            checked(unsafe { libc::fcntl(raw, libc::F_SETFD, 0) })?;
            return Ok(());
        }
        // SAFETY: `dup2` takes no pointers. It replaces `target`, which the caller named for this
        // purpose, and the duplicate has no close-on-exec flag.
        checked(unsafe { libc::dup2(socket.as_raw_fd(), target) })?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    use std::os::unix::process::CommandExt;

    let chain = match parse(std::env::args_os().skip(1)) {
        Ok(chain) => chain,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::from(EXIT_INPUT);
        }
    };
    let name = match utun::open().and_then(|(socket, name)| utun::place(socket, chain.fd).map(|()| name)) {
        Ok(name) => name,
        Err(error) => {
            eprintln!("satmux-utun: cannot open a utun interface: {error}");
            return ExitCode::from(EXIT_TEMPORARY);
        }
    };
    let error = std::process::Command::new(&chain.prog).args(&chain.args).env(&chain.var, name).exec();
    eprintln!("satmux-utun: cannot execute {}: {error}", chain.prog.display());
    ExitCode::from(EXIT_TEMPORARY)
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(_) => eprintln!("satmux-utun: macOS only"),
        Err(why) => eprintln!("{why}"),
    }
    ExitCode::from(EXIT_INPUT)
}
