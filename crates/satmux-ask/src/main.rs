//! `satmux-ask <socket> <verb> [arg]`: writes one request line to the daemon's status socket
//! and copies the reply to standard output.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

/// Bad input: do not retry.
const EXIT_INPUT: u8 = 100;
/// Temporary failure: the socket is absent or the daemon went away.
const EXIT_TEMPORARY: u8 = 111;

/// The whole input, parsed once.
struct Ask {
    socket: PathBuf,
    line: String,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Ask, &'static str> {
    let socket = args.next().ok_or("usage: satmux-ask <socket> <verb> [arg]")?;
    let verb = args.next().ok_or("usage: satmux-ask <socket> <verb> [arg]")?;
    let arg = args.next();
    if args.next().is_some() {
        return Err("usage: satmux-ask <socket> <verb> [arg]");
    }
    let line = match arg {
        Some(arg) => format!("{verb} {arg}\n"),
        None => format!("{verb}\n"),
    };
    if line.trim_end_matches('\n').contains(['\n', '\r']) {
        return Err("satmux-ask: a request is one line");
    }
    Ok(Ask { socket: PathBuf::from(socket), line })
}

fn ask(ask: &Ask) -> io::Result<()> {
    let mut stream = UnixStream::connect(&ask.socket)?;
    stream.write_all(ask.line.as_bytes())?;
    let mut out = io::stdout().lock();
    io::copy(&mut stream, &mut out)?;
    out.flush()
}

fn main() -> ExitCode {
    let parsed = match parse(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::from(EXIT_INPUT);
        }
    };
    match ask(&parsed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("satmux-ask: {}: {error}", parsed.socket.display());
            ExitCode::from(EXIT_TEMPORARY)
        }
    }
}
