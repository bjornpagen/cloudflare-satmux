//! `satmux-key -d <fd>`: makes one device key. The key (32 bytes from the operating system, as
//! base64url without padding) goes to standard output as one line; the lower-case hex SHA-256 of
//! that key text goes to descriptor `<fd>` as one line. The key is written nowhere else.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::process::ExitCode;

/// Bad input: do not retry.
const EXIT_INPUT: u8 = 100;
/// Temporary failure: no randomness, or a descriptor that cannot be written.
const EXIT_TEMPORARY: u8 = 111;
/// Bytes of key material.
const KEY_BYTES: usize = 32;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 with the URL alphabet and no padding (RFC 4648 section 5).
fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let word = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        let sextets = [word >> 18, word >> 12, word >> 6, word];
        for sextet in sextets.iter().take(chunk.len() + 1) {
            out.push(char::from(ALPHABET[(sextet & 63) as usize]));
        }
    }
    out
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<RawFd, &'static str> {
    const USAGE: &str = "usage: satmux-key -d <fd>";
    if args.next().as_deref() != Some("-d") {
        return Err(USAGE);
    }
    let fd: RawFd = args.next().ok_or(USAGE)?.parse().map_err(|_| USAGE)?;
    if args.next().is_some() || fd < 0 {
        return Err(USAGE);
    }
    if fd == 1 {
        return Err("satmux-key: the digest descriptor must not be standard output");
    }
    Ok(fd)
}

fn make(fd: RawFd) -> io::Result<()> {
    let mut key = [0u8; KEY_BYTES];
    getrandom::fill(&mut key).map_err(io::Error::other)?;
    let text = base64url(&key);
    let digest = satmux_core::digest_hex(&satmux_core::key_digest(text.as_bytes()));
    // SAFETY: `fd` is the descriptor the caller handed this process for the digest line; nothing
    // else in this program owns it, and the `File` closes it exactly once.
    let mut digest_out = unsafe { File::from_raw_fd(fd) };
    digest_out.write_all(format!("{digest}\n").as_bytes())?;
    digest_out.flush()?;
    let mut out = io::stdout().lock();
    out.write_all(format!("{text}\n").as_bytes())?;
    out.flush()
}

fn main() -> ExitCode {
    let fd = match parse(std::env::args().skip(1)) {
        Ok(fd) => fd,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::from(EXIT_INPUT);
        }
    };
    match make(fd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("satmux-key: {error}");
            ExitCode::from(EXIT_TEMPORARY)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A reference decoder, written the slow obvious way: characters to a bit string and back.
    fn decode(text: &str) -> Vec<u8> {
        let bits: Vec<bool> = text
            .bytes()
            .flat_map(|c| {
                let v = ALPHABET.iter().position(|a| *a == c).expect("alphabet");
                (0..6).rev().map(move |i| v >> i & 1 == 1)
            })
            .collect();
        bits.chunks_exact(8).map(|byte| byte.iter().fold(0u8, |acc, bit| acc << 1 | u8::from(*bit))).collect()
    }

    proptest! {
        #[test]
        fn encoding_round_trips_and_has_no_padding(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            let text = base64url(&bytes);
            prop_assert_eq!(text.len(), (bytes.len() * 8).div_ceil(6));
            prop_assert_eq!(decode(&text), bytes);
        }
    }
}
