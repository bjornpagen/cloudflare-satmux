//! The proxy front end: an HTTP CONNECT proxy. A `CONNECT host:port` is answered 200 at once,
//! without waiting for the relay, so the client's first bytes can ride with the open.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use satmux_carrier::Uplink;
use satmux_core::{Dest, HostName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The most bytes of request head read before the client is given up on.
const HEAD_MAX: usize = 8192;
/// The most header fields a CONNECT may carry.
const HEAD_FIELDS: usize = 32;
/// The size of one read of the client's first payload: a TLS hello with a hybrid key share fits.
const FIRST_READ: usize = 4096;

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const NOT_CONNECT: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// The two waits the front end is told.
#[derive(Clone, Copy, Debug)]
pub struct Waits {
    /// How long a client has to send its request head.
    pub head: Duration,
    /// How long a new flow waits for the client's first bytes.
    pub first_payload: Duration,
}

/// What a request head asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Asked {
    /// Not a whole head yet.
    More,
    /// A CONNECT to this destination; the head took this many bytes.
    Connect(Dest, usize),
    NotConnect,
    Malformed,
}

/// A CONNECT target: `name:port`, `a.b.c.d:port` or `[v6]:port`.
pub fn target(text: &str) -> Option<Dest> {
    let (host, port) = text.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return Some(Dest::V6(literal.parse::<Ipv6Addr>().ok()?.octets(), port));
    }
    if let Ok(literal) = host.parse::<Ipv4Addr>() {
        return Some(Dest::V4(literal.octets(), port));
    }
    Some(Dest::Name(HostName::parse(host).ok()?, port))
}

/// Reads a request head once.
pub fn asked(head: &[u8]) -> Asked {
    let mut fields = [httparse::EMPTY_HEADER; HEAD_FIELDS];
    let mut request = httparse::Request::new(&mut fields);
    match request.parse(head) {
        Ok(httparse::Status::Partial) => Asked::More,
        Ok(httparse::Status::Complete(used)) => match (request.method, request.path.and_then(target)) {
            (Some("CONNECT"), Some(dest)) => Asked::Connect(dest, used),
            (Some("CONNECT"), None) => Asked::Malformed,
            (_, _) => Asked::NotConnect,
        },
        Err(_) => Asked::Malformed,
    }
}

async fn head(client: &mut TcpStream) -> io::Result<(Asked, BytesMut)> {
    let mut read = BytesMut::new();
    loop {
        match asked(&read) {
            Asked::More if read.len() < HEAD_MAX => {
                if client.read_buf(&mut read).await? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            Asked::More => return Ok((Asked::Malformed, read)),
            decided => return Ok((decided, read)),
        }
    }
}

async fn flow(mut client: TcpStream, uplink: Uplink, waits: Waits) -> io::Result<()> {
    client.set_nodelay(true)?;
    let (asked, mut read) = tokio::time::timeout(waits.head, head(&mut client)).await.map_err(|_| io::ErrorKind::TimedOut)??;
    let (dest, used) = match asked {
        Asked::Connect(dest, used) => (dest, used),
        Asked::NotConnect => return client.write_all(NOT_CONNECT).await,
        Asked::More | Asked::Malformed => return client.write_all(BAD_REQUEST).await,
    };
    client.write_all(ESTABLISHED).await?;
    let mut first = read.split_off(used);
    if first.is_empty() {
        first.reserve(FIRST_READ);
        match tokio::time::timeout(waits.first_payload, client.read_buf(&mut first)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(error)) => return Err(error),
        }
    }
    let first: Bytes = first.freeze();
    let mut onward = match uplink.connect(dest.clone(), first).await {
        Ok(onward) => onward,
        Err(error) => {
            tracing::info!(%dest, %error, "flow failed");
            return Ok(());
        }
    };
    tokio::io::copy_bidirectional(&mut client, &mut onward).await.map(|_| ())
}

/// Serves clients until accepting fails for good.
pub async fn serve(listener: TcpListener, uplink: Uplink, waits: Waits) -> io::Error {
    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                let uplink = uplink.clone();
                tokio::spawn(async move {
                    if let Err(error) = flow(client, uplink, waits).await {
                        tracing::debug!(%error, "flow ended");
                    }
                });
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset) => {}
            Err(error) => return error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn dest() -> impl Strategy<Value = Dest> {
        let host = proptest::collection::vec("[a-z]([a-z0-9-]{0,8}[a-z0-9])?", 1..4)
            .prop_map(|labels| HostName::parse(&labels.join(".")).expect("generated names are host names"));
        prop_oneof![
            (host, any::<u16>()).prop_map(|(h, p)| Dest::Name(h, p)),
            (any::<[u8; 4]>(), any::<u16>()).prop_map(|(a, p)| Dest::V4(a, p)),
            (any::<[u8; 16]>(), any::<u16>()).prop_map(|(a, p)| Dest::V6(a, p)),
        ]
    }

    proptest! {
        /// A CONNECT for any destination, as that destination prints, is read back as it, takes
        /// exactly its own bytes, and every shorter prefix asks for more.
        #[test]
        fn a_connect_head_round_trips(dest in dest(), fields in proptest::collection::vec(("[A-Za-z-]{1,12}", "[a-zA-Z0-9 /.;=-]{0,24}"), 0..6), tail in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut head = format!("CONNECT {dest} HTTP/1.1\r\n");
            for (name, value) in &fields {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let mut wire = head.clone().into_bytes();
            for cut in 0..wire.len() {
                prop_assert_eq!(asked(&wire[..cut]), Asked::More);
            }
            wire.extend_from_slice(&tail);
            prop_assert_eq!(asked(&wire), Asked::Connect(dest, head.len()));
        }

        /// Arbitrary bytes never panic, and never become a destination unless they say CONNECT.
        #[test]
        fn arbitrary_heads_are_total(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Asked::Connect(..) = asked(&bytes) {
                prop_assert!(bytes.starts_with(b"CONNECT "));
            }
        }
    }
}
