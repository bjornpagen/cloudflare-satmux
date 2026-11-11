//! Finding the relay's addresses without asking the cabin: DNS over HTTPS to address literals,
//! the certificate verified for the address itself, then the seed file. There is no third way.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use satmux_core::{DNS_MAX, HostName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::dnsmsg;
use crate::net::{self, SocketFactory};

/// The port HTTPS is served on; a resolver literal names an address only.
pub const HTTPS_PORT: u16 = 443;
const DOH_PATH: &str = "/dns-query";
const DNS_MESSAGE: &str = "application/dns-message";
/// The seed file's name in the state folder.
pub const SEED: &str = "seed";
const SEED_NEW: &str = "seed.new";
/// The most header fields an answer may carry before it is not worth reading.
const RESPONSE_HEADERS: usize = 64;
/// The most bytes read from a resolver: one largest DNS message, and as much again for headers.
const RESPONSE_MAX: usize = DNS_MAX + DNS_MAX;
const HTTP_OK: u16 = 200;

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// One RFC 8484 POST over HTTP/1.1 to a resolver address. Bounding the time is the caller's.
pub async fn doh(tls: &Arc<ClientConfig>, factory: &SocketFactory, resolver: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let tcp = net::connect(factory, resolver).await?;
    let mut stream = TlsConnector::from(tls.clone()).connect(ServerName::IpAddress(resolver.ip().into()), tcp).await?;
    let host = match resolver.ip() {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    let mut request = format!(
        "POST {DOH_PATH} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {DNS_MESSAGE}\r\nAccept: {DNS_MESSAGE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query.len()
    )
    .into_bytes();
    request.extend_from_slice(query);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    loop {
        let mut headers = [httparse::EMPTY_HEADER; RESPONSE_HEADERS];
        let mut parsed = httparse::Response::new(&mut headers);
        if let httparse::Status::Complete(body_at) = parsed.parse(&response).map_err(io::Error::other)? {
            if parsed.code != Some(HTTP_OK) {
                return Err(invalid("the resolver did not answer 200"));
            }
            let length = parsed
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| std::str::from_utf8(h.value).ok()?.trim().parse::<usize>().ok())
                .ok_or_else(|| invalid("the resolver's answer has no length"))?;
            if length > DNS_MAX {
                return Err(invalid("the resolver's answer is over the largest DNS message"));
            }
            if response.len() >= body_at + length {
                return Ok(response[body_at..body_at + length].to_vec());
            }
        }
        if response.len() >= RESPONSE_MAX {
            return Err(invalid("the resolver's answer is too long"));
        }
        let mut chunk = [0u8; DNS_MAX];
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => 0,
            Err(error) => return Err(error),
        };
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        response.extend_from_slice(&chunk[..n]);
    }
}

/// One resolver asked for a name's addresses; an empty answer is `NotFound`.
pub async fn ask(tls: &Arc<ClientConfig>, factory: &SocketFactory, resolver: SocketAddr, name: &HostName) -> io::Result<Vec<Ipv4Addr>> {
    let answer = doh(tls, factory, resolver, &dnsmsg::a_query(name)).await?;
    let addresses = dnsmsg::a_addresses(&answer).map_err(io::Error::other)?;
    if addresses.is_empty() { Err(io::ErrorKind::NotFound.into()) } else { Ok(addresses) }
}

/// Where the relay's addresses came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    Resolver { resolver: IpAddr, addresses: Vec<Ipv4Addr> },
    Seed { addresses: Vec<Ipv4Addr> },
}

impl Found {
    pub fn addresses(&self) -> &[Ipv4Addr] {
        match self {
            Found::Resolver { addresses, .. } | Found::Seed { addresses } => addresses,
        }
    }
}

/// Neither step produced an address.
#[derive(Debug, thiserror::Error)]
#[error("no resolver answered for the relay within {waited:?} (last: {resolvers}), and the seed file gave nothing ({seed})")]
pub struct NotFound {
    pub waited: Duration,
    pub resolvers: String,
    pub seed: String,
}

/// The text of a seed file for these addresses, and back. One address a line.
pub fn seed_text(addresses: &[Ipv4Addr]) -> String {
    addresses.iter().map(|a| format!("{a}\n")).collect()
}

pub fn seed_addresses(text: &str) -> Vec<Ipv4Addr> {
    text.lines().filter_map(|line| line.trim().parse().ok()).collect()
}

/// Asks every resolver at once and takes the first answer; failing that, the seeds. A fresh
/// answer replaces the seed file by rename.
pub async fn relay(
    tls: &Arc<ClientConfig>,
    factory: &SocketFactory,
    resolvers: &[SocketAddr],
    name: &HostName,
    state: &Path,
    wait: Duration,
) -> Result<Found, NotFound> {
    let mut asking: FuturesUnordered<_> =
        resolvers.iter().map(|resolver| async move { (resolver.ip(), ask(tls, factory, *resolver, name).await) }).collect();
    let mut last = String::from("none asked");
    let raced = tokio::time::timeout(wait, async {
        while let Some((resolver, answer)) = asking.next().await {
            match answer {
                Ok(addresses) => return Some((resolver, addresses)),
                Err(error) => last = format!("{resolver}: {error}"),
            }
        }
        None
    })
    .await;
    if let Ok(Some((resolver, addresses))) = raced {
        let fresh = state.join(SEED_NEW);
        let kept = tokio::fs::write(&fresh, seed_text(&addresses)).await;
        let kept = match kept {
            Ok(()) => tokio::fs::rename(&fresh, state.join(SEED)).await,
            Err(error) => Err(error),
        };
        if let Err(error) = kept {
            tracing::warn!(%error, "the seed file was not replaced");
        }
        return Ok(Found::Resolver { resolver, addresses });
    }
    let seed = match tokio::fs::read_to_string(state.join(SEED)).await {
        Ok(text) => match seed_addresses(&text) {
            addresses if addresses.is_empty() => String::from("no address in it"),
            addresses => return Ok(Found::Seed { addresses }),
        },
        Err(error) => error.to_string(),
    };
    Err(NotFound { waited: wait, resolvers: last, seed })
}
