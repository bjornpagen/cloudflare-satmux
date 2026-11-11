//! One DNS-over-HTTPS exchange: a POST of `application/dns-message` on a fresh connection.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName};

/// The most bytes of response the relay reads: headers and one DNS message.
const RESPONSE_MAX: usize = 128 * 1024;

/// Whether the resolver is reached through TLS: the url's scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `http://`, for tests against a local resolver.
    Plain,
    /// `https://`, verified against the Mozilla roots compiled in.
    Tls,
}

/// A parsed `SATMUX_RELAY_DOH`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DohUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

impl DohUrl {
    /// Parses `http://host[:port]/path` or `https://host[:port]/path`. The port, when absent,
    /// is the scheme's own.
    pub fn parse(text: &str) -> Option<Self> {
        let (scheme, rest, port) = match (text.strip_prefix("https://"), text.strip_prefix("http://")) {
            (Some(rest), _) => (Scheme::Tls, rest, 443),
            (_, Some(rest)) => (Scheme::Plain, rest, 80),
            _ => return None,
        };
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => return None,
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(']') || !port.is_empty() => (host, port.parse().ok()?),
            _ => (authority, port),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let clean = |s: &str| s.bytes().all(|b| b.is_ascii_graphic());
        (!host.is_empty() && clean(host) && clean(path)).then(|| Self { scheme, host: host.to_owned(), port, path: path.to_owned() })
    }
}

fn bad(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// The body of a complete HTTP response in `seen`, if it is complete. `ended` says the
/// connection has closed, which completes a response that states no length.
fn body_of(seen: &[u8], ended: bool) -> io::Result<Option<Vec<u8>>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let head = match response.parse(seen).map_err(|_| bad("resolver sent no http"))? {
        httparse::Status::Complete(head) => head,
        httparse::Status::Partial if ended => return Err(bad("resolver closed early")),
        httparse::Status::Partial => return Ok(None),
    };
    if response.code != Some(200) {
        return Err(bad("resolver did not answer 200"));
    }
    let header = |name: &str| response.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value);
    let body = &seen[head..];
    if header("Transfer-Encoding").is_some_and(|v| v.eq_ignore_ascii_case(b"chunked")) {
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            match httparse::parse_chunk_size(&body[at..]).map_err(|_| bad("resolver sent a bad chunk"))? {
                httparse::Status::Complete((used, 0)) => {
                    let _ = used;
                    return Ok(Some(out));
                }
                httparse::Status::Complete((used, size)) => {
                    let size = usize::try_from(size).map_err(|_| bad("resolver sent a bad chunk"))?;
                    let start = at + used;
                    let Some(end) = start.checked_add(size).filter(|end| end + 2 <= body.len()) else {
                        return if ended { Err(bad("resolver closed early")) } else { Ok(None) };
                    };
                    out.extend_from_slice(&body[start..end]);
                    at = end + 2;
                }
                httparse::Status::Partial if ended => return Err(bad("resolver closed early")),
                httparse::Status::Partial => return Ok(None),
            }
        }
    }
    match header("Content-Length") {
        Some(length) => {
            let length: usize = std::str::from_utf8(length).ok().and_then(|l| l.trim().parse().ok()).ok_or(bad("resolver sent a bad length"))?;
            match body.get(..length) {
                Some(body) => Ok(Some(body.to_vec())),
                None if ended => Err(bad("resolver closed early")),
                None => Ok(None),
            }
        }
        None if ended => Ok(Some(body.to_vec())),
        None => Ok(None),
    }
}

async fn over<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, url: &DohUrl, query: &[u8]) -> io::Result<Vec<u8>> {
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        url.path,
        url.host,
        query.len()
    )
    .into_bytes();
    request.extend_from_slice(query);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // A TLS peer that closes without saying so ends the response just the same.
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        seen.extend_from_slice(&chunk[..n]);
        if let Some(body) = body_of(&seen, n == 0)? {
            return Ok(body);
        }
        if seen.len() > RESPONSE_MAX {
            return Err(bad("resolver sent too much"));
        }
    }
}

/// Sends `query` to the resolver and returns the DNS message it answers.
pub async fn exchange(url: &DohUrl, roots: &Arc<rustls::ClientConfig>, query: &[u8]) -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect((url.host.as_str(), url.port)).await?;
    let _ = stream.set_nodelay(true);
    match url.scheme {
        Scheme::Plain => over(stream, url, query).await,
        Scheme::Tls => {
            let name = ServerName::try_from(url.host.clone()).map_err(|_| bad("resolver name is not a server name"))?;
            let stream = tokio_rustls::TlsConnector::from(roots.clone()).connect(name, stream).await?;
            over(stream, url, query).await
        }
    }
}
