//! The native relay as a library, so its tests and the engine's can run it in-process:
//! configuration, the HTTP front (`/c`, `/v`, 404), and tokio as the logic's [`Platform`].

pub mod client;
mod doh;
mod messages;

use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use satmux_core::{CARRIER_PATH, Dest, KeyRing, Status, VERSION_PATH};
use satmux_relay_logic::{Limits, MessageIo, Platform, serve_carrier};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

pub use doh::DohUrl;
pub use messages::Messages;

/// The most bytes of request head the relay reads before giving up on a caller.
const HEAD_MAX: usize = 16 * 1024;

/// Whether the relay itself terminates TLS.
pub enum Tls {
    /// `SATMUX_RELAY_TLS=off`: plain TCP, for tests and for a front that terminates TLS.
    Off,
    /// `SATMUX_RELAY_CERT` and `SATMUX_RELAY_CERT_KEY`: TLS 1.3 with that chain and key.
    On(tokio_rustls::TlsAcceptor),
}

/// What an onward connect to a loopback, private or link-local address gets
/// (`SATMUX_RELAY_ALLOW_PRIVATE`). Cloudflare refuses these for the Worker; `Refused` is the
/// native relay behaving the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateDestinations {
    /// `yes`: connect to them like any other address.
    Allowed,
    /// `no`: answer [`Status::Forbidden`].
    Refused,
}

/// Everything the native relay reads, parsed once. Every field is required.
pub struct Config {
    /// `SATMUX_RELAY_LISTEN`.
    pub listen: SocketAddr,
    /// `SATMUX_RELAY_TLS`, or the certificate pair.
    pub tls: Tls,
    /// `SATMUX_RELAY_KEYS`.
    pub keys: KeyRing,
    /// `SATMUX_RELAY_BUILD`.
    pub build: String,
    /// `SATMUX_RELAY_STREAMS`, `_OPEN_MS`, `_CONNECT_MS`, `_MEASURE_BYTES`.
    pub limits: Limits,
    /// `SATMUX_RELAY_DOH`.
    pub doh: DohUrl,
    /// `SATMUX_RELAY_ALLOW_PRIVATE`.
    pub private: PrivateDestinations,
}

fn tls_acceptor(cert_path: &str, key_path: &str) -> Result<tokio_rustls::TlsAcceptor, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_file_iter(cert_path)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("SATMUX_RELAY_CERT: {error}"))?;
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|error| format!("SATMUX_RELAY_CERT_KEY: {error}"))?;
    let mut server = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| format!("SATMUX_RELAY_CERT: {error}"))?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server)))
}

impl Config {
    /// Parses the relay's whole input from `lookup` (the environment). `Err` is one line naming
    /// the variable that is missing or refused.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let need = |name: &str| lookup(name).ok_or_else(|| format!("{name} is not set"));
        let listen = need("SATMUX_RELAY_LISTEN")?;
        let listen = listen.parse().map_err(|_| "SATMUX_RELAY_LISTEN is not address:port".to_owned())?;
        let tls = match (lookup("SATMUX_RELAY_TLS"), lookup("SATMUX_RELAY_CERT"), lookup("SATMUX_RELAY_CERT_KEY")) {
            (Some(off), None, None) if off == "off" => Tls::Off,
            (Some(_), None, None) => return Err("SATMUX_RELAY_TLS is not `off`".to_owned()),
            (None, Some(cert), Some(key)) => Tls::On(tls_acceptor(&cert, &key)?),
            _ => {
                return Err("exactly one of SATMUX_RELAY_TLS=off, or SATMUX_RELAY_CERT with SATMUX_RELAY_CERT_KEY, must be set".to_owned());
            }
        };
        let keys = KeyRing::parse(&need("SATMUX_RELAY_KEYS")?).map_err(|error| format!("SATMUX_RELAY_KEYS: {error}"))?;
        let build = need("SATMUX_RELAY_BUILD")?;
        let limits = Limits::parse(
            &need("SATMUX_RELAY_STREAMS")?,
            &need("SATMUX_RELAY_OPEN_MS")?,
            &need("SATMUX_RELAY_CONNECT_MS")?,
            &need("SATMUX_RELAY_MEASURE_BYTES")?,
        )
        .map_err(|error| error.to_string())?;
        let doh = DohUrl::parse(&need("SATMUX_RELAY_DOH")?).ok_or("SATMUX_RELAY_DOH is not an http or https url")?;
        let private = match need("SATMUX_RELAY_ALLOW_PRIVATE")?.as_str() {
            "yes" => PrivateDestinations::Allowed,
            "no" => PrivateDestinations::Refused,
            _ => return Err("SATMUX_RELAY_ALLOW_PRIVATE is not `yes` or `no`".to_owned()),
        };
        Ok(Self { listen, tls, keys, build, limits, doh, private })
    }
}

/// Tokio as the relay's platform.
pub struct Native {
    doh: DohUrl,
    private: PrivateDestinations,
    roots: Arc<rustls::ClientConfig>,
}

impl Native {
    /// A platform that resolves through `doh` and treats private destinations as `private` says.
    pub fn new(doh: DohUrl, private: PrivateDestinations) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self { doh, private, roots: Arc::new(client) }
    }
}

/// The addresses Cloudflare would refuse a Worker for being inside somebody's network.
fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_private(IpAddr::V4(v4)),
            None => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_unicast_link_local(),
        },
    }
}

fn status_of_connect(error: &std::io::Error) -> Status {
    match error.kind() {
        std::io::ErrorKind::TimedOut => Status::TimedOut,
        _ => Status::Unreachable,
    }
}

impl Platform for Native {
    type Conn = Compat<TcpStream>;

    async fn connect(&self, dest: &Dest) -> Result<Self::Conn, Status> {
        let addresses: Vec<SocketAddr> = match dest {
            Dest::Name(name, port) => match tokio::net::lookup_host((name.as_str(), *port)).await {
                Ok(found) => found.collect(),
                Err(_) => return Err(Status::NoSuchName),
            },
            Dest::V4(address, port) => vec![SocketAddr::from((*address, *port))],
            Dest::V6(address, port) => vec![SocketAddr::from((*address, *port))],
        };
        let mut outcome = Status::NoSuchName;
        for address in addresses {
            if self.private == PrivateDestinations::Refused && is_private(address.ip()) {
                return Err(Status::Forbidden);
            }
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream.compat());
                }
                Err(error) => outcome = status_of_connect(&error),
            }
        }
        Err(outcome)
    }

    async fn doh(&self, query: &[u8]) -> Result<Vec<u8>, Status> {
        doh::exchange(&self.doh, &self.roots, query).await.map_err(|error| {
            eprintln!("satmux-relay-native: dns: {error}");
            Status::Unreachable
        })
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// What a caller asked for, once its head has been read and its key checked.
enum Asked {
    Nothing,
    Version,
    Carrier { accept: String },
}

fn asked(head: &[u8], keys: &KeyRing) -> Asked {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    let Ok(httparse::Status::Complete(_)) = request.parse(head) else { return Asked::Nothing };
    let header = |name: &str| request.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value);
    let admitted = header("Authorization")
        .and_then(|value| value.strip_prefix(b"Bearer "))
        .and_then(|key| keys.admits(key))
        .is_some();
    if !admitted || request.method != Some("GET") {
        return Asked::Nothing;
    }
    let upgrading = header("Upgrade").is_some_and(|value| value.eq_ignore_ascii_case(b"websocket"));
    match (request.path, header("Sec-WebSocket-Key")) {
        (Some(path), _) if path == VERSION_PATH => Asked::Version,
        (Some(path), Some(key)) if path == CARRIER_PATH && upgrading => Asked::Carrier { accept: derive_accept_key(key) },
        _ => Asked::Nothing,
    }
}

/// Serves one accepted connection (after TLS, if any) to its end.
pub async fn serve_connection<S>(mut stream: S, keys: &KeyRing, build: &str, limits: &Limits, platform: &Native)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let read_head = async {
        let mut head = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                let rest = head.split_off(end + 4);
                return Some((head, rest));
            }
            if head.len() > HEAD_MAX {
                return None;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
        }
    };
    let Ok(Some((head, rest))) = tokio::time::timeout(limits.open, read_head).await else { return };
    match asked(&head, keys) {
        Asked::Nothing => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            let _ = stream.shutdown().await;
        }
        Asked::Version => {
            let answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{build}",
                build.len()
            );
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
        Asked::Carrier { accept } => {
            let answer = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            if stream.write_all(answer.as_bytes()).await.is_err() {
                return;
            }
            let socket = WebSocketStream::from_partially_read(stream, rest, Role::Server, None).await;
            serve_carrier(MessageIo::new(Messages::new(socket)), platform, limits).await;
        }
    }
}

/// Accepts connections forever, each served on the current thread's `LocalSet`. Returns only
/// the error that stopped the listener.
pub async fn serve(listener: TcpListener, config: Config) -> std::io::Error {
    struct Shared {
        tls: Tls,
        keys: KeyRing,
        build: String,
        limits: Limits,
        platform: Native,
    }
    let shared = Rc::new(Shared {
        tls: config.tls,
        keys: config.keys,
        build: config.build,
        limits: config.limits,
        platform: Native::new(config.doh, config.private),
    });
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => return error,
        };
        let _ = stream.set_nodelay(true);
        let shared = shared.clone();
        tokio::task::spawn_local(async move {
            let Shared { tls, keys, build, limits, platform } = &*shared;
            match tls {
                Tls::Off => serve_connection(stream, keys, build, limits, platform).await,
                Tls::On(acceptor) => {
                    if let Ok(Ok(stream)) = tokio::time::timeout(limits.open, acceptor.accept(stream)).await {
                        serve_connection(stream, keys, build, limits, platform).await;
                    }
                }
            }
        });
    }
}
