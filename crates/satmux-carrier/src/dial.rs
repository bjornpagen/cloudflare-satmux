//! One carrier: TCP on a bound socket, TLS 1.3 against the roots file, the WebSocket upgrade
//! with the device key, and a yamux client over it. Each step is timed, because the probe
//! reports the steps and the pool takes the upgrade's round trip as its first measurement.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use satmux_core::{CARRIER_PATH, HostName, Open, Status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

use crate::net::{self, SocketFactory};
use crate::wsio::WsBytes;

const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// TLS 1.3 only, aws-lc-rs, and no root that is not in the file.
pub fn tls_config(roots: &Path) -> io::Result<Arc<ClientConfig>> {
    let mut store = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(roots).map_err(io::Error::other)? {
        store.add(certificate.map_err(io::Error::other)?).map_err(io::Error::other)?;
    }
    if store.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "the roots file holds no certificate"));
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    Ok(Arc::new(config))
}

/// The `Authorization` value for a key file's text. Never printed: it has no `Debug`.
pub fn bearer(key_file_text: &str) -> io::Result<HeaderValue> {
    let mut value = HeaderValue::from_str(&format!("Bearer {}", key_file_text.trim()))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the key file is not header text"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// Which step of a dial failed. The probe prints the distinction; the pool only redials.
#[derive(Debug, thiserror::Error)]
pub enum DialFailed {
    #[error("tcp connect: {0}")]
    Tcp(io::Error),
    #[error("tls: the certificate is not trusted: {0}")]
    Untrusted(io::Error),
    #[error("tls: {0}")]
    Tls(io::Error),
    #[error("websocket upgrade: {0}")]
    Upgrade(tokio_tungstenite::tungstenite::Error),
}

/// How long each step took.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    pub tcp: Duration,
    pub tls: Duration,
    pub upgrade: Duration,
}

pub type Transport = WsBytes<WebSocketStream<TlsStream<TcpStream>>>;
pub type Stream = Compat<yamux::Stream>;

/// Everything a dial needs that does not change between dials.
pub struct Dialer {
    name: HostName,
    server_name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    authorization: HeaderValue,
    factory: SocketFactory,
    streams: usize,
}

impl Dialer {
    pub fn new(name: HostName, tls: Arc<ClientConfig>, authorization: HeaderValue, factory: SocketFactory, streams: usize) -> io::Result<Self> {
        let server_name = ServerName::try_from(name.as_str().to_owned()).map_err(io::Error::other)?;
        Ok(Self { name, server_name, tls, authorization, factory, streams })
    }

    pub fn tls(&self) -> &Arc<ClientConfig> {
        &self.tls
    }

    pub fn factory(&self) -> &SocketFactory {
        &self.factory
    }

    /// Dials one carrier at this address. Bounding the time is the caller's.
    pub async fn dial(&self, relay: SocketAddr) -> Result<(yamux::Connection<Transport>, Timings), DialFailed> {
        let started = Instant::now();
        let tcp = net::connect(&self.factory, relay).await.map_err(DialFailed::Tcp)?;
        let connected = Instant::now();
        let tls = TlsConnector::from(self.tls.clone()).connect(self.server_name.clone(), tcp).await.map_err(|error| {
            let untrusted = error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .is_some_and(|inner| matches!(inner, rustls::Error::InvalidCertificate(_)));
            if untrusted { DialFailed::Untrusted(error) } else { DialFailed::Tls(error) }
        })?;
        let secured = Instant::now();
        let mut request = format!("wss://{}:{}{CARRIER_PATH}", self.name, relay.port()).into_client_request().map_err(DialFailed::Upgrade)?;
        request.headers_mut().insert(AUTHORIZATION, self.authorization.clone());
        let (socket, _response) = tokio_tungstenite::client_async(request, tls).await.map_err(DialFailed::Upgrade)?;
        let upgraded = Instant::now();
        let mut config = yamux::Config::default();
        config.set_max_connection_receive_window(None).set_max_num_streams(self.streams);
        let connection = yamux::Connection::new(WsBytes::new(socket), config, yamux::Mode::Client);
        Ok((connection, Timings { tcp: connected - started, tls: secured - connected, upgrade: upgraded - secured }))
    }
}

type Reply = oneshot::Sender<io::Result<yamux::Stream>>;

/// A live carrier, as the rest of the program holds it: the way to ask its driver for a new
/// stream. When the last clone is dropped the driver closes the carrier.
#[derive(Clone)]
pub struct Session {
    opens: mpsc::UnboundedSender<Reply>,
}

impl Session {
    /// Splits a connection into its handle and the future that drives it until it ends.
    pub fn new<T>(connection: yamux::Connection<T>) -> (Self, impl Future<Output = ()> + Send + 'static)
    where
        T: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
    {
        let (opens, requests) = mpsc::unbounded_channel();
        (Self { opens }, drive(connection, requests))
    }

    /// A new stream with nothing written yet.
    pub async fn open(&self) -> io::Result<yamux::Stream> {
        let (reply, opened) = oneshot::channel();
        self.opens.send(reply).map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
        opened.await.map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?
    }

    /// Opens a stream, writes the open and the first payload in one flight, and reads the
    /// relay's status byte.
    pub async fn request(&self, open: &Open, first: &[u8]) -> io::Result<(Stream, Status)> {
        let mut stream = self.open().await?.compat();
        let mut flight = Vec::new();
        open.encode(&mut flight);
        flight.extend_from_slice(first);
        stream.write_all(&flight).await?;
        stream.flush().await?;
        let status = Status::from_byte(stream.read_u8().await?).ok_or(io::ErrorKind::InvalidData)?;
        Ok((stream, status))
    }
}

/// What a relay's refusal looks like to a caller that speaks `io::Error`.
pub fn refusal(status: Status) -> io::Error {
    let kind = match status {
        Status::Connected => io::ErrorKind::Other,
        Status::Forbidden => io::ErrorKind::PermissionDenied,
        Status::NoSuchName => io::ErrorKind::NotFound,
        Status::Unreachable => io::ErrorKind::ConnectionRefused,
        Status::TimedOut => io::ErrorKind::TimedOut,
        Status::Limit => io::ErrorKind::ResourceBusy,
        Status::Malformed => io::ErrorKind::InvalidInput,
        Status::Spent => io::ErrorKind::QuotaExceeded,
    };
    io::Error::new(kind, format!("the relay answered {status:?}"))
}

async fn drive<T>(mut connection: yamux::Connection<T>, mut requests: mpsc::UnboundedReceiver<Reply>)
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    /// Whether anyone can still ask for a stream.
    enum Asked {
        Open,
        Released,
    }
    let mut asked = Asked::Open;
    let mut waiting: VecDeque<Reply> = VecDeque::new();
    std::future::poll_fn(|cx| {
        while let Asked::Open = asked {
            match requests.poll_recv(cx) {
                Poll::Ready(Some(reply)) => waiting.push_back(reply),
                Poll::Ready(None) => asked = Asked::Released,
                Poll::Pending => break,
            }
        }
        while let Some(reply) = waiting.pop_front() {
            match connection.poll_new_outbound(cx) {
                Poll::Ready(result) => {
                    let _ = reply.send(result.map_err(io::Error::other));
                }
                Poll::Pending => {
                    waiting.push_front(reply);
                    break;
                }
            }
        }
        if let (Asked::Released, true) = (&asked, waiting.is_empty()) {
            return connection.poll_close(cx).map(|_| ());
        }
        loop {
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(_unasked))) => {}
                Poll::Ready(Some(Err(_)) | None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await
}
