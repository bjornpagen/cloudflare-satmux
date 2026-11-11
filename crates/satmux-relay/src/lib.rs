//! The relay as a Cloudflare Worker: one invocation per carrier. It checks the key, accepts the
//! WebSocket, and hands it to `satmux-relay-logic`, which is the same code the native relay runs.

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::Duration;

use futures::sink::Sink;
use futures::stream::Stream;
use satmux_core::{CARRIER_PATH, Dest, KeyRing, Status, VERSION_PATH};
use satmux_relay_logic::{Limits, MessageIo, Platform, serve_carrier};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use worker::{
    Context, Delay, Env, EventStream, Fetch, Headers, Method, Request, RequestInit, Response, Socket, WebSocket,
    WebSocketPair, WebsocketEvent, console_error, event,
};

/// Where the Worker sends DNS queries. It is fixed here: the relay is Cloudflare's, and so
/// is every lookup.
const DOH_URL: &str = "https://cloudflare-dns.com/dns-query";
const DNS_MESSAGE: &str = "application/dns-message";

/// Everything the Worker reads, parsed once per invocation. Every variable is required.
struct Config {
    keys: KeyRing,
    build: String,
    limits: Limits,
}

impl Config {
    /// `Err` names the variable that is missing or refused.
    fn read(env: &Env) -> Result<Self, String> {
        let var = |name: &'static str| env.var(name).map(|v| v.to_string()).map_err(|_| format!("{name} is not set"));
        let keys = KeyRing::parse(&var("SATMUX_RELAY_KEYS")?).map_err(|e| format!("SATMUX_RELAY_KEYS: {e}"))?;
        let build = var("SATMUX_RELAY_BUILD")?;
        let limits = Limits::parse(
            &var("SATMUX_RELAY_STREAMS")?,
            &var("SATMUX_RELAY_OPEN_MS")?,
            &var("SATMUX_RELAY_CONNECT_MS")?,
            &var("SATMUX_RELAY_MEASURE_BYTES")?,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self { keys, build, limits })
    }
}

/// The answer to anything that is not a key holder asking for `/c` or `/v`.
fn nothing_here() -> worker::Result<Response> {
    Ok(Response::empty()?.with_status(404))
}

/// The Worker's entry: `/v` answers the build, `/c` becomes a carrier, all else is a 404 that
/// does not distinguish a wrong key from a wrong path.
#[event(fetch)]
async fn fetch(request: Request, env: Env, context: Context) -> worker::Result<Response> {
    let config = match Config::read(&env) {
        Ok(config) => config,
        Err(reason) => {
            // The Worker's stand-in for exit 100: the line goes to the log, never to the caller.
            console_error!("satmux-relay: {reason}");
            return Ok(Response::empty()?.with_status(500));
        }
    };
    let authorization = request.headers().get("Authorization")?;
    let admitted = authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|key| config.keys.admits(key.as_bytes()))
        .is_some();
    if !admitted || request.method() != Method::Get {
        return nothing_here();
    }
    let path = request.path();
    if path == VERSION_PATH {
        return Response::ok(config.build);
    }
    let upgrade = request.headers().get("Upgrade")?;
    let upgrading = upgrade.is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if path != CARRIER_PATH || !upgrading {
        return nothing_here();
    }
    let pair = WebSocketPair::new()?;
    let server = pair.server;
    // Workers hand binary messages over as ArrayBuffer today; a later compatibility date may
    // make Blob the default, which this code cannot read synchronously. Say which one.
    let _ = js_sys::Reflect::set(server.as_ref(), &"binaryType".into(), &"arraybuffer".into());
    server.accept()?;
    let limits = config.limits;
    // The open WebSocket keeps the invocation alive; wait_until also lets the last writes
    // finish after it closes.
    context.wait_until(async move {
        match server.events() {
            Ok(events) => {
                let io = MessageIo::new(Messages { socket: &server, events });
                serve_carrier(io, &Workers, &limits).await;
            }
            Err(error) => console_error!("satmux-relay: websocket events: {error}"),
        }
        let _ = server.close(Some(1000), None::<&str>);
    });
    Response::from_websocket(pair.client)
}

/// The accepted WebSocket as a stream of incoming binary payloads and a sink of outgoing ones.
struct Messages<'a> {
    socket: &'a WebSocket,
    events: EventStream<'a>,
}

impl Stream for Messages<'_> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(match ready!(Pin::new(&mut self.events).poll_next(cx)) {
            Some(Ok(WebsocketEvent::Message(message))) => Some(match message.bytes() {
                Some(bytes) => Ok(bytes),
                None => Err(io::Error::new(io::ErrorKind::InvalidData, "text message on a carrier")),
            }),
            Some(Ok(WebsocketEvent::Close(_))) | None => None,
            Some(Err(error)) => Some(Err(io::Error::other(error.to_string()))),
        })
    }
}

impl Sink<Vec<u8>> for Messages<'_> {
    type Error = io::Error;

    /// A Worker's WebSocket has no send credit to wait for: `send` queues in the runtime.
    /// The bound on that queue is yamux's windows, which the client only reopens as it reads.
    fn poll_ready(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, message: Vec<u8>) -> io::Result<()> {
        self.socket.send_with_bytes(message).map_err(|error| io::Error::other(error.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let _ = self.socket.close(Some(1000), None::<&str>);
        Poll::Ready(Ok(()))
    }
}

/// The Workers runtime as the relay's platform.
struct Workers;

/// Turns what `connect()` or `opened` rejected with into the status the client acts on.
///
/// This is read from the error's text, because the runtime gives nothing else, and the texts
/// are not a documented interface.
///
/// MEASURED (workerd 1.20260730.1, locally): a connect to a loopback port nothing listens on
/// rejects `opened` with `Error: proxy request failed, cannot connect to the specified
/// address`.
///
/// MEASURED (the edge, free plan): that same text, and nothing else, for every refusal tried:
/// a name Cloudflare serves, a Cloudflare address (IPv4 and IPv6), a private address, loopback,
/// a name that does not exist, a closed port on a public host and an unrouted address. On port
/// 443 the edge appends "It looks like you might be trying to connect to a HTTP-based service —
/// consider using fetch instead"; that follows the port, not the reason. A port that drops
/// packets gets no text: the relay's own connect timer answers `TimedOut`.
///
/// So the text does NOT tell a forbidden destination from a dead one, and it is `Forbidden`:
/// the client then tries the destination directly, and writes its "direct" row only if that
/// connect succeeds (satmux-carrier's `route`). A dead origin costs one failed direct connect
/// per flow and is never remembered.
fn status_of_refusal(text: &str) -> Status {
    let text = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|needle| text.contains(needle));
    if has(&["cannot connect to the specified address", "prohibited", "not allowed", "not permitted", "private", "internal"]) {
        Status::Forbidden
    } else if has(&["dns", "resolve", "no such host", "name not"]) {
        Status::NoSuchName
    } else if has(&["timed out", "timeout"]) {
        Status::TimedOut
    } else {
        Status::Unreachable
    }
}

impl Platform for Workers {
    type Conn = Compat<Socket>;

    async fn connect(&self, dest: &Dest) -> Result<Self::Conn, Status> {
        let (host, port) = match dest {
            Dest::Name(name, port) => (name.as_str().to_owned(), *port),
            Dest::V4(address, port) => (std::net::Ipv4Addr::from(*address).to_string(), *port),
            // The runtime joins host and port with a colon and parses the result, so an
            // IPv6 literal needs its brackets.
            Dest::V6(address, port) => (format!("[{}]", std::net::Ipv6Addr::from(*address)), *port),
        };
        let refused = |error: worker::Error| {
            let text = error.to_string();
            console_error!("satmux-relay: connect {dest}: {text}");
            status_of_refusal(&text)
        };
        let socket = Socket::builder().allow_half_open(true).connect(host, port).map_err(refused)?;
        socket.opened().await.map_err(refused)?;
        Ok(socket.compat())
    }

    async fn doh(&self, query: &[u8]) -> Result<Vec<u8>, Status> {
        let failed = |error: worker::Error| {
            console_error!("satmux-relay: dns: {error}");
            Status::Unreachable
        };
        let headers = Headers::new();
        headers.set("Content-Type", DNS_MESSAGE).map_err(failed)?;
        headers.set("Accept", DNS_MESSAGE).map_err(failed)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post).with_headers(headers).with_body(Some(js_sys::Uint8Array::from(query).into()));
        let request = Request::new_with_init(DOH_URL, &init).map_err(failed)?;
        let mut response = Fetch::Request(request).send().await.map_err(failed)?;
        if response.status_code() != 200 {
            console_error!("satmux-relay: dns: resolver answered {}", response.status_code());
            return Err(Status::Unreachable);
        }
        response.bytes().await.map_err(failed)
    }

    async fn sleep(&self, duration: Duration) {
        Delay::from(duration).await;
    }
}
