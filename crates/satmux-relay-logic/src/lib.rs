//! What a relay does with one carrier and with each stream on it, written once over futures'
//! I/O traits and a [`Platform`]. The Worker and the native relay are this code on two
//! platforms, so the native one is an oracle for the other.

mod message_io;

use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use futures::future::{self, Either};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::stream::{FuturesUnordered, StreamExt};
use satmux_core::{Decoded, Dest, ECHO_NONCE, Open, Status};

pub use message_io::MessageIo;

/// How much one read moves between a stream and its other side.
const COPY_CHUNK: usize = 16 * 1024;

/// What the host gives the relay: onward TCP, DNS over HTTPS, and a clock to race against.
pub trait Platform {
    /// An onward connection. Closing its write side must send a half-close and leave reads open.
    type Conn: AsyncRead + AsyncWrite + Unpin;

    /// Connects onward. A failure is already the status the client is told; never
    /// [`Status::Connected`]. The caller applies the connect deadline.
    fn connect(&self, dest: &Dest) -> impl Future<Output = Result<Self::Conn, Status>>;

    /// Sends one DNS query (wire format) to the resolver and returns its answer.
    fn doh(&self, query: &[u8]) -> impl Future<Output = Result<Vec<u8>, Status>>;

    /// Completes after `duration`.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()>;
}

/// The limits a relay applies itself. Every field comes from a `SATMUX_RELAY_*` variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most streams served at once on one carrier (`SATMUX_RELAY_STREAMS`).
    pub streams: usize,
    /// How long a new stream has to send its open (`SATMUX_RELAY_OPEN_MS`).
    pub open: Duration,
    /// How long an onward connect, or a DNS exchange, may take (`SATMUX_RELAY_CONNECT_MS`).
    pub connect: Duration,
    /// Cap on one Source or Sink (`SATMUX_RELAY_MEASURE_BYTES`).
    pub measure_bytes: u64,
}

/// A value of a `SATMUX_RELAY_*` limit that is not a number in range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitRefused {
    /// The variable whose value was refused.
    pub name: &'static str,
}

impl core::fmt::Display for LimitRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} is not a decimal number in range", self.name)
    }
}

impl Limits {
    /// Parses the four limits both relays read, from the text of their variables.
    pub fn parse(streams: &str, open_ms: &str, connect_ms: &str, measure_bytes: &str) -> Result<Self, LimitRefused> {
        fn number(name: &'static str, text: &str) -> Result<u64, LimitRefused> {
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(LimitRefused { name });
            }
            text.parse().map_err(|_| LimitRefused { name })
        }
        let streams_name = "SATMUX_RELAY_STREAMS";
        let streams = usize::try_from(number(streams_name, streams)?).map_err(|_| LimitRefused { name: streams_name })?;
        // yamux needs room for twice this many streams inside its connection window.
        let fits = streams > 0 && streams.checked_mul(2 * yamux::DEFAULT_CREDIT as usize).is_some();
        if !fits {
            return Err(LimitRefused { name: streams_name });
        }
        Ok(Self {
            streams,
            open: Duration::from_millis(number("SATMUX_RELAY_OPEN_MS", open_ms)?),
            connect: Duration::from_millis(number("SATMUX_RELAY_CONNECT_MS", connect_ms)?),
            measure_bytes: number("SATMUX_RELAY_MEASURE_BYTES", measure_bytes)?,
        })
    }
}

/// Runs `work` against the platform's clock. `None` is the deadline passing first.
async fn within<P: Platform, T>(platform: &P, limit: Duration, work: impl Future<Output = T>) -> Option<T> {
    match future::select(pin!(work), pin!(platform.sleep(limit))).await {
        Either::Left((done, _)) => Some(done),
        Either::Right(((), _)) => None,
    }
}

/// Reads until the bytes so far are an open. `Err` is the stream ending, failing, or sending
/// bytes that are not one.
async fn read_open<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Open, Vec<u8>), ()> {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match Open::decode(&seen) {
            Decoded::Open(open, used) => return Ok((open, seen.split_off(used))),
            Decoded::Malformed(_) => return Err(()),
            Decoded::Incomplete => {}
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(()),
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Writes one status byte and closes the write side: the whole answer to a stream that is not served.
pub async fn refuse_stream<S: AsyncWrite + Unpin>(mut stream: S, status: Status) {
    let _ = stream.write_all(&[status.byte()]).await;
    let _ = stream.close().await;
}

/// Moves bytes from `from` to `to` until `from` ends, flushing after every read so nothing waits
/// in a buffer for bytes that may never come. The caller closes `to`.
async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(from: &mut R, to: &mut W) -> std::io::Result<()> {
    let mut chunk = vec![0u8; COPY_CHUNK];
    loop {
        let n = from.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&chunk[..n]).await?;
        to.flush().await?;
    }
}

/// Serves one stream from its first byte to its end: reads the open, answers the status byte,
/// and does what the open asked. Errors end the stream; there is nobody to report them to.
pub async fn serve_stream<S, P>(mut stream: S, platform: &P, limits: &Limits)
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Platform,
{
    // A stream that sends no open in time never said where it is going: that is not an open.
    let (open, first) = match within(platform, limits.open, read_open(&mut stream)).await {
        Some(Ok(parsed)) => parsed,
        Some(Err(())) | None => return refuse_stream(stream, Status::Malformed).await,
    };
    let _ = match open {
        Open::Connect(dest) => serve_connect(stream, platform, limits, dest, first).await,
        Open::Dns(query) => serve_dns(stream, platform, limits, query).await,
        Open::Echo => serve_echo(stream, first).await,
        Open::Source(bytes) => serve_source(stream, limits, bytes).await,
        Open::Sink => serve_sink(stream, limits, first).await,
    };
}

async fn serve_connect<S, P>(mut stream: S, platform: &P, limits: &Limits, dest: Dest, first: Vec<u8>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Platform,
{
    let conn = match within(platform, limits.connect, platform.connect(&dest)).await {
        Some(Ok(conn)) => conn,
        Some(Err(status)) => return Ok(refuse_stream(stream, status).await),
        None => return Ok(refuse_stream(stream, Status::TimedOut).await),
    };
    stream.write_all(&[Status::Connected.byte()]).await?;
    stream.flush().await?;
    let (mut from_client, mut to_client) = stream.split();
    let (mut from_dest, mut to_dest) = conn.split();
    let up = async {
        to_dest.write_all(&first).await?;
        to_dest.flush().await?;
        copy(&mut from_client, &mut to_dest).await?;
        to_dest.close().await
    };
    let down = async {
        copy(&mut from_dest, &mut to_client).await?;
        to_client.close().await
    };
    // Each direction ends with a half-close of its own; a failure of either ends both.
    future::try_join(up, down).await.map(|_| ())
}

async fn serve_dns<S, P>(mut stream: S, platform: &P, limits: &Limits, query: Vec<u8>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Platform,
{
    let answer = match within(platform, limits.connect, platform.doh(&query)).await {
        Some(Ok(answer)) => answer,
        Some(Err(status)) => return Ok(refuse_stream(stream, status).await),
        None => return Ok(refuse_stream(stream, Status::TimedOut).await),
    };
    let Ok(length) = u16::try_from(answer.len()) else {
        return Ok(refuse_stream(stream, Status::Unreachable).await);
    };
    let mut out = Vec::with_capacity(3 + answer.len());
    out.push(Status::Connected.byte());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&answer);
    stream.write_all(&out).await?;
    stream.close().await
}

async fn serve_echo<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, first: Vec<u8>) -> std::io::Result<()> {
    stream.write_all(&[Status::Connected.byte()]).await?;
    stream.flush().await?;
    let mut held = first;
    let mut chunk = vec![0u8; COPY_CHUNK];
    loop {
        // Only whole nonces go back; a tail the client never completes is not one.
        let whole = held.len() - held.len() % ECHO_NONCE;
        if whole > 0 {
            stream.write_all(&held[..whole]).await?;
            stream.flush().await?;
            held.drain(..whole);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return stream.close().await;
        }
        held.extend_from_slice(&chunk[..n]);
    }
}

async fn serve_source<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, limits: &Limits, bytes: u64) -> std::io::Result<()> {
    if bytes > limits.measure_bytes {
        return Ok(refuse_stream(stream, Status::Limit).await);
    }
    stream.write_all(&[Status::Connected.byte()]).await?;
    let chunk = vec![0u8; COPY_CHUNK];
    let mut left = bytes;
    while left > 0 {
        let n = usize::try_from(left).map_or(chunk.len(), |left| left.min(chunk.len()));
        stream.write_all(&chunk[..n]).await?;
        left -= n as u64;
    }
    stream.close().await
}

/// Counts what arrives until the client closes, then reports the count. A client that sends
/// more than the cap is reset without a count: the status byte has already gone, and a count
/// would be a measurement of something the relay refused to do.
async fn serve_sink<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, limits: &Limits, first: Vec<u8>) -> std::io::Result<()> {
    stream.write_all(&[Status::Connected.byte()]).await?;
    stream.flush().await?;
    let mut count = first.len() as u64;
    let mut chunk = vec![0u8; COPY_CHUNK];
    while count <= limits.measure_bytes {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            stream.write_all(&count.to_be_bytes()).await?;
            return stream.close().await;
        }
        count += n as u64;
    }
    Ok(())
}

/// The yamux settings of a relay's end of a carrier.
fn yamux_config(limits: &Limits) -> yamux::Config {
    // yamux ends the whole carrier at its own stream limit, so it is given twice ours: the
    // second half is room for streams that are being answered `Limit`.
    let room = limits.streams.saturating_mul(2);
    let mut config = yamux::Config::default();
    config.set_max_connection_receive_window(None);
    config.set_max_num_streams(room);
    // The least yamux accepts for that many streams, so no stream's window grows past its first credit.
    config.set_max_connection_receive_window(Some(room.saturating_mul(yamux::DEFAULT_CREDIT as usize)));
    config
}

/// Serves one carrier until it ends: yamux in server mode over `io`, every inbound stream
/// through [`serve_stream`], all in this one future (nothing is spawned, so it runs the same
/// on one thread in a Worker). Streams past `limits.streams` are answered [`Status::Limit`].
/// Dropping the future, or the carrier ending, drops every onward connection it opened.
pub async fn serve_carrier<T, P>(io: T, platform: &P, limits: &Limits)
where
    T: AsyncRead + AsyncWrite + Unpin,
    P: Platform,
{
    let mut connection = yamux::Connection::new(io, yamux_config(limits), yamux::Mode::Server);
    let mut served = FuturesUnordered::new();
    let mut refused = FuturesUnordered::new();
    future::poll_fn(|cx| {
        loop {
            // Finished streams leave first, so their places are free for what arrives next.
            while let Poll::Ready(Some(())) = served.poll_next_unpin(cx) {}
            while let Poll::Ready(Some(())) = refused.poll_next_unpin(cx) {}
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    if served.len() < limits.streams {
                        served.push(serve_stream(stream, platform, limits));
                    } else {
                        refused.push(refuse_stream(stream, Status::Limit));
                    }
                }
                Poll::Ready(Some(Err(_)) | None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;
}
