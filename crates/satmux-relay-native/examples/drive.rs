//! Drives a relay over one plain-TCP carrier and prints what it saw, one `name value` line
//! each: `drive <address:port> <key> <measure-bytes>`. Used against the Worker under workerd
//! and against the native relay, so the two can be compared line by line.
//!
//! Exit 0 when every exchange the relay alone decides (version, 404s, echo, source, sink,
//! malformed, limit) is right; the connect and dns lines report what the platform allowed.

use std::io;
use std::process::ExitCode;

use futures::io::{AsyncReadExt, AsyncWriteExt};
use satmux_core::{Dest, HostName, Open, Status};
use satmux_relay_native::client::{Carrier, dial, drive};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// A deterministic byte pattern, so a reordering or a dropped chunk cannot go unseen.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

async fn http(address: &str, path: &str, key: Option<&str>) -> io::Result<String> {
    let mut stream = TcpStream::connect(address).await?;
    let authorization = key.map(|key| format!("Authorization: Bearer {key}\r\n")).unwrap_or_default();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\n{authorization}Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await?;
    Ok(String::from_utf8_lossy(&answer).into_owned())
}

fn status_line(answer: &str) -> &str {
    answer.lines().next().unwrap_or("")
}

async fn status_of(stream: &mut yamux::Stream) -> io::Result<Status> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await?;
    Status::from_byte(byte[0]).ok_or_else(|| io::Error::other("status byte out of range"))
}

async fn echo(carrier: &Carrier) -> io::Result<bool> {
    let sent = pattern(8 * 1000, 7);
    let mut stream = carrier.open(&Open::Echo, &sent[..3]).await?;
    let status = status_of(&mut stream).await?;
    // Chunks of 13 never line up with a nonce.
    for chunk in sent[3..].chunks(13) {
        stream.write_all(chunk).await?;
    }
    stream.close().await?;
    let mut back = Vec::new();
    stream.read_to_end(&mut back).await?;
    Ok(status == Status::Connected && back == sent)
}

async fn source(carrier: &Carrier, bytes: u64) -> io::Result<(Status, u64)> {
    let mut stream = carrier.open(&Open::Source(bytes), &[]).await?;
    let status = status_of(&mut stream).await?;
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await?;
    Ok((status, got.len() as u64))
}

async fn sink(carrier: &Carrier, bytes: usize) -> io::Result<(Status, u64)> {
    let payload = pattern(bytes, 11);
    let mut stream = carrier.open(&Open::Sink, &[]).await?;
    stream.write_all(&payload).await?;
    stream.close().await?;
    let status = status_of(&mut stream).await?;
    let mut count = [0u8; 8];
    stream.read_exact(&mut count).await?;
    Ok((status, u64::from_be_bytes(count)))
}

async fn malformed(carrier: &Carrier) -> io::Result<Status> {
    // A wire version nobody speaks, written raw.
    let mut stream = carrier.open_raw(&[0xff, 0xff]).await?;
    let status = status_of(&mut stream).await?;
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await?;
    if rest.is_empty() { Ok(status) } else { Err(io::Error::other("bytes after a refusal")) }
}

/// Connects through the relay to a listener of ours that reads to the end of what the client
/// sends, then answers every byte complemented and closes: that only works if a half-close
/// crosses the relay in both directions.
async fn connect(carrier: &Carrier, dest: Dest) -> io::Result<(Status, bool)> {
    let sent = pattern(300_000, 13);
    let mut stream = carrier.open(&Open::Connect(dest), &sent[..1000]).await?;
    stream.write_all(&sent[1000..]).await?;
    stream.close().await?;
    let status = status_of(&mut stream).await?;
    let mut back = Vec::new();
    stream.read_to_end(&mut back).await?;
    let expected: Vec<u8> = sent.iter().map(|byte| !byte).collect();
    Ok((status, back == expected))
}

async fn dns(carrier: &Carrier) -> io::Result<(Status, usize)> {
    // A query for the A records of example.com, identifier zero as DNS over HTTPS asks.
    let mut query = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut stream = carrier.open(&Open::Dns(query), &[]).await?;
    let status = status_of(&mut stream).await?;
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await?;
    let framed = rest.len() >= 2 && usize::from(u16::from_be_bytes([rest[0], rest[1]])) == rest.len() - 2;
    if status == Status::Connected && !framed {
        return Err(io::Error::other("dns answer is not length-framed"));
    }
    Ok((status, rest.len().saturating_sub(2)))
}

async fn complementing_listener() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut all = Vec::new();
                if stream.read_to_end(&mut all).await.is_ok() {
                    all.iter_mut().for_each(|byte| *byte = !*byte);
                    let _ = stream.write_all(&all).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    Ok(port)
}

async fn run(address: &str, key: &str, measure_bytes: u64) -> io::Result<bool> {
    let mut good = true;
    let mut say = |name: &str, value: String, required: Option<bool>| {
        println!("{name} {value}");
        good &= required.unwrap_or(true);
    };

    let version = http(address, "/v", Some(key)).await?;
    say("version-status", status_line(&version).to_owned(), Some(version.starts_with("HTTP/1.1 200")));
    say("version-body", version.rsplit("\r\n\r\n").next().unwrap_or("").trim().to_owned(), None);
    for (name, path, key) in [("version-wrong-key", "/v", Some("not-a-key")), ("version-no-key", "/v", None), ("carrier-no-key", "/c", None), ("other-path", "/", Some(key))] {
        let answer = http(address, path, key).await?;
        let empty = answer.rsplit("\r\n\r\n").next().is_some_and(str::is_empty);
        say(name, status_line(&answer).to_owned(), Some(answer.starts_with("HTTP/1.1 404") && empty));
    }

    let (carrier, driver) = drive(dial(address, key).await?);
    tokio::spawn(driver);

    let echoed = echo(&carrier).await?;
    say("echo", format!("{echoed}"), Some(echoed));
    let (status, got) = source(&carrier, measure_bytes).await?;
    say("source", format!("{status:?} {got}"), Some(status == Status::Connected && got == measure_bytes));
    let (status, got) = source(&carrier, measure_bytes + 1).await?;
    say("source-over-cap", format!("{status:?} {got}"), Some(status == Status::Limit && got == 0));
    let sent = usize::try_from(measure_bytes).map_err(io::Error::other)?;
    let (status, count) = sink(&carrier, sent).await?;
    say("sink", format!("{status:?} {count}"), Some(status == Status::Connected && count == measure_bytes));
    let status = malformed(&carrier).await?;
    say("malformed", format!("{status:?}"), Some(status == Status::Malformed));

    let port = complementing_listener().await?;
    let name = HostName::parse("localhost").map_err(io::Error::other)?;
    for (label, dest) in [("connect-v4", Dest::V4([127, 0, 0, 1], port)), ("connect-name", Dest::Name(name, port))] {
        match connect(&carrier, dest).await {
            Ok((status, intact)) => say(label, format!("{status:?} intact={intact}"), None),
            Err(error) => say(label, format!("error {error}"), None),
        }
    }
    // A port nothing listens on: the listener that had it is gone.
    let closed = TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port();
    let mut stream = carrier.open(&Open::Connect(Dest::V4([127, 0, 0, 1], closed)), &[]).await?;
    say("connect-closed-port", format!("{:?}", status_of(&mut stream).await?), None);
    match dns(&carrier).await {
        Ok((status, len)) => say("dns", format!("{status:?} {len}"), None),
        Err(error) => say("dns", format!("error {error}"), None),
    }
    Ok(good)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [address, key, measure_bytes] = args.as_slice() else {
        eprintln!("usage: drive <address:port> <key> <measure-bytes>");
        return ExitCode::from(100);
    };
    let Ok(measure_bytes) = measure_bytes.parse() else {
        eprintln!("drive: measure-bytes is not a number");
        return ExitCode::from(100);
    };
    match run(address, key, measure_bytes).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("drive: {error}");
            ExitCode::from(111)
        }
    }
}
