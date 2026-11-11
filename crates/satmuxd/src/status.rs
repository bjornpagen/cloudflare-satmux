//! The status socket: one request line, `name value` lines back, then close.

use std::io;
use std::time::Duration;

use satmux_carrier::Uplink;
use satmux_core::{HostName, NAME_MAX};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const STATUS: &str = "status";
const EXPLAIN: &str = "explain ";
/// The longest request there is: `explain`, the longest name, and the line's end.
const LINE_MAX: usize = EXPLAIN.len() + NAME_MAX + 2;

/// A request line, parsed once.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Status,
    Explain(HostName),
    Unknown,
}

pub fn request(line: &str) -> Request {
    let line = line.trim_end_matches(['\r', '\n']);
    match (line, line.strip_prefix(EXPLAIN).map(HostName::parse)) {
        (STATUS, _) => Request::Status,
        (_, Some(Ok(name))) => Request::Explain(name),
        (_, _) => Request::Unknown,
    }
}

async fn answer(stream: UnixStream, uplink: &Uplink) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read.take(LINE_MAX as u64)).read_line(&mut line).await?;
    let reply = match request(&line) {
        Request::Status => uplink.status(),
        Request::Explain(name) => uplink.explain(&name),
        Request::Unknown => String::from("error unknown-request\n"),
    };
    write.write_all(reply.as_bytes()).await?;
    write.shutdown().await
}

/// Answers requests until accepting fails. A caller that sends no line within `wait` is dropped.
pub async fn serve(listener: UnixListener, uplink: Uplink, wait: Duration) -> io::Error {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let uplink = uplink.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(wait, answer(stream, &uplink)).await;
                });
            }
            Err(error) => return error,
        }
    }
}
