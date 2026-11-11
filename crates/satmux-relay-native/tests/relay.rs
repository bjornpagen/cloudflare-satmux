//! The native relay in-process, dialed over real sockets: what the logic's own tests cannot
//! see (yamux, the stream limit, the HTTP front, the DNS-over-HTTPS client).

use std::io;
use std::time::Duration;

use futures::io::{AsyncReadExt, AsyncWriteExt};
use proptest::prelude::*;
use satmux_core::{KeyRing, Open, Status, digest_hex, key_digest};
use satmux_relay_logic::Limits;
use satmux_relay_native::client::{dial, drive};
use satmux_relay_native::{Config, DohUrl, PrivateDestinations, Tls, serve};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const KEY: &str = "a-test-device-key";

/// How the resolver frames its answer; the client must read both.
#[derive(Clone, Copy, Debug)]
enum Framing {
    Length,
    Chunked,
    UntilClose,
}

/// A resolver that answers every query with its bytes reversed.
async fn resolver(framing: Framing) -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::task::spawn_local(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut seen = Vec::new();
            let mut chunk = [0u8; 1024];
            let body = loop {
                let Ok(n) = stream.read(&mut chunk).await else { return };
                seen.extend_from_slice(&chunk[..n]);
                let Some(head) = seen.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                let text = String::from_utf8_lossy(&seen[..head]).to_ascii_lowercase();
                let length: usize = text.lines().find_map(|l| l.strip_prefix("content-length: ")).and_then(|l| l.parse().ok()).unwrap_or(0);
                if seen.len() >= head + 4 + length {
                    break seen[head + 4..head + 4 + length].to_vec();
                }
            };
            let answer: Vec<u8> = body.into_iter().rev().collect();
            let mut out = Vec::new();
            match framing {
                Framing::Length => {
                    out.extend_from_slice(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", answer.len()).as_bytes());
                    out.extend_from_slice(&answer);
                }
                Framing::Chunked => {
                    out.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                    for piece in answer.chunks(7) {
                        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                        out.extend_from_slice(piece);
                        out.extend_from_slice(b"\r\n");
                    }
                    out.extend_from_slice(b"0\r\n\r\n");
                }
                Framing::UntilClose => {
                    out.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
                    out.extend_from_slice(&answer);
                }
            }
            let _ = stream.write_all(&out).await;
            let _ = stream.shutdown().await;
        }
    });
    Ok(port)
}

/// Starts a relay with `streams` as its limit and runs `client` against its address.
fn with_relay<T>(streams: usize, framing: Framing, client: impl AsyncFnOnce(String) -> io::Result<T>) -> io::Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let doh_port = resolver(framing).await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let far = Duration::from_secs(3600);
        let config = Config {
            listen: address,
            tls: Tls::Off,
            keys: KeyRing::parse(&format!("test {}", digest_hex(&key_digest(KEY.as_bytes())))).expect("a key line"),
            build: "test".to_owned(),
            limits: Limits { streams, open: far, connect: far, measure_bytes: 0 },
            doh: DohUrl::parse(&format!("http://127.0.0.1:{doh_port}/dns-query")).expect("a url"),
            private: PrivateDestinations::Allowed,
        };
        tokio::task::spawn_local(serve(listener, config));
        client(address.to_string()).await
    })
}

async fn status_of(stream: &mut yamux::Stream) -> io::Result<Status> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await?;
    Status::from_byte(byte[0]).ok_or_else(|| io::Error::other("status out of range"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn streams_past_the_limit_answer_limit_and_places_come_back(limit in 1usize..6, asked in 1usize..14) {
        let (first, again) = with_relay(limit, Framing::Length, async |address| {
            let (carrier, driver) = drive(dial(&address, KEY).await?);
            tokio::task::spawn_local(driver);
            let mut streams = Vec::new();
            let mut first = Vec::new();
            for _ in 0..asked {
                let mut stream = carrier.open(&Open::Echo, &[]).await?;
                first.push(status_of(&mut stream).await?);
                streams.push(stream);
            }
            // Every stream is ended and seen to end, so every place is free again.
            for mut stream in streams {
                stream.close().await?;
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await?;
            }
            // These are held open to the end, so each keeps its place while the next is opened.
            let mut held = Vec::new();
            let mut again = Vec::new();
            for _ in 0..limit {
                let mut stream = carrier.open(&Open::Echo, &[]).await?;
                again.push(status_of(&mut stream).await?);
                held.push(stream);
            }
            Ok((first, again))
        }).expect("io");
        let expected: Vec<Status> = (0..asked).map(|i| if i < limit { Status::Connected } else { Status::Limit }).collect();
        prop_assert_eq!(first, expected);
        prop_assert_eq!(again, vec![Status::Connected; limit]);
    }

    #[test]
    fn dns_goes_to_the_resolver_and_its_answer_comes_back(
        query in prop::collection::vec(any::<u8>(), 1..1500),
        framing in prop::sample::select(vec![Framing::Length, Framing::Chunked, Framing::UntilClose]),
    ) {
        let back = with_relay(4, framing, async |address| {
            let (carrier, driver) = drive(dial(&address, KEY).await?);
            tokio::task::spawn_local(driver);
            let mut stream = carrier.open(&Open::Dns(query.clone()), &[]).await?;
            let mut back = Vec::new();
            stream.read_to_end(&mut back).await?;
            Ok(back)
        }).expect("io");
        let mut expected = vec![Status::Connected.byte()];
        expected.extend_from_slice(&(query.len() as u16).to_be_bytes());
        expected.extend(query.iter().rev());
        prop_assert_eq!(back, expected);
    }
}
