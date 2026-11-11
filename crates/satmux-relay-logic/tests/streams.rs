//! Properties of one served stream, over in-memory pipes and a platform the test owns.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use futures::future;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use proptest::prelude::*;
use satmux_core::{Decoded, Dest, HostName, Open, Status};
use satmux_relay_logic::{Limits, Platform, serve_stream};

/// One direction of a pipe: bytes in flight, bounded, with the wakers of whoever waits on it.
struct Lane {
    bytes: VecDeque<u8>,
    room: usize,
    closed: bool,
    reader_gone: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// One end of an in-memory duplex pipe. Dropping it closes what it writes and breaks what it reads.
struct End {
    incoming: Rc<RefCell<Lane>>,
    outgoing: Rc<RefCell<Lane>>,
}

fn pipe(room: usize) -> (End, End) {
    let lane = || Rc::new(RefCell::new(Lane { bytes: VecDeque::new(), room, closed: false, reader_gone: false, reader: None, writer: None }));
    let (a, b) = (lane(), lane());
    (End { incoming: a.clone(), outgoing: b.clone() }, End { incoming: b, outgoing: a })
}

impl AsyncRead for End {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut lane = self.incoming.borrow_mut();
        if lane.bytes.is_empty() {
            if lane.closed {
                return Poll::Ready(Ok(0));
            }
            lane.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(lane.bytes.len());
        for (slot, byte) in buf.iter_mut().zip(lane.bytes.drain(..n)) {
            *slot = byte;
        }
        if let Some(writer) = lane.writer.take() {
            writer.wake();
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for End {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut lane = self.outgoing.borrow_mut();
        if lane.reader_gone || lane.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let n = buf.len().min(lane.room - lane.bytes.len());
        if n == 0 {
            lane.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        lane.bytes.extend(&buf[..n]);
        if let Some(reader) = lane.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut lane = self.outgoing.borrow_mut();
        lane.closed = true;
        if let Some(reader) = lane.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for End {
    fn drop(&mut self) {
        let mut outgoing = self.outgoing.borrow_mut();
        outgoing.closed = true;
        if let Some(reader) = outgoing.reader.take() {
            reader.wake();
        }
        let mut incoming = self.incoming.borrow_mut();
        incoming.reader_gone = true;
        if let Some(writer) = incoming.writer.take() {
            writer.wake();
        }
    }
}

/// Lets every other future run once, so a chunk boundary is a boundary the reader can see.
async fn step_aside() {
    let mut stepped = false;
    future::poll_fn(|cx| {
        if stepped {
            return Poll::Ready(());
        }
        stepped = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

/// Writes `bytes` cut at `cuts` (each a chunk length; the last chunk takes the rest).
async fn write_chunked<W: AsyncWrite + Unpin>(to: &mut W, bytes: &[u8], cuts: &[usize]) -> io::Result<()> {
    let mut rest = bytes;
    for cut in cuts {
        if rest.is_empty() {
            break;
        }
        let (now, later) = rest.split_at((*cut).min(rest.len()));
        to.write_all(now).await?;
        step_aside().await;
        rest = later;
    }
    to.write_all(rest).await
}

/// What the test's platform does when asked to connect.
enum Onward {
    /// Hands over this end of a pipe; the test holds the other as the destination.
    Reaches(RefCell<Option<End>>),
    Refuses(Status),
    /// Never answers, so only the deadline can.
    Hangs,
}

/// Which of the platform's sleeps end at once: the test's clock has two hands and no numbers.
#[derive(Clone, Copy)]
enum Clock {
    /// No deadline ever passes.
    Still,
    /// Every deadline has already passed.
    Expired,
}

struct Fake {
    onward: Onward,
    answer: Result<Vec<u8>, Status>,
    clock: Clock,
}

impl Fake {
    fn idle() -> Self {
        Self { onward: Onward::Refuses(Status::Unreachable), answer: Err(Status::Unreachable), clock: Clock::Still }
    }
}

impl Platform for Fake {
    type Conn = End;

    async fn connect(&self, _: &Dest) -> Result<End, Status> {
        match &self.onward {
            Onward::Reaches(end) => Ok(end.borrow_mut().take().expect("one connect per stream")),
            Onward::Refuses(status) => Err(*status),
            Onward::Hangs => future::pending().await,
        }
    }

    async fn doh(&self, _: &[u8]) -> Result<Vec<u8>, Status> {
        self.answer.clone()
    }

    fn sleep(&self, _: Duration) -> impl Future<Output = ()> {
        let clock = self.clock;
        async move {
            match clock {
                Clock::Still => future::pending().await,
                Clock::Expired => {}
            }
        }
    }
}

fn limits(measure_bytes: u64) -> Limits {
    Limits { streams: 1, open: Duration::ZERO, connect: Duration::ZERO, measure_bytes }
}

/// Serves one stream while `client` plays the other end; returns what the client returned.
fn served<T>(platform: &Fake, limits: &Limits, room: usize, client: impl AsyncFnOnce(End) -> T) -> T {
    let (ours, theirs) = pipe(room);
    let (_, out) = futures::executor::block_on(future::join(serve_stream(theirs, platform, limits), client(ours)));
    out
}

fn encoded(open: &Open) -> Vec<u8> {
    let mut bytes = Vec::new();
    open.encode(&mut bytes);
    bytes
}

/// Splits everything the relay wrote into its status byte and the rest.
fn answered(all: &[u8]) -> (Status, &[u8]) {
    let (first, rest) = all.split_first().expect("a status byte");
    (Status::from_byte(*first).expect("a status in range"), rest)
}

fn cuts() -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(1usize..2000, 0..12)
}

fn room() -> impl Strategy<Value = usize> {
    1usize..70_000
}

fn dest() -> impl Strategy<Value = Dest> {
    prop_oneof![
        ("[a-z0-9]{1,20}(\\.[a-z0-9]{1,20}){0,3}", any::<u16>()).prop_map(|(name, port)| Dest::Name(HostName::parse(&name).expect("a host name"), port)),
        (any::<[u8; 4]>(), any::<u16>()).prop_map(|(address, port)| Dest::V4(address, port)),
        (any::<[u8; 16]>(), any::<u16>()).prop_map(|(address, port)| Dest::V6(address, port)),
    ]
}

fn open() -> impl Strategy<Value = Open> {
    prop_oneof![
        dest().prop_map(Open::Connect),
        prop::collection::vec(any::<u8>(), 1..200).prop_map(Open::Dns),
        Just(Open::Echo),
        any::<u64>().prop_map(Open::Source),
        Just(Open::Sink),
    ]
}

/// An open cut short: a strict prefix of its encoding.
fn cut_open() -> impl Strategy<Value = Vec<u8>> {
    (open(), any::<prop::sample::Index>()).prop_map(|(open, at)| {
        let mut bytes = encoded(&open);
        bytes.truncate(at.index(bytes.len()));
        bytes
    })
}

/// Bytes near an open: one cut short, one with a byte changed, or noise after the version.
fn nearly_an_open() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        cut_open(),
        (open(), any::<prop::sample::Index>(), any::<u8>()).prop_map(|(open, at, byte)| {
            let mut bytes = encoded(&open);
            let at = at.index(bytes.len());
            bytes[at] = byte;
            bytes
        }),
        prop::collection::vec(any::<u8>(), 0..300).prop_map(|mut noise| {
            noise.insert(0, satmux_core::WIRE_VERSION);
            noise
        }),
        prop::collection::vec(any::<u8>(), 0..300),
    ]
}

fn refusal() -> impl Strategy<Value = Status> {
    prop::sample::select(Status::ALL[1..].to_vec())
}

proptest! {
    #[test]
    fn echo_returns_every_whole_nonce_and_nothing_else(
        payload in prop::collection::vec(any::<u8>(), 0..6000),
        cuts in cuts(),
        room in room(),
    ) {
        let mut sent = encoded(&Open::Echo);
        sent.extend_from_slice(&payload);
        let back = served(&Fake::idle(), &limits(0), room, async |mut end: End| {
            let (mut reads, mut writes) = (&mut end).split();
            let write = async {
                write_chunked(&mut writes, &sent, &cuts).await.expect("write");
                writes.close().await.expect("close");
            };
            let mut back = Vec::new();
            let (_, read) = future::join(write, reads.read_to_end(&mut back)).await;
            read.expect("read");
            back
        });
        let (status, rest) = answered(&back);
        prop_assert_eq!(status, Status::Connected);
        prop_assert_eq!(rest, &payload[..payload.len() - payload.len() % 8]);
    }

    #[test]
    fn source_sends_exactly_what_was_asked_or_refuses(asked in 0u64..200_000, cap in 0u64..200_000, room in room()) {
        let back = served(&Fake::idle(), &limits(cap), room, async |mut end: End| {
            end.write_all(&encoded(&Open::Source(asked))).await.expect("write");
            let mut back = Vec::new();
            end.read_to_end(&mut back).await.expect("read");
            back
        });
        let (status, rest) = answered(&back);
        if asked <= cap {
            prop_assert_eq!(status, Status::Connected);
            prop_assert_eq!(rest.len() as u64, asked);
        } else {
            prop_assert_eq!(status, Status::Limit);
            prop_assert_eq!(rest.len(), 0);
        }
    }

    #[test]
    fn sink_reports_the_exact_count(payload in prop::collection::vec(any::<u8>(), 0..20_000), cuts in cuts(), room in room()) {
        let mut sent = encoded(&Open::Sink);
        sent.extend_from_slice(&payload);
        let back = served(&Fake::idle(), &limits(payload.len() as u64), room, async |mut end: End| {
            write_chunked(&mut end, &sent, &cuts).await.expect("write");
            end.close().await.expect("close");
            let mut back = Vec::new();
            end.read_to_end(&mut back).await.expect("read");
            back
        });
        let (status, rest) = answered(&back);
        prop_assert_eq!(status, Status::Connected);
        prop_assert_eq!(rest, &(payload.len() as u64).to_be_bytes()[..]);
    }

    #[test]
    fn sink_past_the_cap_is_never_given_a_count(over in 1usize..5000, cap in 0u64..5000, room in room()) {
        let mut sent = encoded(&Open::Sink);
        sent.resize(sent.len() + cap as usize + over, 0);
        let back = served(&Fake::idle(), &limits(cap), room, async |mut end: End| {
            let (mut reads, mut writes) = (&mut end).split();
            let write = async {
                // The relay may hang up mid-write; that is the refusal.
                if writes.write_all(&sent).await.is_ok() {
                    let _ = writes.close().await;
                }
            };
            let mut back = Vec::new();
            let (_, read) = future::join(write, reads.read_to_end(&mut back)).await;
            read.expect("read");
            back
        });
        prop_assert_eq!(back, vec![Status::Connected.byte()]);
    }

    #[test]
    fn connect_carries_both_directions_intact_under_any_chunking_and_close_order(
        dest in dest(),
        up in prop::collection::vec(any::<u8>(), 0..40_000),
        down in prop::collection::vec(any::<u8>(), 0..40_000),
        up_cuts in cuts(),
        down_cuts in cuts(),
        room in room(),
        client_waits_for_the_far_close in any::<bool>(),
        far_waits_for_the_client_close in any::<bool>(),
    ) {
        // If each side waited for the other's close before closing, nobody would close.
        prop_assume!(!(client_waits_for_the_far_close && far_waits_for_the_client_close));
        let (near, mut far) = pipe(room);
        let platform = Fake { onward: Onward::Reaches(RefCell::new(Some(near))), ..Fake::idle() };
        let mut sent = encoded(&Open::Connect(dest));
        sent.extend_from_slice(&up);
        let (back, arrived) = served(&platform, &limits(0), room, async |mut end: End| {
            let client = async {
                let (mut reads, mut writes) = (&mut end).split();
                let mut back = Vec::new();
                if client_waits_for_the_far_close {
                    let write = write_chunked(&mut writes, &sent, &up_cuts);
                    let (wrote, read) = future::join(write, reads.read_to_end(&mut back)).await;
                    wrote.expect("write");
                    read.expect("read");
                    writes.close().await.expect("close");
                } else {
                    let write = async {
                        write_chunked(&mut writes, &sent, &up_cuts).await.expect("write");
                        writes.close().await.expect("close");
                    };
                    let (_, read) = future::join(write, reads.read_to_end(&mut back)).await;
                    read.expect("read");
                }
                back
            };
            let destination = async {
                let (mut reads, mut writes) = (&mut far).split();
                let mut arrived = Vec::new();
                if far_waits_for_the_client_close {
                    let write = write_chunked(&mut writes, &down, &down_cuts);
                    let (wrote, read) = future::join(write, reads.read_to_end(&mut arrived)).await;
                    wrote.expect("write");
                    read.expect("read");
                    writes.close().await.expect("close");
                } else {
                    let write = async {
                        write_chunked(&mut writes, &down, &down_cuts).await.expect("write");
                        writes.close().await.expect("close");
                    };
                    let (_, read) = future::join(write, reads.read_to_end(&mut arrived)).await;
                    read.expect("read");
                }
                arrived
            };
            future::join(client, destination).await
        });
        let (status, rest) = answered(&back);
        prop_assert_eq!(status, Status::Connected);
        prop_assert_eq!(rest, &down[..]);
        prop_assert_eq!(arrived, up);
    }

    #[test]
    fn a_refused_connect_answers_the_platforms_status_then_closes(dest in dest(), status in refusal(), room in room()) {
        let platform = Fake { onward: Onward::Refuses(status), ..Fake::idle() };
        let back = served(&platform, &limits(0), room, async |mut end: End| {
            end.write_all(&encoded(&Open::Connect(dest))).await.expect("write");
            let mut back = Vec::new();
            end.read_to_end(&mut back).await.expect("read");
            back
        });
        prop_assert_eq!(back, vec![status.byte()]);
    }

    #[test]
    fn a_connect_past_its_deadline_answers_timed_out(dest in dest(), room in room()) {
        // The open arrives whole before the clock is asked, so only the connect can be late.
        let platform = Fake { onward: Onward::Hangs, clock: Clock::Expired, ..Fake::idle() };
        let (ours, theirs) = pipe(room.max(64));
        let back = futures::executor::block_on(async {
            let mut ours = ours;
            ours.write_all(&encoded(&Open::Connect(dest))).await.expect("write");
            let limits = limits(0);
            let serve = serve_stream(theirs, &platform, &limits);
            let mut back = Vec::new();
            let (_, read) = future::join(serve, ours.read_to_end(&mut back)).await;
            read.expect("read");
            back
        });
        prop_assert_eq!(back, vec![Status::TimedOut.byte()]);
    }

    #[test]
    fn dns_answers_are_length_framed_and_failures_are_statuses(
        query in prop::collection::vec(any::<u8>(), 1..600),
        answer in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..3000).prop_map(Ok),
            refusal().prop_map(Err),
        ],
        cuts in cuts(),
        room in room(),
    ) {
        let platform = Fake { answer: answer.clone(), ..Fake::idle() };
        let sent = encoded(&Open::Dns(query));
        let back = served(&platform, &limits(0), room, async |mut end: End| {
            write_chunked(&mut end, &sent, &cuts).await.expect("write");
            let mut back = Vec::new();
            end.read_to_end(&mut back).await.expect("read");
            back
        });
        let expected = match answer {
            Ok(answer) => {
                let mut all = vec![Status::Connected.byte()];
                all.extend_from_slice(&(answer.len() as u16).to_be_bytes());
                all.extend_from_slice(&answer);
                all
            }
            Err(status) => vec![status.byte()],
        };
        prop_assert_eq!(back, expected);
    }

    #[test]
    fn bytes_that_are_not_an_open_answer_malformed_then_close(
        bytes in nearly_an_open(),
        cuts in cuts(),
        room in room(),
    ) {
        // The oracle is the decoder both ends share: malformed, or cut short by the close.
        prop_assume!(!matches!(Open::decode(&bytes), Decoded::Open(..)));
        let back = served(&Fake::idle(), &limits(u64::MAX), room, async |mut end: End| {
            let (mut reads, mut writes) = (&mut end).split();
            let write = async {
                // The relay may answer and hang up before the rest is written.
                if write_chunked(&mut writes, &bytes, &cuts).await.is_ok() {
                    let _ = writes.close().await;
                }
            };
            let mut back = Vec::new();
            let (_, read) = future::join(write, reads.read_to_end(&mut back)).await;
            read.expect("read");
            back
        });
        prop_assert_eq!(back, vec![Status::Malformed.byte()]);
    }

    #[test]
    fn an_open_that_misses_its_deadline_answers_malformed(open_bytes in cut_open(), room in 300usize..70_000) {
        let platform = Fake { clock: Clock::Expired, ..Fake::idle() };
        let back = served(&platform, &limits(0), room, async |mut end: End| {
            // Whatever was sent, the stream is held open and the clock has run out.
            let _ = end.write_all(&open_bytes).await;
            let mut back = Vec::new();
            end.read_to_end(&mut back).await.expect("read");
            back
        });
        prop_assert_eq!(Open::decode(&open_bytes), Decoded::Incomplete);
        prop_assert_eq!(back, vec![Status::Malformed.byte()]);
    }
}
