//! End to end on Linux: the front end runs on one end of a datagram socket pair that frames
//! packets as utun does, and a second TCP/IP stack on the other end plays the app. What the app
//! sends must reach the fake uplink, with the name it asked for, and the uplink's bytes must
//! reach the app.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use proptest::prelude::*;
use satmux_core::{Dest, HostName};
use satmux_tun::{Connect, FlowIo, Resolve, TunConfig};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;

const MTU: usize = 1500;
const APP: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
const BLOCK: (Ipv4Addr, u8) = (Ipv4Addr::new(198, 18, 0, 0), 24);

struct Wire {
    arriving: VecDeque<Vec<u8>>,
    leaving: VecDeque<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
impl phy::Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        self.arriving.pop_front().map(|packet| (Rx(packet), Tx(&mut self.leaving)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.leaving))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }
}

/// The app's side: its own stack, and the socket that stands for the utun interface.
struct App {
    interface: Interface,
    sockets: SocketSet<'static>,
    wire: Wire,
    link: UnixDatagram,
    started: tokio::time::Instant,
}

impl App {
    fn new(link: UnixDatagram) -> Self {
        let mut wire = Wire { arriving: VecDeque::new(), leaving: VecDeque::new() };
        let mut interface = Interface::new(Config::new(HardwareAddress::Ip), &mut wire, Instant::ZERO);
        interface.update_ip_addrs(|addresses| addresses.push(IpCidr::new(IpAddress::Ipv4(APP), 0)).expect("room"));
        Self { interface, sockets: SocketSet::new(Vec::new()), wire, link, started: tokio::time::Instant::now() }
    }

    fn now(&self) -> Instant {
        Instant::from_micros(self.started.elapsed().as_micros() as i64)
    }

    /// Runs the app's stack, exchanging packets with the tunnel, until `done` says so.
    async fn until<T>(&mut self, mut done: impl FnMut(&mut Interface, &mut SocketSet<'static>) -> Option<T>) -> T {
        let mut frame = vec![0u8; MTU + 4];
        loop {
            let now = self.now();
            self.interface.poll(now, &mut self.wire, &mut self.sockets);
            if let Some(value) = done(&mut self.interface, &mut self.sockets) {
                let now = self.now();
                self.interface.poll(now, &mut self.wire, &mut self.sockets);
                self.flush().await;
                return value;
            }
            self.flush().await;
            let delay = self.interface.poll_delay(self.now(), &self.sockets);
            let timer = async {
                match delay {
                    Some(delay) => tokio::time::sleep(Duration::from_micros(delay.total_micros())).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                read = self.link.recv(&mut frame) => {
                    let length = read.expect("the link");
                    assert_eq!(frame[..4], (libc::AF_INET as u32).to_be_bytes(), "every packet carries its family");
                    self.wire.arriving.push_back(frame[4..length].to_vec());
                }
                () = timer => {}
            }
        }
    }

    async fn flush(&mut self) {
        while let Some(packet) = self.wire.leaving.pop_front() {
            let mut frame = (libc::AF_INET as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&packet);
            // A full datagram socket blocks the sender on Linux; on macOS the send fails with
            // ENOBUFS at once. Either way the app's side waits for room: it never drops.
            loop {
                match self.link.send(&frame).await {
                    Ok(_) => break,
                    Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => tokio::time::sleep(Duration::from_micros(200)).await,
                    Err(error) => panic!("the link: {error}"),
                }
            }
        }
    }

    /// Asks the tunnel's resolver for the address of `name`.
    async fn address_of(&mut self, name: &HostName, id: u16) -> Ipv4Addr {
        let buffer = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(40_000).expect("a port");
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.as_str().split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        socket.send_slice(&query, IpEndpoint::new(IpAddress::Ipv4(RESOLVER), 53)).expect("room");
        let handle = self.sockets.add(socket);
        let answer = self
            .until(|_, sockets| sockets.get_mut::<udp::Socket>(handle).recv().ok().map(|(bytes, _)| bytes.to_vec()))
            .await;
        self.sockets.remove(handle);
        assert_eq!(answer[..2], id.to_be_bytes());
        assert_eq!(answer[3] & 0x0f, 0, "no error");
        assert_eq!(answer[6..8], [0, 1], "one answer");
        let address: [u8; 4] = answer[answer.len() - 4..].try_into().expect("four bytes");
        Ipv4Addr::from(address)
    }

    fn open(&mut self, target: Ipv4Addr, port: u16, local_port: u16) -> SocketHandle {
        let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 65_535]), tcp::SocketBuffer::new(vec![0; 65_535]));
        socket.connect(self.interface.context(), (IpAddress::Ipv4(target), port), local_port).expect("a connect");
        self.sockets.add(socket)
    }
}

/// What the fake uplink was asked to open.
struct Opened {
    dest: Dest,
    first: Bytes,
    stream: DuplexStream,
}

struct Io(DuplexStream);
impl tokio::io::AsyncRead for Io {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for Io {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl FlowIo for Io {}

/// How the fake uplink treats a flow.
#[derive(Clone, Debug)]
enum Uplink {
    /// Opens, sends these bytes, and closes its side once the app has closed its own.
    Serves(Vec<u8>),
    /// Refuses to open.
    Refuses,
}

/// Where the app connects.
#[derive(Clone, Debug)]
enum Target {
    Name(String),
    Literal(Ipv4Addr),
}

#[derive(Clone, Debug)]
struct Case {
    target: Target,
    port: u16,
    local_port: u16,
    id: u16,
    sent: Vec<u8>,
    uplink: Uplink,
    duplex: usize,
}

fn case() -> impl Strategy<Value = Case> {
    let target = prop_oneof![
        "[a-z][a-z0-9]{0,8}(\\.[a-z][a-z0-9]{0,8}){1,2}".prop_map(Target::Name),
        any::<u32>().prop_map(Ipv4Addr::from).prop_filter("a public unicast address outside the test's own", |address| {
            let first = address.octets()[0];
            (1..224).contains(&first) && first != 127 && first != 10 && !(address.octets()[0] == 198 && address.octets()[1] == 18)
        }).prop_map(Target::Literal),
    ];
    let bytes = || proptest::collection::vec(any::<u8>(), 0..200_000);
    let uplink = prop_oneof![4 => bytes().prop_map(Uplink::Serves), 1 => Just(Uplink::Refuses)];
    (target, 1u16.., 1024u16.., any::<u16>(), bytes(), uplink, 1usize..100_000)
        .prop_map(|(target, port, local_port, id, sent, uplink, duplex)| Case { target, port, local_port, id, sent, uplink, duplex })
}

/// Gives a socket of the pair room for sixteen megabytes each way. macOS's default for a Unix datagram
/// socket is 4 KiB, under three packets, and a full one there loses the packet instead of making
/// the sender wait; with that every window of a flow would be repaired by retransmission.
fn roomy(socket: &std::os::unix::net::UnixDatagram) {
    use std::os::fd::AsRawFd;
    let size: libc::c_int = 16 << 20;
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: the descriptor is open, and the value is a live c_int of the stated length.
        let set = unsafe {
            libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, option, (&raw const size).cast(), size_of::<libc::c_int>() as libc::socklen_t)
        };
        assert_eq!(set, 0, "a socket buffer: {}", std::io::Error::last_os_error());
    }
}

async fn play(case: Case) -> Result<(), TestCaseError> {
    static RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let state = std::env::temp_dir().join(format!("satmux-tun-test-{}-{run}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(&state).expect("a state folder");
    let (ours, theirs) = std::os::unix::net::UnixDatagram::pair().expect("a socket pair");
    roomy(&ours);
    roomy(&theirs);
    theirs.set_nonblocking(true).expect("non-blocking");
    let mut app = App::new(UnixDatagram::from_std(theirs).expect("a runtime"));

    let (opened_tx, mut opened) = mpsc::unbounded_channel::<Opened>();
    let (refuses, duplex) = (matches!(case.uplink, Uplink::Refuses), case.duplex);
    let connect: Connect = Arc::new(move |dest, first| {
        let opened_tx = opened_tx.clone();
        async move {
            let (near, far) = tokio::io::duplex(duplex);
            let _ = opened_tx.send(Opened { dest, first, stream: far });
            if refuses {
                return Err(std::io::ErrorKind::ConnectionRefused.into());
            }
            Ok(Box::new(Io(near)) as Box<dyn FlowIo>)
        }
        .boxed()
    });
    let resolve: Resolve = Arc::new(|_| async { Err(std::io::ErrorKind::Unsupported.into()) }.boxed());
    let config = TunConfig {
        dns_address: RESOLVER,
        placeholders: BLOCK,
        answer_ttl: Duration::from_secs(1),
        placeholder_hold: Duration::from_secs(3600),
        state: state.clone(),
        mtu: MTU,
        first_payload_wait: Duration::from_millis(1),
    };
    let tunnel = tokio::spawn(satmux_tun::run(OwnedFd::from(ours), config, connect, resolve));

    let (address, expected) = match &case.target {
        Target::Name(name) => {
            let name = HostName::parse(name).expect("a host name");
            let address = app.address_of(&name, case.id).await;
            let again = app.address_of(&name, case.id.wrapping_add(1)).await;
            prop_assert_eq!(address, again, "a name keeps its placeholder");
            prop_assert!(u32::from(address) & 0xffff_ff00 == u32::from(BLOCK.0));
            (address, Dest::Name(name, case.port))
        }
        Target::Literal(address) => (*address, Dest::V4(address.octets(), case.port)),
    };

    let handle = app.open(address, case.port, case.local_port);
    let reply = match &case.uplink {
        Uplink::Serves(reply) => reply.clone(),
        Uplink::Refuses => {
            app.until(|_, sockets| (sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed).then_some(())).await;
            let Opened { dest, .. } = opened.recv().await.expect("an open");
            prop_assert_eq!(dest, expected);
            tunnel.abort();
            let _ = std::fs::remove_dir_all(&state);
            return Ok(());
        }
    };

    let remote = tokio::spawn({
        let reply = reply.clone();
        async move {
            let Opened { dest, first, stream } = opened.recv().await.expect("an open");
            let (mut reading, mut writing) = tokio::io::split(stream);
            let mut received = first.to_vec();
            let (read, wrote) = tokio::join!(reading.read_to_end(&mut received), async {
                writing.write_all(&reply).await?;
                Ok::<(), std::io::Error>(())
            });
            read.expect("the app's bytes");
            wrote.expect("the reply");
            writing.shutdown().await.expect("a close");
            (dest, received)
        }
    });

    let (mut unsent, mut got, mut closed) = (&case.sent[..], Vec::new(), false);
    app.until(|_, sockets| {
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if socket.may_send() && !unsent.is_empty() {
            let sent = socket.send_slice(unsent).expect("an open socket");
            unsent = &unsent[sent..];
        }
        if unsent.is_empty() && socket.may_send() && !closed {
            socket.close();
            closed = true;
        }
        while socket.can_recv() {
            socket.recv(|bytes| { got.extend_from_slice(bytes); (bytes.len(), ()) }).expect("readable");
        }
        (closed && !socket.may_recv() && !socket.can_recv() && matches!(socket.state(), tcp::State::TimeWait | tcp::State::Closed)).then_some(())
    })
    .await;

    let (dest, received) = remote.await.expect("the uplink's side");
    prop_assert_eq!(dest, expected);
    prop_assert!(received == case.sent, "the uplink got {} bytes of {}", received.len(), case.sent.len());
    prop_assert!(got == reply, "the app got {} bytes of {}", got.len(), reply.len());
    if let Target::Name(name) = &case.target {
        // The pool is written behind the answer; the file appears by rename, whole.
        let wanted = |text: String| text.lines().any(|line| line.starts_with(&address.to_string()) && line.ends_with(name.as_str()));
        while !std::fs::read_to_string(state.join("placeholders")).is_ok_and(wanted) {
            tokio::task::yield_now().await;
        }
    }
    tunnel.abort();
    let _ = std::fs::remove_dir_all(&state);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn a_flow_through_the_tunnel_carries_its_name_and_its_bytes(case in case()) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime");
        runtime.block_on(play(case))?;
    }
}
