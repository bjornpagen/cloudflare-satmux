//! The userspace TCP/IP stack and the flows it ends. One task owns the stack; each flow has a
//! task of its own that holds the uplink stream, and the two exchange bytes over channels of one
//! message, so a slow side holds the other back through TCP's own window.

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes, BytesMut};
use satmux_core::Dest;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as StackInstant;
use smoltcp::wire::{
    HardwareAddress, IPV4_MIN_MTU, IpAddress, IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr, TcpPacket, UdpPacket,
    UdpRepr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinSet;

use crate::device::Device;
use crate::dns::{self, Action, Answer, Incoming, Rcode};
use crate::pool::{Block, Pool};
use crate::{Connect, Resolve, TunConfig, store};

/// The DNS port.
const DNS_PORT: u16 = 53;
/// The largest TCP window that needs no scaling; each flow's two buffers are this size.
const WINDOW: usize = 65_535;
/// The hop limit of packets made here (RFC 1700's recommended default).
const HOP_LIMIT: u8 = 64;
/// Bytes of a UDP header.
const UDP_HEADER: usize = 8;

/// The packets waiting to enter and leave the stack.
pub(crate) struct Queue {
    pub(crate) arriving: Option<Vec<u8>>,
    pub(crate) leaving: VecDeque<Vec<u8>>,
    pub(crate) mtu: usize,
}

pub(crate) struct Arriving(Vec<u8>);
pub(crate) struct Leaving<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for Arriving {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Leaving<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl phy::Device for Queue {
    type RxToken<'a> = Arriving;
    type TxToken<'a> = Leaving<'a>;

    fn receive(&mut self, _: StackInstant) -> Option<(Arriving, Leaving<'_>)> {
        self.arriving.take().map(|packet| (Arriving(packet), Leaving(&mut self.leaving)))
    }

    fn transmit(&mut self, _: StackInstant) -> Option<Leaving<'_>> {
        Some(Leaving(&mut self.leaving))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

/// What a packet from the device is, as far as this module treats packets differently.
enum Arrival<'a> {
    /// A datagram for the tunnel's resolver.
    Dns { asker: SocketAddrV4, query: &'a [u8] },
    /// The first packet of an IPv4 TCP flow.
    Syn { source: SocketAddrV4, target: SocketAddrV4 },
    /// Anything else: the stack's own business.
    Other,
}

fn classify(packet: &[u8], resolver: Ipv4Addr) -> Arrival<'_> {
    let checksums = ChecksumCapabilities::default();
    let Ok(ip) = Ipv4Packet::new_checked(packet) else {
        return Arrival::Other;
    };
    if ip.version() != 4 || ip.more_frags() || ip.frag_offset() != 0 {
        return Arrival::Other;
    }
    let Ok(header) = Ipv4Repr::parse(&ip, &checksums) else {
        return Arrival::Other;
    };
    let (source, target) = (header.src_addr, header.dst_addr);
    match header.next_header {
        IpProtocol::Udp => {
            let Ok(udp) = UdpPacket::new_checked(ip.payload()) else {
                return Arrival::Other;
            };
            match UdpRepr::parse(&udp, &source.into(), &target.into(), &checksums) {
                Ok(ports) if target == resolver && ports.dst_port == DNS_PORT => {
                    Arrival::Dns { asker: SocketAddrV4::new(source, ports.src_port), query: udp.payload() }
                }
                _ => Arrival::Other,
            }
        }
        IpProtocol::Tcp => match TcpPacket::new_checked(ip.payload()) {
            Ok(tcp) if tcp.syn() && !tcp.ack() && !tcp.rst() => Arrival::Syn {
                source: SocketAddrV4::new(source, tcp.src_port()),
                target: SocketAddrV4::new(target, tcp.dst_port()),
            },
            _ => Arrival::Other,
        },
        _ => Arrival::Other,
    }
}

/// From the stack to a flow's task. The channel closing without `Fin` means the app reset.
enum FromApp {
    Data(Bytes),
    Fin,
}

/// From a flow's task to the stack. The channel closing without `Fin` means the uplink failed.
enum FromUplink {
    Data(Bytes),
    Fin,
}

/// The app-to-uplink half of a flow.
enum Up {
    Open(mpsc::Sender<FromApp>),
    Closed,
}

/// The uplink-to-app half of a flow.
enum Down {
    Open { arriving: mpsc::Receiver<FromUplink>, pending: Bytes },
    Closed,
}

struct Flow {
    handle: SocketHandle,
    source: SocketAddrV4,
    target: SocketAddrV4,
    up: Up,
    down: Down,
}

/// One step of moving a flow's bytes.
enum Step {
    /// Nothing can move now.
    Idle,
    /// Something moved; try again.
    Moved,
    /// This half is finished.
    Finished,
    /// The other side is gone: reset the flow.
    Gone,
}

fn lift(sender: &mpsc::Sender<FromApp>, socket: &mut tcp::Socket<'_>) -> Step {
    let finished = !socket.can_recv()
        && matches!(socket.state(), tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait);
    if !socket.can_recv() && !finished {
        return Step::Idle;
    }
    match sender.try_reserve() {
        Ok(permit) if finished => {
            permit.send(FromApp::Fin);
            Step::Finished
        }
        Ok(permit) => match socket.recv(|bytes| (bytes.len(), Bytes::copy_from_slice(bytes))) {
            Ok(bytes) if !bytes.is_empty() => {
                permit.send(FromApp::Data(bytes));
                Step::Moved
            }
            Ok(_) | Err(_) => Step::Idle,
        },
        Err(TrySendError::Full(())) => Step::Idle,
        Err(TrySendError::Closed(())) => Step::Gone,
    }
}

fn lower(arriving: &mut mpsc::Receiver<FromUplink>, pending: &mut Bytes, socket: &mut tcp::Socket<'_>) -> Step {
    if pending.is_empty() {
        return match arriving.try_recv() {
            Ok(FromUplink::Data(bytes)) => {
                *pending = bytes;
                Step::Moved
            }
            Ok(FromUplink::Fin) => {
                socket.close();
                Step::Finished
            }
            Err(TryRecvError::Empty) => Step::Idle,
            Err(TryRecvError::Disconnected) => Step::Gone,
        };
    }
    if !socket.can_send() {
        return Step::Idle;
    }
    match socket.send_slice(pending) {
        Ok(sent) if sent > 0 => {
            pending.advance(sent);
            Step::Moved
        }
        Ok(_) | Err(_) => Step::Idle,
    }
}

/// Moves what can move in both directions. True when anything changed.
fn pump(flow: &mut Flow, socket: &mut tcp::Socket<'_>) -> bool {
    let mut progressed = false;
    loop {
        let step = match &flow.up {
            Up::Open(sender) => lift(sender, socket),
            Up::Closed => Step::Idle,
        };
        let step = match step {
            Step::Idle => match &mut flow.down {
                Down::Open { arriving, pending } => match lower(arriving, pending, socket) {
                    Step::Finished => {
                        flow.down = Down::Closed;
                        Step::Moved
                    }
                    other => other,
                },
                Down::Closed => Step::Idle,
            },
            Step::Finished => {
                flow.up = Up::Closed;
                Step::Moved
            }
            other => other,
        };
        match step {
            Step::Idle => return progressed,
            Step::Moved | Step::Finished => progressed = true,
            Step::Gone => {
                socket.abort();
                flow.up = Up::Closed;
                flow.down = Down::Closed;
                return true;
            }
        }
    }
}

/// A flow's task: waits for the app's first bytes, opens the uplink, then splices.
async fn carry(
    dest: Dest,
    mut from_app: mpsc::Receiver<FromApp>,
    to_app: mpsc::Sender<FromUplink>,
    wake: Arc<Notify>,
    connect: Connect,
    first_payload_wait: Duration,
) {
    let (first, app_finished) = match tokio::time::timeout(first_payload_wait, from_app.recv()).await {
        Ok(Some(FromApp::Data(bytes))) => (bytes, false),
        Ok(Some(FromApp::Fin)) => (Bytes::new(), true),
        Ok(None) => return,
        Err(_) => (Bytes::new(), false),
    };
    wake.notify_one();
    let uplink = tokio::select! {
        opened = connect(dest, first) => opened,
        () = to_app.closed() => return,
    };
    let Ok(uplink) = uplink else {
        wake.notify_one();
        return;
    };
    let (mut reading, mut writing) = tokio::io::split(uplink);
    let upward = async {
        let mut finished = app_finished;
        while !finished {
            match from_app.recv().await {
                Some(FromApp::Data(bytes)) => {
                    wake.notify_one();
                    writing.write_all(&bytes).await?;
                }
                Some(FromApp::Fin) => finished = true,
                None => return Err(io::ErrorKind::ConnectionReset.into()),
            }
        }
        writing.shutdown().await
    };
    let downward = async {
        let mut buffer = BytesMut::with_capacity(WINDOW);
        loop {
            let message = match reading.read_buf(&mut buffer).await? {
                0 => FromUplink::Fin,
                _ => FromUplink::Data(buffer.split().freeze()),
            };
            let finished = matches!(message, FromUplink::Fin);
            to_app.send(message).await.map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))?;
            wake.notify_one();
            if finished {
                return Ok::<(), io::Error>(());
            }
            buffer.reserve(WINDOW);
        }
    };
    let _ = tokio::try_join!(upward, downward);
    drop(to_app);
    wake.notify_one();
}

/// An answer on its way back to whoever asked the resolver.
struct Reply {
    asker: SocketAddrV4,
    bytes: Vec<u8>,
}

/// Seconds since the Unix epoch; a clock set before it reads as the epoch.
fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

struct Stack {
    interface: Interface,
    sockets: SocketSet<'static>,
    queue: Queue,
    flows: Vec<Flow>,
    pool: Pool,
    kept_revision: u64,
    keep: watch::Sender<String>,
    resolver: Ipv4Addr,
    answer_ttl: u32,
    first_payload_wait: Duration,
    started: tokio::time::Instant,
    wake: Arc<Notify>,
    tasks: JoinSet<()>,
    replies: mpsc::UnboundedSender<Reply>,
    connect: Connect,
    resolve: Resolve,
}

impl Stack {
    fn now(&self) -> StackInstant {
        StackInstant::from_micros(self.started.elapsed().as_micros() as i64)
    }

    fn poll(&mut self) {
        let now = self.now();
        self.interface.poll(now, &mut self.queue, &mut self.sockets);
    }

    /// Runs the stack and the flows until nothing more can move.
    fn turn(&mut self) {
        loop {
            self.poll();
            let sockets = &mut self.sockets;
            self.flows.retain(|flow| {
                let over = matches!(sockets.get::<tcp::Socket>(flow.handle).state(), tcp::State::Closed | tcp::State::Listen);
                if over {
                    sockets.remove(flow.handle);
                }
                !over
            });
            let mut progressed = false;
            for flow in &mut self.flows {
                progressed |= pump(flow, self.sockets.get_mut::<tcp::Socket>(flow.handle));
            }
            if !progressed {
                break;
            }
        }
        if self.pool.revision() != self.kept_revision {
            self.kept_revision = self.pool.revision();
            self.keep.send_replace(store::render(&self.pool));
        }
    }

    fn arrive(&mut self, packet: &[u8]) {
        match classify(packet, self.resolver) {
            Arrival::Dns { asker, query } => self.ask(asker, query),
            Arrival::Syn { source, target } => {
                let listening = self.listen(source, target);
                self.queue.arriving = Some(packet.to_vec());
                self.poll();
                if let Some((handle, dest)) = listening {
                    self.admit(handle, source, target, dest);
                }
            }
            Arrival::Other => self.queue.arriving = Some(packet.to_vec()),
        }
    }

    /// Where a flow to `target` goes. `None` is a flow nothing is opened for: the resolver's own
    /// address, or a placeholder that stands for no name. The stack resets it.
    fn destination(&mut self, target: SocketAddrV4) -> Option<Dest> {
        let address = *target.ip();
        if address == self.resolver {
            None
        } else if self.pool.block().contains(address) {
            self.pool.touch(address, unix_now()).cloned().map(|name| Dest::Name(name, target.port()))
        } else {
            Some(Dest::V4(address.octets(), target.port()))
        }
    }

    /// Puts a socket where the coming SYN will find it.
    fn listen(&mut self, source: SocketAddrV4, target: SocketAddrV4) -> Option<(SocketHandle, Dest)> {
        if self.flows.iter().any(|flow| flow.source == source && flow.target == target) {
            return None;
        }
        let dest = self.destination(target)?;
        let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; WINDOW]), tcp::SocketBuffer::new(vec![0; WINDOW]));
        let endpoint = IpListenEndpoint { addr: Some(IpAddress::Ipv4(*target.ip())), port: target.port() };
        socket.listen(endpoint).ok()?;
        Some((self.sockets.add(socket), dest))
    }

    /// Starts the flow's task if the stack took the SYN, and takes the socket back if it did not.
    fn admit(&mut self, handle: SocketHandle, source: SocketAddrV4, target: SocketAddrV4, dest: Dest) {
        if self.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Listen {
            self.sockets.remove(handle);
            return;
        }
        let (to_task, from_app) = mpsc::channel(1);
        let (to_app, arriving) = mpsc::channel(1);
        self.tasks.spawn(carry(dest, from_app, to_app, self.wake.clone(), self.connect.clone(), self.first_payload_wait));
        self.flows.push(Flow { handle, source, target, up: Up::Open(to_task), down: Down::Open { arriving, pending: Bytes::new() } });
    }

    /// Answers one datagram sent to the resolver, by the table in [`dns::action`].
    fn ask(&mut self, asker: SocketAddrV4, datagram: &[u8]) {
        let ttl = self.answer_ttl;
        let bytes = match dns::read(datagram) {
            Incoming::Ignored => return,
            Incoming::Refused { head, rcode } => dns::refusal(head, rcode),
            Incoming::Asked { head, question, query } => match dns::action(query, self.pool.block()) {
                Action::Placeholder(name) => match self.pool.lookup(&name, unix_now()) {
                    Some(address) => dns::reply(head, question, Rcode::NoError, Answer::Address { address, ttl }),
                    None => dns::reply(head, question, Rcode::ServFail, Answer::Nothing),
                },
                Action::Empty => dns::reply(head, question, Rcode::NoError, Answer::Nothing),
                Action::NameOf(address) => match self.pool.name_of(address) {
                    Some(name) => dns::reply(head, question, Rcode::NoError, Answer::Name { name, ttl }),
                    None => dns::reply(head, question, Rcode::NxDomain, Answer::Nothing),
                },
                Action::Forward => {
                    let (resolve, replies) = (self.resolve.clone(), self.replies.clone());
                    let (question, query) = (question.to_vec(), datagram.to_vec());
                    self.tasks.spawn(async move {
                        let bytes = dns::relayed(head, &question, resolve(query).await);
                        let _ = replies.send(Reply { asker, bytes });
                    });
                    return;
                }
            },
        };
        self.answer(Reply { asker, bytes });
    }

    /// Queues a resolver reply as one UDP packet; one that would not fit is sent truncated.
    fn answer(&mut self, reply: Reply) {
        let header = Ipv4Repr {
            src_addr: self.resolver,
            dst_addr: *reply.asker.ip(),
            next_header: IpProtocol::Udp,
            payload_len: 0,
            hop_limit: HOP_LIMIT,
        };
        let room = self.queue.mtu - header.buffer_len() - UDP_HEADER;
        let bytes = if reply.bytes.len() <= room { Some(reply.bytes) } else { dns::truncated(&reply.bytes) };
        let Some(bytes) = bytes else {
            return;
        };
        let header = Ipv4Repr { payload_len: UDP_HEADER + bytes.len(), ..header };
        let checksums = ChecksumCapabilities::default();
        let mut packet = vec![0; header.buffer_len() + header.payload_len];
        let (ip, udp) = packet.split_at_mut(header.buffer_len());
        header.emit(&mut Ipv4Packet::new_unchecked(ip), &checksums);
        UdpRepr { src_port: DNS_PORT, dst_port: reply.asker.port() }.emit(
            &mut UdpPacket::new_unchecked(udp),
            &header.src_addr.into(),
            &header.dst_addr.into(),
            bytes.len(),
            |payload| payload.copy_from_slice(&bytes),
            &checksums,
        );
        self.queue.leaving.push_back(packet);
    }
}

fn refused(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_owned())
}

async fn pause(delay: Option<smoltcp::time::Duration>) {
    match delay {
        Some(delay) => tokio::time::sleep(Duration::from_micros(delay.total_micros())).await,
        None => std::future::pending().await,
    }
}

/// Writes each new text of the pool to the state folder. Ends only when a write fails.
async fn keeper(state: std::path::PathBuf, mut texts: watch::Receiver<String>) -> io::Result<()> {
    while texts.changed().await.is_ok() {
        let (state, text) = (state.clone(), texts.borrow_and_update().clone());
        tokio::task::spawn_blocking(move || store::save(&state, &text)).await.map_err(io::Error::other)??;
    }
    std::future::pending().await
}

/// Runs the front end on any packet device until the device or the state folder fails.
pub async fn serve<D: Device>(device: D, config: TunConfig, connect: Connect, resolve: Resolve) -> io::Result<()> {
    let (address, prefix) = config.placeholders;
    let block = Block::new(address, prefix).ok_or_else(|| refused("placeholders: not a CIDR block"))?;
    if block.contains(config.dns_address) {
        return Err(refused("dns_address: inside the placeholder block"));
    }
    let answer_ttl = u32::try_from(config.answer_ttl.as_secs()).map_err(|_| refused("answer_ttl: too long for a DNS record"))?;
    if config.mtu < IPV4_MIN_MTU {
        return Err(refused("mtu: smaller than IPv4 allows"));
    }
    let pool = store::load(&config.state, block, config.placeholder_hold)?;

    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).map_err(io::Error::other)?;
    let mut interface_config = Config::new(HardwareAddress::Ip);
    interface_config.random_seed = u64::from_ne_bytes(seed);
    let mut queue = Queue { arriving: None, leaving: VecDeque::new(), mtu: config.mtu };
    let started = tokio::time::Instant::now();
    let mut interface = Interface::new(interface_config, &mut queue, StackInstant::ZERO);
    interface.set_any_ip(true);

    let wake = Arc::new(Notify::new());
    let (replies, mut replied) = mpsc::unbounded_channel();
    let (keep, texts) = watch::channel(String::new());
    let mut keeping = pin!(keeper(config.state.clone(), texts));
    let mut stack = Stack {
        interface,
        sockets: SocketSet::new(Vec::new()),
        queue,
        flows: Vec::new(),
        kept_revision: pool.revision(),
        pool,
        keep,
        resolver: config.dns_address,
        answer_ttl,
        first_payload_wait: config.first_payload_wait,
        started,
        wake: wake.clone(),
        tasks: JoinSet::new(),
        replies,
        connect,
        resolve,
    };
    let mut packet = vec![0u8; config.mtu];
    loop {
        stack.turn();
        while let Some(leaving) = stack.queue.leaving.pop_front() {
            device.send(&leaving).await?;
        }
        let now = stack.now();
        let delay = stack.interface.poll_delay(now, &stack.sockets);
        tokio::select! {
            read = device.recv(&mut packet) => {
                let length = read?;
                stack.arrive(&packet[..length]);
            }
            () = wake.notified() => {}
            Some(reply) = replied.recv() => stack.answer(reply),
            Some(_) = stack.tasks.join_next() => {}
            kept = &mut keeping => return kept,
            () = pause(delay) => {}
        }
    }
}
