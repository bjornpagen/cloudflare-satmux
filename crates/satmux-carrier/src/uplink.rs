//! The shell around the pool machine, and the one way a front end sends anything: an
//! [`Uplink`]. It executes the machine's actions (dial, echo, close), feeds back what happened,
//! and routes each flow by its verdict.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use satmux_core::{DNS_MAX, Dest, ECHO_NONCE, HostName, Open, Status};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::config::Common;
use crate::dial::{self, Dialer, Session, Stream};
use crate::find::{self, HTTPS_PORT};
use crate::net;
use crate::pool::{Action, At, CarrierId, Cover, Event, Machine, Rules, State};
use crate::verdict::{Table, Verdict, WallClock, Why};
use crate::{dnsmsg, pool};

/// A carrier as the machine holds it: how to open streams on it and how to ask for an echo.
#[derive(Clone)]
struct Carrier {
    session: Session,
    echoes: mpsc::UnboundedSender<()>,
}

/// Everything the pool's shell needs that is not in the machine's rules.
pub struct Parts {
    pub rules: Rules,
    pub dialer: Dialer,
    /// The relay's addresses, already found.
    pub relay: Vec<IpAddr>,
    /// How long one dial may take from socket to upgrade.
    pub dial_wait: Duration,
    /// How long a stream may wait for a ready carrier and its status byte.
    pub status_wait: Duration,
    /// How long one direct connect may take.
    pub direct_wait: Duration,
    pub verdict_life: Duration,
    pub state: PathBuf,
}

#[derive(Default)]
struct Counters {
    relayed: AtomicU64,
    direct: AtomicU64,
    replayed: AtomicU64,
    refused: AtomicU64,
    failed: AtomicU64,
    dials_ok: AtomicU64,
    dials_failed: AtomicU64,
    lookups: AtomicU64,
}

struct Shared {
    machine: Mutex<Machine<Carrier>>,
    epoch: Instant,
    events: mpsc::UnboundedSender<Event<Carrier>>,
    ready: watch::Sender<bool>,
    abandoned: watch::Sender<bool>,
    dialer: Dialer,
    relay: Vec<IpAddr>,
    dial_wait: Duration,
    status_wait: Duration,
    direct_wait: Duration,
    verdict_life: Duration,
    verdicts: Mutex<Table>,
    counters: Counters,
}

/// The carriers, the verdicts and the direct path, behind two calls. Cheap to clone.
#[derive(Clone)]
pub struct Uplink {
    shared: Arc<Shared>,
}

/// Why the uplink could not start. Each is a temporary failure, except a bad file.
#[derive(Debug, thiserror::Error)]
pub enum StartFailed {
    #[error("SATMUX_DAEMON_KEY: {0}")]
    Key(io::Error),
    #[error("SATMUX_DAEMON_ROOTS: {0}")]
    Roots(io::Error),
    #[error("SATMUX_DAEMON_BIND_INTERFACE: {0}")]
    Interface(io::Error),
    #[error("SATMUX_DAEMON_STATE: {0}")]
    State(io::Error),
    #[error("SATMUX_RELAY_NAME: {0}")]
    Name(io::Error),
    #[error("finding the relay: {0}")]
    Find(#[from] find::NotFound),
}

/// A uniform draw from zero to `most`, from the standard library's per-process hash keys.
fn jitter(most: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let draw = std::collections::hash_map::RandomState::new().build_hasher().finish();
    let nanos = u64::try_from(most.as_nanos()).unwrap_or(u64::MAX);
    Duration::from_nanos(nanos.checked_add(1).map_or(draw, |span| draw % span))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    fn now(&self) -> At {
        At(self.epoch.elapsed())
    }

    /// Feeds one event to the machine and carries out what it asks.
    fn apply(self: &Arc<Self>, event: Event<Carrier>) {
        let actions = {
            let mut machine = lock(&self.machine);
            let actions = machine.handle(self.now(), event);
            self.ready.send_replace(matches!(machine.cover(), Cover::Covered));
            actions
        };
        self.execute(actions);
    }

    fn execute(self: &Arc<Self>, actions: Vec<Action<Carrier>>) {
        for action in actions {
            match action {
                Action::Dial { id, port, attempt, wait_up_to } => {
                    tokio::spawn(self.clone().dial(id, port, attempt, wait_up_to));
                }
                Action::SendEcho { id: _, session } => {
                    let _ = session.echoes.send(());
                }
                Action::Close { id, session } => {
                    tracing::info!(carrier = %id, "carrier released");
                    drop(session);
                }
                Action::NoCarrier => {
                    self.abandoned.send_replace(true);
                }
            }
        }
    }

    async fn dial(self: Arc<Self>, id: CarrierId, port: u16, attempt: u32, wait_up_to: Duration) {
        tokio::time::sleep(jitter(wait_up_to)).await;
        let address = self.relay[attempt as usize % self.relay.len()];
        let relay = SocketAddr::new(address, port);
        match tokio::time::timeout(self.dial_wait, self.dialer.dial(relay)).await {
            Ok(Ok((connection, timings))) => {
                tracing::info!(carrier = %id, %relay, tcp_ms = timings.tcp.as_millis(), tls_ms = timings.tls.as_millis(), upgrade_ms = timings.upgrade.as_millis(), "carrier up");
                self.counters.dials_ok.fetch_add(1, Ordering::Relaxed);
                let (session, driver) = Session::new(connection);
                let (echoes, asked) = mpsc::unbounded_channel();
                let pool = self.clone();
                tokio::spawn(async move {
                    driver.await;
                    tracing::info!(carrier = %id, "carrier ended");
                    let _ = pool.events.send(Event::Died { id });
                });
                tokio::spawn(echo(self.clone(), id, session.clone(), asked));
                self.apply(Event::DialOk { id, session: Carrier { session, echoes }, rtt: timings.upgrade });
            }
            Ok(Err(error)) => {
                tracing::warn!(carrier = %id, %relay, %error, "dial failed");
                self.counters.dials_failed.fetch_add(1, Ordering::Relaxed);
                self.apply(Event::DialFailed { id });
            }
            Err(_) => {
                tracing::warn!(carrier = %id, %relay, "dial timed out");
                self.counters.dials_failed.fetch_add(1, Ordering::Relaxed);
                self.apply(Event::DialFailed { id });
            }
        }
    }
}

/// One carrier's liveness stream: writes a nonce each time it is asked, and reports every
/// nonce that comes back. Ends with the carrier.
async fn echo(pool: Arc<Shared>, id: CarrierId, session: Session, mut asked: mpsc::UnboundedReceiver<()>) {
    let Ok((stream, Status::Connected)) = session.request(&Open::Echo, &[]).await else { return };
    drop(session);
    let (mut replies, mut nonces) = tokio::io::split(stream);
    let writer = async {
        let mut nonce: u64 = 0;
        while asked.recv().await.is_some() {
            let written = async {
                nonces.write_all(&nonce.to_be_bytes()).await?;
                nonces.flush().await
            };
            if written.await.is_err() {
                return;
            }
            nonce = nonce.wrapping_add(1);
        }
    };
    let reader = async {
        let mut reply = [0u8; ECHO_NONCE];
        while replies.read_exact(&mut reply).await.is_ok() {
            let _ = pool.events.send(Event::EchoReply { id });
        }
    };
    tokio::select! {
        () = writer => {}
        () = reader => {}
    }
}

/// The task every event without a caller comes through: the clock, and what other tasks saw.
async fn run(pool: Arc<Shared>, mut events: mpsc::UnboundedReceiver<Event<Carrier>>) {
    loop {
        let deadline = lock(&pool.machine).next_deadline();
        let due = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(pool.epoch + at.0).await,
                None => std::future::pending().await,
            }
        };
        let event = tokio::select! {
            () = due => Event::Tick,
            event = events.recv() => match event {
                Some(event) => event,
                None => return,
            },
        };
        pool.apply(event);
    }
}

/// A stream the machine counted; dropping it tells the machine.
struct Counted {
    pool: Arc<Shared>,
    id: CarrierId,
}

impl Drop for Counted {
    fn drop(&mut self) {
        let _ = self.pool.events.send(Event::FlowClosed { id: self.id });
    }
}

enum Path {
    Relay { stream: Stream, _counted: Counted },
    Direct(TcpStream),
}

/// One flow's bytes, wherever they go.
pub struct Flow(Path);

impl Flow {
    /// Whether this flow left through the relay or directly.
    pub fn is_direct(&self) -> bool {
        matches!(self.0, Path::Direct(_))
    }
}

impl AsyncRead for Flow {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Path::Relay { stream, .. } => Pin::new(stream).poll_read(cx, buf),
            Path::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Flow {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            Path::Relay { stream, .. } => Pin::new(stream).poll_write(cx, buf),
            Path::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Path::Relay { stream, .. } => Pin::new(stream).poll_flush(cx),
            Path::Direct(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Path::Relay { stream, .. } => Pin::new(stream).poll_shutdown(cx),
            Path::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// What the relay said to an open.
enum Answered {
    Connected(Stream, Counted),
    Refused(Status),
}

impl Uplink {
    /// Reads the files the configuration names, finds the relay, and starts the pool.
    pub async fn from_config(common: &Common) -> Result<Self, StartFailed> {
        let key = tokio::fs::read_to_string(&common.key).await.map_err(StartFailed::Key)?;
        let authorization = dial::bearer(&key).map_err(StartFailed::Key)?;
        let tls = dial::tls_config(&common.roots).map_err(StartFailed::Roots)?;
        let factory = net::bound_to(&common.bind_interface).map_err(StartFailed::Interface)?;
        let resolvers: Vec<SocketAddr> = common.resolvers.iter().map(|ip| SocketAddr::new(*ip, HTTPS_PORT)).collect();
        let found = find::relay(&tls, &factory, &resolvers, &common.relay_name, &common.state, common.relay_connect).await?;
        tracing::info!(?found, "relay found");
        let relay = found.addresses().iter().copied().map(IpAddr::V4).collect();
        let dialer = Dialer::new(common.relay_name.clone(), tls, authorization, factory, usize::from(common.streams.get())).map_err(StartFailed::Name)?;
        Self::start(Parts::from_config(common, dialer, relay)).map_err(StartFailed::State)
    }

    /// Starts the pool: every port is dialed at once.
    pub fn start(parts: Parts) -> io::Result<Self> {
        let verdicts = Table::load(parts.state)?;
        let epoch = Instant::now();
        let (machine, actions) = Machine::new(parts.rules, At(Duration::ZERO));
        let (events, received) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            machine: Mutex::new(machine),
            epoch,
            events,
            ready: watch::Sender::new(false),
            abandoned: watch::Sender::new(false),
            dialer: parts.dialer,
            relay: parts.relay,
            dial_wait: parts.dial_wait,
            status_wait: parts.status_wait,
            direct_wait: parts.direct_wait,
            verdict_life: parts.verdict_life,
            verdicts: Mutex::new(verdicts),
            counters: Counters::default(),
        });
        shared.execute(actions);
        tokio::spawn(run(shared.clone(), received));
        Ok(Self { shared })
    }

    /// True while at least one carrier is ready.
    pub fn ready(&self) -> watch::Receiver<bool> {
        self.shared.ready.subscribe()
    }

    /// Resolves once there has been no ready carrier for the whole allowance.
    pub async fn no_carrier(&self) {
        let mut abandoned = self.shared.abandoned.subscribe();
        let _ = abandoned.wait_for(|gone| *gone).await;
    }

    /// Opens a flow to `dest` and sends `first` with it. Applies the name's verdict: through
    /// the relay, or direct once the relay has refused the name.
    pub async fn connect(&self, dest: Dest, first: Bytes) -> io::Result<Flow> {
        let result = self.route(&dest, &first).await;
        if result.is_err() {
            self.shared.counters.failed.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn route(&self, dest: &Dest, first: &Bytes) -> io::Result<Flow> {
        let verdict = match dest {
            Dest::Name(name, _) => lock(&self.shared.verdicts).rows().verdict(name, WallClock::now()),
            Dest::V4(..) | Dest::V6(..) => Verdict::Relay,
        };
        match verdict {
            Verdict::Relay => match self.through_relay(&Open::Connect(dest.clone()), first).await? {
                Answered::Connected(stream, counted) => Ok(self.relayed(stream, counted)),
                Answered::Refused(Status::Forbidden) => {
                    // The relay's platform says the same thing for a destination it forbids
                    // and for one that is down or does not exist (measured: satmux-relay's
                    // `status_of_refusal`). Only a direct connect that succeeds tells them
                    // apart, so only that writes the row.
                    let flow = self.direct(dest, first).await?;
                    if let Dest::Name(name, _) = dest {
                        let until = WallClock::now().after(self.shared.verdict_life);
                        tracing::info!(%name, "the relay refuses this name and it answers directly; it goes direct from now on");
                        lock(&self.shared.verdicts).change(|rows| rows.direct(name.clone(), Why::Forbidden, until));
                    }
                    Ok(flow)
                }
                Answered::Refused(status) => Err(dial::refusal(status)),
            },
            Verdict::Direct { .. } => match self.direct(dest, first).await {
                Ok(flow) => Ok(flow),
                Err(direct_error) => match self.through_relay(&Open::Connect(dest.clone()), first).await {
                    Ok(Answered::Connected(stream, counted)) => {
                        if let Dest::Name(name, _) = dest {
                            tracing::info!(%name, "the relay accepts this name again; its direct verdict is dropped");
                            lock(&self.shared.verdicts).change(|rows| rows.relay(name));
                        }
                        Ok(self.relayed(stream, counted))
                    }
                    Ok(Answered::Refused(_)) | Err(_) => Err(direct_error),
                },
            },
        }
    }

    fn relayed(&self, stream: Stream, counted: Counted) -> Flow {
        self.shared.counters.relayed.fetch_add(1, Ordering::Relaxed);
        Flow(Path::Relay { stream, _counted: counted })
    }

    /// A ready carrier with room, waiting for one until `deadline` if none is ready.
    async fn pick(&self, deadline: Instant) -> io::Result<(CarrierId, Carrier)> {
        let mut ready = self.shared.ready.subscribe();
        loop {
            if let Some(picked) = lock(&self.shared.machine).pick() {
                return Ok(picked);
            }
            if *ready.borrow_and_update() {
                return Err(dial::refusal(Status::Limit));
            }
            match tokio::time::timeout_at(deadline, ready.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(io::ErrorKind::NotConnected.into()),
                Err(_) => return Err(io::Error::new(io::ErrorKind::NotConnected, "no carrier is ready")),
            }
        }
    }

    /// Sends an open and its first payload on a ready carrier and reads the status byte. A
    /// carrier that fails before any status byte has delivered nothing, so the same flight is
    /// sent again on another, at most once per port.
    async fn through_relay(&self, open: &Open, first: &[u8]) -> io::Result<Answered> {
        let deadline = Instant::now() + self.shared.status_wait;
        let mut last = io::Error::from(io::ErrorKind::NotConnected);
        let carriers = lock(&self.shared.machine).rules().ports.len();
        for _ in 0..carriers {
            let (id, carrier) = self.pick(deadline).await?;
            let counted = Counted { pool: self.shared.clone(), id };
            match tokio::time::timeout_at(deadline, carrier.session.request(open, first)).await {
                Ok(Ok((stream, Status::Connected))) => return Ok(Answered::Connected(stream, counted)),
                Ok(Ok((_, status))) => {
                    self.shared.counters.refused.fetch_add(1, Ordering::Relaxed);
                    return Ok(Answered::Refused(status));
                }
                Ok(Err(error)) => {
                    tracing::debug!(carrier = %id, %error, "no status byte; the flight goes to another carrier");
                    self.shared.counters.replayed.fetch_add(1, Ordering::Relaxed);
                    last = error;
                }
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "the relay sent no status byte in time")),
            }
        }
        Err(last)
    }

    /// Connects outside the relay, on a bound socket, and sends the first payload.
    async fn direct(&self, dest: &Dest, first: &[u8]) -> io::Result<Flow> {
        let targets: Vec<SocketAddr> = match dest {
            Dest::V4(address, port) => vec![SocketAddr::from((*address, *port))],
            Dest::V6(address, port) => vec![SocketAddr::from((*address, *port))],
            Dest::Name(name, port) => self.addresses(name).await?.into_iter().map(|a| SocketAddr::from((a, *port))).collect(),
        };
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for target in targets {
            let connecting = async {
                let mut stream = net::connect(self.shared.dialer.factory(), target).await?;
                stream.write_all(first).await?;
                io::Result::Ok(stream)
            };
            match tokio::time::timeout(self.shared.direct_wait, connecting).await {
                Ok(Ok(stream)) => {
                    self.shared.counters.direct.fetch_add(1, Ordering::Relaxed);
                    return Ok(Flow(Path::Direct(stream)));
                }
                Ok(Err(error)) => last = error,
                Err(_) => last = io::ErrorKind::TimedOut.into(),
            }
        }
        Err(last)
    }

    async fn addresses(&self, name: &HostName) -> io::Result<Vec<std::net::Ipv4Addr>> {
        let answer = self.dns(dnsmsg::a_query(name)).await?;
        dnsmsg::a_addresses(&answer).map_err(io::Error::other)
    }

    /// One DNS query, answered by the relay's resolver over a carrier that is already up.
    pub async fn dns(&self, query: Vec<u8>) -> io::Result<Vec<u8>> {
        self.shared.counters.lookups.fetch_add(1, Ordering::Relaxed);
        match self.through_relay(&Open::Dns(query), &[]).await? {
            Answered::Connected(mut stream, _counted) => {
                let length = usize::from(stream.read_u16().await?);
                if length > DNS_MAX {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let mut answer = vec![0; length];
                stream.read_exact(&mut answer).await?;
                Ok(answer)
            }
            Answered::Refused(status) => Err(dial::refusal(status)),
        }
    }

    /// A stream for measuring: an echo, source or sink open on a ready carrier.
    pub async fn measure(&self, open: Open) -> io::Result<Flow> {
        match self.through_relay(&open, &[]).await? {
            Answered::Connected(stream, counted) => Ok(Flow(Path::Relay { stream, _counted: counted })),
            Answered::Refused(status) => Err(dial::refusal(status)),
        }
    }

    /// The status socket's `status`: `name value` lines.
    pub fn status(&self) -> String {
        use std::fmt::Write;
        let now = self.shared.now();
        let mut out = String::new();
        let machine = lock(&self.shared.machine);
        let cover = match machine.cover() {
            Cover::Covered => "covered",
            Cover::Bare { .. } => "bare",
            Cover::Abandoned => "abandoned",
        };
        let _ = writeln!(out, "cover {cover}");
        for carrier in machine.carriers() {
            let id = carrier.id;
            let _ = writeln!(out, "carrier.{id}.port {}", carrier.port);
            let age = |since: &At| now.0.saturating_sub(since.0).as_secs();
            match &carrier.state {
                State::Dialing { since } => {
                    let _ = writeln!(out, "carrier.{id}.state dialing\ncarrier.{id}.age_s {}", age(since));
                }
                State::Ready { live, born, rtt, .. } => {
                    let _ = writeln!(out, "carrier.{id}.state ready\ncarrier.{id}.rtt_ms {}\ncarrier.{id}.age_s {}\ncarrier.{id}.streams {}", rtt.as_millis(), age(born), live.streams);
                }
                State::Suspect { live, since } => {
                    let _ = writeln!(out, "carrier.{id}.state suspect\ncarrier.{id}.age_s {}\ncarrier.{id}.streams {}", age(since), live.streams);
                }
                State::Draining { live, until } => {
                    let _ = writeln!(out, "carrier.{id}.state draining\ncarrier.{id}.left_s {}\ncarrier.{id}.streams {}", until.0.saturating_sub(now.0).as_secs(), live.streams);
                }
            }
        }
        drop(machine);
        let counters = &self.shared.counters;
        for (name, counter) in [
            ("flows.relayed", &counters.relayed),
            ("flows.direct", &counters.direct),
            ("flows.replayed", &counters.replayed),
            ("flows.refused", &counters.refused),
            ("flows.failed", &counters.failed),
            ("dials.ok", &counters.dials_ok),
            ("dials.failed", &counters.dials_failed),
            ("lookups", &counters.lookups),
        ] {
            let _ = writeln!(out, "{name} {}", counter.load(Ordering::Relaxed));
        }
        let _ = writeln!(out, "verdicts.direct {}", lock(&self.shared.verdicts).rows().len());
        out
    }

    /// The status socket's `explain <name>`: the name's verdict as `name value` lines.
    pub fn explain(&self, name: &HostName) -> String {
        format!("{name} {}\n", lock(&self.shared.verdicts).rows().verdict(name, WallClock::now()))
    }
}

impl Parts {
    /// The waits every caller derives the same way from the configuration: a dial may take as
    /// long as the relay's own onward connect, a status byte that long plus the suspect time
    /// for the round trip, and a direct connect the same as a relayed one.
    pub fn from_config(common: &Common, dialer: Dialer, relay: Vec<IpAddr>) -> Self {
        Self {
            rules: pool::Rules {
                ports: common.ports.clone(),
                streams: usize::from(common.streams.get()),
                echo_idle: common.echo_idle,
                suspect: common.suspect,
                rotate: common.rotate,
                no_carrier_exit: common.no_carrier_exit,
            },
            dialer,
            relay,
            dial_wait: common.relay_connect,
            status_wait: common.relay_connect.saturating_add(common.suspect),
            direct_wait: common.relay_connect,
            verdict_life: common.verdict_life,
            state: common.state.clone(),
        }
    }
}
