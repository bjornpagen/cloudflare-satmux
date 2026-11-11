//! The whole input of `satmuxd` and `satmux-probe`, parsed once into one value whose fields are
//! all required. A missing, unknown or malformed variable is refused by name.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU64};
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::Duration;

use satmux_core::HostName;

const RELAY_PREFIX: &str = "SATMUX_RELAY_";
const DAEMON_PREFIX: &str = "SATMUX_DAEMON_";
const PROBE_PREFIX: &str = "SATMUX_PROBE_";

const RELAY_NAME: &str = "SATMUX_RELAY_NAME";
const RELAY_STREAMS: &str = "SATMUX_RELAY_STREAMS";
const RELAY_OPEN_MS: &str = "SATMUX_RELAY_OPEN_MS";
const RELAY_CONNECT_MS: &str = "SATMUX_RELAY_CONNECT_MS";
const RELAY_MEASURE_BYTES: &str = "SATMUX_RELAY_MEASURE_BYTES";
const DAEMON_PORTS: &str = "SATMUX_DAEMON_PORTS";
const DAEMON_RESOLVERS: &str = "SATMUX_DAEMON_RESOLVERS";
const DAEMON_DNS_ADDRESS: &str = "SATMUX_DAEMON_DNS_ADDRESS";
const DAEMON_PLACEHOLDERS: &str = "SATMUX_DAEMON_PLACEHOLDERS";
const DAEMON_ANSWER_TTL_S: &str = "SATMUX_DAEMON_ANSWER_TTL_S";
const DAEMON_PLACEHOLDER_HOLD_S: &str = "SATMUX_DAEMON_PLACEHOLDER_HOLD_S";
const DAEMON_ECHO_IDLE_MS: &str = "SATMUX_DAEMON_ECHO_IDLE_MS";
const DAEMON_SUSPECT_MS: &str = "SATMUX_DAEMON_SUSPECT_MS";
const DAEMON_ROTATE_S: &str = "SATMUX_DAEMON_ROTATE_S";
const DAEMON_NO_CARRIER_EXIT_MS: &str = "SATMUX_DAEMON_NO_CARRIER_EXIT_MS";
const DAEMON_CARRIER_FLOWS: &str = "SATMUX_DAEMON_CARRIER_FLOWS";
const DAEMON_CARRIER_RENEW: &str = "SATMUX_DAEMON_CARRIER_RENEW";
const DAEMON_VERDICT_DAYS: &str = "SATMUX_DAEMON_VERDICT_DAYS";
const DAEMON_BIND_INTERFACE: &str = "SATMUX_DAEMON_BIND_INTERFACE";
const DAEMON_KEY: &str = "SATMUX_DAEMON_KEY";
const DAEMON_ROOTS: &str = "SATMUX_DAEMON_ROOTS";
const DAEMON_STATE: &str = "SATMUX_DAEMON_STATE";
const DAEMON_FIRST_PAYLOAD_MS: &str = "SATMUX_DAEMON_FIRST_PAYLOAD_MS";
const DAEMON_TUN_MTU: &str = "SATMUX_DAEMON_TUN_MTU";
const DAEMON_STATUS_SOCKET: &str = "SATMUX_DAEMON_STATUS_SOCKET";
pub const DAEMON_READY_FD: &str = "SATMUX_DAEMON_READY_FD";
pub const DAEMON_UTUN_FD: &str = "SATMUX_DAEMON_UTUN_FD";
const DAEMON_PROXY_LISTEN: &str = "SATMUX_DAEMON_PROXY_LISTEN";
const PROBE_BURST: &str = "SATMUX_PROBE_BURST";
const PROBE_SECONDS: &str = "SATMUX_PROBE_SECONDS";

/// The names only `satmuxd` reads. The probe is run from the same environment, so it lets
/// these four pass unread; every other name under the two prefixes is refused by both.
const DAEMON_ONLY: [&str; 4] = [DAEMON_STATUS_SOCKET, DAEMON_READY_FD, DAEMON_UTUN_FD, DAEMON_PROXY_LISTEN];

const SECONDS_PER_DAY: u64 = 86_400;

/// Why an environment is not a configuration. Every variant names the variable.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigRefused {
    #[error("{0} is required and not set")]
    Missing(&'static str),
    #[error("{0} is not a name this program reads")]
    Unknown(String),
    #[error("{name} is not {expected}")]
    Malformed { name: &'static str, expected: &'static str },
    #[error("SATMUX_DAEMON_UTUN_FD and SATMUX_DAEMON_PROXY_LISTEN are both set; exactly one front end is allowed")]
    BothFrontEnds,
    #[error("neither SATMUX_DAEMON_UTUN_FD nor SATMUX_DAEMON_PROXY_LISTEN is set; exactly one front end is required")]
    NoFrontEnd,
}

/// A block of IPv4 addresses, as policy wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub base: Ipv4Addr,
    pub prefix: u8,
}

/// What both programs read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Common {
    pub relay_name: HostName,
    pub streams: NonZeroU16,
    pub relay_open: Duration,
    pub relay_connect: Duration,
    pub measure_bytes: u64,
    pub ports: Vec<u16>,
    pub resolvers: Vec<IpAddr>,
    pub dns_address: Ipv4Addr,
    pub placeholders: Cidr,
    pub answer_ttl: Duration,
    pub placeholder_hold: Duration,
    pub echo_idle: Duration,
    pub suspect: Duration,
    pub rotate: Duration,
    pub no_carrier_exit: Duration,
    /// Most streams one carrier opens in its life: the relay platform's allowance for it.
    pub carrier_flows: usize,
    /// How many a carrier opens before its successor is dialed.
    pub carrier_renew: usize,
    pub verdict_life: Duration,
    pub bind_interface: String,
    pub key: PathBuf,
    pub roots: PathBuf,
    pub state: PathBuf,
    /// How long a new flow waits for the app's first bytes so they ride with the open.
    pub first_payload_wait: Duration,
    /// The tunnel interface's largest packet.
    pub tun_mtu: NonZeroU16,
}

/// How flows reach the daemon. Which variable is present picks the variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontEnd {
    Tunnel(RawFd),
    Proxy(SocketAddr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonConfig {
    pub common: Common,
    pub status_socket: PathBuf,
    pub ready_fd: RawFd,
    pub front_end: FrontEnd,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeConfig {
    pub common: Common,
    pub burst: NonZeroU16,
    pub run: Duration,
}

/// The variables under our prefixes, each taken exactly once by the parser; what is left over
/// is unknown.
struct Input(BTreeMap<String, String>);

impl Input {
    fn gather(vars: impl IntoIterator<Item = (String, String)>, prefixes: &[&str]) -> Self {
        Self(vars.into_iter().filter(|(name, _)| prefixes.iter().any(|p| name.starts_with(p))).collect())
    }

    fn take(&mut self, name: &'static str) -> Result<String, ConfigRefused> {
        self.0.remove(name).ok_or(ConfigRefused::Missing(name))
    }

    fn parsed<T>(&mut self, name: &'static str, expected: &'static str, parse: impl FnOnce(&str) -> Option<T>) -> Result<T, ConfigRefused> {
        let text = self.take(name)?;
        parse(&text).ok_or(ConfigRefused::Malformed { name, expected })
    }

    fn millis(&mut self, name: &'static str) -> Result<Duration, ConfigRefused> {
        self.parsed(name, "a whole number of milliseconds above zero", |t| Some(Duration::from_millis(nonzero(t)?.get())))
    }

    fn seconds(&mut self, name: &'static str) -> Result<Duration, ConfigRefused> {
        self.parsed(name, "a whole number of seconds above zero", |t| Some(Duration::from_secs(nonzero(t)?.get())))
    }

    fn path(&mut self, name: &'static str) -> Result<PathBuf, ConfigRefused> {
        self.parsed(name, "a path", |t| (!t.is_empty()).then(|| PathBuf::from(t)))
    }

    fn finish(self) -> Result<(), ConfigRefused> {
        match self.0.into_keys().next() {
            Some(name) => Err(ConfigRefused::Unknown(name)),
            None => Ok(()),
        }
    }
}

/// Decimal digits only, no sign, no leading zero: the one spelling of a number.
fn number(text: &str) -> Option<u64> {
    let canonical = text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

fn nonzero(text: &str) -> Option<NonZeroU64> {
    NonZeroU64::new(number(text)?)
}

fn nonzero_u16(text: &str) -> Option<NonZeroU16> {
    NonZeroU16::new(u16::try_from(number(text)?).ok()?)
}

fn descriptor(text: &str) -> Option<RawFd> {
    RawFd::try_from(number(text)?).ok()
}

fn list<T: PartialEq>(text: &str, parse: impl Fn(&str) -> Option<T>) -> Option<Vec<T>> {
    let mut items = Vec::new();
    for word in text.split(' ') {
        let item = parse(word)?;
        if items.contains(&item) {
            return None;
        }
        items.push(item);
    }
    Some(items)
}

fn cidr(text: &str) -> Option<Cidr> {
    let (base, prefix) = text.split_once('/')?;
    let prefix = u8::try_from(number(prefix)?).ok().filter(|p| u32::from(*p) <= Ipv4Addr::BITS)?;
    Some(Cidr { base: base.parse().ok()?, prefix })
}

fn common(input: &mut Input) -> Result<Common, ConfigRefused> {
    Ok(Common {
        relay_name: input.parsed(RELAY_NAME, "a lower-case host name", |t| HostName::parse(t).ok().filter(|n| n.as_str() == t))?,
        streams: input.parsed(RELAY_STREAMS, "a stream count from 1 to 65535", nonzero_u16)?,
        relay_open: input.millis(RELAY_OPEN_MS)?,
        relay_connect: input.millis(RELAY_CONNECT_MS)?,
        measure_bytes: input.parsed(RELAY_MEASURE_BYTES, "a byte count above zero", |t| Some(nonzero(t)?.get()))?,
        ports: input.parsed(DAEMON_PORTS, "distinct ports from 1 to 65535 separated by single spaces", |t| {
            list(t, |w| Some(nonzero_u16(w)?.get()))
        })?,
        resolvers: input.parsed(DAEMON_RESOLVERS, "distinct address literals separated by single spaces", |t| {
            list(t, |w| w.parse::<IpAddr>().ok().filter(|a| a.to_string() == w))
        })?,
        dns_address: input.parsed(DAEMON_DNS_ADDRESS, "an IPv4 address", |t| t.parse().ok())?,
        placeholders: input.parsed(DAEMON_PLACEHOLDERS, "an IPv4 block written address/prefix", cidr)?,
        answer_ttl: input.seconds(DAEMON_ANSWER_TTL_S)?,
        placeholder_hold: input.seconds(DAEMON_PLACEHOLDER_HOLD_S)?,
        echo_idle: input.millis(DAEMON_ECHO_IDLE_MS)?,
        suspect: input.millis(DAEMON_SUSPECT_MS)?,
        rotate: input.seconds(DAEMON_ROTATE_S)?,
        no_carrier_exit: input.millis(DAEMON_NO_CARRIER_EXIT_MS)?,
        carrier_flows: input.parsed(DAEMON_CARRIER_FLOWS, "a count above zero", |t| usize::try_from(nonzero(t)?.get()).ok())?,
        carrier_renew: input.parsed(DAEMON_CARRIER_RENEW, "a count above zero", |t| usize::try_from(nonzero(t)?.get()).ok())?,
        verdict_life: input.parsed(DAEMON_VERDICT_DAYS, "a whole number of days above zero", |t| {
            Some(Duration::from_secs(nonzero(t)?.get().checked_mul(SECONDS_PER_DAY)?))
        })?,
        bind_interface: input.parsed(DAEMON_BIND_INTERFACE, "an interface name", |t| {
            (!t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic())).then(|| t.to_owned())
        })?,
        key: input.path(DAEMON_KEY)?,
        roots: input.path(DAEMON_ROOTS)?,
        state: input.path(DAEMON_STATE)?,
        first_payload_wait: input.millis(DAEMON_FIRST_PAYLOAD_MS)?,
        tun_mtu: input.parsed(DAEMON_TUN_MTU, "a packet size from 1 to 65535", nonzero_u16)?,
    })
}

impl Common {
    fn render(&self, out: &mut BTreeMap<String, String>) {
        let mut put = |name: &str, value: String| {
            out.insert(name.to_owned(), value);
        };
        let words = |items: Vec<String>| items.join(" ");
        put(RELAY_NAME, self.relay_name.to_string());
        put(RELAY_STREAMS, self.streams.to_string());
        put(RELAY_OPEN_MS, self.relay_open.as_millis().to_string());
        put(RELAY_CONNECT_MS, self.relay_connect.as_millis().to_string());
        put(RELAY_MEASURE_BYTES, self.measure_bytes.to_string());
        put(DAEMON_PORTS, words(self.ports.iter().map(u16::to_string).collect()));
        put(DAEMON_RESOLVERS, words(self.resolvers.iter().map(IpAddr::to_string).collect()));
        put(DAEMON_DNS_ADDRESS, self.dns_address.to_string());
        put(DAEMON_PLACEHOLDERS, format!("{}/{}", self.placeholders.base, self.placeholders.prefix));
        put(DAEMON_ANSWER_TTL_S, self.answer_ttl.as_secs().to_string());
        put(DAEMON_PLACEHOLDER_HOLD_S, self.placeholder_hold.as_secs().to_string());
        put(DAEMON_ECHO_IDLE_MS, self.echo_idle.as_millis().to_string());
        put(DAEMON_SUSPECT_MS, self.suspect.as_millis().to_string());
        put(DAEMON_ROTATE_S, self.rotate.as_secs().to_string());
        put(DAEMON_NO_CARRIER_EXIT_MS, self.no_carrier_exit.as_millis().to_string());
        put(DAEMON_CARRIER_FLOWS, self.carrier_flows.to_string());
        put(DAEMON_CARRIER_RENEW, self.carrier_renew.to_string());
        put(DAEMON_VERDICT_DAYS, (self.verdict_life.as_secs() / SECONDS_PER_DAY).to_string());
        put(DAEMON_BIND_INTERFACE, self.bind_interface.clone());
        put(DAEMON_KEY, self.key.to_string_lossy().into_owned());
        put(DAEMON_ROOTS, self.roots.to_string_lossy().into_owned());
        put(DAEMON_STATE, self.state.to_string_lossy().into_owned());
        put(DAEMON_FIRST_PAYLOAD_MS, self.first_payload_wait.as_millis().to_string());
        put(DAEMON_TUN_MTU, self.tun_mtu.to_string());
    }
}

impl DaemonConfig {
    /// Parses the daemon's configuration out of an environment. Names outside the two prefixes
    /// are not ours and are not looked at.
    pub fn parse(vars: impl IntoIterator<Item = (String, String)>) -> Result<Self, ConfigRefused> {
        let mut input = Input::gather(vars, &[RELAY_PREFIX, DAEMON_PREFIX]);
        let common = common(&mut input)?;
        let status_socket = input.path(DAEMON_STATUS_SOCKET)?;
        let ready_fd = input.parsed(DAEMON_READY_FD, "a descriptor number", descriptor)?;
        let front_end = match (input.0.remove(DAEMON_UTUN_FD), input.0.remove(DAEMON_PROXY_LISTEN)) {
            (Some(_), Some(_)) => return Err(ConfigRefused::BothFrontEnds),
            (None, None) => return Err(ConfigRefused::NoFrontEnd),
            (Some(fd), None) => FrontEnd::Tunnel(
                descriptor(&fd).ok_or(ConfigRefused::Malformed { name: DAEMON_UTUN_FD, expected: "a descriptor number" })?,
            ),
            (None, Some(listen)) => FrontEnd::Proxy(
                listen
                    .parse::<SocketAddr>()
                    .ok()
                    .filter(|a| a.to_string() == listen)
                    .ok_or(ConfigRefused::Malformed { name: DAEMON_PROXY_LISTEN, expected: "address:port" })?,
            ),
        };
        input.finish()?;
        Ok(Self { common, status_socket, ready_fd, front_end })
    }

    /// The environment this configuration parses from.
    pub fn render(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        self.common.render(&mut out);
        out.insert(DAEMON_STATUS_SOCKET.to_owned(), self.status_socket.to_string_lossy().into_owned());
        out.insert(DAEMON_READY_FD.to_owned(), self.ready_fd.to_string());
        match self.front_end {
            FrontEnd::Tunnel(fd) => out.insert(DAEMON_UTUN_FD.to_owned(), fd.to_string()),
            FrontEnd::Proxy(addr) => out.insert(DAEMON_PROXY_LISTEN.to_owned(), addr.to_string()),
        };
        out
    }
}

impl ProbeConfig {
    /// Parses the probe's configuration. The four daemon-only names pass unread.
    pub fn parse(vars: impl IntoIterator<Item = (String, String)>) -> Result<Self, ConfigRefused> {
        let mut input = Input::gather(vars, &[RELAY_PREFIX, DAEMON_PREFIX, PROBE_PREFIX]);
        for name in DAEMON_ONLY {
            input.0.remove(name);
        }
        let common = common(&mut input)?;
        let burst = input.parsed(PROBE_BURST, "a count from 1 to 65535", nonzero_u16)?;
        let run = input.seconds(PROBE_SECONDS)?;
        input.finish()?;
        Ok(Self { common, burst, run })
    }

    pub fn render(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        self.common.render(&mut out);
        out.insert(PROBE_BURST.to_owned(), self.burst.to_string());
        out.insert(PROBE_SECONDS.to_owned(), self.run.as_secs().to_string());
        out
    }
}

/// The process environment, for the parsers. A variable that is not UTF-8 is passed with the
/// replacement character, which no field accepts.
pub fn process_environment() -> Vec<(String, String)> {
    std::env::vars_os().map(|(n, v)| (n.to_string_lossy().into_owned(), v.to_string_lossy().into_owned())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn count(max: u64) -> impl Strategy<Value = String> {
        (1..=max).prop_map(|n| n.to_string())
    }

    fn path() -> impl Strategy<Value = String> {
        "/[a-zA-Z0-9_./ -]{0,24}"
    }

    fn common_env() -> impl Strategy<Value = BTreeMap<String, String>> {
        let relay = (
            proptest::collection::vec("[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?", 1..4).prop_map(|l| l.join(".")),
            count(u64::from(u16::MAX)),
            count(1 << 40),
            count(1 << 40),
            count(1 << 50),
        );
        let lists = (
            proptest::collection::hash_set(1..=u16::MAX, 1..6),
            proptest::collection::hash_set(any::<IpAddr>(), 1..5),
            any::<Ipv4Addr>(),
            any::<Ipv4Addr>(),
            0..=32u8,
        );
        let timers = (count(1 << 30), count(1 << 30), count(1 << 40), count(1 << 40), count(1 << 30), count(1 << 40), count(1 << 20));
        let places = ("[a-z0-9]{1,12}", path(), path(), path(), count(1 << 30), count(u64::from(u16::MAX)), count(1 << 30), count(1 << 30));
        (relay, lists, timers, places).prop_map(|(relay, lists, timers, places)| {
            let join = |items: Vec<String>| items.join(" ");
            BTreeMap::from(
                [
                    (RELAY_NAME, relay.0),
                    (RELAY_STREAMS, relay.1),
                    (RELAY_OPEN_MS, relay.2),
                    (RELAY_CONNECT_MS, relay.3),
                    (RELAY_MEASURE_BYTES, relay.4),
                    (DAEMON_PORTS, join(lists.0.iter().map(u16::to_string).collect())),
                    (DAEMON_RESOLVERS, join(lists.1.iter().map(IpAddr::to_string).collect())),
                    (DAEMON_DNS_ADDRESS, lists.2.to_string()),
                    (DAEMON_PLACEHOLDERS, format!("{}/{}", lists.3, lists.4)),
                    (DAEMON_ANSWER_TTL_S, timers.0),
                    (DAEMON_PLACEHOLDER_HOLD_S, timers.1),
                    (DAEMON_ECHO_IDLE_MS, timers.2),
                    (DAEMON_SUSPECT_MS, timers.3),
                    (DAEMON_ROTATE_S, timers.4),
                    (DAEMON_NO_CARRIER_EXIT_MS, timers.5),
                    (DAEMON_VERDICT_DAYS, timers.6),
                    (DAEMON_BIND_INTERFACE, places.0),
                    (DAEMON_KEY, places.1),
                    (DAEMON_ROOTS, places.2),
                    (DAEMON_STATE, places.3),
                    (DAEMON_FIRST_PAYLOAD_MS, places.4),
                    (DAEMON_TUN_MTU, places.5),
                    (DAEMON_CARRIER_FLOWS, places.6),
                    (DAEMON_CARRIER_RENEW, places.7),
                ]
                .map(|(n, v)| (n.to_owned(), v)),
            )
        })
    }

    fn daemon_env() -> impl Strategy<Value = BTreeMap<String, String>> {
        let front = prop_oneof![
            (0..=i32::MAX).prop_map(|fd| (DAEMON_UTUN_FD, fd.to_string())),
            any::<SocketAddr>().prop_map(|a| (DAEMON_PROXY_LISTEN, SocketAddr::new(a.ip(), a.port()).to_string())),
        ];
        (common_env(), path(), 0..=i32::MAX, front).prop_map(|(mut env, socket, ready, front)| {
            env.insert(DAEMON_STATUS_SOCKET.to_owned(), socket);
            env.insert(DAEMON_READY_FD.to_owned(), ready.to_string());
            env.insert(front.0.to_owned(), front.1);
            env
        })
    }

    fn probe_env() -> impl Strategy<Value = BTreeMap<String, String>> {
        (common_env(), count(u64::from(u16::MAX)), count(1 << 30)).prop_map(|(mut env, burst, seconds)| {
            env.insert(PROBE_BURST.to_owned(), burst);
            env.insert(PROBE_SECONDS.to_owned(), seconds);
            env
        })
    }

    fn stranger(prefixes: &'static [&'static str]) -> impl Strategy<Value = String> {
        (proptest::sample::select(prefixes), "[A-Z_]{1,12}").prop_map(|(p, tail)| format!("{p}{tail}"))
    }

    proptest! {
        /// A valid environment parses, and the configuration renders back to exactly it.
        #[test]
        fn daemon_environment_round_trips(env in daemon_env(), noise in proptest::collection::btree_map("[A-Z]{1,6}", ".{0,8}", 0..4)) {
            let mut vars = env.clone();
            vars.extend(noise.into_iter().filter(|(n, _)| !n.starts_with("SATMUX_")));
            let config = DaemonConfig::parse(vars).expect("a generated environment is a configuration");
            prop_assert_eq!(config.render(), env);
        }

        #[test]
        fn probe_environment_round_trips(env in probe_env(), socket in path()) {
            let mut vars = env.clone();
            vars.insert(DAEMON_STATUS_SOCKET.to_owned(), socket);
            let config = ProbeConfig::parse(vars).expect("a generated environment is a configuration");
            prop_assert_eq!(config.render(), env);
        }

        /// Taking any one name away is refused, and the refusal names it (or, for the front
        /// end, says that none is left).
        #[test]
        fn a_missing_name_is_refused_by_name(env in daemon_env(), pick in any::<proptest::sample::Index>()) {
            let name = pick.get(&env.keys().cloned().collect::<Vec<_>>()).clone();
            let mut vars = env;
            vars.remove(&name);
            let refused = DaemonConfig::parse(vars).expect_err("a required name is gone");
            if name == DAEMON_UTUN_FD || name == DAEMON_PROXY_LISTEN {
                prop_assert_eq!(refused, ConfigRefused::NoFrontEnd);
            } else {
                prop_assert!(matches!(refused, ConfigRefused::Missing(missing) if missing == name));
            }
        }

        #[test]
        fn a_missing_probe_name_is_refused_by_name(env in probe_env(), pick in any::<proptest::sample::Index>()) {
            let name = pick.get(&env.keys().cloned().collect::<Vec<_>>()).clone();
            let mut vars = env;
            vars.remove(&name);
            let refused = ProbeConfig::parse(vars).expect_err("a required name is gone");
            prop_assert!(matches!(refused, ConfigRefused::Missing(missing) if missing == name));
        }

        /// Any other name under our prefixes is refused, and the refusal names it.
        #[test]
        fn an_unknown_name_is_refused_by_name(env in daemon_env(), name in stranger(&[RELAY_PREFIX, DAEMON_PREFIX]), value in ".{0,8}") {
            prop_assume!(!env.contains_key(&name) && name != DAEMON_UTUN_FD && name != DAEMON_PROXY_LISTEN);
            let mut vars = env;
            vars.insert(name.clone(), value);
            prop_assert_eq!(DaemonConfig::parse(vars), Err(ConfigRefused::Unknown(name)));
        }

        #[test]
        fn an_unknown_probe_name_is_refused_by_name(env in probe_env(), name in stranger(&[RELAY_PREFIX, DAEMON_PREFIX, PROBE_PREFIX]), value in ".{0,8}") {
            prop_assume!(!env.contains_key(&name) && !DAEMON_ONLY.contains(&name.as_str()));
            let mut vars = env;
            vars.insert(name.clone(), value);
            prop_assert_eq!(ProbeConfig::parse(vars), Err(ConfigRefused::Unknown(name)));
        }

        /// Both front ends at once is its own refusal.
        #[test]
        fn both_front_ends_are_refused(env in daemon_env(), fd in 0..=i32::MAX, addr in any::<SocketAddr>()) {
            let mut vars = env;
            vars.insert(DAEMON_UTUN_FD.to_owned(), fd.to_string());
            vars.insert(DAEMON_PROXY_LISTEN.to_owned(), addr.to_string());
            prop_assert_eq!(DaemonConfig::parse(vars), Err(ConfigRefused::BothFrontEnds));
        }
    }
}
