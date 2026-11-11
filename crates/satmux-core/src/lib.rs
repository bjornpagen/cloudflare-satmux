//! The only wire format that is satmux's own: the stream-open a client writes at the start of
//! every yamux stream, the one status byte the relay answers with, and the device-key check.
//! No I/O and no clock: both ends link this crate, so they cannot disagree about a byte.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The one accepted wire version. A new format is a cutover of both ends, never a negotiation.
pub const WIRE_VERSION: u8 = 1;
/// The path a carrier's WebSocket upgrade asks for.
pub const CARRIER_PATH: &str = "/c";
/// The path that answers the relay's build identifier to a holder of a key.
pub const VERSION_PATH: &str = "/v";
/// The longest name DNS allows on the wire in presentation form.
pub const NAME_MAX: usize = 253;
/// The largest DNS message a `dns` stream carries in either direction.
pub const DNS_MAX: usize = 4096;
/// The size of one echo nonce.
pub const ECHO_NONCE: usize = 8;

/// A host name that has already been checked: 1 to 253 bytes of lower-case letters, digits,
/// hyphen and dot, no empty label, no label over 63 bytes, no leading or trailing hyphen in a
/// label. Only [`HostName::parse`] makes one, so nothing downstream checks a name again.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

impl HostName {
    /// Lower-cases ASCII, drops one trailing dot, then admits or refuses the name.
    pub fn parse(text: &str) -> Result<Self, Malformed> {
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        let lowered = trimmed.to_ascii_lowercase();
        if lowered.is_empty() || lowered.len() > NAME_MAX {
            return Err(Malformed::Name);
        }
        for label in lowered.split('.') {
            let bytes = label.as_bytes();
            let shaped = !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first() != Some(&b'-')
                && bytes.last() != Some(&b'-')
                && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_');
            if !shaped {
                return Err(Malformed::Name);
            }
        }
        Ok(Self(lowered))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for HostName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a flow is going. Built once, from an open or from a front end.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Dest {
    Name(HostName, u16),
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

impl core::fmt::Display for Dest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Dest::Name(name, port) => write!(f, "{name}:{port}"),
            Dest::V4(a, port) => write!(f, "{}:{port}", std::net::Ipv4Addr::from(*a)),
            Dest::V6(a, port) => write!(f, "[{}]:{port}", std::net::Ipv6Addr::from(*a)),
        }
    }
}

/// What a yamux stream is for. One byte on the wire selects one of these shapes, and each
/// carries exactly its own fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Open {
    /// Connect onward; the stream then carries the flow's bytes both ways.
    Connect(Dest),
    /// One DNS query in wire format; the relay answers with two length bytes and the answer.
    Dns(Vec<u8>),
    /// The client sends 8-byte nonces; the relay returns each.
    Echo,
    /// The relay sends this many bytes, then closes.
    Source(u64),
    /// The relay discards what arrives and, at end of stream, writes the count as 8 bytes.
    Sink,
}

const KIND_NAME: u8 = 1;
const KIND_V4: u8 = 2;
const KIND_V6: u8 = 3;
const KIND_DNS: u8 = 4;
const KIND_ECHO: u8 = 5;
const KIND_SOURCE: u8 = 6;
const KIND_SINK: u8 = 7;

/// Why bytes are not an open. The relay answers every one with [`Status::Malformed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    #[error("wire version is not {WIRE_VERSION}")]
    Version,
    #[error("unknown kind")]
    Kind,
    #[error("name is not a host name")]
    Name,
    #[error("dns query is empty or over {DNS_MAX} bytes")]
    Dns,
}

/// The result of looking at the bytes received so far on a new stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// Not enough bytes yet; read more and ask again with the whole prefix.
    Incomplete,
    /// An open, and how many bytes it took. Everything after belongs to the flow.
    Open(Open, usize),
    Malformed(Malformed),
}

impl Open {
    /// Appends the open's bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(WIRE_VERSION);
        match self {
            Open::Connect(Dest::Name(name, port)) => {
                out.push(KIND_NAME);
                out.extend_from_slice(&port.to_be_bytes());
                out.push(name.as_str().len() as u8);
                out.extend_from_slice(name.as_str().as_bytes());
            }
            Open::Connect(Dest::V4(addr, port)) => {
                out.push(KIND_V4);
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(addr);
            }
            Open::Connect(Dest::V6(addr, port)) => {
                out.push(KIND_V6);
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(addr);
            }
            Open::Dns(query) => {
                out.push(KIND_DNS);
                out.extend_from_slice(&(query.len() as u16).to_be_bytes());
                out.extend_from_slice(query);
            }
            Open::Echo => out.push(KIND_ECHO),
            Open::Source(bytes) => {
                out.push(KIND_SOURCE);
                out.extend_from_slice(&bytes.to_be_bytes());
            }
            Open::Sink => out.push(KIND_SINK),
        }
    }

    /// Reads an open from the front of `buf`.
    pub fn decode(buf: &[u8]) -> Decoded {
        let Some((&version, rest)) = buf.split_first() else { return Decoded::Incomplete };
        if version != WIRE_VERSION {
            return Decoded::Malformed(Malformed::Version);
        }
        let Some((&kind, body)) = rest.split_first() else { return Decoded::Incomplete };
        let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
        match kind {
            KIND_NAME => {
                if body.len() < 3 {
                    return Decoded::Incomplete;
                }
                let len = body[2] as usize;
                if body.len() < 3 + len {
                    return Decoded::Incomplete;
                }
                let Ok(text) = core::str::from_utf8(&body[3..3 + len]) else {
                    return Decoded::Malformed(Malformed::Name);
                };
                // The wire carries the canonical form only: what parse returns must be what came.
                match HostName::parse(text) {
                    Ok(name) if name.as_str() == text => {
                        Decoded::Open(Open::Connect(Dest::Name(name, port(body))), 2 + 3 + len)
                    }
                    _ => Decoded::Malformed(Malformed::Name),
                }
            }
            KIND_V4 => {
                if body.len() < 6 {
                    return Decoded::Incomplete;
                }
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&body[2..6]);
                Decoded::Open(Open::Connect(Dest::V4(addr, port(body))), 2 + 6)
            }
            KIND_V6 => {
                if body.len() < 18 {
                    return Decoded::Incomplete;
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&body[2..18]);
                Decoded::Open(Open::Connect(Dest::V6(addr, port(body))), 2 + 18)
            }
            KIND_DNS => {
                if body.len() < 2 {
                    return Decoded::Incomplete;
                }
                let len = u16::from_be_bytes([body[0], body[1]]) as usize;
                if len == 0 || len > DNS_MAX {
                    return Decoded::Malformed(Malformed::Dns);
                }
                if body.len() < 2 + len {
                    return Decoded::Incomplete;
                }
                Decoded::Open(Open::Dns(body[2..2 + len].to_vec()), 2 + 2 + len)
            }
            KIND_ECHO => Decoded::Open(Open::Echo, 2),
            KIND_SOURCE => {
                if body.len() < 8 {
                    return Decoded::Incomplete;
                }
                let mut n = [0u8; 8];
                n.copy_from_slice(&body[..8]);
                Decoded::Open(Open::Source(u64::from_be_bytes(n)), 2 + 8)
            }
            KIND_SINK => Decoded::Open(Open::Sink, 2),
            _ => Decoded::Malformed(Malformed::Kind),
        }
    }
}

/// The first byte the relay writes on every stream. Each value changes what the client does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Status {
    Connected = 0,
    /// The platform refuses this destination (a Cloudflare address, or a private one).
    Forbidden = 1,
    NoSuchName = 2,
    Unreachable = 3,
    TimedOut = 4,
    Limit = 5,
    Malformed = 6,
    /// This carrier can open nothing more: the relay's platform gives one carrier a fixed
    /// number of onward connections and they are used. Nothing was sent onward, so the same
    /// open is good on another carrier.
    Spent = 7,
}

impl Status {
    pub const ALL: [Status; 8] = [
        Status::Connected,
        Status::Forbidden,
        Status::NoSuchName,
        Status::Unreachable,
        Status::TimedOut,
        Status::Limit,
        Status::Malformed,
        Status::Spent,
    ];

    pub fn from_byte(byte: u8) -> Option<Self> {
        Self::ALL.get(byte as usize).copied()
    }

    pub fn byte(self) -> u8 {
        self as u8
    }
}

/// The SHA-256 digest of a presented device key, as the bytes the key ring holds.
pub fn key_digest(key: &[u8]) -> [u8; 32] {
    Sha256::digest(key).into()
}

/// The devices a relay admits: a name and the digest of that device's key. Digests of 32
/// random bytes are public data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRing(Vec<(String, [u8; 32])>);

/// A key-ring line that is not `name digest` with a 64-digit lower-case hex digest.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("key line {line} is not `name sha256-hex`")]
pub struct KeyLineRefused {
    pub line: usize,
}

impl KeyRing {
    /// Parses lines of `name digest`. Blank lines are skipped. An empty ring admits nobody.
    pub fn parse(text: &str) -> Result<Self, KeyLineRefused> {
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let refused = KeyLineRefused { line: index + 1 };
            let mut words = line.split_ascii_whitespace();
            let Some(name) = words.next() else { continue };
            let (Some(hex), None) = (words.next(), words.next()) else { return Err(refused) };
            if hex.len() != 64 {
                return Err(refused);
            }
            let mut digest = [0u8; 32];
            for (slot, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
                let nibble = |c: u8| match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    _ => None,
                };
                let (Some(high), Some(low)) = (nibble(pair[0]), nibble(pair[1])) else { return Err(refused) };
                *slot = high << 4 | low;
            }
            entries.push((name.to_owned(), digest));
        }
        Ok(Self(entries))
    }

    /// The device a presented key belongs to. Every digest is compared, in constant time, with
    /// no early exit.
    pub fn admits(&self, presented: &[u8]) -> Option<&str> {
        let digest = key_digest(presented);
        let mut found = None;
        for (name, held) in &self.0 {
            if bool::from(held.ct_eq(&digest)) {
                found = Some(name.as_str());
            }
        }
        found
    }
}

/// Lower-case hex of a digest, the form a key-ring line holds.
pub fn digest_hex(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        out.push(char::from(b"0123456789abcdef"[(byte & 15) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn host() -> impl Strategy<Value = HostName> {
        proptest::collection::vec("[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", 1..5)
            .prop_map(|labels| HostName::parse(&labels.join(".")).expect("generated names are host names"))
    }

    fn open() -> impl Strategy<Value = Open> {
        prop_oneof![
            (host(), any::<u16>()).prop_map(|(h, p)| Open::Connect(Dest::Name(h, p))),
            (any::<[u8; 4]>(), any::<u16>()).prop_map(|(a, p)| Open::Connect(Dest::V4(a, p))),
            (any::<[u8; 16]>(), any::<u16>()).prop_map(|(a, p)| Open::Connect(Dest::V6(a, p))),
            proptest::collection::vec(any::<u8>(), 1..600).prop_map(Open::Dns),
            Just(Open::Echo),
            any::<u64>().prop_map(Open::Source),
            Just(Open::Sink),
        ]
    }

    proptest! {
        /// Every open decodes to itself, takes exactly its own bytes, and is incomplete at
        /// every shorter prefix: the payload that follows can never be mistaken for the open.
        #[test]
        fn open_round_trips_and_every_prefix_is_incomplete(open in open(), tail in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut wire = Vec::new();
            open.encode(&mut wire);
            let len = wire.len();
            for cut in 0..len {
                prop_assert_eq!(Open::decode(&wire[..cut]), Decoded::Incomplete);
            }
            wire.extend_from_slice(&tail);
            prop_assert_eq!(Open::decode(&wire), Decoded::Open(open, len));
        }

        /// Arbitrary bytes never panic the decoder, and whatever it accepts re-encodes to the
        /// bytes it consumed: there is one spelling of every open.
        #[test]
        fn decode_is_total_and_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Decoded::Open(open, used) = Open::decode(&bytes) {
                let mut again = Vec::new();
                open.encode(&mut again);
                prop_assert_eq!(&again[..], &bytes[..used]);
            }
        }

        /// A ring admits exactly the keys whose digests it holds, under the name on that line.
        #[test]
        fn ring_admits_its_own_keys_only(keys in proptest::collection::hash_set(any::<[u8; 32]>(), 1..6), stranger in any::<[u8; 32]>()) {
            let keys: Vec<_> = keys.into_iter().collect();
            let text: String = keys.iter().enumerate().map(|(i, k)| format!("dev{i} {}\n", digest_hex(&key_digest(k)))).collect();
            let ring = KeyRing::parse(&text).expect("generated lines are key lines");
            for (i, k) in keys.iter().enumerate() {
                let expected = format!("dev{i}");
                prop_assert_eq!(ring.admits(k), Some(expected.as_str()));
            }
            prop_assume!(!keys.contains(&stranger));
            prop_assert_eq!(ring.admits(&stranger), None);
        }

        #[test]
        fn status_bytes_round_trip(byte in any::<u8>()) {
            match Status::from_byte(byte) {
                Some(status) => prop_assert_eq!(status.byte(), byte),
                None => prop_assert!(byte as usize >= Status::ALL.len()),
            }
        }
    }
}
