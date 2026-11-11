//! The tunnel resolver's wire codec and its table from query to action. Total over any bytes:
//! every datagram is a query with one question, a refusal that echoes its ID, or nothing.

use std::net::Ipv4Addr;

use satmux_core::HostName;

use crate::pool::Block;

/// Bytes of a DNS header.
const HEADER: usize = 12;
/// The longest encoded name.
const NAME_WIRE_MAX: usize = 255;
/// The Internet class.
const CLASS_IN: u16 = 1;
/// Record types the table names.
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;
const TYPE_SVCB: u16 = 64;
const TYPE_HTTPS: u16 = 65;
/// Header bits.
const FLAG_RESPONSE: u8 = 0x80;
const OPCODE_MASK: u8 = 0x78;
const FLAG_RECURSION_DESIRED: u8 = 0x01;
const FLAG_RECURSION_AVAILABLE: u8 = 0x80;
/// A compression pointer to the question's name, which always starts right after the header.
const QUESTION_NAME: [u8; 2] = [0xC0, HEADER as u8];
/// The labels a reverse lookup of an IPv4 address ends with.
const REVERSE_ZONE: [&str; 2] = ["in-addr", "arpa"];

/// What was asked, as far as the table distinguishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// The IPv4 address of a name a flow can be opened to.
    A(HostName),
    /// An IPv6 address.
    Aaaa,
    /// An HTTPS service binding.
    Https,
    /// A general service binding.
    Svcb,
    /// The name of an IPv4 address.
    Ptr(Ipv4Addr),
    /// Anything else.
    Other,
}

/// What the resolver does about a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Answer with the name's placeholder address.
    Placeholder(HostName),
    /// Answer with no records and no error.
    Empty,
    /// Answer with the name the placeholder stands for.
    NameOf(Ipv4Addr),
    /// Send the query to the uplink's resolver and relay its answer.
    Forward,
}

/// The table (SPEC 6.4.1). Adding a query type is adding a row.
pub fn action(query: Query, placeholders: Block) -> Action {
    match query {
        Query::A(name) => Action::Placeholder(name),
        Query::Aaaa | Query::Https | Query::Svcb => Action::Empty,
        Query::Ptr(address) if placeholders.contains(address) => Action::NameOf(address),
        Query::Ptr(_) | Query::Other => Action::Forward,
    }
}

/// A response code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
}

/// The parts of a query's header an answer repeats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    id: [u8; 2],
    recursion_desired: bool,
}

/// One datagram, read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming<'a> {
    /// A standard query with exactly one question; `question` is its bytes, to be echoed.
    Asked { head: Head, question: &'a [u8], query: Query },
    /// Has a header but is not something this resolver answers; the code says why.
    Refused { head: Head, rcode: Rcode },
    /// Not a query at all. Nothing is sent back.
    Ignored,
}

/// Reads one datagram.
pub fn read(datagram: &[u8]) -> Incoming<'_> {
    let Some((header, body)) = datagram.split_first_chunk::<HEADER>() else {
        return Incoming::Ignored;
    };
    if header[2] & FLAG_RESPONSE != 0 {
        return Incoming::Ignored;
    }
    let head = Head { id: [header[0], header[1]], recursion_desired: header[2] & FLAG_RECURSION_DESIRED != 0 };
    if header[2] & OPCODE_MASK != 0 {
        return Incoming::Refused { head, rcode: Rcode::NotImp };
    }
    if [header[4], header[5]] != [0, 1] {
        return Incoming::Refused { head, rcode: Rcode::FormErr };
    }
    let Some((labels, rest)) = labels(body) else {
        return Incoming::Refused { head, rcode: Rcode::FormErr };
    };
    let Some((fixed, _)) = rest.split_first_chunk::<4>() else {
        return Incoming::Refused { head, rcode: Rcode::FormErr };
    };
    let question = &body[..body.len() - rest.len() + fixed.len()];
    let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
    let class = u16::from_be_bytes([fixed[2], fixed[3]]);
    let query = if class == CLASS_IN { classify(record_type, &labels) } else { Query::Other };
    Incoming::Asked { head, question, query }
}

/// The labels of an uncompressed name at the start of `bytes`, and what follows it.
fn labels(bytes: &[u8]) -> Option<(Vec<&[u8]>, &[u8])> {
    let mut labels = Vec::new();
    let mut rest = bytes;
    loop {
        let (length, after) = rest.split_first()?;
        let length = usize::from(*length);
        if length == 0 {
            return Some((labels, after));
        }
        if length > 63 || bytes.len() - after.len() + length >= NAME_WIRE_MAX {
            return None;
        }
        let (label, after) = after.split_at_checked(length)?;
        labels.push(label);
        rest = after;
    }
}

fn classify(record_type: u16, labels: &[&[u8]]) -> Query {
    match record_type {
        TYPE_A => host(labels).map_or(Query::Other, Query::A),
        TYPE_AAAA => Query::Aaaa,
        TYPE_HTTPS => Query::Https,
        TYPE_SVCB => Query::Svcb,
        TYPE_PTR => reversed(labels).map_or(Query::Other, Query::Ptr),
        _ => Query::Other,
    }
}

/// The labels as a host name, when they spell one.
fn host(labels: &[&[u8]]) -> Option<HostName> {
    let mut text = String::new();
    for label in labels {
        if !text.is_empty() {
            text.push('.');
        }
        let label = std::str::from_utf8(label).ok()?;
        if label.contains('.') {
            return None;
        }
        text.push_str(label);
    }
    HostName::parse(&text).ok()
}

/// The address a `d.c.b.a.in-addr.arpa` name asks about.
fn reversed(labels: &[&[u8]]) -> Option<Ipv4Addr> {
    let [d, c, b, a, zone @ ..] = labels else {
        return None;
    };
    let in_zone = zone.len() == REVERSE_ZONE.len()
        && zone.iter().zip(REVERSE_ZONE).all(|(label, expected)| label.eq_ignore_ascii_case(expected.as_bytes()));
    if !in_zone {
        return None;
    }
    let octet = |label: &[u8]| -> Option<u8> {
        let canonical = !label.is_empty() && label.iter().all(u8::is_ascii_digit) && (label.len() == 1 || label[0] != b'0');
        if !canonical {
            return None;
        }
        std::str::from_utf8(label).ok()?.parse().ok()
    };
    Some(Ipv4Addr::new(octet(a)?, octet(b)?, octet(c)?, octet(d)?))
}

/// The record data an answer carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// No records.
    Nothing,
    /// One `A` record.
    Address { address: Ipv4Addr, ttl: u32 },
    /// One `PTR` record.
    Name { name: &'a HostName, ttl: u32 },
}

fn header(head: Head, rcode: Rcode, questions: u16, answers: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER);
    out.extend_from_slice(&head.id);
    out.push(FLAG_RESPONSE | (u8::from(head.recursion_desired) * FLAG_RECURSION_DESIRED));
    out.push(FLAG_RECURSION_AVAILABLE | rcode as u8);
    out.extend_from_slice(&questions.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out
}

/// A reply that echoes `question` and carries `answer`.
pub fn reply(head: Head, question: &[u8], rcode: Rcode, answer: Answer<'_>) -> Vec<u8> {
    let (record_type, ttl, data) = match answer {
        Answer::Nothing => {
            let mut out = header(head, rcode, 1, 0);
            out.extend_from_slice(question);
            return out;
        }
        Answer::Address { address, ttl } => (TYPE_A, ttl, address.octets().to_vec()),
        Answer::Name { name, ttl } => {
            let mut data = Vec::with_capacity(name.as_str().len() + 2);
            for label in name.as_str().split('.') {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
            data.push(0);
            (TYPE_PTR, ttl, data)
        }
    };
    let mut out = header(head, rcode, 1, 1);
    out.extend_from_slice(question);
    out.extend_from_slice(&QUESTION_NAME);
    out.extend_from_slice(&record_type.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&data);
    out
}

/// A reply with no question, for a datagram whose question could not be read.
pub fn refusal(head: Head, rcode: Rcode) -> Vec<u8> {
    header(head, rcode, 0, 0)
}

/// What goes back for a forwarded query: the uplink's answer under the asker's ID, or a server
/// failure when the uplink gave none.
pub fn relayed(head: Head, question: &[u8], answer: std::io::Result<Vec<u8>>) -> Vec<u8> {
    match answer {
        Ok(mut answer) if answer.len() >= HEADER => {
            answer[..2].copy_from_slice(&head.id);
            answer
        }
        Ok(_) | Err(_) => reply(head, question, Rcode::ServFail, Answer::Nothing),
    }
}

/// A reply too long for one packet, cut down to its header and marked truncated.
pub fn truncated(reply: &[u8]) -> Option<Vec<u8>> {
    const FLAG_TRUNCATED: u8 = 0x02;
    let (header, _) = reply.split_first_chunk::<HEADER>()?;
    let mut out = header.to_vec();
    out[2] |= FLAG_TRUNCATED;
    out[4..].fill(0);
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A well-formed query, built without the codec under test.
    pub(crate) fn encode(id: u16, recursion_desired: bool, labels: &[Vec<u8>], record_type: u16, class: u16, tail: &[u8]) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.push(u8::from(recursion_desired));
        out.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out.extend_from_slice(&record_type.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(tail);
        out
    }

    fn host_label() -> impl Strategy<Value = Vec<u8>> {
        "[a-zA-Z0-9]([a-zA-Z0-9-]{0,10}[a-zA-Z0-9])?".prop_map(String::into_bytes)
    }

    /// Names: host names, reverse names inside and outside any block, and arbitrary labels.
    fn name() -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop_oneof![
            proptest::collection::vec(host_label(), 1..5),
            (any::<[u8; 4]>(), prop_oneof![Just("in-addr"), Just("IN-ADDR"), Just("ip6")], "(arpa|ARPA|example)").prop_map(
                |(octets, zone, top)| {
                    let mut labels: Vec<Vec<u8>> = octets.iter().rev().map(|octet| octet.to_string().into_bytes()).collect();
                    labels.push(zone.as_bytes().to_vec());
                    labels.push(top.into_bytes());
                    labels
                }
            ),
            proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..20), 0..5),
        ]
    }

    fn record_type() -> impl Strategy<Value = u16> {
        prop_oneof![Just(TYPE_A), Just(TYPE_AAAA), Just(TYPE_HTTPS), Just(TYPE_SVCB), Just(TYPE_PTR), any::<u16>()]
    }

    fn block() -> impl Strategy<Value = Block> {
        (0u8..=32, any::<u32>()).prop_map(|(prefix, anywhere)| {
            let size = 1u64 << (32 - u32::from(prefix));
            Block::new(Ipv4Addr::from((u64::from(anywhere) / size * size) as u32), prefix).expect("aligned")
        })
    }

    /// The table of SPEC 6.4.1, restated over the generator's own inputs.
    fn expected(labels: &[Vec<u8>], record_type: u16, class: u16, block: Block) -> Action {
        let text = labels.iter().map(|label| String::from_utf8_lossy(label).into_owned()).collect::<Vec<_>>().join(".");
        let hostlike = labels.iter().all(|label| label.iter().all(|byte| byte.is_ascii() && *byte != b'.'));
        if class != CLASS_IN {
            return Action::Forward;
        }
        match record_type {
            TYPE_A => match HostName::parse(&text) {
                Ok(name) if hostlike => Action::Placeholder(name),
                _ => Action::Forward,
            },
            TYPE_AAAA | TYPE_HTTPS | TYPE_SVCB => Action::Empty,
            TYPE_PTR => match text.to_ascii_lowercase().strip_suffix(".in-addr.arpa").map(str::parse::<Ipv4Addr>) {
                Some(Ok(address)) if labels.len() == 6 => {
                    let address = Ipv4Addr::from(u32::from(address).swap_bytes());
                    if block.contains(address) { Action::NameOf(address) } else { Action::Forward }
                }
                _ => Action::Forward,
            },
            _ => Action::Forward,
        }
    }

    proptest! {
        #[test]
        fn every_well_formed_query_gets_its_row(
            id in any::<u16>(),
            recursion_desired in any::<bool>(),
            labels in name(),
            record_type in record_type(),
            class in prop_oneof![4 => Just(CLASS_IN), 1 => any::<u16>()],
            tail in proptest::collection::vec(any::<u8>(), 0..24),
            block in block(),
        ) {
            let datagram = encode(id, recursion_desired, &labels, record_type, class, &tail);
            let Incoming::Asked { head, question, query } = read(&datagram) else {
                return Err(TestCaseError::fail("a well-formed query was not read as one"));
            };
            prop_assert_eq!(head.id, id.to_be_bytes());
            prop_assert_eq!(question, &datagram[HEADER..datagram.len() - tail.len()]);
            prop_assert_eq!(action(query, block), expected(&labels, record_type, class, block));
        }

        #[test]
        fn any_bytes_are_ignored_or_answered_with_their_id(datagram in proptest::collection::vec(any::<u8>(), 0..300)) {
            let answer = match read(&datagram) {
                Incoming::Ignored => None,
                Incoming::Refused { head, rcode } => Some(refusal(head, rcode)),
                Incoming::Asked { head, question, .. } => Some(reply(head, question, Rcode::NoError, Answer::Nothing)),
            };
            if let Some(answer) = answer {
                prop_assert_eq!(&answer[..2], &datagram[..2]);
                prop_assert!(answer[2] & FLAG_RESPONSE != 0);
                prop_assert_eq!(read(&answer), Incoming::Ignored);
            } else {
                prop_assert!(datagram.len() < HEADER || datagram[2] & FLAG_RESPONSE != 0);
            }
        }

        #[test]
        fn an_answer_echoes_the_question_and_carries_its_record(
            id in any::<u16>(),
            labels in proptest::collection::vec(host_label(), 1..5),
            address in any::<u32>(),
            ttl in any::<u32>(),
        ) {
            let datagram = encode(id, true, &labels, TYPE_A, CLASS_IN, &[]);
            let Incoming::Asked { head, question, query: Query::A(name) } = read(&datagram) else {
                return Err(TestCaseError::fail("not an address query"));
            };
            let address = Ipv4Addr::from(address);
            let answer = reply(head, question, Rcode::NoError, Answer::Address { address, ttl });
            prop_assert_eq!(&answer[..2], &id.to_be_bytes());
            prop_assert_eq!(&answer[4..8], &[0, 1, 0, 1]);
            prop_assert_eq!(&answer[HEADER..HEADER + question.len()], question);
            let record = &answer[HEADER + question.len()..];
            let mut wanted = QUESTION_NAME.to_vec();
            wanted.extend_from_slice(&[0, 1, 0, 1]);
            wanted.extend_from_slice(&ttl.to_be_bytes());
            wanted.extend_from_slice(&[0, 4]);
            wanted.extend_from_slice(&address.octets());
            prop_assert_eq!(record, &wanted[..]);

            let named = reply(head, question, Rcode::NoError, Answer::Name { name: &name, ttl });
            let data = &named[HEADER + question.len() + 12..];
            let (spelled, rest) = super::labels(data).expect("a name");
            prop_assert!(rest.is_empty());
            prop_assert_eq!(host(&spelled), Some(name));
        }
    }
}
