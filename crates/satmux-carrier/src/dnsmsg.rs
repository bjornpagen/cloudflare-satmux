//! The two DNS messages this side ever writes or reads itself: a question for a name's `A`
//! records, and the addresses in an answer. Total over arbitrary bytes.

use std::net::Ipv4Addr;

use satmux_core::HostName;

const HEADER: usize = 12;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const RCODE_MASK: u16 = 0x000f;
const POINTER: u8 = 0xc0;
const A_LENGTH: usize = 4;

/// Why bytes are not a usable answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnswerRefused {
    #[error("the message ends before its own counts say it should")]
    Short,
    #[error("the message is a question, not an answer")]
    NotAnAnswer,
    #[error("the resolver answered with response code {0}")]
    Code(u8),
}

fn put_name(name: &HostName, out: &mut Vec<u8>) {
    for label in name.as_str().split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// The question "what are this name's A records", with identifier zero as DNS over HTTPS asks.
pub fn a_query(name: &HostName) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&FLAG_RECURSION_DESIRED.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    put_name(name, &mut out);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// An answer to [`a_query`] carrying these addresses. The relays' tests and ours share it.
pub fn a_answer(name: &HostName, ttl: u32, addresses: &[Ipv4Addr]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(FLAG_RESPONSE | FLAG_RECURSION_DESIRED).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    put_name(name, &mut out);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    for address in addresses {
        out.extend_from_slice(&[POINTER, HEADER as u8]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(A_LENGTH as u16).to_be_bytes());
        out.extend_from_slice(&address.octets());
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AnswerRefused> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(AnswerRefused::Short)?;
        self.0 = tail;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, AnswerRefused> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Steps over a name where it stands: labels up to the root, or up to a pointer, which
    /// ends the name here whatever it points at.
    fn skip_name(&mut self) -> Result<(), AnswerRefused> {
        loop {
            let length = self.take(1)?[0];
            if length & POINTER == POINTER {
                self.take(1)?;
                return Ok(());
            }
            if length == 0 {
                return Ok(());
            }
            self.take(usize::from(length))?;
        }
    }
}

/// The `A` addresses in the answer section, in order. A name with none is an empty list.
pub fn a_addresses(message: &[u8]) -> Result<Vec<Ipv4Addr>, AnswerRefused> {
    let mut reader = Reader(message);
    let _id = reader.u16()?;
    let flags = reader.u16()?;
    let questions = reader.u16()?;
    let answers = reader.u16()?;
    reader.take(4)?;
    if flags & FLAG_RESPONSE == 0 {
        return Err(AnswerRefused::NotAnAnswer);
    }
    if flags & RCODE_MASK != 0 {
        return Err(AnswerRefused::Code((flags & RCODE_MASK) as u8));
    }
    for _ in 0..questions {
        reader.skip_name()?;
        reader.take(4)?;
    }
    let mut found = Vec::new();
    for _ in 0..answers {
        reader.skip_name()?;
        let kind = reader.u16()?;
        let class = reader.u16()?;
        reader.take(4)?;
        let length = reader.u16()?;
        let data = reader.take(usize::from(length))?;
        if let (TYPE_A, CLASS_IN, Ok(octets)) = (kind, class, <[u8; A_LENGTH]>::try_from(data)) {
            found.push(Ipv4Addr::from(octets));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn host() -> impl Strategy<Value = HostName> {
        proptest::collection::vec("[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", 1..5)
            .prop_map(|labels| HostName::parse(&labels.join(".")).expect("generated names are host names"))
    }

    proptest! {
        /// Whatever addresses an answer was built from are the addresses read out of it.
        #[test]
        fn answers_round_trip(name in host(), ttl in any::<u32>(), addresses in proptest::collection::vec(any::<Ipv4Addr>(), 0..12)) {
            prop_assert_eq!(a_addresses(&a_answer(&name, ttl, &addresses)), Ok(addresses));
        }

        /// Every strict prefix of an answer is short, never a different answer.
        #[test]
        fn a_cut_answer_is_short(name in host(), addresses in proptest::collection::vec(any::<Ipv4Addr>(), 1..6), cut in any::<proptest::sample::Index>()) {
            let wire = a_answer(&name, 0, &addresses);
            let cut = cut.index(wire.len());
            prop_assert_eq!(a_addresses(&wire[..cut]), Err(AnswerRefused::Short));
        }

        /// A question is never read as an answer.
        #[test]
        fn a_query_is_not_an_answer(name in host()) {
            prop_assert_eq!(a_addresses(&a_query(&name)), Err(AnswerRefused::NotAnAnswer));
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = a_addresses(&bytes);
        }
    }
}
