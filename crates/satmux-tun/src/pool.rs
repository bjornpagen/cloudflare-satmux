//! The placeholder pool: which name each address of the block stands for. A pure data structure;
//! time is a value the caller passes in (whole seconds since the Unix epoch, so it survives a
//! restart). [`crate::store`] keeps it on disk.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::time::Duration;

use satmux_core::HostName;

/// A CIDR block as a half-open range of addresses: `base .. base + size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    base: u32,
    prefix: u8,
}

impl Block {
    /// Admits `address/prefix` when the prefix is at most 32 and no host bit is set.
    pub fn new(address: Ipv4Addr, prefix: u8) -> Option<Self> {
        let base = u32::from(address);
        let block = Self { base, prefix };
        (prefix <= 32 && u64::from(base) % block.size() == 0).then_some(block)
    }

    /// How many addresses the block holds.
    pub fn size(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix))
    }

    /// The first address.
    pub fn base(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base)
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `address` is inside the block.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        self.index(address).is_some()
    }

    /// `address - base`, for an address inside the block.
    pub fn index(&self, address: Ipv4Addr) -> Option<u32> {
        let offset = u32::from(address).checked_sub(self.base)?;
        (u64::from(offset) < self.size()).then_some(offset)
    }

    fn address(&self, index: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.base + index)
    }
}

/// One address of the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Stands for nothing.
    Free,
    /// Stands for `name`, last asked for or connected to at `last_used`.
    Held { name: HostName, last_used: u64 },
}

/// The pool. One address per held name; an address used within the hold is never given to
/// another name.
#[derive(Debug)]
pub struct Pool {
    block: Block,
    hold: u64,
    /// Indexed by `address - base`. Addresses past the end have never been used and are free.
    entries: Vec<Entry>,
    /// Free entries inside `entries`.
    holes: BTreeSet<u32>,
    by_name: HashMap<HostName, u32>,
    by_age: BTreeSet<(u64, u32)>,
    revision: u64,
}

impl Pool {
    /// An empty pool over `block`. The hold is rounded up to whole seconds.
    pub fn new(block: Block, hold: Duration) -> Self {
        let hold = hold.as_secs() + u64::from(hold.subsec_nanos() != 0);
        Self {
            block,
            hold,
            entries: Vec::new(),
            holes: BTreeSet::new(),
            by_name: HashMap::new(),
            by_age: BTreeSet::new(),
            revision: 0,
        }
    }

    /// The block the pool hands out.
    pub fn block(&self) -> Block {
        self.block
    }

    /// Changes whenever the pool does; what a keeper compares to know there is something to write.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The address standing for `name`, giving it one if it has none: a free address first, else
    /// the least recently used one whose hold has run out. `None` when every address is held.
    pub fn lookup(&mut self, name: &HostName, now: u64) -> Option<Ipv4Addr> {
        if let Some(index) = self.by_name.get(name).copied() {
            self.refresh(index, now);
            return Some(self.block.address(index));
        }
        let index = match self.holes.pop_first() {
            Some(hole) => hole,
            None if (self.entries.len() as u64) < self.block.size() => {
                self.entries.push(Entry::Free);
                (self.entries.len() - 1) as u32
            }
            None => {
                let (last_used, oldest) = self.by_age.first().copied()?;
                if now.saturating_sub(last_used) < self.hold {
                    return None;
                }
                self.by_age.remove(&(last_used, oldest));
                if let Entry::Held { name, .. } = std::mem::replace(&mut self.entries[oldest as usize], Entry::Free) {
                    self.by_name.remove(&name);
                }
                oldest
            }
        };
        self.hold_entry(index, name.clone(), now);
        Some(self.block.address(index))
    }

    /// A flow arrived for `address`: the name it stands for, counted as a use.
    pub fn touch(&mut self, address: Ipv4Addr, now: u64) -> Option<&HostName> {
        let index = self.block.index(address)?;
        self.refresh(index, now);
        self.name_of(address)
    }

    /// The name `address` stands for, not counted as a use.
    pub fn name_of(&self, address: Ipv4Addr) -> Option<&HostName> {
        match self.entries.get(self.block.index(address)? as usize)? {
            Entry::Held { name, .. } => Some(name),
            Entry::Free => None,
        }
    }

    /// Every held address, in address order.
    pub fn held(&self) -> impl Iterator<Item = (Ipv4Addr, &HostName, u64)> {
        self.entries.iter().enumerate().filter_map(|(index, entry)| match entry {
            Entry::Held { name, last_used } => Some((self.block.address(index as u32), name, *last_used)),
            Entry::Free => None,
        })
    }

    /// Puts back one remembered entry. Refuses an address outside the block, an address already
    /// held, and a name already held.
    pub fn restore(&mut self, address: Ipv4Addr, name: HostName, last_used: u64) -> Result<(), Unrestorable> {
        let index = self.block.index(address).ok_or(Unrestorable)?;
        if self.by_name.contains_key(&name) || self.name_of(address).is_some() {
            return Err(Unrestorable);
        }
        while self.entries.len() <= index as usize {
            self.holes.insert(self.entries.len() as u32);
            self.entries.push(Entry::Free);
        }
        self.holes.remove(&index);
        self.hold_entry(index, name, last_used);
        Ok(())
    }

    fn hold_entry(&mut self, index: u32, name: HostName, now: u64) {
        self.by_name.insert(name.clone(), index);
        self.by_age.insert((now, index));
        self.entries[index as usize] = Entry::Held { name, last_used: now };
        self.revision += 1;
    }

    /// Moves a held entry's last use forward to `now`. A clock that stepped back changes nothing.
    fn refresh(&mut self, index: u32, now: u64) {
        if let Some(Entry::Held { last_used, .. }) = self.entries.get_mut(index as usize)
            && now > *last_used
        {
            self.by_age.remove(&(*last_used, index));
            self.by_age.insert((now, index));
            *last_used = now;
            self.revision += 1;
        }
    }
}

/// A remembered entry that does not fit the pool it is being put back into.
#[derive(Debug, PartialEq, Eq)]
pub struct Unrestorable;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The reference: a flat list scanned from the start, nothing indexed.
    struct Reference {
        slots: Vec<Option<(String, u64)>>,
        hold: u64,
    }

    impl Reference {
        fn lookup(&mut self, name: &str, now: u64) -> Option<usize> {
            if let Some(index) = self.slots.iter().position(|slot| slot.as_ref().is_some_and(|held| held.0 == name)) {
                self.touch(index, now);
                return Some(index);
            }
            let free = self.slots.iter().position(Option::is_none);
            let index = free.or_else(|| {
                let mut oldest: Option<(u64, usize)> = None;
                for (index, slot) in self.slots.iter().enumerate() {
                    let last_used = slot.as_ref().expect("no free slot").1;
                    if oldest.is_none_or(|(least, _)| last_used < least) {
                        oldest = Some((last_used, index));
                    }
                }
                oldest.filter(|(last_used, _)| now.saturating_sub(*last_used) >= self.hold).map(|(_, index)| index)
            })?;
            self.slots[index] = Some((name.to_owned(), now));
            Some(index)
        }

        fn touch(&mut self, index: usize, now: u64) -> Option<String> {
            let held = self.slots.get_mut(index)?.as_mut()?;
            held.1 = held.1.max(now);
            Some(held.0.clone())
        }
    }

    #[derive(Clone, Debug)]
    enum Step {
        Lookup { name: u8, wait: u64 },
        Touch { offset: u32, wait: u64 },
    }

    fn step(names: u8, addresses: u32, longest_wait: u64) -> impl Strategy<Value = Step> {
        prop_oneof![
            (0..names, 0..=longest_wait).prop_map(|(name, wait)| Step::Lookup { name, wait }),
            (0..addresses + 2, 0..=longest_wait).prop_map(|(offset, wait)| Step::Touch { offset, wait }),
        ]
    }

    /// A block, a hold, and steps whose waits straddle the hold, over more names than addresses.
    fn scenario() -> impl Strategy<Value = (Block, u64, Vec<Step>)> {
        (24u8..=32, any::<u32>(), 0u64..40).prop_flat_map(|(prefix, anywhere, hold)| {
            let size = 1u64 << (32 - u32::from(prefix));
            let base = (u64::from(anywhere) / size * size) as u32;
            let block = Block::new(Ipv4Addr::from(base), prefix).expect("aligned");
            let names = (size.min(100) as u8).saturating_mul(2).max(2);
            let steps = proptest::collection::vec(step(names, size as u32, hold + 2), 0..300);
            (Just(block), Just(hold), steps)
        })
    }

    fn host(name: u8) -> HostName {
        HostName::parse(&format!("n{name}.example")).expect("a host name")
    }

    proptest! {
        #[test]
        fn pool_agrees_with_the_reference((block, hold, steps) in scenario()) {
            let mut pool = Pool::new(block, Duration::from_secs(hold));
            let mut reference = Reference { slots: vec![None; block.size() as usize], hold };
            let mut now = 1_000u64;
            let mut last_given: HashMap<Ipv4Addr, (HostName, u64)> = HashMap::new();
            for step in steps {
                match step {
                    Step::Lookup { name, wait } => {
                        now += wait;
                        let name = host(name);
                        let got = pool.lookup(&name, now);
                        let expected = reference.lookup(name.as_str(), now).map(|index| Ipv4Addr::from(u32::from(block.base()) + index as u32));
                        prop_assert_eq!(got, expected);
                        if let Some(address) = got {
                            prop_assert!(block.contains(address));
                            if let Some((before, used)) = last_given.get(&address) && *before != name {
                                prop_assert!(now - used >= hold, "{address} reused {}s after its last use, hold {hold}s", now - used);
                            }
                            last_given.insert(address, (name, now));
                        }
                    }
                    Step::Touch { offset, wait } => {
                        now += wait;
                        let address = Ipv4Addr::from(u32::from(block.base()).wrapping_add(offset));
                        let got = pool.touch(address, now).cloned();
                        let expected = if block.contains(address) { reference.touch(offset as usize, now) } else { None };
                        prop_assert_eq!(got.as_ref().map(HostName::as_str), expected.as_deref());
                        if let Some(name) = got {
                            last_given.insert(address, (name, now));
                        }
                    }
                }
                let held: Vec<_> = pool.held().collect();
                let names: std::collections::HashSet<_> = held.iter().map(|(_, name, _)| *name).collect();
                prop_assert_eq!(names.len(), held.len(), "a name holds two addresses");
                let model: Vec<_> = reference.slots.iter().enumerate().filter_map(|(index, slot)| {
                    slot.as_ref().map(|(name, last_used)| (Ipv4Addr::from(u32::from(block.base()) + index as u32), name.clone(), *last_used))
                }).collect();
                let held: Vec<_> = held.into_iter().map(|(address, name, last_used)| (address, name.as_str().to_owned(), last_used)).collect();
                prop_assert_eq!(held, model);
            }
        }

        #[test]
        fn a_block_contains_exactly_its_range(prefix in 0u8..=32, anywhere in any::<u32>(), probe in any::<u32>()) {
            let size = 1u64 << (32 - u32::from(prefix));
            let base = (u64::from(anywhere) / size * size) as u32;
            let block = Block::new(Ipv4Addr::from(base), prefix).expect("aligned");
            let inside = u64::from(probe) >= u64::from(base) && u64::from(probe) < u64::from(base) + size;
            prop_assert_eq!(block.contains(Ipv4Addr::from(probe)), inside);
            prop_assert_eq!(Block::new(Ipv4Addr::from(anywhere), prefix).is_some(), u64::from(anywhere) % size == 0);
        }
    }
}
