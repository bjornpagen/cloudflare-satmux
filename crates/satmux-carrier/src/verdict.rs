//! Every name has a verdict. `Relay` is the row a name has until the relay refuses it; a
//! refusal writes a `Direct` row, which lasts until its own end and is kept across starts.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use satmux_core::HostName;

/// Seconds since the Unix epoch: the one clock that means the same thing after a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallClock(pub u64);

impl WallClock {
    pub fn now() -> Self {
        Self(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()))
    }

    pub fn after(self, life: Duration) -> Self {
        Self(self.0.saturating_add(life.as_secs()))
    }
}

/// Why a name goes direct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The relay's platform refuses the destination.
    Forbidden,
}

impl Why {
    const ALL: [Why; 1] = [Why::Forbidden];

    fn word(self) -> &'static str {
        match self {
            Why::Forbidden => "forbidden",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Relay,
    Direct { why: Why, until: WallClock },
}

impl core::fmt::Display for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Verdict::Relay => f.write_str("relay"),
            Verdict::Direct { why, until } => write!(f, "direct {} {}", why.word(), until.0),
        }
    }
}

/// The direct rows. A name without one has the verdict `Relay`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rows(BTreeMap<HostName, (Why, WallClock)>);

impl Rows {
    /// Reads lines of `name why until`. A line that is not one is not a row.
    pub fn parse(text: &str) -> Self {
        let rows = text.lines().filter_map(|line| {
            let mut words = line.split(' ');
            let (Some(name), Some(why), Some(until), None) = (words.next(), words.next(), words.next(), words.next()) else {
                return None;
            };
            let name = HostName::parse(name).ok()?;
            let why = Why::ALL.into_iter().find(|w| w.word() == why)?;
            Some((name, (why, WallClock(until.parse().ok()?))))
        });
        Self(rows.collect())
    }

    pub fn render(&self) -> String {
        self.0.iter().map(|(name, (why, until))| format!("{name} {} {}\n", why.word(), until.0)).collect()
    }

    pub fn verdict(&self, name: &HostName, now: WallClock) -> Verdict {
        match self.0.get(name) {
            Some((why, until)) if now < *until => Verdict::Direct { why: *why, until: *until },
            Some(_) | None => Verdict::Relay,
        }
    }

    pub fn direct(&mut self, name: HostName, why: Why, until: WallClock) {
        self.0.insert(name, (why, until));
    }

    pub fn relay(&mut self, name: &HostName) {
        self.0.remove(name);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

const VERDICTS: &str = "verdicts";
const VERDICTS_NEW: &str = "verdicts.new";

/// The rows and the file they are kept in.
pub struct Table {
    rows: Rows,
    state: PathBuf,
}

impl Table {
    /// Loads the table. No file yet is an empty table; an unreadable one is an error.
    pub fn load(state: PathBuf) -> io::Result<Self> {
        let rows = match std::fs::read_to_string(state.join(VERDICTS)) {
            Ok(text) => Rows::parse(&text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Rows::default(),
            Err(error) => return Err(error),
        };
        Ok(Self { rows, state })
    }

    pub fn rows(&self) -> &Rows {
        &self.rows
    }

    /// Changes the rows and replaces the file by rename. A failed write is logged: the verdict
    /// still holds for this run.
    pub fn change(&mut self, change: impl FnOnce(&mut Rows)) {
        change(&mut self.rows);
        let fresh = self.state.join(VERDICTS_NEW);
        let kept = std::fs::write(&fresh, self.rows.render()).and_then(|()| std::fs::rename(&fresh, self.state.join(VERDICTS)));
        if let Err(error) = kept {
            tracing::warn!(%error, "the verdict file was not replaced");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn host() -> impl Strategy<Value = HostName> {
        proptest::collection::vec("[a-z0-9]([a-z0-9-]{0,6}[a-z0-9])?", 1..4)
            .prop_map(|labels| HostName::parse(&labels.join(".")).expect("generated names are host names"))
    }

    proptest! {
        /// The file is the table: rendering and reading back loses nothing.
        #[test]
        fn rows_round_trip(entries in proptest::collection::btree_map(host(), any::<u64>(), 0..12)) {
            let mut rows = Rows::default();
            for (name, until) in &entries {
                rows.direct(name.clone(), Why::Forbidden, WallClock(*until));
            }
            prop_assert_eq!(Rows::parse(&rows.render()), rows);
        }

        /// A name is direct exactly while a row for it has not ended; everything else is relay.
        #[test]
        fn a_verdict_is_its_unexpired_row(entries in proptest::collection::btree_map(host(), any::<u64>(), 0..8), asked in host(), now in any::<u64>()) {
            let mut rows = Rows::default();
            for (name, until) in &entries {
                rows.direct(name.clone(), Why::Forbidden, WallClock(*until));
            }
            let expected = match entries.get(&asked) {
                Some(until) if now < *until => Verdict::Direct { why: Why::Forbidden, until: WallClock(*until) },
                _ => Verdict::Relay,
            };
            prop_assert_eq!(rows.verdict(&asked, WallClock(now)), expected);
        }

        #[test]
        fn arbitrary_text_never_panics(text in ".{0,200}") {
            let _ = Rows::parse(&text);
        }
    }
}
