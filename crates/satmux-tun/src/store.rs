//! The pool on disk: `<state>/placeholders`, so a restart does not orphan addresses that apps
//! still hold. The first line names the block; each other line is `address last_used name`.
//! A file written for another block is not this pool's and is left unread.

use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use satmux_core::HostName;

use crate::pool::{Block, Pool};

/// The file's name inside the state folder.
const FILE: &str = "placeholders";
/// What the new text is written to before it replaces the file.
const SCRATCH: &str = "placeholders.new";

/// Where the pool is kept.
pub fn path(state: &Path) -> PathBuf {
    state.join(FILE)
}

fn heading(block: Block) -> String {
    format!("block {}/{}", block.base(), block.prefix())
}

/// The pool as the text of its file.
pub fn render(pool: &Pool) -> String {
    let mut text = heading(pool.block());
    text.push('\n');
    for (address, name, last_used) in pool.held() {
        text.push_str(&format!("{address} {last_used} {name}\n"));
    }
    text
}

/// A pool from the text of its file. `None` when the text is not a pool file.
pub fn parse(text: &str, block: Block, hold: Duration) -> Option<Pool> {
    let mut pool = Pool::new(block, hold);
    let mut lines = text.lines();
    if lines.next()? != heading(block) {
        return Some(pool);
    }
    for line in lines {
        let mut fields = line.split(' ');
        let address: Ipv4Addr = fields.next()?.parse().ok()?;
        let last_used: u64 = fields.next()?.parse().ok()?;
        let name = HostName::parse(fields.next()?).ok()?;
        if fields.next().is_some() {
            return None;
        }
        pool.restore(address, name, last_used).ok()?;
    }
    Some(pool)
}

/// The pool as last kept, or an empty one when nothing was kept yet.
pub fn load(state: &Path, block: Block, hold: Duration) -> io::Result<Pool> {
    let file = path(state);
    match std::fs::read_to_string(&file) {
        Ok(text) => parse(&text, block, hold)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{}: not a placeholder file", file.display()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Pool::new(block, hold)),
        Err(error) => Err(error),
    }
}

/// Replaces the file with `text` in one rename, so a reader sees the old pool or the new one.
pub fn save(state: &Path, text: &str) -> io::Result<()> {
    let scratch = state.join(SCRATCH);
    let mut file = std::fs::File::create(&scratch)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&scratch, path(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn a_pool_survives_its_file(
            lookups in proptest::collection::vec((0u8..40, 0u64..5), 0..80),
            hold in 0u64..10,
            other_prefix in 17u8..=24,
        ) {
            let block = Block::new(Ipv4Addr::new(198, 18, 0, 0), 28).expect("aligned");
            let hold = Duration::from_secs(hold);
            let mut pool = Pool::new(block, hold);
            let mut now = 50u64;
            for (name, wait) in lookups {
                now += wait;
                let _ = pool.lookup(&HostName::parse(&format!("h{name}.test")).expect("a host name"), now);
            }
            let text = render(&pool);
            let back = parse(&text, block, hold).expect("its own file");
            prop_assert_eq!(back.held().collect::<Vec<_>>(), pool.held().collect::<Vec<_>>());
            prop_assert_eq!(render(&back), text.clone());

            let other = Block::new(Ipv4Addr::new(10, 0, 0, 0), other_prefix).expect("aligned");
            let emptied = parse(&text, other, hold).expect("another block's file is left unread");
            prop_assert_eq!(emptied.held().count(), 0);
        }

        #[test]
        fn any_text_is_a_pool_or_refused(text in "\\PC{0,200}") {
            let block = Block::new(Ipv4Addr::new(198, 18, 0, 0), 28).expect("aligned");
            if let Some(pool) = parse(&text, block, Duration::ZERO) {
                for (address, _, _) in pool.held() {
                    prop_assert!(block.contains(address));
                }
            }
        }
    }
}
