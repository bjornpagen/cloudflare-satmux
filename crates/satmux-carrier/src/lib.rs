//! The Mac side of a carrier: the configuration both programs parse, finding the relay without
//! the cabin's resolver, dialing one carrier, the pool that keeps one carrier per port alive,
//! and the [`Uplink`] every front end sends its flows through.

pub mod config;
pub mod dial;
pub mod dnsmsg;
pub mod find;
pub mod net;
pub mod pool;
pub mod uplink;
pub mod verdict;
pub mod wsio;

pub use config::{Common, ConfigRefused, DaemonConfig, FrontEnd, ProbeConfig};
pub use uplink::{Flow, Uplink};

/// Bad input: do not restart.
pub const EXIT_BAD_INPUT: u8 = 100;
/// Temporary failure: restart.
pub const EXIT_TEMPORARY: u8 = 111;
