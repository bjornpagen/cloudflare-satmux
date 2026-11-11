//! The tunnel front end: every TCP flow an app opens through a utun interface is ended here by
//! a userspace TCP/IP stack and handed, as a destination and a byte stream, to the uplink. Names
//! are answered with placeholder addresses so the name, not an address, travels with the flow.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::future::BoxFuture;
use satmux_core::Dest;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod device;
pub mod dns;
pub mod pool;
mod stack;
pub mod store;

pub use device::{Device, Utun};
pub use stack::serve;

/// Everything the front end is told. Every field is required.
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Where the tunnel's resolver answers (UDP port 53).
    pub dns_address: Ipv4Addr,
    /// The block of placeholder addresses, as an address and a prefix length.
    pub placeholders: (Ipv4Addr, u8),
    /// The lifetime of a placeholder answer.
    pub answer_ttl: Duration,
    /// How long after its last use a placeholder is kept for its name.
    pub placeholder_hold: Duration,
    /// The folder the placeholder table is kept in.
    pub state: PathBuf,
    /// The interface's largest packet.
    pub mtu: usize,
    /// How long a new flow waits for the app's first bytes so they ride with the open.
    pub first_payload_wait: Duration,
}

/// The stream a flow is spliced to.
pub trait FlowIo: AsyncRead + AsyncWrite + Send + Unpin {}

/// Opens a flow to a destination, given the bytes the app has already sent.
pub type Connect = Arc<dyn Fn(Dest, Bytes) -> BoxFuture<'static, io::Result<Box<dyn FlowIo>>> + Send + Sync>;

/// Answers one DNS query in wire format.
pub type Resolve = Arc<dyn Fn(Vec<u8>) -> BoxFuture<'static, io::Result<Vec<u8>>> + Send + Sync>;

/// Runs the front end on a utun descriptor until the device fails. It never returns `Ok`.
pub async fn run(device: OwnedFd, config: TunConfig, connect: Connect, resolve: Resolve) -> io::Result<()> {
    serve(Utun::new(device)?, config, connect, resolve).await
}
