//! Outbound sockets. Every one is bound to the interface policy names, so nothing this side
//! dials can follow the tunnel's own routes.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream};

/// Makes one unconnected TCP socket fit to dial `to`. Production has exactly one: [`bound_to`].
pub type SocketFactory = Arc<dyn Fn(SocketAddr) -> io::Result<Socket> + Send + Sync>;

fn stream_socket(to: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(to), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_keepalive(true)?;
    Ok(socket)
}

/// Sockets bound to the named interface. The name is resolved here, once, so a wrong name
/// fails the start and not the first dial.
#[cfg(target_os = "macos")]
pub fn bound_to(interface: &str) -> io::Result<SocketFactory> {
    let index = std::num::NonZeroU32::new(nix::net::if_::if_nametoindex(interface).map_err(io::Error::from)?);
    Ok(Arc::new(move |to| {
        let socket = stream_socket(to)?;
        match to {
            SocketAddr::V4(_) => socket.bind_device_by_index_v4(index)?,
            SocketAddr::V6(_) => socket.bind_device_by_index_v6(index)?,
        }
        Ok(socket)
    }))
}

/// Sockets bound to the named interface. The first socket is made here, so a wrong name fails
/// the start and not the first dial.
#[cfg(not(target_os = "macos"))]
pub fn bound_to(interface: &str) -> io::Result<SocketFactory> {
    let name = interface.as_bytes().to_vec();
    let factory: SocketFactory = Arc::new(move |to| {
        let socket = stream_socket(to)?;
        socket.bind_device(Some(&name))?;
        Ok(socket)
    });
    factory(SocketAddr::from(([0, 0, 0, 0], 0)))?;
    Ok(factory)
}

/// Connects a socket from the factory.
pub async fn connect(factory: &SocketFactory, to: SocketAddr) -> io::Result<TcpStream> {
    let socket = TcpSocket::from_std_stream(factory(to)?.into());
    socket.connect(to).await
}
