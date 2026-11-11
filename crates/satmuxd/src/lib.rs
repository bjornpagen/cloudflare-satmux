//! The daemon's own parts: the descriptors it inherits, the proxy front end and the status socket. `main` wires them to the
//! uplink and to the tunnel front end.

pub mod inherited;
pub mod proxy;
pub mod status;
