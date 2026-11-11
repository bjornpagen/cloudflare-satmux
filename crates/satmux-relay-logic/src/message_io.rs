//! A byte stream over a WebSocket's binary messages, whose boundaries mean nothing.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use futures::io::{AsyncRead, AsyncWrite};
use futures::sink::Sink;
use futures::stream::Stream;

/// The most bytes gathered into one outgoing message before it is sent without waiting for a
/// flush. Well under the 1 MiB a Worker's WebSocket accepts in one message.
const MESSAGE_MAX: usize = 64 * 1024;

/// Reads the concatenated payloads of incoming binary messages, and writes outgoing bytes as
/// binary messages: one per flush, so a yamux header and its body travel together.
///
/// `T` yields each incoming binary payload and accepts each outgoing one; the end of the
/// stream is the end of the carrier.
pub struct MessageIo<T> {
    inner: T,
    incoming: Vec<u8>,
    taken: usize,
    outgoing: Vec<u8>,
}

impl<T> MessageIo<T> {
    /// Wraps a message transport.
    pub fn new(inner: T) -> Self {
        Self { inner, incoming: Vec::new(), taken: 0, outgoing: Vec::new() }
    }
}

impl<T> MessageIo<T>
where
    T: Sink<Vec<u8>, Error = io::Error> + Unpin,
{
    /// Hands everything gathered so far to the transport as one message.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.outgoing.is_empty() {
            return Poll::Ready(Ok(()));
        }
        ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
        let message = std::mem::take(&mut self.outgoing);
        Poll::Ready(Pin::new(&mut self.inner).start_send(message))
    }
}

impl<T> AsyncRead for MessageIo<T>
where
    T: Stream<Item = io::Result<Vec<u8>>> + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        while this.taken == this.incoming.len() {
            match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
                Some(Ok(message)) => {
                    this.incoming = message;
                    this.taken = 0;
                }
                Some(Err(error)) => return Poll::Ready(Err(error)),
                None => return Poll::Ready(Ok(0)),
            }
        }
        let n = buf.len().min(this.incoming.len() - this.taken);
        buf[..n].copy_from_slice(&this.incoming[this.taken..this.taken + n]);
        this.taken += n;
        Poll::Ready(Ok(n))
    }
}

impl<T> AsyncWrite for MessageIo<T>
where
    T: Sink<Vec<u8>, Error = io::Error> + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.outgoing.len() >= MESSAGE_MAX {
            ready!(this.poll_send(cx))?;
        }
        let n = buf.len().min(MESSAGE_MAX - this.outgoing.len());
        this.outgoing.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.inner).poll_close(cx)
    }
}
