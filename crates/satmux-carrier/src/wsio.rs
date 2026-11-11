//! WebSocket binary messages as one byte stream, for yamux. Message boundaries mean nothing:
//! a read drains whatever the last message still holds, and every write is one message.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use futures::{AsyncRead, AsyncWrite, Sink, Stream};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

pub struct WsBytes<S> {
    inner: S,
    unread: Bytes,
}

impl<S> WsBytes<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, unread: Bytes::new() }
    }
}

fn io_error(error: WsError) -> io::Error {
    match error {
        WsError::Io(error) => error,
        WsError::ConnectionClosed | WsError::AlreadyClosed => io::ErrorKind::BrokenPipe.into(),
        other => io::Error::other(other),
    }
}

impl<S> AsyncRead for WsBytes<S>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        while self.unread.is_empty() {
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(payload))) => self.unread = payload,
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Text(_))) => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(0)),
                Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => return Poll::Ready(Ok(0)),
                Some(Err(error)) => return Poll::Ready(Err(io_error(error))),
            }
        }
        let n = buf.len().min(self.unread.len());
        self.unread.copy_to_slice(&mut buf[..n]);
        Poll::Ready(Ok(n))
    }
}

impl<S> AsyncWrite for WsBytes<S>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(io_error)?;
        Pin::new(&mut self.inner).start_send(Message::Binary(Bytes::copy_from_slice(buf))).map_err(io_error)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(io_error)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx).map_err(io_error)
    }
}
