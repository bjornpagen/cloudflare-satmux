//! A tungstenite WebSocket as binary payloads in and out, for `MessageIo`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use futures::sink::Sink;
use futures::stream::Stream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error, Message};

/// Incoming binary payloads as a stream, outgoing ones as a sink. Pings are answered by
/// tungstenite; a text message is an error, since a carrier has none.
pub struct Messages<S>(WebSocketStream<S>);

impl<S> Messages<S> {
    /// Wraps an established WebSocket of either role.
    pub fn new(socket: WebSocketStream<S>) -> Self {
        Self(socket)
    }
}

fn io_error(error: Error) -> io::Error {
    match error {
        Error::Io(error) => error,
        other => io::Error::other(other),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for Messages<S> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            return Poll::Ready(match ready!(Pin::new(&mut self.0).poll_next(cx)) {
                Some(Ok(Message::Binary(payload))) => Some(Ok(payload.to_vec())),
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Text(_))) => Some(Err(io::Error::new(io::ErrorKind::InvalidData, "text message on a carrier"))),
                Some(Ok(Message::Close(_))) | None => None,
                Some(Err(Error::ConnectionClosed | Error::AlreadyClosed)) => None,
                Some(Err(error)) => Some(Err(io_error(error))),
            });
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Vec<u8>> for Messages<S> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_ready(cx).map_err(io_error)
    }

    fn start_send(mut self: Pin<&mut Self>, message: Vec<u8>) -> io::Result<()> {
        Pin::new(&mut self.0).start_send(Message::Binary(message.into())).map_err(io_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx).map_err(io_error)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx).map_err(io_error)
    }
}
