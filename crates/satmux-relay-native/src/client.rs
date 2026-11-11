//! A minimal carrier client: enough of the Mac's side to drive a relay in this crate's tests
//! and in `examples/drive.rs`. It is not the daemon's carrier; that is `satmux-carrier`.

use std::io;
use std::task::Poll;

use futures::channel::{mpsc, oneshot};
use futures::future;
use futures::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use futures::stream::StreamExt;
use satmux_core::{CARRIER_PATH, Open};
use satmux_relay_logic::MessageIo;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::ClientRequestBuilder;

use crate::Messages;

/// A handle that opens streams on a carrier whose yamux connection [`drive`] is running.
#[derive(Clone)]
pub struct Carrier {
    asks: mpsc::UnboundedSender<oneshot::Sender<yamux::Stream>>,
}

impl Carrier {
    /// Opens a stream and writes `open` and `first` on it at once, as the contract says.
    pub async fn open(&self, open: &Open, first: &[u8]) -> io::Result<yamux::Stream> {
        let mut bytes = Vec::new();
        open.encode(&mut bytes);
        bytes.extend_from_slice(first);
        self.open_raw(&bytes).await
    }

    /// Opens a stream and writes `bytes` on it as they are: how a test sends what is not an open.
    pub async fn open_raw(&self, bytes: &[u8]) -> io::Result<yamux::Stream> {
        let (answer, stream) = oneshot::channel();
        let gone = || io::Error::new(io::ErrorKind::BrokenPipe, "carrier ended");
        self.asks.unbounded_send(answer).map_err(|_| gone())?;
        let mut stream = stream.await.map_err(|_| gone())?;
        stream.write_all(bytes).await?;
        stream.flush().await?;
        Ok(stream)
    }
}

/// Runs yamux in client mode over `io` until the carrier ends, opening a stream for every ask
/// of the returned handle's clones. Spawn it.
pub fn drive<T>(io: T) -> (Carrier, impl Future<Output = ()>)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (asks, mut asked) = mpsc::unbounded::<oneshot::Sender<yamux::Stream>>();
    let mut connection = yamux::Connection::new(io, yamux::Config::default(), yamux::Mode::Client);
    let mut waiting: Option<oneshot::Sender<yamux::Stream>> = None;
    let mut handles_left = true;
    let driver = future::poll_fn(move |cx| {
        loop {
            if waiting.is_none() && handles_left {
                match asked.poll_next_unpin(cx) {
                    Poll::Ready(Some(answer)) => waiting = Some(answer),
                    Poll::Ready(None) => handles_left = false,
                    Poll::Pending => {}
                }
            }
            if let Some(answer) = waiting.take() {
                match connection.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        let _ = answer.send(stream);
                        continue;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => waiting = Some(answer),
                }
            }
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(_)) | None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
    });
    (Carrier { asks }, driver)
}

/// Dials `address` in plain TCP, upgrades to a WebSocket on the carrier path with `key`, and
/// returns the carrier's byte stream.
pub async fn dial(address: &str, key: &str) -> io::Result<MessageIo<Messages<TcpStream>>> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let uri = format!("ws://{address}{CARRIER_PATH}").parse().map_err(io::Error::other)?;
    let request = ClientRequestBuilder::new(uri).with_header("Authorization", format!("Bearer {key}"));
    let (socket, _) = tokio_tungstenite::client_async(request, stream).await.map_err(io::Error::other)?;
    Ok(MessageIo::new(Messages::new(socket)))
}
