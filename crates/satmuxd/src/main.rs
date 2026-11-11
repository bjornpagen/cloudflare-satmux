//! `satmuxd`: carriers, the flow engine, one front end and the status socket. Environment in,
//! one newline on the readiness descriptor out, and three exits: 100, 111, 0.

use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::process::ExitCode;
use std::sync::Arc;

use satmux_carrier::config::{self, DaemonConfig, FrontEnd};
use satmux_carrier::uplink::StartFailed;
use satmux_carrier::{EXIT_BAD_INPUT, EXIT_TEMPORARY, Flow, Uplink};
use satmuxd::{inherited, proxy, status};
use tokio::net::{TcpListener, UnixListener};
use tokio::signal::unix::{SignalKind, signal};

/// A flow, as the tunnel front end takes it.
struct TunFlow(Flow);

impl tokio::io::AsyncRead for TunFlow {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TunFlow {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl satmux_tun::FlowIo for TunFlow {}

/// How the daemon ends.
enum Ended {
    Asked,
    BadInput(String),
    Temporary(String),
}

/// Runs the configured front end until it fails.
async fn front_end(config: &DaemonConfig, uplink: Uplink, device: Option<OwnedFd>) -> Ended {
    let common = &config.common;
    match (config.front_end, device) {
        (FrontEnd::Proxy(listen), _) => match TcpListener::bind(listen).await {
            Ok(listener) => {
                let waits = proxy::Waits { head: common.relay_connect, first_payload: common.first_payload_wait };
                Ended::Temporary(format!("proxy front end: {}", proxy::serve(listener, uplink, waits).await))
            }
            Err(error) => Ended::Temporary(format!("SATMUX_DAEMON_PROXY_LISTEN: {error}")),
        },
        (FrontEnd::Tunnel(_), Some(device)) => {
            let tun = satmux_tun::TunConfig {
                dns_address: common.dns_address,
                placeholders: (common.placeholders.base, common.placeholders.prefix),
                answer_ttl: common.answer_ttl,
                placeholder_hold: common.placeholder_hold,
                state: common.state.clone(),
                mtu: usize::from(common.tun_mtu.get()),
                first_payload_wait: common.first_payload_wait,
            };
            let connecting = uplink.clone();
            let connect: satmux_tun::Connect = Arc::new(move |dest, first| {
                let uplink = connecting.clone();
                Box::pin(async move { Ok(Box::new(TunFlow(uplink.connect(dest, first).await?)) as Box<dyn satmux_tun::FlowIo>) })
            });
            let resolve: satmux_tun::Resolve = Arc::new(move |query| {
                let uplink = uplink.clone();
                Box::pin(async move { uplink.dns(query).await })
            });
            match satmux_tun::run(device, tun, connect, resolve).await {
                Ok(()) => Ended::Temporary(String::from("tunnel front end ended")),
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ended::BadInput(format!("tunnel front end: {error}")),
                Err(error) => Ended::Temporary(format!("tunnel front end: {error}")),
            }
        }
        (FrontEnd::Tunnel(_), None) => Ended::BadInput(String::from("SATMUX_DAEMON_UTUN_FD: no descriptor")),
    }
}

async fn run(config: DaemonConfig, ready_fd: OwnedFd, device: Option<OwnedFd>) -> Ended {
    let (Ok(mut asked_to_stop), Ok(mut interrupted)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
        return Ended::Temporary(String::from("signal handlers could not be installed"));
    };
    let starting = Uplink::from_config(&config.common);
    let uplink = tokio::select! {
        started = starting => match started {
            Ok(uplink) => uplink,
            Err(error @ StartFailed::Find(_)) => return Ended::Temporary(error.to_string()),
            Err(error) => return Ended::BadInput(error.to_string()),
        },
        _ = asked_to_stop.recv() => return Ended::Asked,
        _ = interrupted.recv() => return Ended::Asked,
    };
    let _ = std::fs::remove_file(&config.status_socket);
    let status_listener = match UnixListener::bind(&config.status_socket) {
        Ok(listener) => listener,
        Err(error) => return Ended::BadInput(format!("SATMUX_DAEMON_STATUS_SOCKET: {error}")),
    };
    let mut ready = uplink.ready();
    tokio::spawn(async move {
        if ready.wait_for(|up| *up).await.is_ok() {
            tracing::info!("first carrier ready");
            let mut descriptor = std::fs::File::from(ready_fd);
            if let Err(error) = descriptor.write_all(b"\n") {
                tracing::warn!(%error, "the readiness descriptor could not be written");
            }
        }
    });
    tokio::select! {
        _ = asked_to_stop.recv() => Ended::Asked,
        _ = interrupted.recv() => Ended::Asked,
        () = uplink.no_carrier() => Ended::Temporary(format!("no carrier for {:?}", config.common.no_carrier_exit)),
        error = status::serve(status_listener, uplink.clone(), config.common.relay_connect) => Ended::Temporary(format!("status socket: {error}")),
        ended = front_end(&config, uplink.clone(), device) => ended,
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt().with_writer(io::stderr).with_ansi(false).init();
    let config = match DaemonConfig::parse(config::process_environment()) {
        Ok(config) => config,
        Err(refused) => {
            eprintln!("satmuxd: {refused}");
            return ExitCode::from(EXIT_BAD_INPUT);
        }
    };
    // The inherited descriptors are checked and taken before the runtime is built: see
    // `inherited`. A number that names nothing is a bad setting, like any other.
    let adopted = (|| {
        if let FrontEnd::Tunnel(fd) = config.front_end {
            inherited::distinct(config::DAEMON_UTUN_FD, fd, config::DAEMON_READY_FD, config.ready_fd)?;
        }
        // SAFETY: the supervisor opened this descriptor for this process, nothing here owns it
        // yet, and no descriptor of our own has been opened since the process began.
        let ready_fd = unsafe { inherited::adopt(config::DAEMON_READY_FD, config.ready_fd) }?;
        let device = match config.front_end {
            // SAFETY: as above: `satmux-utun` put the utun on this number for this process.
            FrontEnd::Tunnel(fd) => Some(unsafe { inherited::adopt(config::DAEMON_UTUN_FD, fd) }?),
            FrontEnd::Proxy(_) => None,
        };
        Ok::<_, inherited::NotAdopted>((ready_fd, device))
    })();
    let (ready_fd, device) = match adopted {
        Ok(adopted) => adopted,
        Err(refused) => {
            eprintln!("satmuxd: {refused}");
            return ExitCode::from(EXIT_BAD_INPUT);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("satmuxd: runtime: {error}");
            return ExitCode::from(EXIT_TEMPORARY);
        }
    };
    match runtime.block_on(run(config, ready_fd, device)) {
        Ended::Asked => ExitCode::SUCCESS,
        Ended::BadInput(why) => {
            eprintln!("satmuxd: {why}");
            ExitCode::from(EXIT_BAD_INPUT)
        }
        Ended::Temporary(why) => {
            eprintln!("satmuxd: {why}");
            ExitCode::from(EXIT_TEMPORARY)
        }
    }
}
