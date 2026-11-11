//! `satmux-probe`: measures the network between here and the relay and prints `name value`
//! lines. It changes nothing, and it draws no conclusion: classifying the numbers is policy's.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use futures::future::join_all;
use satmux_carrier::config::{self, ProbeConfig};
use satmux_carrier::dial::{self, DialFailed, Dialer, Session};
use satmux_carrier::find::{self, HTTPS_PORT};
use satmux_carrier::net;
use satmux_carrier::{EXIT_BAD_INPUT, EXIT_TEMPORARY};
use satmux_core::{ECHO_NONCE, Open, Status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Echoes per port: enough for a minimum and a median.
const ECHOES: u64 = 5;
/// The size of one write to a sink and one read from a source.
const CHUNK: usize = 16 * 1024;

fn say(name: impl core::fmt::Display, value: impl core::fmt::Display) {
    println!("{name} {value}");
}

async fn within<T>(wait: Duration, work: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(wait, work).await.map_err(|_| io::ErrorKind::TimedOut)?
}

/// Asks every resolver, printing each one's reachability and time; returns the first answer.
async fn resolvers(config: &ProbeConfig, dialer: &Dialer) -> Vec<Ipv4Addr> {
    let common = &config.common;
    let asked = join_all(common.resolvers.iter().map(|resolver| async move {
        let started = Instant::now();
        let answer = within(common.relay_connect, find::ask(dialer.tls(), dialer.factory(), SocketAddr::new(*resolver, HTTPS_PORT), &common.relay_name)).await;
        (resolver, started.elapsed(), answer)
    }))
    .await;
    let mut found = Vec::new();
    for (resolver, took, answer) in asked {
        match answer {
            Ok(addresses) => {
                say(format_args!("resolver.{resolver}"), "ok");
                say(format_args!("resolver_ms.{resolver}"), took.as_millis());
                if found.is_empty() {
                    found = addresses;
                }
            }
            Err(_) => say(format_args!("resolver.{resolver}"), "failed"),
        }
    }
    found
}

/// Five echoes on a new stream: the minimum and the median round trip.
async fn echoes(session: &Session, port: u16, wait: Duration) -> io::Result<()> {
    let (mut stream, status) = within(wait, session.request(&Open::Echo, &[])).await?;
    if status != Status::Connected {
        return Err(dial::refusal(status));
    }
    let mut times = Vec::new();
    for nonce in 0..ECHOES {
        let started = Instant::now();
        let mut back = [0u8; ECHO_NONCE];
        within(wait, async {
            stream.write_all(&nonce.to_be_bytes()).await?;
            stream.flush().await?;
            stream.read_exact(&mut back).await.map(|_| ())
        })
        .await?;
        times.push(started.elapsed());
    }
    times.sort();
    if let (Some(least), Some(median)) = (times.first(), times.get(times.len() / 2)) {
        say(format_args!("echo_min_ms.{port}"), least.as_millis());
        say(format_args!("echo_median_ms.{port}"), median.as_millis());
    }
    Ok(())
}

/// The relay sends; we count what arrives until it ends or the time is up.
async fn source(session: &Session, config: &ProbeConfig) -> io::Result<()> {
    let wait = config.common.relay_connect;
    let (mut stream, status) = within(wait, session.request(&Open::Source(config.common.measure_bytes), &[])).await?;
    if status != Status::Connected {
        return Err(dial::refusal(status));
    }
    let started = Instant::now();
    let mut bytes: u64 = 0;
    let mut chunk = vec![0u8; CHUNK];
    let _ = tokio::time::timeout(config.run, async {
        while let Ok(n @ 1..) = stream.read(&mut chunk).await {
            bytes += n as u64;
        }
    })
    .await;
    say("source_bytes", bytes);
    say("source_ms", started.elapsed().as_millis());
    Ok(())
}

/// We send until the cap or the time is up; the relay reports what it counted.
async fn sink(session: &Session, config: &ProbeConfig) -> io::Result<()> {
    let wait = config.common.relay_connect;
    let (mut stream, status) = within(wait, session.request(&Open::Sink, &[])).await?;
    if status != Status::Connected {
        return Err(dial::refusal(status));
    }
    let started = Instant::now();
    let chunk = vec![0u8; CHUNK];
    let mut left = config.common.measure_bytes;
    let _ = tokio::time::timeout(config.run, async {
        while left > 0 {
            let n = usize::try_from(left).map_or(CHUNK, |l| l.min(CHUNK));
            if stream.write_all(&chunk[..n]).await.is_err() {
                return;
            }
            left -= n as u64;
        }
        let _ = stream.flush().await;
    })
    .await;
    let sending = started.elapsed();
    let counted = within(wait, async {
        stream.shutdown().await?;
        stream.read_u64().await
    })
    .await?;
    say("sink_bytes", counted);
    say("sink_ms", sending.as_millis());
    Ok(())
}

/// One port: the three setup times, the certificate's standing, and the echoes. Returns the
/// carrier if it came up.
async fn port(dialer: &Dialer, relay: SocketAddr, wait: Duration) -> Option<Session> {
    let port = relay.port();
    match tokio::time::timeout(wait, dialer.dial(relay)).await {
        Ok(Ok((connection, timings))) => {
            say(format_args!("tcp.{port}"), "ok");
            say(format_args!("tls.{port}"), "ok");
            say(format_args!("ws.{port}"), "ok");
            say(format_args!("tcp_connect_ms.{port}"), timings.tcp.as_millis());
            say(format_args!("tls_ms.{port}"), timings.tls.as_millis());
            say(format_args!("ws_ms.{port}"), timings.upgrade.as_millis());
            let (session, driver) = Session::new(connection);
            tokio::spawn(driver);
            match echoes(&session, port, wait).await {
                Ok(()) => say(format_args!("echo.{port}"), "ok"),
                Err(_) => say(format_args!("echo.{port}"), "failed"),
            }
            Some(session)
        }
        Ok(Err(DialFailed::Tcp(_))) => {
            say(format_args!("tcp.{port}"), "failed");
            None
        }
        Ok(Err(DialFailed::Untrusted(_))) => {
            say(format_args!("tcp.{port}"), "ok");
            say(format_args!("tls.{port}"), "untrusted");
            None
        }
        Ok(Err(DialFailed::Tls(_))) => {
            say(format_args!("tcp.{port}"), "ok");
            say(format_args!("tls.{port}"), "failed");
            None
        }
        Ok(Err(DialFailed::Upgrade(_))) => {
            say(format_args!("tcp.{port}"), "ok");
            say(format_args!("tls.{port}"), "ok");
            say(format_args!("ws.{port}"), "failed");
            None
        }
        Err(_) => {
            say(format_args!("setup.{port}"), "timed-out");
            None
        }
    }
}

/// Many carrier setups at once on one port: how many did not come up.
async fn burst(dialer: &Dialer, relay: SocketAddr, count: u16, wait: Duration) {
    let started = Instant::now();
    let outcomes = join_all((0..count).map(|_| tokio::time::timeout(wait, dialer.dial(relay)))).await;
    let failed = outcomes.iter().filter(|outcome| !matches!(outcome, Ok(Ok(_)))).count();
    let port = relay.port();
    say(format_args!("burst_setups.{port}"), count);
    say(format_args!("burst_failed.{port}"), failed);
    say(format_args!("burst_ms.{port}"), started.elapsed().as_millis());
}

async fn run(config: ProbeConfig) -> Result<(), (u8, String)> {
    let common = &config.common;
    let bad = |name: &str, error: io::Error| (EXIT_BAD_INPUT, format!("{name}: {error}"));
    let key = tokio::fs::read_to_string(&common.key).await.map_err(|e| bad("SATMUX_DAEMON_KEY", e))?;
    let authorization = dial::bearer(&key).map_err(|e| bad("SATMUX_DAEMON_KEY", e))?;
    let tls = dial::tls_config(&common.roots).map_err(|e| bad("SATMUX_DAEMON_ROOTS", e))?;
    let factory = net::bound_to(&common.bind_interface).map_err(|e| bad("SATMUX_DAEMON_BIND_INTERFACE", e))?;
    let dialer = Dialer::new(common.relay_name.clone(), tls, authorization, factory, usize::from(common.streams.get())).map_err(|e| bad("SATMUX_RELAY_NAME", e))?;
    let wait = common.relay_connect;

    let mut addresses = resolvers(&config, &dialer).await;
    if addresses.is_empty() {
        let seeds = tokio::fs::read_to_string(common.state.join(find::SEED)).await.unwrap_or_default();
        addresses = find::seed_addresses(&seeds);
        say("relay_addresses_from", "seed");
    } else {
        say("relay_addresses_from", "resolver");
    }
    say("relay_addresses", addresses.len());
    let Some(address) = addresses.first().copied() else {
        return Err((EXIT_TEMPORARY, String::from("the relay's address is not known: no resolver answered and there is no seed")));
    };

    let mut carriers = Vec::new();
    for number in &common.ports {
        if let Some(session) = port(&dialer, SocketAddr::new(IpAddr::V4(address), *number), wait).await {
            carriers.push(session);
        }
    }
    for number in &common.ports {
        burst(&dialer, SocketAddr::new(IpAddr::V4(address), *number), config.burst.get(), wait).await;
    }
    if let Some(session) = carriers.first() {
        if source(session, &config).await.is_err() {
            say("source", "failed");
        }
        if sink(session, &config).await.is_err() {
            say("sink", "failed");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let config = match ProbeConfig::parse(config::process_environment()) {
        Ok(config) => config,
        Err(refused) => {
            eprintln!("satmux-probe: {refused}");
            return ExitCode::from(EXIT_BAD_INPUT);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("satmux-probe: runtime: {error}");
            return ExitCode::from(EXIT_TEMPORARY);
        }
    };
    match runtime.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, why)) => {
            eprintln!("satmux-probe: {why}");
            ExitCode::from(code)
        }
    }
}
