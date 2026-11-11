//! End to end on loopback: a client speaks CONNECT to the proxy front end, the uplink carries
//! the flow over real carriers (TLS 1.3 under a throwaway authority, WebSocket, yamux) to the
//! native relay, and the relay connects onward to an echo server. What comes back must be
//! exactly what went in.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::{Config as Cases, TestRunner};
use satmux_carrier::Uplink;
use satmux_carrier::dial::{self, Dialer};
use satmux_carrier::net::SocketFactory;
use satmux_carrier::pool::Rules;
use satmux_carrier::uplink::Parts;
use satmux_core::{HostName, KeyRing, digest_hex, key_digest};
use satmux_relay_logic::Limits;
use satmux_relay_native::{Config, DohUrl, PrivateDestinations, Tls};
use satmuxd::proxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls;

const RELAY_NAME: &str = "relay.test";
const KEY: &str = "a-device-key-for-tests";
const STREAMS: usize = 64;
const LONG: Duration = Duration::from_secs(3600);

/// A throwaway authority and a relay certificate under it.
struct Authority {
    roots_pem: String,
    acceptor: tokio_rustls::TlsAcceptor,
}

fn authority() -> Authority {
    let ca_key = rcgen::KeyPair::generate().expect("a key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("a root");
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf_key = rcgen::KeyPair::generate().expect("a key");
    let leaf = rcgen::CertificateParams::new(vec![RELAY_NAME.to_owned()]).expect("params").signed_by(&leaf_key, &issuer).expect("a leaf");
    let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).expect("a private key");
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .expect("a server");
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Authority { roots_pem: ca.pem(), acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server)) }
}

/// Runs the native relay on its own thread (it is single-threaded by design) and returns its port.
fn relay(acceptor: tokio_rustls::TlsAcceptor, private: PrivateDestinations) -> u16 {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("an address").port();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let config = Config {
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                tls: Tls::On(acceptor),
                keys: KeyRing::parse(&format!("device {}\n", digest_hex(&key_digest(KEY.as_bytes())))).expect("a ring"),
                build: String::from("test"),
                limits: Limits { streams: STREAMS, open: LONG, connect: LONG, measure_bytes: 1 << 20 },
                doh: DohUrl::parse("http://127.0.0.1:9/dns-query").expect("a url"),
                private,
            };
            let error = satmux_relay_native::serve(TcpListener::from_std(listener).expect("a listener"), config).await;
            panic!("the relay stopped: {error}");
        });
    });
    port
}

async fn echo_server() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("a listener");
    let port = listener.local_addr().expect("an address").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    port
}

/// Loopback sockets: the one thing the tests replace, because no interface is theirs to bind.
fn loopback() -> SocketFactory {
    Arc::new(|to| {
        let socket = socket2::Socket::new(socket2::Domain::for_address(to), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        Ok(socket)
    })
}

fn uplink(state: &Path, roots_pem: &str, key: &str, ports: Vec<u16>) -> Uplink {
    let roots = state.join("roots.pem");
    std::fs::write(&roots, roots_pem).expect("a roots file");
    let tls = dial::tls_config(&roots).expect("roots");
    let dialer = Dialer::new(HostName::parse(RELAY_NAME).expect("a name"), tls, dial::bearer(key).expect("a key"), loopback(), STREAMS).expect("a dialer");
    Uplink::start(Parts {
        rules: Rules { ports, streams: STREAMS, echo_idle: LONG, suspect: LONG, rotate: LONG, no_carrier_exit: LONG },
        dialer,
        relay: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        dial_wait: LONG,
        status_wait: LONG,
        direct_wait: LONG,
        verdict_life: LONG,
        state: state.to_owned(),
    })
    .expect("an uplink")
}

fn state_folder(tag: &str) -> std::path::PathBuf {
    let folder = std::env::temp_dir().join(format!("satmuxd-e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a folder");
    folder
}

async fn proxy_front(uplink: Uplink) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("a listener");
    let address = listener.local_addr().expect("an address");
    tokio::spawn(proxy::serve(listener, uplink, proxy::Waits { head: LONG, first_payload: LONG }));
    address
}

/// One flow through the proxy: CONNECT, then the chunks, then end of stream; returns all that
/// came back.
async fn through(proxy: SocketAddr, target: SocketAddr, chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).await.expect("the proxy");
    client.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.expect("a request");
    let mut reply = [0u8; 39];
    client.read_exact(&mut reply).await.expect("a reply");
    assert_eq!(&reply[..], b"HTTP/1.1 200 Connection established\r\n\r\n");
    let (mut read, mut write) = client.split();
    let sending = async {
        for chunk in chunks {
            write.write_all(chunk).await.expect("a write");
        }
        write.shutdown().await.expect("a half-close");
    };
    let receiving = async {
        let mut back = Vec::new();
        read.read_to_end(&mut back).await.expect("the echo");
        back
    };
    tokio::join!(sending, receiving).1
}

fn counter(status: &str, name: &str) -> u64 {
    status.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok()).expect("the counter is in the status")
}

fn payload() -> impl Strategy<Value = Vec<Vec<u8>>> {
    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..20_000), 1..8)
}

/// Whatever bytes a client sends through proxy, uplink and relay to an echo server come back
/// unchanged, over carriers on two ports, several flows at a time.
#[test]
fn bytes_survive_the_whole_path() {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime");
    let authority = authority();
    let ports = vec![relay(authority.acceptor.clone(), PrivateDestinations::Allowed), relay(authority.acceptor.clone(), PrivateDestinations::Allowed)];
    let state = state_folder("relay");
    let (uplink, proxy, echo) = runtime.block_on(async {
        let uplink = uplink(&state, &authority.roots_pem, KEY, ports);
        uplink.ready().wait_for(|up| *up).await.expect("a ready carrier");
        (uplink.clone(), proxy_front(uplink).await, SocketAddr::from((Ipv4Addr::LOCALHOST, echo_server().await)))
    });
    let flows = std::cell::Cell::new(0u64);
    TestRunner::new(Cases::with_cases(24))
        .run(&proptest::collection::vec(payload(), 1..5), |payloads| {
            flows.set(flows.get() + payloads.len() as u64);
            let echoed = runtime.block_on(futures::future::join_all(payloads.iter().map(|chunks| through(proxy, echo, chunks))));
            for (chunks, back) in payloads.iter().zip(echoed) {
                prop_assert_eq!(back, chunks.concat());
            }
            Ok(())
        })
        .expect("every flow echoes");
    let status = uplink.status();
    assert_eq!(counter(&status, "flows.relayed"), flows.get(), "{status}");
    assert_eq!(counter(&status, "flows.direct"), 0, "{status}");
}

/// A destination the relay refuses as forbidden is reached directly, first payload replayed,
/// and the bytes are still exactly the client's.
#[test]
fn a_forbidden_destination_goes_direct() {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime");
    let authority = authority();
    let ports = vec![relay(authority.acceptor.clone(), PrivateDestinations::Refused)];
    let state = state_folder("direct");
    let (uplink, proxy, echo) = runtime.block_on(async {
        let uplink = uplink(&state, &authority.roots_pem, KEY, ports);
        uplink.ready().wait_for(|up| *up).await.expect("a ready carrier");
        (uplink.clone(), proxy_front(uplink).await, SocketAddr::from((Ipv4Addr::LOCALHOST, echo_server().await)))
    });
    let flows = std::cell::Cell::new(0u64);
    TestRunner::new(Cases::with_cases(16))
        .run(&payload(), |chunks| {
            flows.set(flows.get() + 1);
            prop_assert_eq!(runtime.block_on(through(proxy, echo, &chunks)), chunks.concat());
            Ok(())
        })
        .expect("every flow echoes");
    let status = uplink.status();
    assert_eq!(counter(&status, "flows.direct"), flows.get(), "{status}");
    assert_eq!(counter(&status, "flows.relayed"), 0, "{status}");
}
