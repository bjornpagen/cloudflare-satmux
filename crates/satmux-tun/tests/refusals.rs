//! What the tunnel refuses, seen as raw packets on the device: UDP anywhere but the resolver is
//! answered with an ICMP port-unreachable, and an IPv6 TCP open is reset.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use proptest::prelude::*;
use satmux_tun::{Connect, Resolve, TunConfig};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4DstUnreachable, Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};
use tokio::net::UnixDatagram;

const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);

fn unicast(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    (1..224).contains(&first) && first != 127
}

async fn exchange(family: i32, packet: Vec<u8>) -> Vec<u8> {
    // One folder per exchange: the two properties run at once in one process, and each removes
    // its folder when it is done.
    static EXCHANGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let exchange = EXCHANGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let state = std::env::temp_dir().join(format!("satmux-tun-refusals-{}-{exchange}", std::process::id()));
    std::fs::create_dir_all(&state).expect("a state folder");
    let (ours, theirs) = std::os::unix::net::UnixDatagram::pair().expect("a socket pair");
    theirs.set_nonblocking(true).expect("non-blocking");
    let link = UnixDatagram::from_std(theirs).expect("a runtime");
    let connect: Connect = Arc::new(|_, _| async { Err(std::io::ErrorKind::ConnectionRefused.into()) }.boxed());
    let resolve: Resolve = Arc::new(|_| async { Err(std::io::ErrorKind::Unsupported.into()) }.boxed());
    let config = TunConfig {
        dns_address: RESOLVER,
        placeholders: (Ipv4Addr::new(198, 18, 0, 0), 24),
        answer_ttl: Duration::from_secs(1),
        placeholder_hold: Duration::from_secs(3600),
        state: state.clone(),
        mtu: 1500,
        first_payload_wait: Duration::from_millis(1),
    };
    let tunnel = tokio::spawn(satmux_tun::run(OwnedFd::from(ours), config, connect, resolve));
    let mut frame = (family as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&packet);
    link.send(&frame).await.expect("the link");
    let mut answer = vec![0u8; 1504];
    let length = link.recv(&mut answer).await.expect("the link");
    tunnel.abort();
    let _ = std::fs::remove_dir_all(&state);
    assert_eq!(answer[..4], (family as u32).to_be_bytes());
    answer[4..length].to_vec()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn udp_elsewhere_is_refused_at_once(
        source in any::<u32>().prop_map(Ipv4Addr::from).prop_filter("unicast", |a| unicast(*a)),
        target in any::<u32>().prop_map(Ipv4Addr::from).prop_filter("unicast", |a| unicast(*a)),
        source_port in 1u16..,
        target_port in 1u16..,
        payload in proptest::collection::vec(any::<u8>(), 0..1200),
    ) {
        prop_assume!(!(target == RESOLVER && target_port == 53) && source != target);
        let checksums = ChecksumCapabilities::default();
        let header = Ipv4Repr { src_addr: source, dst_addr: target, next_header: IpProtocol::Udp, payload_len: 8 + payload.len(), hop_limit: 64 };
        let mut packet = vec![0; header.buffer_len() + header.payload_len];
        let (ip, udp) = packet.split_at_mut(header.buffer_len());
        header.emit(&mut Ipv4Packet::new_unchecked(ip), &checksums);
        UdpRepr { src_port: source_port, dst_port: target_port }.emit(
            &mut UdpPacket::new_unchecked(udp), &source.into(), &target.into(), payload.len(), |bytes| bytes.copy_from_slice(&payload), &checksums,
        );
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime");
        let answer = runtime.block_on(exchange(libc::AF_INET, packet));
        let ip = Ipv4Packet::new_checked(&answer[..]).expect("an IPv4 packet");
        let back = Ipv4Repr::parse(&ip, &checksums).expect("a sound header");
        prop_assert_eq!((back.src_addr, back.dst_addr, back.next_header), (target, source, IpProtocol::Icmp));
        let icmp = Icmpv4Packet::new_checked(ip.payload()).expect("an ICMP packet");
        prop_assert!(icmp.verify_checksum());
        prop_assert_eq!(icmp.msg_type(), Icmpv4Message::DstUnreachable);
        prop_assert_eq!(icmp.msg_code(), u8::from(Icmpv4DstUnreachable::PortUnreachable));
        let quoted = icmp.data();
        prop_assert_eq!(&quoted[12..16], &source.octets());
        prop_assert_eq!(&quoted[16..20], &target.octets());
        prop_assert_eq!(&quoted[20..24], &[source_port.to_be_bytes(), target_port.to_be_bytes()].concat()[..]);
    }

    #[test]
    fn an_ipv6_open_is_reset(
        source in any::<[u8; 16]>().prop_map(|mut a| { a[0] = 0x20; Ipv6Addr::from(a) }),
        target in any::<[u8; 16]>().prop_map(|mut a| { a[0] = 0x26; Ipv6Addr::from(a) }),
        source_port in 1u16..,
        target_port in 1u16..,
        sequence in any::<i32>(),
    ) {
        let checksums = ChecksumCapabilities::default();
        let syn = TcpRepr {
            src_port: source_port, dst_port: target_port, control: TcpControl::Syn, seq_number: TcpSeqNumber(sequence),
            ack_number: None, window_len: 65_535, window_scale: None, max_seg_size: Some(1220), sack_permitted: false,
            sack_ranges: [None, None, None], timestamp: None, payload: &[],
        };
        let header = Ipv6Repr { src_addr: source, dst_addr: target, next_header: IpProtocol::Tcp, payload_len: syn.buffer_len(), hop_limit: 64 };
        let mut packet = vec![0; header.buffer_len() + header.payload_len];
        let (ip, tcp) = packet.split_at_mut(header.buffer_len());
        header.emit(&mut Ipv6Packet::new_unchecked(ip));
        syn.emit(&mut TcpPacket::new_unchecked(tcp), &source.into(), &target.into(), &checksums);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime");
        let answer = runtime.block_on(exchange(libc::AF_INET6, packet));
        let ip = Ipv6Packet::new_checked(&answer[..]).expect("an IPv6 packet");
        let back = Ipv6Repr::parse(&ip).expect("a sound header");
        prop_assert_eq!((back.src_addr, back.dst_addr, back.next_header), (target, source, IpProtocol::Tcp));
        let tcp = TcpPacket::new_checked(ip.payload()).expect("a TCP segment");
        let reset = TcpRepr::parse(&tcp, &target.into(), &source.into(), &checksums).expect("a sound segment");
        prop_assert_eq!(reset.control, TcpControl::Rst);
        prop_assert_eq!((reset.src_port, reset.dst_port), (target_port, source_port));
        prop_assert_eq!(reset.ack_number, Some(TcpSeqNumber(sequence) + 1));
    }
}
