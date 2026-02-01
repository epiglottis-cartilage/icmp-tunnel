pub mod ipv4 {
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{LazyLock, Mutex};
    static STAT: LazyLock<Mutex<BTreeMap<(Ipv4Addr, Ipv4Addr), usize>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    const PROTO_ICMP: u8 = 0x1;
    const PROTO_TCP: u8 = 0x6;
    const PROTO_UDP: u8 = 0x11;
    fn add_wrapper(packet: &mut [u8]) {
        match packet[9] {
            PROTO_TCP => {}
            PROTO_UDP => {
                packet[6] |= 0x80;
            }
            _ => unreachable!("Only wrap TCP or UDP packets"),
        }
        packet[9] = PROTO_ICMP;
    }

    fn rm_wrapper(packet: &mut [u8]) {
        match packet[6] & 0x80 {
            0x00 => {
                packet[9] = PROTO_TCP;
            }
            _ => {
                packet[9] = PROTO_UDP;
            }
        }
        packet[6] &= !0x80;
    }

    #[inline]
    fn should_warp(packet: &[u8]) -> bool {
        packet[9] == PROTO_TCP
            || (packet[9] == PROTO_UDP && u16::from_be_bytes([packet[22], packet[23]]) != 53)
    }

    #[inline]
    fn is_wrapped(packet: &[u8]) -> bool {
        packet[9] == PROTO_ICMP
            && packet.len() > 22
            && !(packet[21] == 0 && (packet[20] == 0 || packet[20] == 8))
    }

    #[inline]
    fn is_broadcast(packet: &[u8]) -> bool {
        let dst = std::net::Ipv4Addr::from_octets(*packet[16..].first_chunk().unwrap());
        dst.octets()[3] == 255
    }
    fn speed_statistics(packet: &[u8]) {
        let src = Ipv4Addr::from_octets(*packet[12..].first_chunk().unwrap());
        let dst = Ipv4Addr::from_octets(*packet[16..].first_chunk().unwrap());
        *STAT.lock().unwrap().entry((src, dst)).or_default() += packet.len();
    }
    #[allow(dead_code)]
    fn display(packet: &[u8]) {
        let src = Ipv4Addr::from_octets(*packet[12..].first_chunk().unwrap());
        let dst = Ipv4Addr::from_octets(*packet[16..].first_chunk().unwrap());
        match packet[9] {
            PROTO_ICMP => {
                eprint!(
                    "ICMP {:>20} -> {:>20} {}",
                    src,
                    dst,
                    match packet[20] {
                        0 => "Echo Reply  ",
                        8 => "Echo Request",
                        _ => "Unknown     ",
                    }
                );
            }
            PROTO_TCP => {
                let src = SocketAddrV4::new(src, u16::from_be_bytes([packet[20], packet[21]]));
                let dst = SocketAddrV4::new(dst, u16::from_be_bytes([packet[22], packet[23]]));
                eprint!("TCP  {:>20} -> {:<20}", src, dst);
            }
            PROTO_UDP => {
                let src = SocketAddrV4::new(src, u16::from_be_bytes([packet[20], packet[21]]));
                let dst = SocketAddrV4::new(dst, u16::from_be_bytes([packet[22], packet[23]]));
                eprint!("UDP  {:>20} -> {:<20}", src, dst);
            }
            _ => {
                eprint!("Unknown protocol {:X}", packet[9]);
            }
        }
        eprintln!("\tlen:[{}]", packet.len());
    }
    pub fn handle(packet: &mut [u8], broadcast: Option<Ipv4Addr>) {
        if is_wrapped(packet) {
            rm_wrapper(packet);

            #[cfg(debug_assertions)]
            display(packet);
            speed_statistics(packet);
        } else if should_warp(packet) {
            #[cfg(debug_assertions)]
            display(packet);
            speed_statistics(packet);

            if is_broadcast(packet) {
                if let Some(broadcast) = broadcast {
                    packet[16..20].copy_from_slice(&broadcast.octets());
                }
            }
            add_wrapper(packet);
        } else {
            #[cfg(debug_assertions)]
            display(packet);
        }
    }
    pub fn summary() {
        let mut guard = STAT.lock().unwrap();
        guard.retain(|_, cnt| *cnt != 0);
        for (l, cnt) in guard.iter_mut() {
            eprintln!("{} - {} {}KiB", l.0, l.1, *cnt / 1024);
            *cnt = 0;
        }
    }
}
pub mod ipv6 {
    use std::{
        collections::BTreeMap,
        net::{Ipv6Addr, SocketAddrV6},
        sync::{LazyLock, Mutex},
    };
    static STAT: LazyLock<Mutex<BTreeMap<(Ipv6Addr, Ipv6Addr), usize>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    const PROTO_ICMPV6: u8 = 0x3A;
    const PROTO_TCP: u8 = 0x6;
    const PROTO_UDP: u8 = 0x11;

    fn add_wrapper(packet: &mut [u8]) {
        match packet[6] {
            PROTO_TCP => {
                packet[1] |= 0xE0;
            }
            PROTO_UDP => {
                packet[1] |= 0xC0;
            }
            _ => unreachable!("Only wrap TCP or UDP packets"),
        }
        packet[6] = PROTO_ICMPV6;
    }

    fn rm_wrapper(packet: &mut [u8]) {
        let traffic_class = packet[1];
        let proto = match traffic_class & 0xE0 {
            0xE0 => PROTO_TCP,
            0xC0 => PROTO_UDP,
            _ => unreachable!("Unknown mark {:X}", traffic_class),
        };
        packet[6] = proto;
        packet[1] &= !0xE0;
    }

    #[inline]
    fn should_wrap(packet: &[u8]) -> bool {
        packet[6] == PROTO_TCP
            || (packet[6] == PROTO_UDP && u16::from_be_bytes([packet[26], packet[27]]) != 53)
    }

    #[inline]
    fn is_wrapped(packet: &[u8]) -> bool {
        packet[6] == PROTO_ICMPV6
            && packet[1] & !0xE0 != 0
            && packet.len() > 42
            && !(packet[41] == 0 && (packet[40] == 0 || packet[40] == 128))
    }

    #[inline]
    fn is_broadcast(packet: &[u8]) -> bool {
        let dst = Ipv6Addr::from_octets(*packet[24..].first_chunk().unwrap());
        dst.octets()[0] == 0xFF
    }
    fn speed_statistics(packet: &[u8]) {
        let src = Ipv6Addr::from_octets(*packet[8..].first_chunk().unwrap());
        let dst = Ipv6Addr::from_octets(*packet[24..].first_chunk().unwrap());
        *STAT.lock().unwrap().entry((src, dst)).or_default() += packet.len();
    }
    #[allow(dead_code)]
    fn display(packet: &[u8]) {
        let src = Ipv6Addr::from_octets(*packet[8..].first_chunk().unwrap());
        let dst = Ipv6Addr::from_octets(*packet[24..].first_chunk().unwrap());
        match packet[6] {
            PROTO_ICMPV6 => {
                eprint!(
                    "ICMP {:>46} -> {:<46} {}",
                    src,
                    dst,
                    match packet[40] {
                        0 => "Echo Reply  ",
                        128 => "Echo Request",
                        _ => "Unknown     ",
                    }
                );
            }
            PROTO_TCP => {
                let src =
                    SocketAddrV6::new(src, u16::from_be_bytes([packet[24], packet[25]]), 0, 0);
                let dst =
                    SocketAddrV6::new(dst, u16::from_be_bytes([packet[26], packet[27]]), 0, 0);
                eprint!("TCP  {:>46} -> {:<46}", src, dst);
            }
            PROTO_UDP => {
                let src =
                    SocketAddrV6::new(src, u16::from_be_bytes([packet[24], packet[25]]), 0, 0);
                let dst =
                    SocketAddrV6::new(dst, u16::from_be_bytes([packet[26], packet[27]]), 0, 0);
                eprint!("UDP  {:>46} -> {:<46}", src, dst);
            }
            _ => {
                eprint!("Unknown protocol {:X}", packet[6]);
            }
        }
        eprintln!("\tlen:[{}]", packet.len());
    }

    pub fn handle(packet: &mut [u8], broadcast: Option<Ipv6Addr>) {
        if is_wrapped(packet) {
            rm_wrapper(packet);

            #[cfg(debug_assertions)]
            display(packet);
            speed_statistics(packet);
        } else if should_wrap(packet) {
            add_wrapper(packet);

            #[cfg(debug_assertions)]
            display(packet);
            speed_statistics(packet);

            if is_broadcast(packet) {
                if let Some(broadcast) = broadcast {
                    packet[24..32].copy_from_slice(&broadcast.octets());
                }
            }
        } else {
            #[cfg(debug_assertions)]
            display(packet);
        }
    }
    pub fn summary() {
        let mut guard = STAT.lock().unwrap();
        guard.retain(|_, cnt| *cnt != 0);
        for (l, cnt) in guard.iter_mut() {
            eprintln!("{} - {} {}KiB", l.0, l.1, *cnt / 1024);
            *cnt = 0;
        }
    }
}
