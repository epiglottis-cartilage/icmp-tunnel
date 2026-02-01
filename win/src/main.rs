#![allow(static_mut_refs)]
use core::{ipv4, ipv6};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    thread,
    time::Duration,
};
use windivert::prelude::{WinDivert, WinDivertFlags};
use windivert_sys::ChecksumFlags;

fn handle(broadcast4: Option<Ipv4Addr>, broadcast6: Option<Ipv6Addr>) {
    let filter = WinDivert::network(
        String::from_utf8(std::fs::read("filter.cfg").expect("Cannot read filter.cfg")).unwrap(),
        0,
        WinDivertFlags::new().set_fragments(),
    )
    .expect("Run as admin?");

    #[allow(invalid_value)]
    let mut buffer: [u8; 9001] = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    #[cfg(not(debug_assertions))]
    thread::spawn(|| {
        loop {
            eprintln!(".");
            ipv4::summary();
            ipv6::summary();
            thread::sleep(Duration::from_secs(3));
        }
    });

    while let Ok(mut packet) = filter.recv(Some(&mut buffer)) {
        match packet.data[0] >> 4 {
            4 => ipv4::handle(packet.data.to_mut(), broadcast4),
            6 => ipv6::handle(packet.data.to_mut(), broadcast6),
            x @ _ => {
                eprintln!("Unknown IP protocol {}", x);
            }
        }
        packet
            .recalculate_checksums(ChecksumFlags::new().set_no_icmp().set_no_icmpv6())
            .unwrap();
        filter.send(&packet).unwrap();
    }
}

fn main() {
    let mut broadcast4 = None;
    let mut broadcast6 = None;
    std::env::args()
        .filter_map(|str| IpAddr::from_str(&str).ok())
        .for_each(|addr| match addr {
            IpAddr::V4(addr) => broadcast4 = Some(addr),
            IpAddr::V6(addr) => broadcast6 = Some(addr),
        });
    eprintln!("IPv4 broadcast package redirect to {:?}", broadcast4);
    eprintln!("IPv6 broadcast package redirect to {:?}", broadcast6);
    handle(broadcast4, broadcast6);
}
