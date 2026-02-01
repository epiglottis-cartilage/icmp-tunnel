use core::{ipv4, ipv6};
use nfq::{Queue, Verdict};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    thread,
    time::Duration,
};
const QUE: u16 = 472;

fn handle(broadcast4: Option<Ipv4Addr>, broadcast6: Option<Ipv6Addr>) {
    let mut queue = Queue::open().expect("Failed to open queue");
    queue.bind(QUE).expect("Run as admin?");
    eprintln!("[info] listen to queue {}", QUE);
    #[cfg(not(debug_assertions))]
    thread::spawn(|| {
        loop {
            eprintln!(".");
            ipv4::summary();
            ipv6::summary();
            thread::sleep(Duration::from_secs(3));
        }
    });

    while let Ok(mut msg) = queue.recv() {
        let payload = msg.get_payload_mut();
        match payload[0] >> 4 {
            4 => ipv4::handle(payload, broadcast4),
            6 => ipv6::handle(payload, broadcast6),
            x @ _ => {
                eprintln!("Unknown IP protocol {}", x);
            }
        }
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg).unwrap();
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
