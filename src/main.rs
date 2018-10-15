extern crate libc;
extern crate nflog;
extern crate dns_parser;
extern crate dnsnfset;
use std::net::IpAddr;
use libc::AF_INET;
use nflog::{Queue, Message, CopyMode};
use dns_parser::{Packet, rdata::RData};

use dnsnfset::nft::NftCommand;

fn callback(msg: &Message) {
    let payload = msg.get_payload();
    if payload.len() < 20 + 8 {
        println!("packet too short, ignored");
        return;
    }
    if payload[0] != 0x45 {
        println!("not ip4 packet, ignored");
        return;
    }
    match Packet::parse(&payload[28..]) {
        Err(err) => println!("fail to parse packet: {}", err),
        Ok(packet) => handle_packet(packet),
    }
}

fn handle_packet(pkt: Packet) {
    let records = pkt.answers.iter().filter_map(|record| {
        match record.data {
            RData::A(addr) => Some((record.name.to_string(), IpAddr::V4(addr.0))),
            RData::AAAA(addr) => Some((record.name.to_string(), IpAddr::V6(addr.0))),
            _ => None,
        }
    });
    let vec: Vec<_> = records.collect();

    println!("answers: {:?}", vec);
}

fn suffix_match(domain: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let mut domain = domain.split('.').rev();
    suffix.split('.').rev()
        .skip_while(|s| match domain.next() {
            Some(ss) => ss.eq_ignore_ascii_case(s),
            None => false,
        }).next() == None
}

fn main() {
    let mut queue = Queue::new();
    queue.open();
    let rc = queue.bind(AF_INET);
    if rc != 0 {
        panic!("fail to bind nfqueue");
    }
    queue.bind_group(1);
    queue.set_mode(CopyMode::CopyPacket, 0xffff);
    queue.set_callback(callback);
    queue.run_loop();
    queue.close();
}

#[test]
fn test_suffix_match() {
    assert_eq!(true, suffix_match("example.com", ""));
    assert_eq!(true, suffix_match("example.com", "com"));
    assert_eq!(true, suffix_match("eXaMpLe.cOm", "example.com"));
    assert_eq!(false, suffix_match("example.com", "other.example.com"));
    assert_eq!(false, suffix_match("examp1e.com", "example.com"));
}
