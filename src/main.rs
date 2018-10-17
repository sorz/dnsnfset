#[macro_use]
extern crate log;
extern crate env_logger;
extern crate libc;
extern crate nflog;
extern crate dns_parser;
extern crate dnsnfset;
extern crate clap;
use std::net::IpAddr;
use std::cell::RefCell;
use libc::AF_INET;
use nflog::{Queue, Message, CopyMode};
use dns_parser::{Packet, rdata::RData};
use clap::{App, Arg};

use dnsnfset::nft::{NftCommand, NftSetElemType};
use dnsnfset::rule::{Rule, load_rules};

thread_local! {
    static RULES: RefCell<Vec<Rule>> = RefCell::default();
}

fn callback(msg: &Message) {
    let payload = msg.get_payload();
    if payload.len() < 20 + 8 {
        warn!("packet too short, ignored");
        return;
    }
    if payload[0] != 0x45 {
        warn!("not ip4 packet, ignored");
        return;
    }
    match Packet::parse(&payload[28..]) {
        Err(err) => warn!("fail to parse packet: {}", err),
        Ok(packet) => handle_packet(packet),
    }
}

fn handle_packet(pkt: Packet) {
    let records = pkt.answers.iter().filter_map(|record| {
        match record.data {
            RData::A(addr) =>
                Some((record.name.to_string(), IpAddr::V4(addr.0))),
            RData::AAAA(addr) =>
                Some((record.name.to_string(), IpAddr::V6(addr.0))),
            _ => None,
        }
    });

    let mut nft = NftCommand::new();
    RULES.with(|rules| {
        let rules = rules.borrow();
        for (name, addr) in records {
            for rule in rules.iter() {
                if rule.is_match(&name) {
                    add_element(&mut nft, rule, &name, &addr);
                }
            }
        }
    });
    if !nft.is_empty() {
        debug!("{}", nft.cmd);
        let result = nft.execute().expect("fail to run nft");
        if !result.success() {
            warn!("nft return error: {:?}", result.code());
        }
    }
}

fn add_element(nft: &mut NftCommand, rule: &Rule, name: &str, addr: &IpAddr) {
    match (rule.elem_type, addr) {
        (NftSetElemType::Ipv4Addr, IpAddr::V6(_)) |
        (NftSetElemType::Ipv6Addr, IpAddr::V4(_)) => (),
        _ => {
            info!("add {} {:?} to {}", name, addr, rule.set);
            nft.add_element(
                rule.family, &rule.table, &rule.set,
                addr, &rule.timeout,
            );
        }
    }
}

fn main() {
    env_logger::init();
    let matches = App::new("dnsnfset")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Shell Chen <me@sorz.org>")
        .about("Add IPs in DNS response to nftables sets")
        .arg(Arg::with_name("group")
             .long("group")
             .short("n")
             .help("NFLOG group to bind on")
             .takes_value(true)
             .default_value("0"))
        .arg(Arg::with_name("rules")
             .long("rules")
             .short("f")
             .help("Rules file")
             .takes_value(true)
             .default_value("rules.conf"))
        .get_matches();
    let group = matches.value_of("group")
        .expect("missing NFLOG group")
        .parse().expect("group must be a natural number");
    let file = matches.value_of("rules")
        .expect("missing rules file path");

    let rules = load_rules(file);
    info!("{} rules loaded", rules.len());
    RULES.with(|r| r.borrow_mut().extend(rules.into_iter()));

    let mut queue = Queue::new();
    queue.open();
    let rc = queue.bind(AF_INET);
    if rc != 0 {
        panic!("fail to bind nfqueue");
    }
    queue.bind_group(group);
    queue.set_mode(CopyMode::CopyPacket, 0xffff);
    queue.set_callback(callback);
    info!("listen on queue {}", group);
    queue.run_loop();
    info!("exit");
    queue.close();
}

