use clap::{App, Arg};
use dns_parser::{rdata::RData, Packet, QueryType};
use env_logger;
use libc::AF_INET;
use log::{debug, info, warn};
use nflog::{CopyMode, Message, Queue};
use std::cell::RefCell;
use std::net::IpAddr;
use std::time::Instant;
use etherparse::{SlicedPacket, TransportSlice};

use dnsnfset::nft::{NftCommand, NftSetElemType};
use dnsnfset::rule::{load_rules, Rule};
use dnsnfset::nftables::Nftables;

thread_local! {
    static RULES: RefCell<Vec<Rule>> = RefCell::default();
    static NFT: RefCell<Option<Nftables>> = RefCell::default();
}

fn callback(msg: &Message) {
    let ip = msg.get_payload();
    let payload = match SlicedPacket::from_ip(&ip) {
        Err(err) => return warn!("fail to parse ip packet: {:?}", err),
        Ok(packet) => match packet.transport {
            None => return warn!("missing tranposrt-layer packet"),
            Some(TransportSlice::Tcp(_)) => return warn!("tcp segment found"),
            Some(TransportSlice::Udp(_)) => packet.payload,
        }
    };
    match Packet::parse(payload) {
        Err(err) => warn!("fail to parse packet: {}", err),
        Ok(packet) => handle_packet(packet),
    }
}

fn handle_packet(pkt: Packet) {
    let name = pkt
        .questions
        .iter()
        .find(|question| match question.qtype {
            QueryType::A | QueryType::AAAA => true,
            _ => false,
        })
        .map(|question| question.qname.to_string());

    if let Some(name) = name {
        let records: Vec<_> = pkt
            .answers
            .iter()
            .filter_map(|record| match record.data {
                RData::A(addr) => Some(IpAddr::V4(addr.0)),
                RData::AAAA(addr) => Some(IpAddr::V6(addr.0)),
                _ => None,
            })
            .collect(); // TODO: avoid allocate before match rule

        let mut cmds = NftCommand::new();
        RULES.with(|rules| {
            let ruleset = rules.borrow();
            let rules = ruleset.iter().filter(|rule| rule.is_match(&name));
            for rule in rules {
                for addr in records.iter() {
                    add_element(&mut cmds, rule, &name, &addr);
                }
            }
        });
        if !cmds.is_empty() {
            info!("{} matched", name);
            debug!("{}", cmds.cmd);
            let t = Instant::now();
            let result = NFT.with(|opt| {
                let mut opt = opt.borrow_mut();
                let nft = opt.get_or_insert_with(|| Nftables::new());
                nft.run(cmds.cmd)
            });
            if result.is_err() {
                warn!("fail to run nft cmd");
            }
            debug!("{:?}", t.elapsed());
        }
    }
}

fn add_element(nft: &mut NftCommand, rule: &Rule, name: &str, addr: &IpAddr) {
    match (rule.elem_type, addr) {
        (NftSetElemType::Ipv4Addr, IpAddr::V6(_)) | (NftSetElemType::Ipv6Addr, IpAddr::V4(_)) => (),
        _ => {
            debug!("add {} {:?} to {}", name, addr, rule.set);
            nft.add_element(rule.family, &rule.table, &rule.set, addr, &rule.timeout);
        }
    }
}

fn main() {
    env_logger::builder()
        .default_format_timestamp(false)
        .init();
    let matches = App::new("dnsnfset")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Shell Chen <me@sorz.org>")
        .about("Add IPs in DNS response to nftables sets")
        .arg(
            Arg::with_name("group")
                .long("group")
                .short("n")
                .help("NFLOG group to bind on")
                .takes_value(true)
                .default_value("0"),
        )
        .arg(
            Arg::with_name("rules")
                .long("rules")
                .short("f")
                .help("Rules file")
                .takes_value(true)
                .default_value("rules.conf"),
        )
        .get_matches();
    let group = matches
        .value_of("group")
        .expect("missing NFLOG group")
        .parse()
        .expect("group must be a natural number");
    let file = matches.value_of("rules").expect("missing rules file path");

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
