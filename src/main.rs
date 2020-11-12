use clap::{App, Arg};
use env_logger;
use log::{debug, info, trace, warn};
use protobuf::CodedInputStream;
use std::{
    cell::RefCell,
    io::{Read, Result},
    net::IpAddr,
    os::unix::net::{UnixListener, UnixStream},
    thread,
};

use dnsnfset::{
    dnstap::Dnstap,
    nft::{NftCommand, NftSetElemType},
    nftables::Nftables,
    rule::{RuleSet, Set},
    socks::AutoRemoveFile,
};

thread_local! {
    static RULES: RefCell<Option<RuleSet>> = RefCell::default();
    static NFT: RefCell<Option<Nftables>> = RefCell::default();
}

fn handle_stream(mut stream: UnixStream) -> Result<()> {
    info!("unbound connected");

    let mut input = CodedInputStream::new(&mut stream);

    loop {
        let msg: Dnstap = input.read_message()?;
        debug!("recv: {:?}", msg);
    }

    /*
    let ip = msg.get_payload();
    let payload = match SlicedPacket::from_ip(&ip) {
        Err(err) => return warn!("fail to parse ip packet: {:?}", err),
        Ok(packet) => match packet.transport {
            None => return warn!("missing tranposrt-layer packet"),
            Some(TransportSlice::Tcp(_)) => return warn!("tcp segment found"),
            Some(TransportSlice::Udp(_)) => packet.payload,
        },
    };
    match Packet::parse(payload) {
        Err(err) => debug!("fail to parse dns packet: {}", err),
        Ok(packet) => handle_packet(packet),
    }
    */
}

/*
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
        let sets = RULES.with(|ruleset| {
            ruleset
                .borrow()
                .as_ref()
                .expect("uninitialised ruleset")
                .match_all(&name)
        });
        if sets.is_empty() {
            return;
        }
        let records: Vec<_> = pkt
            .answers
            .iter()
            .filter_map(|record| match record.data {
                RData::A(addr) => Some(IpAddr::V4(addr.0)),
                RData::AAAA(addr) => Some(IpAddr::V6(addr.0)),
                _ => None,
            })
            .collect();

        let mut cmd = String::new();
        for set in sets {
            for addr in records.iter() {
                add_element(&mut cmd, &set, &name, &addr);
            }
        }
        if cmd.is_empty() {
            return;
        }

        info!("{} matched", name);
        trace!("{}", cmd);
        let t = Instant::now();
        let result = NFT.with(|opt| {
            let mut opt = opt.borrow_mut();
            let nft = opt.get_or_insert_with(|| Nftables::new());
            nft.run(cmd)
        });
        if result.is_err() {
            warn!("fail to run nft cmd");
        }
        debug!("{:?}", t.elapsed());
    }
}
*/

fn add_element(buf: &mut String, set: &Set, name: &str, addr: &IpAddr) {
    match (set.elem_type, addr) {
        (NftSetElemType::Ipv4Addr, IpAddr::V6(_)) | (NftSetElemType::Ipv6Addr, IpAddr::V4(_)) => (),
        _ => {
            debug!("add {} {:?} to {}", name, addr, set.set_name);
            buf.add_element(set.family, &set.table, &set.set_name, addr, &set.timeout);
        }
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let matches = App::new("dnsnfset")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Shell Chen <me@sorz.org>")
        .about("Add IPs in DNS response to nftables sets")
        .arg(
            Arg::with_name("socks-path")
                .long("socks-path")
                .short("s")
                .help("UNIX domain socket to bind on")
                .takes_value(true)
                .default_value("/var/run/dnsnfset/dnstap.sock"),
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
    let socks_path: AutoRemoveFile = matches
        .value_of("socks-path")
        .expect("missing socks-path argument")
        .into();
    let file = matches.value_of("rules").expect("missing rules file path");

    let ruleset = RuleSet::from_file(file).expect("fail to load rules");
    info!("{} rules loaded", ruleset.len());
    RULES.with(|r| r.borrow_mut().replace(ruleset));

    let listener = UnixListener::bind(&socks_path).expect("fail to bind socket");
    info!("listen on {}", socks_path);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || match handle_stream(stream) {
                    Ok(_) => info!("unbound disconnected"),
                    Err(err) => warn!("error on thread: {}", err),
                });
            }
            Err(err) => panic!("fail to connect: {}", err),
        }
    }
}
