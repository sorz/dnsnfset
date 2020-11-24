use clap::{App, Arg};
use dns_parser::{rdata::RData, Packet as DnsPacket, QueryType};
use fstrm::FstrmReader;
use log::{debug, info, trace, warn};
use protobuf::parse_from_reader;
use std::{
    cell::RefCell,
    io::Result,
    net::IpAddr,
    os::unix::net::{UnixListener, UnixStream},
    thread,
    time::Instant,
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

fn handle_stream(stream: UnixStream) -> Result<()> {
    info!("unbound connected");

    let reader = FstrmReader::<_, ()>::new(stream);
    let mut reader = reader.accept()?.start()?;

    debug!("FSTRM handshake finish {:?}", reader.content_types());

    while let Some(mut frame) = reader.read_frame()? {
        let dnstap: Dnstap = parse_from_reader(&mut frame)?;
        let msg = dnstap.get_message();
        let resp = msg.get_response_message();
        debug!("got {:?} ({}B resp)", msg.get_field_type(), resp.len());
        if resp.is_empty() {
            continue;
        }
        match DnsPacket::parse(resp) {
            Err(err) => debug!("fail to parse dns packet: {}", err),
            Ok(packet) => handle_packet(packet),
        }
    }
    Ok(())
}

fn handle_packet(pkt: DnsPacket) {
    let name = pkt
        .questions
        .iter()
        .find(|question| matches!(question.qtype, QueryType::A | QueryType::AAAA))
        .map(|question| question.qname.to_string());
    trace!("name {:?}", name);

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
            let nft = opt.get_or_insert_with(Nftables::new);
            nft.run(cmd)
        });
        if result.is_err() {
            warn!("fail to run nft cmd");
        }
        debug!("{:?}", t.elapsed());
    }
}

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
    let mut socks_path: AutoRemoveFile = matches
        .value_of("socks-path")
        .expect("missing socks-path argument")
        .into();
    let file = matches.value_of("rules").expect("missing rules file path");

    let ruleset = RuleSet::from_file(file).expect("fail to load rules");
    info!("{} rules loaded", ruleset.len());
    RULES.with(|r| r.borrow_mut().replace(ruleset));

    let listener = UnixListener::bind(&socks_path).expect("fail to bind socket");
    info!("listen on {}", socks_path);
    socks_path.set_auto_remove(true);

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
