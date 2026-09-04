use clap::{Arg, Command};
use dns_parser::{rdata::RData, Error as DnsError, Packet as DnsPacket, QueryType};
use fstrm::FstrmReader;
use log::{debug, info, trace, warn};
use protobuf::prelude::*;
use std::{
    io::{self, Read, Result},
    net::IpAddr,
    os::unix::net::{UnixListener, UnixStream},
    sync::Arc,
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

fn handle_stream(stream: UnixStream, ruleset: Arc<RuleSet>) -> Result<()> {
    info!("unbound connected");
    let reader = FstrmReader::<_, ()>::new(stream);
    let mut reader = reader.accept()?.start()?;
    debug!("FSTRM handshake finish {:?}", reader.content_types());

    let mut nft = Nftables::new();
    let mut buf = Vec::new();

    while let Some(mut frame) = reader.read_frame()? {
        buf.clear();
        frame.read_to_end(&mut buf)?;
        // FIXME: bubble up parse error
        let dnstap = Dnstap::parse(&buf).map_err(|_| io::ErrorKind::InvalidData)?;
        let msg = dnstap.message();
        let resp = msg.response_message();
        trace!("got {:?} ({}B resp)", msg.r#type(), resp.len());
        if resp.is_empty() {
            continue;
        }
        match DnsPacket::parse(resp) {
            Err(DnsError::InvalidQueryType(_)) => (),
            Err(err) => debug!("fail to parse dns packet: {}", err),
            Ok(packet) => handle_packet(packet, &ruleset, &mut nft),
        }
    }
    Ok(())
}

fn handle_packet(pkt: DnsPacket, ruleset: &RuleSet, nft: &mut Nftables) {
    let qtype_qname = pkt
        .questions
        .iter()
        .find(|q| matches!(q.qtype, QueryType::A | QueryType::AAAA))
        .map(|q| (q.qtype, q.qname.to_string()));
    trace!("name {:?}", qtype_qname);

    if let Some((qtype, name)) = qtype_qname {
        let sets = ruleset.match_all(&name);
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
            debug!("match {} with zero {:?} record", name, qtype);
            return;
        }
        info!(
            "match {} with {} {:?} record(s)",
            name,
            records.len(),
            qtype
        );
        trace!("{}", cmd);
        let t = Instant::now();
        if nft.run(cmd).is_err() {
            warn!("fail to run nft cmd");
        }
        debug!("{:?}", t.elapsed());
    }
}

fn add_element(buf: &mut String, set: &Set, name: &str, addr: &IpAddr) {
    match (set.elem_type, addr) {
        (NftSetElemType::Ipv4Addr, IpAddr::V6(_)) | (NftSetElemType::Ipv6Addr, IpAddr::V4(_)) => (),
        _ => {
            debug!("  add {} {:?} to {}", name, addr, set.set_name);
            buf.add_element(set.family, &set.table, &set.set_name, addr, &set.timeout);
        }
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let matches = Command::new("dnsnfset")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Shell Chen <me@sorz.org>")
        .about("Add IPs in DNS response to nftables sets")
        .arg(
            Arg::new("socks-path")
                .long("socks-path")
                .short('s')
                .help("UNIX domain socket to bind on")
                .default_value("/var/run/dnsnfset/dnstap.sock"),
        )
        .arg(
            Arg::new("rules")
                .long("rules")
                .short('f')
                .help("Rules file")
                .default_value("rules.conf"),
        )
        .get_matches();
    let socks_path = matches
        .get_one::<String>("socks-path")
        .expect("missing socks-path argument");
    let mut socks_path: AutoRemoveFile = socks_path.as_str().into();

    let ruleset = matches
        .get_one::<String>("rules")
        .expect("missing rules file path");
    let ruleset = RuleSet::from_file(ruleset).expect("fail to load rules");
    let ruleset = Arc::new(ruleset);
    info!("{} rules loaded", ruleset.len());

    let listener = UnixListener::bind(&socks_path).expect("fail to bind socket");
    info!("listen on {}", socks_path);
    socks_path.set_auto_remove(true);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rules = ruleset.clone();
                thread::spawn(move || match handle_stream(stream, rules) {
                    Ok(_) => info!("unbound disconnected"),
                    Err(err) => warn!("error on thread: {}", err),
                });
            }
            Err(err) => panic!("fail to connect: {}", err),
        }
    }
}
