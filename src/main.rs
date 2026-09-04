use anyhow::{Context, Result};
use clap::{Arg, Command};
use dns_parser::{rdata::RData, Error as DnsError, Packet as DnsPacket, QueryType};
use fstrm::FstrmReader;
use log::{debug, info, trace, warn};
use protobuf::prelude::*;
use std::{
    io::Read,
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
    rule::RuleSet,
    socks::AutoRemoveFile,
    state::{SetState, UpdateAction},
};

fn handle_stream(
    stream: UnixStream,
    ruleset: Arc<RuleSet>,
    state: Arc<SetState>,
) -> Result<()> {
    info!("unbound connected");
    let reader = FstrmReader::<_, ()>::new(stream);
    let mut reader = reader
        .accept()
        .context("failed to accept FSTRM stream")?
        .start()
        .context("failed to start FSTRM reader")?;
    debug!("FSTRM handshake finish {:?}", reader.content_types());

    let mut nft = Nftables::new();
    let mut buf = Vec::new();

    while let Some(mut frame) = reader.read_frame().context("failed to read FSTRM frame")? {
        buf.clear();
        frame
            .read_to_end(&mut buf)
            .context("failed to read frame content")?;
        let dnstap = Dnstap::parse(&buf).context("failed to parse dnstap message")?;
        let msg = dnstap.message();
        let resp = msg.response_message();
        trace!("got {:?} ({}B resp)", msg.r#type(), resp.len());
        if resp.is_empty() {
            continue;
        }
        match DnsPacket::parse(resp) {
            Err(DnsError::InvalidQueryType(_)) => (),
            Err(err) => debug!("fail to parse dns packet: {}", err),
            Ok(packet) => handle_packet(packet, &ruleset, &state, &mut nft),
        }
    }
    Ok(())
}

fn handle_packet(
    pkt: DnsPacket,
    ruleset: &RuleSet,
    state: &SetState,
    nft: &mut Nftables,
) {
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
        let mut to_record = Vec::new();

        for set in sets {
            for addr in records.iter() {
                match (set.elem_type, addr) {
                    (NftSetElemType::Ipv4Addr, IpAddr::V6(_))
                    | (NftSetElemType::Ipv6Addr, IpAddr::V4(_)) => (),
                    _ => match state.check_update(&set, addr) {
                        UpdateAction::Add => {
                            debug!("  add {} {:?} to {}", name, addr, set.set_name);
                            cmd.add_element(
                                set.family,
                                &set.table,
                                &set.set_name,
                                addr,
                                set.timeout,
                            );
                            to_record.push((set.clone(), *addr));
                        }
                        UpdateAction::Refresh => {
                            debug!("  refresh {} {:?} in {}", name, addr, set.set_name);
                            cmd.refresh_element(
                                set.family,
                                &set.table,
                                &set.set_name,
                                addr,
                                set.timeout,
                            );
                            to_record.push((set.clone(), *addr));
                        }
                        UpdateAction::Skip => {
                            trace!(
                                "  skip {} {:?} in {} (lifetime > 2/3)",
                                name, addr, set.set_name
                            );
                        }
                    },
                }
            }
        }
        if cmd.is_empty() {
            debug!("match {} with zero {:?} record to update", name, qtype);
            return;
        }
        info!(
            "match {} with {} {:?} record(s) ({} to add)",
            name,
            records.len(),
            qtype,
            to_record.len(),
        );
        trace!("{}", cmd);
        let t = Instant::now();
        match nft.run(cmd) {
            Ok(()) => {
                for (set, addr) in to_record {
                    state.record_added(&set, addr);
                }
            }
            Err(err) => {
                warn!("fail to run nft cmd: {:#}", err);
            }
        }
        debug!("{:?}", t.elapsed());
    }
}

fn main() -> Result<()> {
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
                .default_value("rules.toml"),
        )
        .get_matches();
    let socks_path = matches
        .get_one::<String>("socks-path")
        .expect("missing socks-path argument");
    let mut socks_path: AutoRemoveFile = socks_path.as_str().into();

    let rules_file = matches
        .get_one::<String>("rules")
        .expect("missing rules file path");
    let ruleset = RuleSet::from_file(rules_file)
        .with_context(|| format!("fail to load rules from {}", rules_file))?;
    let ruleset = Arc::new(ruleset);
    info!("{} rules loaded", ruleset.len());

    let mut nft = Nftables::new();
    let state = Arc::new(SetState::new());
    info!("syncing existing set elements from nftables...");
    state.sync_from_nft(&mut nft, &ruleset);

    let listener = UnixListener::bind(&socks_path)
        .with_context(|| format!("fail to bind socket on {}", socks_path))?;
    info!("listen on {}", socks_path);
    socks_path.set_auto_remove(true);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rules = ruleset.clone();
                let state = state.clone();
                thread::spawn(move || match handle_stream(stream, rules, state) {
                    Ok(_) => info!("unbound disconnected"),
                    Err(err) => warn!("error on thread: {:#}", err),
                });
            }
            Err(err) => warn!("fail to accept connection: {:#}", err),
        }
    }
    Ok(())
}
