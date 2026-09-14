use anyhow::{Context, Result};
use clap::{Arg, Command};
use fstrm::FstrmReader;
use log::{debug, info, trace, warn};
use protobuf::prelude::*;
use sd_notify::NotifyState;
use signal_hook::{consts::SIGHUP, iterator::Signals};
use simple_dns::{rdata::RData, Packet as DnsPacket, QTYPE, TYPE};
use std::{
    io::{self, Read},
    net::IpAddr,
    os::unix::net::{UnixListener, UnixStream},
    sync::{Arc, RwLock},
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
    ruleset: Arc<RwLock<Arc<RuleSet>>>,
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
            Err(err) => debug!("fail to parse dns packet: {}", err),
            Ok(packet) => {
                let ruleset = ruleset.read().unwrap().clone();
                handle_packet(packet, &ruleset, &state, &mut nft);
            }
        }
    }
    Ok(())
}

fn handle_packet(pkt: DnsPacket, ruleset: &RuleSet, state: &SetState, nft: &mut Nftables) {
    let qtype_qname = pkt
        .questions
        .iter()
        .find(|q| matches!(q.qtype, QTYPE::TYPE(TYPE::A | TYPE::AAAA)))
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
            .filter_map(|record| match &record.rdata {
                RData::A(addr) => Some(IpAddr::V4(addr.address.into())),
                RData::AAAA(addr) => Some(IpAddr::V6(addr.address.into())),
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
                                name,
                                addr,
                                set.set_name
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

fn reload_rules_and_sync(
    rules_path: &str,
    ruleset: &RwLock<Arc<RuleSet>>,
    state: &SetState,
    nft: &mut Nftables,
) -> Result<()> {
    let new_ruleset = RuleSet::from_file(rules_path)
        .with_context(|| format!("fail to load rules from {}", rules_path))?;
    info!("{} rules loaded from {}", new_ruleset.len(), rules_path);
    info!("syncing existing set elements from nftables...");
    state.sync_from_nft(nft, &new_ruleset);
    *ruleset.write().unwrap() = Arc::new(new_ruleset);
    info!("reload completed successfully");
    Ok(())
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
    let ruleset = Arc::new(RwLock::new(Arc::new(ruleset)));
    info!("{} rules loaded", ruleset.read().unwrap().len());

    let mut nft = Nftables::new();
    let state = Arc::new(SetState::new());
    info!("syncing existing set elements from nftables...");
    state.sync_from_nft(&mut nft, &ruleset.read().unwrap());

    let mut signals = Signals::new([SIGHUP]).context("failed to register SIGHUP signal handler")?;
    let signal_ruleset = ruleset.clone();
    let signal_state = state.clone();
    let signal_rules_path = rules_file.clone();
    thread::spawn(move || {
        let mut nft = Nftables::new();
        for sig in signals.forever() {
            if sig == SIGHUP {
                info!("received SIGHUP, reloading...");
                if let Err(err) = NotifyState::monotonic_usec_now()
                    .and_then(|now| sd_notify::notify(&[NotifyState::Reloading, now]))
                {
                    debug!("failed to notify systemd: {:#}", err);
                }

                if let Err(err) = reload_rules_and_sync(
                    &signal_rules_path,
                    &signal_ruleset,
                    &signal_state,
                    &mut nft,
                ) {
                    warn!("failed to reload: {:#}", err);
                }

                if let Err(err) = sd_notify::notify(&[NotifyState::Ready]) {
                    debug!("failed to notify systemd: {:#}", err);
                }
            }
        }
    });

    let listener = UnixListener::bind(&socks_path)
        .with_context(|| format!("fail to bind socket on {}", socks_path))?;
    info!("listen on {}", socks_path);
    socks_path.set_auto_remove(true);

    if let Err(err) = sd_notify::notify(&[NotifyState::Ready]) {
        debug!("failed to notify systemd: {:#}", err);
    }

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
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => warn!("fail to accept connection: {:#}", err),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{
        rdata::{A, AAAA},
        Name, Question, ResourceRecord, CLASS,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_and_extract_ips() {
        let mut packet = DnsPacket::new_reply(42);
        packet.questions.push(Question::new(
            Name::new("example.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            CLASS::IN.into(),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new("example.com").unwrap(),
            CLASS::IN,
            300,
            RData::A(A {
                address: Ipv4Addr::new(93, 184, 216, 34).into(),
            }),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new("example.com").unwrap(),
            CLASS::IN,
            300,
            RData::AAAA(AAAA {
                address: Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)
                    .into(),
            }),
        ));

        let wire_bytes = packet.build_bytes_vec_compressed().unwrap();
        let parsed = DnsPacket::parse(&wire_bytes).unwrap();

        let question = parsed
            .questions
            .iter()
            .find(|q| matches!(q.qtype, QTYPE::TYPE(TYPE::A | TYPE::AAAA)))
            .map(|q| (q.qtype, q.qname.to_string()));
        assert_eq!(
            question,
            Some((QTYPE::TYPE(TYPE::A), "example.com".to_string()))
        );

        let records: Vec<IpAddr> = parsed
            .answers
            .iter()
            .filter_map(|record| match &record.rdata {
                RData::A(addr) => Some(IpAddr::V4(addr.address.into())),
                RData::AAAA(addr) => Some(IpAddr::V6(addr.address.into())),
                _ => None,
            })
            .collect();

        assert_eq!(
            records,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946
                )),
            ]
        );
    }

    #[test]
    fn test_reload_rules_and_sync() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!(
            "dnsnfset-test-rules-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let initial_rules = r#"
        [nat.whitelist]
        family = "ip"
        type = "ipv4"
        domains = ["test1.example.com"]
        "#;
        std::fs::write(&test_file, initial_rules).unwrap();

        let ruleset = RuleSet::from_file(&test_file).unwrap();
        assert_eq!(ruleset.len(), 1);
        let shared_ruleset = Arc::new(RwLock::new(Arc::new(ruleset)));
        let state = SetState::new();
        let mut nft = Nftables::new();

        // Overwrite rules file with new content
        let updated_rules = r#"
        [nat.whitelist]
        family = "ip"
        type = "ipv4"
        domains = ["test1.example.com", "test2.example.com"]

        [filter.block]
        family = "ip6"
        domains = ["block.example.com"]
        "#;
        std::fs::write(&test_file, updated_rules).unwrap();

        // Perform reload
        reload_rules_and_sync(
            test_file.to_str().unwrap(),
            &shared_ruleset,
            &state,
            &mut nft,
        )
        .unwrap();

        assert_eq!(shared_ruleset.read().unwrap().len(), 3);
        assert_eq!(
            shared_ruleset
                .read()
                .unwrap()
                .match_all("block.example.com")
                .len(),
            1
        );

        // Now write invalid TOML and check that reload fails gracefully without changing shared_ruleset
        std::fs::write(&test_file, "this is invalid toml [[[ }").unwrap();
        let res = reload_rules_and_sync(
            test_file.to_str().unwrap(),
            &shared_ruleset,
            &state,
            &mut nft,
        );
        assert!(res.is_err());
        // Ruleset should remain unchanged at 3 rules
        assert_eq!(shared_ruleset.read().unwrap().len(), 3);

        // Clean up
        let _ = std::fs::remove_file(&test_file);
    }
}
