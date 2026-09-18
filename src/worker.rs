use anyhow::{Context, Result};
use log::{debug, info, trace, warn};
use protobuf::prelude::*;
use simple_dns::{rdata::RData, Packet as DnsPacket, QTYPE, TYPE};
use std::{
    cell::RefCell,
    io::Read,
    net::IpAddr,
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, RwLock},
    time::Instant,
};

use crate::{
    dnstap::Dnstap,
    fstrm::FstrmReader,
    nft::{NftCommand, NftSetElemType},
    nftables::Nftables,
    rule::RuleSet,
    state::{SetState, UpdateAction},
};

thread_local! {
    static NFT: RefCell<Nftables> = Nftables::new().into();
}

#[derive(Clone)]
pub struct Worker {
    ruleset: Arc<RwLock<Arc<RuleSet>>>,
    state: Arc<SetState>,
}

impl Worker {
    pub fn new(ruleset: Arc<RwLock<Arc<RuleSet>>>, state: Arc<SetState>) -> Self {
        info!("syncing existing set elements from nftables...");
        NFT.with(|nft| state.sync_from_nft(&mut nft.borrow_mut(), &ruleset.read().unwrap()));
        Self { ruleset, state }
    }

    pub fn handle_stream(&self, stream: UnixStream) -> Result<()> {
        info!("unbound connected");
        let reader = FstrmReader::<_, ()>::new(stream);
        let mut reader = reader
            .accept()
            .context("failed to accept FSTRM stream")?
            .start()
            .context("failed to start FSTRM reader")?;
        debug!("FSTRM handshake finish {:?}", reader.content_types());

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
                Ok(packet) => self.handle_packet(packet),
            }
        }
        Ok(())
    }

    /// Reload rules from config file then sync state from nftables.
    pub fn reload<P: AsRef<Path>>(&self, rules_path: P) -> Result<()> {
        let rules_path = rules_path.as_ref();
        let new_ruleset = RuleSet::from_file(rules_path)
            .with_context(|| format!("fail to load rules from {}", rules_path.display()))?;
        info!(
            "{} rules loaded from {}",
            new_ruleset.len(),
            rules_path.display()
        );
        info!("syncing existing set elements from nftables...");
        NFT.with(|nft| {
            self.state
                .sync_from_nft(&mut nft.borrow_mut(), &new_ruleset)
        });
        *self.ruleset.write().unwrap() = Arc::new(new_ruleset);
        info!("reload completed successfully");
        Ok(())
    }

    fn handle_packet(&self, pkt: DnsPacket) {
        let qtype_qname = pkt
            .questions
            .iter()
            .find(|q| matches!(q.qtype, QTYPE::TYPE(TYPE::A | TYPE::AAAA)))
            .map(|q| (q.qtype, q.qname.to_string()));
        trace!("name {:?}", qtype_qname);

        if let Some((qtype, name)) = qtype_qname {
            let sets = self.ruleset.read().unwrap().match_all(&name);
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
                        _ => match self.state.check_update(&set, addr) {
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
            NFT.with(|nft| match nft.borrow_mut().run(cmd) {
                Ok(()) => {
                    for (set, addr) in to_record {
                        self.state.record_added(&set, addr);
                    }
                }
                Err(err) => {
                    warn!("fail to run nft cmd: {:#}", err);
                }
            });
            debug!("{:?}", t.elapsed());
        }
    }
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
        let state = Arc::new(SetState::new());
        let worker = Worker::new(shared_ruleset, state);

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
        worker.reload(&test_file).unwrap();

        assert_eq!(worker.ruleset.read().unwrap().len(), 3);
        assert_eq!(
            worker
                .ruleset
                .read()
                .unwrap()
                .match_all("block.example.com")
                .len(),
            1
        );

        // Now write invalid TOML and check that reload fails gracefully without changing shared_ruleset
        std::fs::write(&test_file, "this is invalid toml [[[ }").unwrap();
        let res = worker.reload(&test_file);
        assert!(res.is_err());
        // Ruleset should remain unchanged at 3 rules
        assert_eq!(worker.ruleset.read().unwrap().len(), 3);

        // Clean up
        let _ = std::fs::remove_file(&test_file);
    }
}
