use anyhow::{Context, Result};
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::nft::NftFamily;
use crate::nftables::Nftables;
use crate::rule::{RuleSet, Set};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SetKey {
    pub family: Option<NftFamily>,
    pub table: Box<str>,
    pub set_name: Box<str>,
}

impl From<&Set> for SetKey {
    fn from(set: &Set) -> Self {
        Self {
            family: set.family,
            table: set.table.clone(),
            set_name: set.set_name.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedNftElement {
    pub ip: IpAddr,
    pub expires: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateAction {
    Skip,
    Add,
    Refresh,
}

#[derive(Debug, Default)]
pub struct SetState {
    cache: RwLock<HashMap<SetKey, HashMap<IpAddr, Option<Instant>>>>,
}

impl SetState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether and how the element should be updated in nftables.
    ///
    /// Rules:
    /// - If element is not in cache: return `UpdateAction::Add`.
    /// - If element has no timeout (permanent):
    ///   - If already recorded as permanent: return `UpdateAction::Skip`.
    ///   - If previously recorded with expiry: return `UpdateAction::Refresh`.
    /// - If element has a timeout T:
    ///   - If was recorded as permanent (no expiry): return `UpdateAction::Refresh`.
    ///   - If recorded with expiry:
    ///     - If expired (now >= expires_at): return `UpdateAction::Add` (expired in nftables).
    ///     - If remaining lifetime R > 2/3 * T: return `UpdateAction::Skip` (ignore).
    ///     - If remaining lifetime R <= 2/3 * T: return `UpdateAction::Refresh` (delete + re-add to reset timeout).
    pub fn check_update(&self, set: &Set, addr: &IpAddr) -> UpdateAction {
        let key = SetKey::from(set);
        let cache = self.cache.read().unwrap();
        let set_cache = match cache.get(&key) {
            Some(sc) => sc,
            None => return UpdateAction::Add,
        };
        let expires_at = match set_cache.get(addr) {
            Some(exp) => exp,
            None => return UpdateAction::Add,
        };

        match set.timeout {
            None => {
                match expires_at {
                    None => UpdateAction::Skip, // Already permanent in nftables
                    Some(_) => UpdateAction::Refresh, // Was temporary in nftables, refresh to permanent
                }
            }
            Some(timeout) => {
                match expires_at {
                    None => UpdateAction::Refresh, // Was permanent in cache, refresh to timed
                    Some(expires_at) => {
                        let now = Instant::now();
                        if now >= *expires_at {
                            UpdateAction::Add // Expired and cleaned up by kernel
                        } else {
                            let remaining = *expires_at - now;
                            if remaining.saturating_mul(3) > timeout.saturating_mul(2) {
                                UpdateAction::Skip // Remaining lifetime > 2/3, ignore
                            } else {
                                UpdateAction::Refresh // Remaining lifetime <= 2/3, delete + re-add
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if the element should be updated in nftables (helper returning bool).
    pub fn should_update(&self, set: &Set, addr: &IpAddr) -> bool {
        self.check_update(set, addr) != UpdateAction::Skip
    }

    /// Record an element that was added or refreshed in nftables.
    pub fn record_added(&self, set: &Set, addr: IpAddr) {
        let key = SetKey::from(set);
        let expires_at = set.timeout.map(|t| Instant::now() + t);
        let mut cache = self.cache.write().unwrap();
        cache.entry(key).or_default().insert(addr, expires_at);
    }

    /// Insert or update records directly (useful for testing or batch operations).
    pub fn insert_record(&self, set: &Set, addr: IpAddr, expires_at: Option<Instant>) {
        let key = SetKey::from(set);
        let mut cache = self.cache.write().unwrap();
        cache.entry(key).or_default().insert(addr, expires_at);
    }

    /// Load parsed elements for a set (e.g. from startup sync).
    pub fn load_elements(&self, set: &Set, elements: Vec<ParsedNftElement>) {
        let key = SetKey::from(set);
        let now = Instant::now();
        let mut cache = self.cache.write().unwrap();
        let set_cache = cache.entry(key).or_default();
        for elem in elements {
            let expires_at = elem.expires.map(|exp| now + exp);
            set_cache.insert(elem.ip, expires_at);
        }
    }

    /// Sync internal state from nftables for all sets in the ruleset.
    pub fn sync_from_nft(&self, nft: &mut Nftables, ruleset: &RuleSet) {
        for set in ruleset.sets() {
            match nft.list_set_json(set.family, &set.table, &set.set_name) {
                Ok(json_str) => match parse_nft_set_elements(&json_str) {
                    Ok(elements) => {
                        let count = elements.len();
                        self.load_elements(set.as_ref(), elements);
                        info!(
                            "synced {} element(s) for set [{}.{}]",
                            count, set.table, set.set_name
                        );
                    }
                    Err(err) => {
                        warn!(
                            "failed to parse nftables JSON for set [{}.{}]: {:#}",
                            set.table, set.set_name, err
                        );
                    }
                },
                Err(err) => {
                    warn!(
                        "failed to sync set [{}.{}] from nftables: {:#}",
                        set.table, set.set_name, err
                    );
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct NftOutput {
    #[serde(default)]
    nftables: Vec<NftItem>,
}

#[derive(Debug, Deserialize)]
struct NftItem {
    set: Option<NftSet>,
}

#[derive(Debug, Deserialize)]
struct NftSet {
    #[serde(default)]
    elem: Vec<NftElem>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NftElem {
    Plain(IpAddr),
    Wrapped { elem: NftElemData },
    Direct(NftElemData),
    // ignore prefixes / ranges / other non-IP elements
    Other(#[allow(dead_code)] serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct NftElemData {
    val: Option<IpAddr>,
    expires: Option<u64>,
}

/// Parse elements from nftables JSON output.
pub fn parse_nft_set_elements(json_str: &str) -> Result<Vec<ParsedNftElement>> {
    let output: NftOutput =
        serde_json::from_str(json_str).context("failed to parse JSON from nftables")?;

    let mut results = Vec::new();
    for item in output.nftables {
        if let Some(set) = item.set {
            for elem in set.elem {
                match elem {
                    NftElem::Plain(ip) => {
                        results.push(ParsedNftElement { ip, expires: None });
                    }
                    NftElem::Wrapped { elem } | NftElem::Direct(elem) => {
                        if let Some(ip) = elem.val {
                            results.push(ParsedNftElement {
                                ip,
                                expires: elem.expires.map(Duration::from_secs),
                            });
                        }
                    }
                    NftElem::Other(_) => (), // ignore prefixes / ranges
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nft::NftSetElemType;

    fn sample_set(timeout: Option<Duration>) -> Set {
        Set {
            family: Some(NftFamily::Ip),
            table: "nat".into(),
            set_name: "whitelist".into(),
            elem_type: NftSetElemType::Ipv4Addr,
            timeout,
        }
    }

    #[test]
    fn test_permanent_element() {
        let state = SetState::new();
        let set = sample_set(None);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Not in cache yet -> should update
        assert!(state.should_update(&set, &ip));

        // Add to cache
        state.record_added(&set, ip);

        // Already in cache as permanent -> should NOT update
        assert!(!state.should_update(&set, &ip));
    }

    #[test]
    fn test_two_thirds_timeout_rule() {
        let state = SetState::new();
        let timeout = Duration::from_secs(3600);
        let set = sample_set(Some(timeout));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 1. Not in cache -> should Add
        assert_eq!(state.check_update(&set, &ip), UpdateAction::Add);

        // 2. Just added -> full remaining lifetime (3600s) > 2/3 (2400s) -> should Skip
        state.record_added(&set, ip);
        assert_eq!(state.check_update(&set, &ip), UpdateAction::Skip);

        // 3. Set remaining lifetime to 2500s (> 2/3 * 3600 = 2400s) -> should Skip
        let now = Instant::now();
        state.insert_record(&set, ip, Some(now + Duration::from_secs(2500)));
        assert_eq!(state.check_update(&set, &ip), UpdateAction::Skip);

        // 4. Set remaining lifetime to 2400s (= 2/3 * 3600 = 2400s) -> should Refresh (delete + add)
        state.insert_record(&set, ip, Some(now + Duration::from_secs(2400)));
        assert_eq!(state.check_update(&set, &ip), UpdateAction::Refresh);

        // 5. Set remaining lifetime to 1000s (< 2400s) -> should Refresh
        state.insert_record(&set, ip, Some(now + Duration::from_secs(1000)));
        assert_eq!(state.check_update(&set, &ip), UpdateAction::Refresh);

        // 6. Expired (0s remaining) -> should Add (cleaned up by kernel)
        state.insert_record(&set, ip, Some(now - Duration::from_secs(10)));
        assert_eq!(state.check_update(&set, &ip), UpdateAction::Add);
    }

    #[test]
    fn test_parse_nft_set_elements() {
        let json_data = r#"
        {
          "nftables": [
            {
              "metainfo": {
                "version": "1.0.0",
                "release_name": "Commodore Bullmoose",
                "json_schema_version": 1
              }
            },
            {
              "set": {
                "family": "ip",
                "name": "whitelist",
                "table": "nat",
                "type": "ipv4_addr",
                "elem": [
                  "1.1.1.1",
                  {
                    "elem": {
                      "val": "2.2.2.2",
                      "timeout": 3600,
                      "expires": 1200
                    }
                  },
                  {
                    "elem": {
                      "val": {
                        "prefix": {
                          "addr": "10.0.0.0",
                          "len": 8
                        }
                      }
                    }
                  },
                  "192.168.0.0/16"
                ]
              }
            }
          ]
        }
        "#;

        let elements = parse_nft_set_elements(json_data).unwrap();
        assert_eq!(elements.len(), 2);

        assert_eq!(elements[0].ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(elements[0].expires, None);

        assert_eq!(elements[1].ip, "2.2.2.2".parse::<IpAddr>().unwrap());
        assert_eq!(elements[1].expires, Some(Duration::from_secs(1200)));
    }
}
