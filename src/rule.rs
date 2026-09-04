use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use crate::nft::{NftFamily, NftSetElemType};

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    sets: HashSet<Arc<Set>>,
    rules: HashMap<Box<[u8]>, Vec<Arc<Set>>>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Set {
    pub family: Option<NftFamily>,
    pub table: Box<str>,
    pub set_name: Box<str>,
    pub elem_type: NftSetElemType,
    pub timeout: Option<Box<str>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetConfig {
    pub table: Option<String>,
    pub set: Option<String>,
    #[serde(alias = "set_name")]
    pub name: Option<String>,
    pub family: Option<NftFamily>,
    #[serde(default)]
    pub r#type: Option<NftSetElemType>,
    pub timeout: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

fn normalize_domain(domain: &str) -> Box<[u8]> {
    let d = domain.trim().to_ascii_lowercase();
    if d == "*" || d.is_empty() {
        return Box::new([]);
    }
    let d = d.strip_prefix('.').unwrap_or(&d);
    let d = d.strip_suffix('.').unwrap_or(d);
    d.as_bytes().to_vec().into_boxed_slice()
}

impl RuleSet {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let mut file = File::open(path_ref)
            .with_context(|| format!("failed to open rules file {}", path_ref.display()))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .with_context(|| format!("failed to read rules file {}", path_ref.display()))?;
        Self::from_str(&content)
            .with_context(|| format!("failed to parse rules in {}", path_ref.display()))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let tables: HashMap<String, HashMap<String, SetConfig>> =
            toml::from_str(s).context("failed to parse TOML configuration")?;

        let mut ruleset = RuleSet::default();
        for (table_key, sets) in tables {
            for (set_key, config) in sets {
                let table = config.table.unwrap_or_else(|| table_key.clone());
                let set_name = config
                    .set
                    .or(config.name)
                    .unwrap_or_else(|| set_key.clone());

                let elem_type = match config.r#type {
                    Some(t) => t,
                    None => match config.family {
                        Some(NftFamily::Ip) | None => NftSetElemType::Ipv4Addr,
                        Some(NftFamily::Ip6) => NftSetElemType::Ipv6Addr,
                        Some(NftFamily::Inet) => {
                            bail!(
                                "missing 'type' in [{}.{}]: for inet family, element type must be specified",
                                table,
                                set_name
                            );
                        }
                    },
                };

                let timeout = config.timeout.map(|t| t.into_boxed_str());

                let set = Set {
                    family: config.family,
                    table: table.clone().into_boxed_str(),
                    set_name: set_name.clone().into_boxed_str(),
                    elem_type,
                    timeout: timeout.clone(),
                };

                let set_arc = match ruleset.sets.get(&set) {
                    Some(v) => v.clone(),
                    None => {
                        let v = Arc::new(set);
                        ruleset.sets.insert(v.clone());
                        v
                    }
                };

                for domain in &config.domains {
                    let domain_key = normalize_domain(domain);
                    ruleset
                        .rules
                        .entry(domain_key)
                        .or_default()
                        .push(set_arc.clone());
                }
            }
        }
        Ok(ruleset)
    }

    pub fn match_all(&self, domain: &str) -> Vec<Arc<Set>> {
        let domain = domain.to_ascii_lowercase();
        let domain = if domain.ends_with('.') {
            &domain.as_bytes()[..domain.len() - 1]
        } else {
            domain.as_bytes()
        };

        let mut matched_set = Vec::new();
        let mut match_add = |suffix: &[u8]| {
            if let Some(sets) = self.rules.get(suffix) {
                matched_set.extend(sets.iter().cloned());
            }
        };

        match_add(&[]);
        for n in (0..domain.len()).rev() {
            if domain[n] == 46 {
                match_add(&domain[n + 1..]);
            }
        }
        match_add(domain);
        matched_set
    }

    pub fn len(&self) -> usize {
        self.rules.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suffix_match() {
        let toml_data = r#"
        [nat.whitelist]
        family = "ip"
        type = "ipv4"
        domains = ["google.com"]

        [filter.netflix]
        family = "inet"
        type = "ipv6"
        timeout = "1d"
        domains = ["netflix.com"]

        [nat.match_all]
        type = "ipv4"
        domains = ["*"]

        [nat.match_v4]
        set = "match"
        type = "ipv4"
        domains = ["com", "example.com"]

        [nat.match_v6]
        set = "match"
        type = "ipv6"
        domains = ["com"]
        "#;
        let ruleset = RuleSet::from_str(toml_data).unwrap();
        assert_eq!(6, ruleset.len());
        assert_eq!(1, ruleset.match_all("others").len());
        assert_eq!(3, ruleset.match_all("com").len());
        assert_eq!(3, ruleset.match_all("one.com").len());
        assert_eq!(4, ruleset.match_all("a.b.example.com").len());
    }

    #[test]
    fn test_load_default_file() {
        let ruleset = RuleSet::from_file("rules.toml").unwrap();
        assert!(!ruleset.is_empty());
    }

    #[test]
    fn test_single_table_and_aliases() {
        let toml_data = r#"
        [filter.proxy]
        family = "inet"
        type = "ipv4"
        domains = ["youtube.com"]

        [filter.netflix]
        family = "ip6"
        domains = [".netflix.com", "nflxext.com."]
        timeout = "2h"
        "#;
        let ruleset = RuleSet::from_str(toml_data).unwrap();
        assert_eq!(3, ruleset.len());

        let yt_matches = ruleset.match_all("youtube.com");
        assert_eq!(1, yt_matches.len());
        assert_eq!("filter", &*yt_matches[0].table);
        assert_eq!("proxy", &*yt_matches[0].set_name);
        assert_eq!(Some(NftFamily::Inet), yt_matches[0].family);
        assert_eq!(NftSetElemType::Ipv4Addr, yt_matches[0].elem_type);

        let nf_matches = ruleset.match_all("app.netflix.com");
        assert_eq!(1, nf_matches.len());
        assert_eq!("netflix", &*nf_matches[0].set_name);
        assert_eq!(Some(NftFamily::Ip6), nf_matches[0].family);
        assert_eq!(NftSetElemType::Ipv6Addr, nf_matches[0].elem_type);
        assert_eq!(Some("2h".into()), nf_matches[0].timeout);
    }

    #[test]
    fn test_type_inference_by_family() {
        let toml_data = r#"
        [nat.v4_set]
        family = "ip"
        domains = ["ipv4.example.com"]

        [filter.v6_set]
        family = "ip6"
        domains = ["ipv6.example.com"]

        [nat.no_family_set]
        domains = ["no-family.example.com"]
        "#;
        let ruleset = RuleSet::from_str(toml_data).unwrap();
        let v4_matches = ruleset.match_all("ipv4.example.com");
        assert_eq!(1, v4_matches.len());
        assert_eq!(NftSetElemType::Ipv4Addr, v4_matches[0].elem_type);

        let v6_matches = ruleset.match_all("ipv6.example.com");
        assert_eq!(1, v6_matches.len());
        assert_eq!(NftSetElemType::Ipv6Addr, v6_matches[0].elem_type);

        let no_family_matches = ruleset.match_all("no-family.example.com");
        assert_eq!(1, no_family_matches.len());
        assert_eq!(None, no_family_matches[0].family);
        assert_eq!(NftSetElemType::Ipv4Addr, no_family_matches[0].elem_type);

        // inet requires type to be explicitly set
        let toml_inet_missing_type = r#"
        [filter.inet_set]
        family = "inet"
        domains = ["example.com"]
        "#;
        assert!(RuleSet::from_str(toml_inet_missing_type).is_err());
    }

    #[test]
    fn test_empty_domains_allowed() {
        let toml_data = r#"
        [nat.empty_set]
        family = "ip"
        domains = []

        [nat.omitted_set]
        family = "ip"
        "#;
        let ruleset = RuleSet::from_str(toml_data).unwrap();
        assert_eq!(0, ruleset.len());
    }

    #[test]
    fn test_unknown_field_denied() {
        let toml_typo = r#"
        [nat.foo]
        family = "ip"
        domians = ["example.com"]
        "#;
        assert!(RuleSet::from_str(toml_typo).is_err());
    }
}
