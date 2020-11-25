use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::sync::Arc;

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

impl RuleSet {
    pub fn from_file(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut ruleset = RuleSet::default();
        for line in BufReader::new(file).lines() {
            let line = line?;
            let line = line.trim();
            if line.starts_with("#") || line.starts_with("//") || line.is_empty() {
                continue;
            }
            ruleset.add(&line);
        }
        Ok(ruleset)
    }

    fn add(&mut self, s: &str) {
        let mut cols = s.split(",").map(|s| s.trim().to_string().into_boxed_str());
        let domain = cols.next().expect("domain is missing");
        let family = cols.next().expect("family is missing");
        let family = if family.is_empty() {
            None
        } else {
            Some(family.parse().expect("illegal family"))
        };
        let table = cols.next().expect("table is missing");
        let set_name = cols.next().expect("set is missing");
        let elem_type = cols
            .next()
            .expect("set type is missing")
            .parse()
            .expect("type is either ipv4_addr or ipv6_addr");
        let timeout = cols.next().filter(|t| !t.is_empty());

        let set = Set {
            family,
            table,
            set_name,
            elem_type,
            timeout,
        };
        let set = match self.sets.get(&set) {
            Some(v) => v.clone(),
            None => {
                let v = Arc::new(set);
                self.sets.insert(v.clone());
                v
            }
        };
        self.rules.entry(domain.into()).or_default().push(set);
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
}

#[test]
fn test_suffix_match() {
    let ruleset = RuleSet::from_file("rules.conf").unwrap();
    assert_eq!(6, ruleset.len());
    assert_eq!(1, ruleset.match_all("others").len());
    assert_eq!(3, ruleset.match_all("com").len());
    assert_eq!(3, ruleset.match_all("one.com").len());
    assert_eq!(4, ruleset.match_all("a.b.example.com").len());
}
