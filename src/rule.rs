use std::io::{BufRead, BufReader};
use std::fs::File;

use ::nft::NftFamily;


#[derive(Debug)]
pub struct Rule {
    pub domain: Box<str>,
    pub family: Option<NftFamily>,
    pub table: Box<str>,
    pub set: Box<str>,
    pub timeout: Option<Box<str>>,
}

impl Rule {
    fn from_str(s: &str) -> Self {
        let mut cols = s.split(",")
            .map(|s| s.trim().to_string().into_boxed_str());
        let domain = cols.next().expect("domain is missing");
        let family = cols.next().expect("family is missing");
        let family = if family.is_empty() {
            None
        } else {
            Some(family.parse().expect("illegal family"))
        };
        let table = cols.next().expect("table is missing");
        let set = cols.next().expect("set is missing");
        let timeout = cols.next().filter(|t| !t.is_empty());
        Rule { domain, family, table, set, timeout }
    }

    fn is_match(&self, domain: &str) -> bool {
        suffix_match(domain, &self.domain)
    }
}

pub fn load_rules(path: &str) -> Vec<Rule> {
    let file = File::open(path)
        .expect("fail to open file");
    BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.expect("fail to read");
            let line = line.trim();
            if line.starts_with("#")
                    || line.starts_with("//")
                    || line.is_empty() {
                None
            } else {
                Some(Rule::from_str(line))
            }
        }).collect()
}

fn suffix_match(domain: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let mut domain = domain.split('.').rev();
    suffix.split('.').rev()
        .skip_while(|s| match domain.next() {
            Some(ss) => ss.eq_ignore_ascii_case(s),
            None => false,
        }).next() == None
}

#[test]
fn test_suffix_match() {
    assert_eq!(true, suffix_match("example.com", ""));
    assert_eq!(true, suffix_match("example.com", "com"));
    assert_eq!(true, suffix_match("eXaMpLe.cOm", "example.com"));
    assert_eq!(false, suffix_match("example.com", "other.example.com"));
    assert_eq!(false, suffix_match("examp1e.com", "example.com"));
}
