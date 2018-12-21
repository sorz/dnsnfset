use std::io;
use std::net::IpAddr;
use std::fmt::{self, Display, Formatter};
use std::fmt::Write;
use std::str::FromStr;
use std::process::{Command, ExitStatus};

pub struct NftCommand {
    pub cmd: String,
}

#[derive(Clone, Copy, Debug)]
pub enum NftFamily { Ip, Ip6, Inet }
impl Display for NftFamily {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            NftFamily::Ip => write!(f, "ip"),
            NftFamily::Ip6 => write!(f, "ip6"),
            NftFamily::Inet => write!(f, "inet"),
        }
    }
}
impl FromStr for NftFamily {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ip" => Ok(NftFamily::Ip),
            "ip6" => Ok(NftFamily::Ip6),
            "inet" => Ok(NftFamily::Inet),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NftSetElemType { Ipv4Addr, Ipv6Addr }
impl FromStr for NftSetElemType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ipv4_addr" | "ipv4" | "ip4" => Ok(NftSetElemType::Ipv4Addr),
            "ipv6_addr" | "ipv6" | "ip6" => Ok(NftSetElemType::Ipv6Addr),
            _ => Err(()),
        }
    }
}


impl NftCommand {
    pub fn new() -> Self {
        NftCommand {
            cmd: String::new(),
        }
    }

    pub fn add_element(&mut self, family: Option<NftFamily>, table: &str,
                       set: &str, addr: &IpAddr, timeout: &Option<Box<str>>) {
        self.cmd += "add element ";
        if let Some(family) = family {
            write!(self.cmd, "{} ", family).unwrap();
        }
        write!(self.cmd, "{} {} {{ {} ", table, set, addr).unwrap();
        if let Some(timeout) = timeout {
            write!(self.cmd, "timeout {} ", timeout).unwrap();
        }
        self.cmd += "}; ";
    }

    pub fn execute(self) -> Result<ExitStatus, io::Error> {
        Command::new("nft")
            .arg(self.cmd)
            .status()
    }

    pub fn is_empty(&self) -> bool {
        self.cmd.is_empty()
    }
}

#[test]
fn test_add_element() {
    let mut nft = NftCommand::new();
    let ip4 = "127.0.0.1".parse().unwrap();
    let ip6 = "::1".parse().unwrap();
    nft.add_element(None, "filter", "test", ip4, None);
    assert_eq!("add element filter test { 127.0.0.1 }; ", nft.cmd);

    let inet = "inet".parse().unwrap();
    nft.add_element(Some(inet), "nat", "test", ip6, Some("1h4s"));
    assert_eq!("add element filter test { 127.0.0.1 }; \
                add element inet nat test { ::1 timeout 1h4s }; ", nft.cmd);
}
