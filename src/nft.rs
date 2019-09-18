use std::fmt::Write;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;


pub trait NftCommand {
    fn add_element(
        &mut self,
        family: Option<NftFamily>,
        table: &str,
        set: &str,
        addr: &IpAddr,
        timeout: &Option<Box<str>>,
    );
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum NftFamily {
    Ip,
    Ip6,
    Inet,
}
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

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum NftSetElemType {
    Ipv4Addr,
    Ipv6Addr,
}
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

impl NftCommand for String {
    fn add_element(
        &mut self,
        family: Option<NftFamily>,
        table: &str,
        set: &str,
        addr: &IpAddr,
        timeout: &Option<Box<str>>,
    ) {
        self.push_str("add element ");
        if let Some(family) = family {
            write!(self, "{} ", family).unwrap();
        }
        write!(self, "{} {} {{ {} ", table, set, addr).unwrap();
        if let Some(timeout) = timeout {
            write!(self, "timeout {} ", timeout).unwrap();
        }
        self.push_str("}; ");
    }
}

