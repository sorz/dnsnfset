use serde::Deserialize;
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

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
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

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Deserialize)]
pub enum NftSetElemType {
    #[serde(rename = "ipv4", alias = "ipv4_addr", alias = "ip4")]
    Ipv4Addr,
    #[serde(rename = "ipv6", alias = "ipv6_addr", alias = "ip6")]
    Ipv6Addr,
}
impl Display for NftSetElemType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            NftSetElemType::Ipv4Addr => write!(f, "ipv4"),
            NftSetElemType::Ipv6Addr => write!(f, "ipv6"),
        }
    }
}
impl FromStr for NftSetElemType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ipv4" | "ipv4_addr" | "ip4" => Ok(NftSetElemType::Ipv4Addr),
            "ipv6" | "ipv6_addr" | "ip6" => Ok(NftSetElemType::Ipv6Addr),
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
