pub mod cli;
pub mod fstrm;
pub mod nft;
pub mod nftables;
pub mod rule;
pub mod socks;
pub mod state;
pub mod worker;

#[allow(clippy::all)]
pub mod dnstap {
    include!(concat!(env!("OUT_DIR"), "/protobuf_generated/generated.rs"));
}
