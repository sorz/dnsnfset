pub mod nft;
pub mod nftables;
pub mod rule;
pub mod socks;

#[allow(clippy::all)]
pub mod dnstap {
    include!(concat!(env!("OUT_DIR"), "/protobuf_generated/generated.rs"));
}
