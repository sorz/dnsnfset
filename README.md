# dnsnfset

Add IP addresses from DNS replies into nftables' sets.

*DNS replies* are UDP packets catched by NFLOG.


## Build
Install Rust toolchain ([rustup.rs](https://rustup.rs)). Then,

```bash
git clone https://github.com/sorz/dnsnfset
cd dnsnfset
cargo build --release
target/release/dnsnfset --help
```

## Usage
1. Add nftables rule(s) to forward DNS replies (UDP only) via NFLOG.
2. Create set(s) in nftables using `nft`.
3. Edit `rules.conf` to specify which domain going to which set.
4. Run `dnsnfset --group <N> --rules <FILE>`.

## Future works
1. Handle CNAME properly.
2. Constant-time rules matching.

