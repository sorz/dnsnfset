# dnsnfset

Add IP addresses from DNS replies into nftables' sets.

Two sources of *DNS replies* are avaliable:

- (LEGACY) UDP packets catched with NFLOG (by kernel firewall)
  -> Use the branch [nflog](https://github.com/sorz/dnsnfset/tree/nflog) instead.

- (NEW) Receive via [dnstap](https://dnstap.info) from your resolver software
  -> Tested on [unbound](https://nlnetlabs.nl/projects/unbound/about/).

Use dnstap if your resolver support it. It's faster (you got nfset updated BEFORE
DNS replies sending out), and it avoid redundant nfset updatings.

## Build
Install Rust toolchain ([rustup.rs](https://rustup.rs)). Then,

```bash
git clone https://github.com/sorz/dnsnfset
cd dnsnfset
cargo build --release
target/release/dnsnfset --help
```

Make sure you have the header of `libnftables` in your system.

## Usage
1. Configure your resolver to log DNS replies via dnstap. Unbound for example:
```
# /etc/unbound/unbound.conf
dnstap:
  dnstap-enable: yes
  dnstap-bidirectional: yes
  dnstap-socket-path: /run/dnsnfset/dnstap.sock
  dnstap-log-resolver-response-messages: yes
  dnstap-log-forwarder-response-messages: yes
```
2. Create set(s) in nftables using `nft`.
3. Edit `rules.conf` to specify which domain going to which set.
4. Run `dnsnfset --rules <FILE> --socks-path <UNIX-SOCK>`.

## Future works
1. Handle CNAME properly.
2. Better rule config syntax.
