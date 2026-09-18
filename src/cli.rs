use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use std::{
    os::unix::{io::FromRawFd, net::UnixListener},
    path::PathBuf,
};

use crate::socks::AutoRemoveFile;

/// Add IPs in DNS response to nftables sets
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(
    name = "dnsnfset",
    version,
    author = "Shell Chen <me@sorz.org>",
    about = "Add IPs in DNS response to nftables sets"
)]
pub struct Cli {
    /// UNIX domain socket to bind on
    #[arg(short = 's', long, default_value = "/var/run/dnsnfset/dnstap.sock")]
    pub socks_path: PathBuf,

    /// Rules file
    #[arg(short = 'f', long, default_value = "rules.toml")]
    pub rules: PathBuf,
}

impl Cli {
    pub fn get_listener(&self, socks_path: &mut AutoRemoveFile) -> Result<UnixListener> {
        let mut fds = sd_notify::listen_fds().context("failed to check systemd listen fds")?;
        if let Some(fd) = fds.next() {
            info!("using systemd socket activation (fd {})", fd);
            // Safety: fds provided by systemd are always owned & opened.
            Ok(unsafe { UnixListener::from_raw_fd(fd) })
        } else {
            let listener = UnixListener::bind(socks_path.as_ref())
                .with_context(|| format!("fail to bind socket on {}", socks_path))?;
            info!("listen on {}", socks_path);
            socks_path.set_auto_remove(true);
            Ok(listener)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test_cli_defaults() {
        let cli = Cli::try_parse_from(["dnsnfset"]).unwrap();
        assert_eq!(
            cli.socks_path,
            PathBuf::from("/var/run/dnsnfset/dnstap.sock")
        );
        assert_eq!(cli.rules, PathBuf::from("rules.toml"));
    }

    #[test]
    fn test_cli_custom_long_flags() {
        let cli = Cli::try_parse_from([
            "dnsnfset",
            "--socks-path",
            "/tmp/test.sock",
            "--rules",
            "/etc/rules.toml",
        ])
        .unwrap();
        assert_eq!(cli.socks_path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(cli.rules, PathBuf::from("/etc/rules.toml"));
    }

    #[test]
    fn test_cli_custom_short_flags() {
        let cli =
            Cli::try_parse_from(["dnsnfset", "-s", "/tmp/test.sock", "-f", "/etc/rules.toml"])
                .unwrap();
        assert_eq!(cli.socks_path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(cli.rules, PathBuf::from("/etc/rules.toml"));
    }

    #[test]
    fn test_get_listener_fallback_to_bind() {
        let temp_dir = std::env::temp_dir();
        let sock_path = temp_dir.join(format!(
            "dnsnfset-test-sock-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut auto_remove_sock: AutoRemoveFile = sock_path.as_path().into();
        let cli = Cli {
            socks_path: sock_path.clone(),
            rules: PathBuf::from("rules.toml"),
        };

        let listener = cli.get_listener(&mut auto_remove_sock).unwrap();
        assert!(sock_path.exists());
        drop(listener);
        drop(auto_remove_sock);
        assert!(!sock_path.exists());
    }

    #[test]
    fn test_listener_from_raw_fd() {
        use std::os::unix::io::IntoRawFd;

        let temp_dir = std::env::temp_dir();
        let sock_path = temp_dir.join(format!(
            "dnsnfset-test-rawfd-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let original = UnixListener::bind(&sock_path).unwrap();
        let raw = original.into_raw_fd();
        let listener = unsafe { UnixListener::from_raw_fd(raw) };

        let client = UnixStream::connect(&sock_path).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(client);
        drop(server);
        drop(listener);
        let _ = std::fs::remove_file(&sock_path);
    }
}
