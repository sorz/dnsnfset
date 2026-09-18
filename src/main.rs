use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, info, warn};
use sd_notify::NotifyState;
use signal_hook::{consts::SIGHUP, iterator::Signals};
use std::{
    io,
    sync::{Arc, RwLock},
    thread,
};

use dnsnfset::{cli::Cli, rule::RuleSet, socks::AutoRemoveFile, state::SetState, worker::Worker};

fn main() -> Result<()> {
    env_logger::builder().format_timestamp(None).init();
    let cli = Cli::parse();
    let mut socks_path: AutoRemoveFile = (&cli.socks_path).into();

    let ruleset = RuleSet::from_file(&cli.rules)
        .with_context(|| format!("fail to load rules from {}", cli.rules.display()))?;
    let ruleset = Arc::new(RwLock::new(Arc::new(ruleset)));
    info!("{} rules loaded", ruleset.read().unwrap().len());

    let state = Arc::new(SetState::new());
    let worker = Worker::new(ruleset, state);

    let mut signals = Signals::new([SIGHUP]).context("failed to register SIGHUP signal handler")?;
    let signal_worker = worker.clone();
    let signal_rules_path = cli.rules.clone();
    thread::spawn(move || {
        for sig in signals.forever() {
            if sig == SIGHUP {
                info!("received SIGHUP, reloading...");
                if let Err(err) = NotifyState::monotonic_usec_now()
                    .and_then(|now| sd_notify::notify(&[NotifyState::Reloading, now]))
                {
                    debug!("failed to notify systemd: {:#}", err);
                }

                if let Err(err) = signal_worker.reload(&signal_rules_path) {
                    warn!("failed to reload: {:#}", err);
                }

                if let Err(err) = sd_notify::notify(&[NotifyState::Ready]) {
                    debug!("failed to notify systemd: {:#}", err);
                }
            }
        }
    });

    let listener = cli.get_listener(&mut socks_path)?;

    if let Err(err) = sd_notify::notify(&[NotifyState::Ready]) {
        debug!("failed to notify systemd: {:#}", err);
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let worker = worker.clone();
                thread::spawn(move || match worker.handle_stream(stream) {
                    Ok(_) => info!("unbound disconnected"),
                    Err(err) => warn!("error on thread: {:#}", err),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => warn!("fail to accept connection: {:#}", err),
        }
    }
    Ok(())
}
