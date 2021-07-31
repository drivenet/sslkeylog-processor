mod configuration;
mod datamodel;
mod filesystem;
mod geolocator;
mod logging;
mod process;
mod processor;
mod storage;
mod to_bson;

#[macro_use]
extern crate lazy_static;

use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;

#[cfg(unix)]
use anyhow::Context;

fn main() {
    if let Err(err) = try_main() {
        logging::print_error(&err);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let args = configuration::parse_args(&std::env::args().collect::<Vec<_>>())?;
    let args = if let Some(args) = args {
        args
    } else {
        return Ok(());
    };

    let term_token = Arc::new(AtomicBool::new(false));
    register_signal(&term_token)?;
    process::process(args, &term_token)?;
    Ok(())
}

#[cfg(unix)]
fn register_signal(token: &Arc<AtomicBool>) -> Result<()> {
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&token))
        .map(|_| ())
        .context("Failed to register signal")
}

#[cfg(not(unix))]
fn register_signal(_: &Arc<AtomicBool>) -> Result<()> {
    Ok(())
}
