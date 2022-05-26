mod configuration;
mod data_model;
mod errors;
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

fn main() {
    if let Err(err) = try_main() {
        logging::print(&err);
        if err.is::<errors::TerminatedError>() {
            return;
        }

        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let args = configuration::parse_args(std::env::args())?;
    let args = if let Some(args) = args {
        args
    } else {
        return Ok(());
    };

    let term_token = Arc::new(AtomicBool::new(false));
    register_signal(&term_token)?;
    process::process(&args, &term_token)?;
    Ok(())
}

fn register_signal(token: &Arc<AtomicBool>) -> Result<()> {
    #[cfg(unix)]
    {
        use anyhow::Context;
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(token))
            .map(|_| ())
            .context("Failed to register signal")
    }
    #[cfg(not(unix))]
    {
        _ = token;
        Ok(())
    }
}
