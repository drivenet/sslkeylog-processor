use std::ffi::OsStr;

use anyhow::{Error, Result};

pub(crate) struct Configuration {
    pub patterns: Vec<String>,
    pub connection_string: String,
    pub db_name: String,
}

pub(crate) fn parse_args(args: &[impl AsRef<OsStr>]) -> Result<Option<Configuration>> {
    let mut opts = getopts::Options::new();
    opts.reqopt("s", "connection", "set connection string", "mongodb://...");
    opts.reqopt("d", "db", "set database name", "test");
    opts.optflag("h", "help", "print this help menu");

    let program = args[0].as_ref().to_string_lossy();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&program, opts);
            return Err(Error::from(e));
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(None);
    }

    let db_name = matches.opt_str("d").unwrap();
    let connection_string = matches.opt_str("s").unwrap();
    let patterns = matches.free;
    if patterns.is_empty() {
        print_usage(&program, opts);
        return Err(Error::msg("Missing file names"));
    };

    Ok(Some(Configuration {
        patterns,
        connection_string,
        db_name,
    }))
}

fn print_usage(program: &str, opts: getopts::Options) {
    let brief = format!("Usage: {} file1 [file2...fileN] [options]", program);
    print!("{}", opts.usage(&brief));
}
