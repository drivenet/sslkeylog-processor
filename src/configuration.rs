use std::ffi::OsStr;

use anyhow::{anyhow, bail, Context, Result};

pub(crate) struct Configuration {
    pub patterns: Vec<String>,
    pub connection_string: String,
    pub db_name: String,
}

pub(crate) fn parse_args(args: &[impl AsRef<OsStr>]) -> Result<Configuration> {
    let mut opts = getopts::Options::new();
    opts.reqopt(
        "c",
        "connection",
        "set connection string, start with @ to load from file",
        "mongodb://.../dbname?params... | @file",
    );

    let program = args[0].as_ref().to_string_lossy();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&program, &opts);
            bail!(e);
        }
    };

    let connection_string = matches.opt_str("c").unwrap();
    let patterns = matches.free;
    if patterns.is_empty() {
        print_usage(&program, &opts);
        bail!("Missing file names");
    };

    let connection_string = if let Some(cs_name) = connection_string.strip_prefix('@') {
        let content = std::fs::read(cs_name)
            .with_context(|| format!("Failed to read connection string from file {}", cs_name))?;
        let content = std::str::from_utf8(&content)
            .with_context(|| format!("Broken connection string encoding in file {}", cs_name))?;
        content
            .strip_prefix("\u{FEFF}")
            .unwrap_or(content)
            .to_owned()
    } else {
        connection_string
    };

    let url = url::Url::parse(&connection_string).context("Failed to parse connection string")?;
    let db_name = url
        .path()
        .strip_prefix('/')
        .and_then(|d| if d.is_empty() { None } else { Some(d) })
        .ok_or_else(|| anyhow!("Failed to parse database name from connection string"))?
        .to_owned();

    Ok(Configuration {
        patterns,
        connection_string,
        db_name,
    })
}

fn print_usage(program: &str, opts: &getopts::Options) {
    let brief = format!("Usage: {} file1 [file2...fileN] [options]", program);
    print!("{}", opts.usage(&brief));
}
