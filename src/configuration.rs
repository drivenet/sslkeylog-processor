use std::ffi::OsStr;

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub(crate) struct Configuration {
    pub files: Vec<String>,
    pub options: mongodb::options::ClientOptions,
    pub db_name: String,
    pub sni_filter: Option<Regex>,
}

pub(crate) fn parse_args(args: &[impl AsRef<OsStr>]) -> Result<Option<Configuration>> {
    let mut opts = getopts::Options::new();
    opts.optflag("h", "help", "show this help");
    opts.optflag("v", "version", "check version");
    opts.optopt(
        "c",
        "connection",
        "set connection string, start with @ to load from file",
        "mongodb://.../dbname?params... | @file",
    );
    opts.optopt(
        "f",
        "filter",
        "set fitler regex, strict (/^...$/)",
        "www\\.domain\\.(com|net)",
    );

    let program = args[0].as_ref().to_string_lossy();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&program, &opts);
            bail!(e);
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return Ok(None);
    }

    if matches.opt_present("v") {
        println!("sslkeylog-processor {}", PACKAGE_VERSION);
        return Ok(None);
    }

    let connection_string = matches.opt_str("c").ok_or_else(|| {
        print_usage(&program, &opts);
        anyhow!("Missing connection string")
    })?;

    let sni_filter = matches
        .opt_str("f")
        .map(|f| Regex::new(&format!("^{}$", f)))
        .transpose()
        .context("Invalid SNI filter")?;

    let files = matches.free;
    if files.is_empty() {
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
            .trim()
            .to_owned()
    } else {
        connection_string
    };

    let options = mongodb::options::ClientOptions::parse(&connection_string)
        .context("Failed to parse connection string")?;

    let db_name = connection_string
        .find("://")
        .and_then(|i| {
            let s = &connection_string[i + 3..];
            s.find('/').map(|i| &s[i + 1..])
        })
        .map(|s| s.find('?').map(|i| &s[..i]).unwrap_or(s))
        .and_then(|d| if d.is_empty() { None } else { Some(d) })
        .ok_or_else(|| anyhow!("Failed to parse database name from connection string"))?
        .to_owned();

    Ok(Some(Configuration {
        files,
        options,
        db_name,
        sni_filter,
    }))
}

fn print_usage(program: &str, opts: &getopts::Options) {
    let brief = format!(
        "Usage: {} file1 [file2...fileN] [options]\nVersion: {}",
        program, PACKAGE_VERSION
    );
    print!("{}", opts.usage(&brief));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let config = parse_args(&[
            "program",
            "test",
            "test2",
            "-c",
            "mongodb://user:pass@host1:27017,host2:27017,host3:27017/keys?replicaSet=rs&authSource=admin",
        ])
        .expect("Failed to parse arguments")
        .expect("Failed to get real arguments");

        assert_eq!(config.files, &["test", "test2"]);
        assert_eq!(config.db_name, "keys");
    }
}
