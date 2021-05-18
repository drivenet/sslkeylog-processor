#[macro_use]
extern crate lazy_static;

use anyhow::{Context, Error, Result};
use chrono::{DateTime, Utc};
use mongodb::bson::{self, doc, Bson};
use regex::Regex;
use std::{io::BufRead, net::IpAddr, str::FromStr, time::Duration, time::SystemTime};

const TIME_TO_LIVE: u16 = 183;
const KEYS_COLLECTION_NAME: &str = "keys";

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let program = args[0].clone();

    let mut opts = getopts::Options::new();
    opts.reqopt("s", "connection", "set connection string", "mongodb://...");
    opts.reqopt("d", "db", "set database name", "test");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&program, opts);
            return Err(Error::from(e));
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(());
    }

    let db_name = matches.opt_str("d").unwrap();
    let connection_string = matches.opt_str("s").unwrap();
    let patterns = matches.free;
    if patterns.is_empty() {
        print_usage(&program, opts);
        return Err(Error::msg("Missing file names"));
    };

    let db = mongodb::sync::Client::with_uri_str(&connection_string)?.database(&db_name);
    let keys_collection = db.collection(KEYS_COLLECTION_NAME);

    // TODO: create indexes with method calls when available
    db.run_command(
        doc! {
        "createIndexes": keys_collection.name(),
        "indexes": vec![
            doc! {
                "key": doc! { "t" : 1 },
                "name": "expiration",
                "expireAfterSeconds": u64::from(TIME_TO_LIVE) * 86400,
            },
            doc! {
                "key": doc! { "_id.c" : 1 },
                "name": "client_random",
            },
        ],
        },
        None,
    )
    .context("Failed to create indexes")?;

    let threshold = SystemTime::now() + Duration::from_secs(60);
    let paths: Vec<_> = if cfg!(windows) {
        let glob_result: Result<Vec<_>, _> = patterns.iter().map(|p| glob::glob(p)).collect();
        let globbed_paths: Result<Vec<_>, _> = glob_result?.into_iter().flatten().collect();
        globbed_paths?.into_iter().collect()
    } else {
        patterns.iter().map(std::path::PathBuf::from).collect()
    };

    for path in paths {
        process_entry(&path, threshold, &keys_collection)?;
    }

    Ok(())
}

fn print_usage(program: &str, opts: getopts::Options) {
    let brief = format!("Usage: {} file1 [file2...fileN] [options]", program);
    print!("{}", opts.usage(&brief));
}

fn process_entry(
    path: &std::path::Path,
    threshold: SystemTime,
    keys_collection: &mongodb::sync::Collection,
) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for entry {}", path.display()))?;
    if !metadata.is_file() {
        return Ok(());
    }

    let mtime = metadata
        .modified()
        .with_context(|| format!("Failed to get mtime for file {}", path.display()))?;
    if mtime > threshold {
        return Ok(());
    }

    process_file(path, keys_collection)?;

    Ok(())
}

fn process_file(
    path: &std::path::Path,
    keys_collection: &mongodb::sync::Collection,
) -> Result<(), Error> {
    let file_name = &path.display();

    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open file {}", file_name))?;
    let lines = std::io::BufReader::new(file).lines().map(|l| {
        l.with_context(|| format!("Failed to read line from file {}", file_name))
            .unwrap()
    });

    process_lines(lines, file_name, keys_collection)?;

    std::fs::remove_file(&path)
        .with_context(|| format!("Failed to remove file {}", path.display()))?;

    Ok(())
}

fn process_lines(
    lines: impl IntoIterator<Item = String>,
    file_name: &impl std::fmt::Display,
    keys_collection: &mongodb::sync::Collection,
) -> Result<()> {
    let mut batch: Vec<bson::Document> = Vec::new();
    let mut line_num: u64 = 0;
    for line in lines {
        line_num += 1;
        let context = ParseContext {
            file_name,
            line_num,
        };

        let record = parse(&line, &context)?;
        let document = convert(&record);
        batch.push(document);

        const BATCH_SIZE: usize = 1000;
        if batch.len() >= BATCH_SIZE {
            write_batch(&keys_collection, batch, &context)?;
            batch = Vec::new();
        }
    }

    if !batch.is_empty() {
        let context = ParseContext {
            file_name,
            line_num,
        };
        write_batch(&keys_collection, batch, &context)?;
    }

    println!("{}: {}", file_name, line_num);
    Ok(())
}

fn write_batch(
    keys_collection: &mongodb::sync::Collection,
    batch: Vec<bson::Document>,
    context: &ParseContext,
) -> Result<()> {
    let options = mongodb::options::InsertManyOptions::builder()
        .ordered(false)
        .build();
    match keys_collection.insert_many(batch, options) {
        Ok(_) => Ok(()),
        Err(e) => {
            if let mongodb::error::ErrorKind::BulkWriteError(failure) = e.kind.as_ref() {
                if failure.write_concern_error.is_none()
                    && failure
                        .write_errors
                        .as_ref()
                        .map(|e| e.iter().all(|error| error.code == 11000))
                        .unwrap_or(false)
                {
                    return Ok(());
                }
            }

            Err(Error::from(e))
                .with_context(|| format!("Failed to insert records from {}", context))
        }
    }
}

fn parse(line: &str, context: &ParseContext) -> Result<Record> {
    const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{1,4}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{16,})$";
    lazy_static! {
        static ref FILTER_REGEX: Regex = Regex::new(FILTER_REGEX_PATTERN).unwrap();
    }

    let captures = FILTER_REGEX
        .captures(line)
        .with_context(|| format!("Failed to parse line at {}\n{}", context, line))?;
    let timestamp = &captures[1];
    let timestamp = DateTime::parse_from_rfc3339(timestamp)
        .with_context(|| format!("Invalid timestamp {} at {}", timestamp, context))?
        .with_timezone(&Utc);
    let client_ip = &captures[2];
    let client_ip = IpAddr::from_str(client_ip)
        .with_context(|| format!("Invalid client IP address {} at {}", client_ip, context))?;
    let client_port = &captures[3];
    let client_port = u16::from_str(client_port)
        .with_context(|| format!("Invalid client port {} at {}", client_port, context))?;
    let server_ip = &captures[4];
    let server_ip = IpAddr::from_str(server_ip)
        .with_context(|| format!("Invalid server IP address {} at {}", server_ip, context))?;
    let server_port = &captures[5];
    let server_port = u16::from_str(server_port)
        .with_context(|| format!("Invalid server port {} at {}", server_port, context))?;
    let sni = &captures[6];
    let cipher_id = &captures[7];
    let cipher_id = u16::from_str_radix(cipher_id, 16)
        .with_context(|| format!("Invalid cipher id {} at {}", cipher_id, context))?;
    let server_random = &captures[8];
    let server_random = hex::decode(server_random)
        .with_context(|| format!("Invalid server random {} at {}", server_random, context))?;
    let client_random = &captures[9];
    let client_random = hex::decode(client_random)
        .with_context(|| format!("Invalid client random {} at {}", client_random, context))?;
    let premaster = &captures[10];
    let premaster = hex::decode(premaster)
        .with_context(|| format!("Invalid premaster secret {} at {}", premaster, context))?;

    Ok(Record {
        timestamp,
        client_ip,
        client_port,
        server_ip,
        server_port,
        sni: sni.to_string(),
        cipher_id,
        server_random,
        client_random,
        premaster,
    })
}

fn convert(record: &Record) -> bson::Document {
    let id = doc! {
        "p": record.server_port as i32,
        "i": record.server_ip.to_bson(),
        "h": &record.sni,
        "c": record.client_random.to_bson(),
    };
    doc! {
        "_id": id,
        "t": record.timestamp,
        "i": record.client_ip.to_bson(),
        "p": record.client_port as i32,
        "c": record.cipher_id as i32,
        "r": record.server_random.to_bson(),
        "p": record.premaster.to_bson(),
    }
}

struct Record {
    pub timestamp: DateTime<Utc>,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub sni: String,
    pub cipher_id: u16,
    pub server_random: Vec<u8>,
    pub client_random: Vec<u8>,
    pub premaster: Vec<u8>,
}

trait ToBson {
    fn to_bson(&self) -> Bson;
}

impl ToBson for Vec<u8> {
    fn to_bson(&self) -> Bson {
        Bson::from(bson::Binary {
            subtype: bson::spec::BinarySubtype::UserDefined(0),
            bytes: self.to_vec(),
        })
    }
}

impl ToBson for IpAddr {
    fn to_bson(&self) -> Bson {
        match self {
            IpAddr::V4(a) => Bson::from(u32::from(*a)),
            IpAddr::V6(a) => Bson::from(bson::Binary {
                subtype: bson::spec::BinarySubtype::UserDefined(0),
                bytes: a.octets().to_vec(),
            }),
        }
    }
}

struct ParseContext<'local> {
    pub file_name: &'local dyn std::fmt::Display,
    pub line_num: u64,
}

impl<'local> std::fmt::Display for ParseContext<'local> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.file_name, self.line_num))
    }
}
