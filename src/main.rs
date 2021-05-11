#[macro_use]
extern crate lazy_static;

use anyhow::Context;
use chrono::{DateTime, Utc};
use mongodb::bson;
use regex::Regex;
use std::{io::BufRead, net::IpAddr, path::Path, str::FromStr, time::Duration, time::SystemTime};

fn main() -> anyhow::Result<()> {
    let collection = mongodb::sync::Client::with_uri_str("mongodb://localhost/")?
        .database("keys")
        .collection("keys");
    let threshold = SystemTime::now() + Duration::from_secs(60);
    for path in glob::glob(r"C:\Users\xm\Projects\dumps\sslkeylog\nginx-*")?.flatten() {
        process_file(&path, threshold, &collection)?;
    }

    Ok(())
}

fn process_file(
    path: &Path,
    threshold: SystemTime,
    collection: &mongodb::sync::Collection,
) -> anyhow::Result<()> {
    let entry_name = &path.display();

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for entry {}", entry_name))?;
    if !metadata.is_file() {
        return Ok(());
    }
    let mtime = metadata
        .modified()
        .with_context(|| format!("Failed to get mtime for file {}", entry_name))?;
    if mtime > threshold {
        return Ok(());
    }

    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open file {}", entry_name))?;
    let lines = std::io::BufReader::new(file).lines().map(|l| {
        l.with_context(|| format!("Failed to read line from file {}", entry_name))
            .unwrap()
    });
    process_lines(lines, entry_name, collection)
}

fn process_lines(
    lines: impl IntoIterator<Item = String>,
    file_name: &impl std::fmt::Display,
    collection: &mongodb::sync::Collection,
) -> anyhow::Result<()> {
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
            write_batch(&collection, batch, &context)?;
            batch = Vec::new();
        }
    }

    if !batch.is_empty() {
        let context = ParseContext {
            file_name,
            line_num,
        };
        write_batch(&collection, batch, &context)?;
    }

    println!("{}: {}", file_name, line_num);
    Ok(())
}

fn write_batch(
    collection: &mongodb::sync::Collection,
    batch: Vec<bson::Document>,
    context: &ParseContext,
) -> anyhow::Result<()> {
    collection
        .insert_many(batch, None)
        .with_context(|| format!("Failed to insert records from {}", context))?;
    Ok(())
}

fn parse(line: &str, context: &ParseContext) -> anyhow::Result<Record> {
    const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{2,}) ([0-9a-fA-F]{2,})$";
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
    let src_ip = &captures[2];
    let src_ip = IpAddr::from_str(src_ip)
        .with_context(|| format!("Invalid source IP address {} at {}", src_ip, context))?;
    let src_port = &captures[3];
    let src_port = u16::from_str(src_port)
        .with_context(|| format!("Invalid source port {} at {}", src_port, context))?;
    let dst_ip = &captures[4];
    let dst_ip = IpAddr::from_str(dst_ip)
        .with_context(|| format!("Invalid destination IP address {} at {}", dst_ip, context))?;
    let dst_port = &captures[5];
    let dst_port = u16::from_str(dst_port)
        .with_context(|| format!("Invalid destination port {} at {}", dst_port, context))?;
    let sni = &captures[6];
    let client_random = &captures[7];
    let client_random = hex::decode(client_random)
        .with_context(|| format!("Invalid client random {} at {}", client_random, context))?;
    let premaster_key = &captures[8];
    let premaster_key = hex::decode(premaster_key)
        .with_context(|| format!("Invalid premaster key {} at {}", premaster_key, context))?;

    Ok(Record {
        timestamp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        sni: sni.to_string(),
        client_random,
        premaster_key,
    })
}

fn convert(record: &Record) -> bson::Document {
    let mut document = bson::Document::new();
    document.insert("_id", record.client_random.to_bson());
    document.insert("s", record.src_ip.to_bson());
    document.insert("sp", record.src_port as i32);
    document.insert("d", record.dst_ip.to_bson());
    document.insert("dp", record.dst_port as i32);
    document.insert("t", record.timestamp);
    document.insert("h", &record.sni);
    document.insert("k", record.premaster_key.to_bson());
    document
}

struct Record {
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub sni: String,
    pub client_random: Vec<u8>,
    pub premaster_key: Vec<u8>,
}

trait ToBson {
    fn to_bson(&self) -> bson::Bson;
}

impl ToBson for Vec<u8> {
    fn to_bson(&self) -> bson::Bson {
        bson::Bson::from(bson::Binary {
            subtype: bson::spec::BinarySubtype::UserDefined(0),
            bytes: self.to_vec(),
        })
    }
}

impl ToBson for IpAddr {
    fn to_bson(&self) -> bson::Bson {
        match self {
            IpAddr::V4(a) => bson::Bson::from(u32::from(*a)),
            IpAddr::V6(a) => bson::Bson::from(bson::Binary {
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
