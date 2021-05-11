use anyhow::Context;
use mongodb::bson;
use std::{fs, io::BufRead, net, path, str::FromStr, time};

fn main() -> anyhow::Result<()> {
    let regex = regex::Regex::new(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{2,}) ([0-9a-fA-F]{2,})$",
    )?;
    let collection = mongodb::sync::Client::with_uri_str("mongodb://localhost/")?
        .database("keys")
        .collection("keys");
    let threshold = time::SystemTime::now() + time::Duration::from_secs(60);
    for entry_name in glob::glob(r"C:\Users\xm\Projects\dumps\sslkeylog\nginx-*")?.flatten() {
        let entry_name = entry_name.as_path();
        let metadata = fs::metadata(entry_name)
            .with_context(|| format!("Failed to get metadata for entry {:?}", entry_name))?;
        if !metadata.is_file() {
            continue;
        }

        let mtime = metadata
            .modified()
            .with_context(|| format!("Failed to get mtime for {:?}", entry_name))?;
        if mtime > threshold {
            continue;
        }

        let file = fs::File::open(entry_name)
            .with_context(|| format!("Failed to open file {:?}", entry_name))?;
        let reader = std::io::BufReader::new(file);
        let mut batch: Vec<bson::Document> = Vec::new();
        let mut line_num: u64 = 0;
        for line in reader
            .lines()
            .map(|l| l.with_context(|| format!("Failed to read line from file {:?}", entry_name)))
        {
            let line = &line?;
            let captures = regex.captures(line).with_context(|| {
                format!(
                    "Failed to parse line {:?}:{}\n{}",
                    entry_name, line_num, line
                )
            })?;
            let timestamp = &captures[1];
            let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
                .with_context(|| {
                    format!(
                        "Invalid timestamp {} at {:?}:{}",
                        timestamp, entry_name, line_num
                    )
                })?
                .with_timezone(&chrono::Utc);
            let source_ip = &captures[2];
            let source_ip = net::IpAddr::from_str(source_ip).with_context(|| {
                format!(
                    "Invalid source IP address {} at {:?}:{}",
                    source_ip, entry_name, line_num
                )
            })?;
            let source_port = &captures[3];
            let source_port = u16::from_str(source_port).with_context(|| {
                format!(
                    "Invalid source port {} at {:?}:{}",
                    source_port, entry_name, line_num
                )
            })?;
            let destination_ip = &captures[4];
            let destination_ip = net::IpAddr::from_str(destination_ip).with_context(|| {
                format!(
                    "Invalid destination IP address {} at {:?}:{}",
                    destination_ip, entry_name, line_num
                )
            })?;
            let destination_port = &captures[5];
            let destination_port = u16::from_str(destination_port).with_context(|| {
                format!(
                    "Invalid destination port {} at {:?}:{}",
                    destination_port, entry_name, line_num
                )
            })?;
            let sni = &captures[6];
            let client_random = &captures[7];
            let client_random = hex::decode(client_random).with_context(|| {
                format!(
                    "Invalid client random {} at {:?}:{}",
                    client_random, entry_name, line_num
                )
            })?;
            let premaster_key = &captures[8];
            let premaster_key = hex::decode(premaster_key).with_context(|| {
                format!(
                    "Invalid premaster key {} at {:?}:{}",
                    premaster_key, entry_name, line_num
                )
            })?;

            let mut document = bson::Document::new();
            document.insert("_id", client_random.to_bson());
            document.insert("s", source_ip.to_bson());
            document.insert("sp", source_port as i32);
            document.insert("d", destination_ip.to_bson());
            document.insert("dp", destination_port as i32);
            document.insert("t", timestamp);
            document.insert("h", sni);
            document.insert("k", premaster_key.to_bson());
            batch.push(document);
            if batch.len() >= 1000 {
                write_batch(&collection, batch, entry_name, line_num)?;
                batch = Vec::new();
            }

            line_num += 1;
        }

        if !batch.is_empty() {
            write_batch(&collection, batch, entry_name, line_num)?;
        }

        println!("{:?}: {}", entry_name, line_num);
    }

    Ok(())
}

fn write_batch(
    collection: &mongodb::sync::Collection,
    batch: Vec<bson::Document>,
    entry_name: &path::Path,
    line_num: u64,
) -> anyhow::Result<()> {
    collection.insert_many(batch, None).with_context(|| {
        format!(
            "Failed to insert records, last at {:?}:{}",
            entry_name, line_num
        )
    })?;
    Ok(())
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

impl ToBson for net::IpAddr {
    fn to_bson(&self) -> bson::Bson {
        match self {
            net::IpAddr::V4(a) => bson::Bson::from(u32::from(*a)),
            net::IpAddr::V6(a) => bson::Bson::from(bson::Binary {
                subtype: bson::spec::BinarySubtype::UserDefined(0),
                bytes: a.octets().to_vec(),
            }),
        }
    }
}
