use anyhow::Context;
use mongodb::bson;
use std::{fs, io::BufRead, net, str::FromStr, time};

fn main() -> anyhow::Result<()> {
    let regex = regex::Regex::new(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{2,}) ([0-9a-fA-F]{2,})$",
    )?;
    let collection = mongodb::sync::Client::with_uri_str("mongodb://localhost/")?
        .database("keys")
        .collection("keys");
    let threshold = time::SystemTime::now() + time::Duration::from_secs(60);
    for entry_path in glob::glob(r"C:\Users\xm\Projects\dumps\sslkeylog\nginx-*")?.flatten() {
        let entry_path = entry_path.as_path();
        let entry_name = entry_path.display();
        let metadata = fs::metadata(entry_path)
            .with_context(|| format!("Failed to get metadata for entry {}", entry_name))?;
        if !metadata.is_file() {
            continue;
        }

        let mtime = metadata
            .modified()
            .with_context(|| format!("Failed to get mtime for file {}", entry_name))?;
        if mtime > threshold {
            continue;
        }

        let file = fs::File::open(entry_path)
            .with_context(|| format!("Failed to open file {}", entry_name))?;
        let reader = std::io::BufReader::new(file);
        let mut batch: Vec<bson::Document> = Vec::new();
        let mut line_num: u64 = 0;
        for line in reader
            .lines()
            .map(|l| l.with_context(|| format!("Failed to read line from file {}", entry_name)))
        {
            let context = ParseContext {
                entry_name: &entry_name,
                line_num,
            };
            let line = &line?;
            let captures = regex.captures(line).with_context(|| {
                format!(
                    "Failed to parse line at {}\n{}",
                    context, line
                )
            })?;
            let timestamp = &captures[1];
            let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
                .with_context(|| {
                    format!(
                        "Invalid timestamp {} at {}",
                        timestamp, context
                    )
                })?
                .with_timezone(&chrono::Utc);
            let source_ip = &captures[2];
            let source_ip = net::IpAddr::from_str(source_ip).with_context(|| {
                format!(
                    "Invalid source IP address {} at {}",
                    source_ip, context
                )
            })?;
            let source_port = &captures[3];
            let source_port = u16::from_str(source_port).with_context(|| {
                format!(
                    "Invalid source port {} at {}",
                    source_port, context
                )
            })?;
            let destination_ip = &captures[4];
            let destination_ip = net::IpAddr::from_str(destination_ip).with_context(|| {
                format!(
                    "Invalid destination IP address {} at {}",
                    destination_ip, context
                )
            })?;
            let destination_port = &captures[5];
            let destination_port = u16::from_str(destination_port).with_context(|| {
                format!(
                    "Invalid destination port {} at {}",
                    destination_port, context
                )
            })?;
            let sni = &captures[6];
            let client_random = &captures[7];
            let client_random = hex::decode(client_random).with_context(|| {
                format!(
                    "Invalid client random {} at {}",
                    client_random, context
                )
            })?;
            let premaster_key = &captures[8];
            let premaster_key = hex::decode(premaster_key).with_context(|| {
                format!(
                    "Invalid premaster key {} at {}",
                    premaster_key, context
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
                write_batch(&collection, batch, &context)?;
                batch = Vec::new();
            }

            line_num += 1;
        }

        if !batch.is_empty() {
            write_batch(&collection, batch, &ParseContext { entry_name: &entry_name, line_num })?;
        }

        println!("{}: {}", entry_name, line_num);
    }

    Ok(())
}

fn write_batch(
    collection: &mongodb::sync::Collection,
    batch: Vec<bson::Document>,
    context: &ParseContext,
) -> anyhow::Result<()> {
    collection.insert_many(batch, None).with_context(|| {
        format!(
            "Failed to insert records from {}", context
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

struct ParseContext<'local> {
    pub entry_name: &'local dyn std::fmt::Display,
    pub line_num: u64,
}

impl<'local> std::fmt::Display for ParseContext<'local> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.entry_name, self.line_num))
    }
}
