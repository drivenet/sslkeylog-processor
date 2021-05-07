use anyhow::{self, Context};
use chrono;
use glob;
use hex;
use mongodb::bson;
use regex::Regex;
use std::{self, fs, io::{self, BufRead}, net, str::FromStr, time};

fn main() -> anyhow::Result<()> {
    let regex = Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{2,}) ([0-9a-fA-F]{2,})$")?;
    let db_client = mongodb::sync::Client::with_uri_str("mongodb://localhost/")?;
    let db = db_client.database("keys").collection("keys");
    let threshold = time::SystemTime::now() + time::Duration::from_secs(60);
    for entry_name in glob::glob(r"C:\Users\xm\Projects\dumps\sslkeylog\nginx-*")?.flat_map(|f| f)
    {
        let metadata = std::fs::metadata(&entry_name).with_context(|| format!("Failed to get metadata for entry {:?}", entry_name))?;
        if !metadata.is_file() {
            continue;
        }

        let mtime = metadata.modified().with_context(|| format!("Failed to get mtime for {:?}", entry_name))?;
        if mtime > threshold {
            continue;
        }
        
        let file = fs::File::open(&entry_name).with_context(|| format!("Failed to open file {:?}", entry_name))?;
        let reader = io::BufReader::new(file);
        let mut line_num: u64 = 0;
        for line in reader.lines().map(|l| l.with_context(|| format!("Failed to read line from file {:?}", entry_name))) {
            let line = line?;
            let captures = regex.captures(&line).with_context(|| format!("Failed to parse line {:?}:{}\n{}", entry_name, line_num, line))?;
            let timestamp = &captures[1];
            let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp).with_context(|| format!("Invalid timestamp {} at {:?}:{}", timestamp, entry_name, line_num))?.with_timezone(&chrono::Utc);
            let source_ip = &captures[2];
            let source_ip = net::IpAddr::from_str(source_ip).with_context(|| format!("Invalid source IP address {} at {:?}:{}", source_ip, entry_name, line_num))?;
            let source_port = &captures[3];
            let source_port = u16::from_str(source_port).with_context(|| format!("Invalid source port {} at {:?}:{}", source_port, entry_name, line_num))?;
            let destination_ip = &captures[4];
            let destination_ip = net::IpAddr::from_str(destination_ip).with_context(|| format!("Invalid destination IP address {} at {:?}:{}", destination_ip, entry_name, line_num))?;
            let destination_port = &captures[5];
            let destination_port = u16::from_str(destination_port).with_context(|| format!("Invalid destination port {} at {:?}:{}", destination_port, entry_name, line_num))?;
            let sni = &captures[6];
            let client_random = &captures[7];
            let client_random = hex::decode(client_random).with_context(|| format!("Invalid client random {} at {:?}:{}", client_random, entry_name, line_num))?;
            let premaster_key = &captures[8];
            let premaster_key = hex::decode(premaster_key).with_context(|| format!("Invalid premaster key {} at {:?}:{}", premaster_key, entry_name, line_num))?;

            let mut document = bson::Document::new();
            document.insert("_id", bson::Binary { subtype: bson::spec::BinarySubtype::UserDefined(0), bytes: client_random });
            insert_addr(&mut document, "s", &source_ip);
            document.insert("sp", source_port as i32);
            insert_addr(&mut document, "d", &destination_ip);
            document.insert("dp", destination_port as i32);
            document.insert("t", timestamp);
            document.insert("h", sni);
            document.insert("k", bson::Binary { subtype: bson::spec::BinarySubtype::UserDefined(0), bytes: premaster_key });
            db.insert_one(document,None).with_context(|| format!("Failed to insert record read at {:?}:{}", entry_name, line_num))?;
            line_num += 1;
        }

        println!("{:?}: {}", entry_name, line_num);
    }

    Ok(())
}

fn insert_addr(document: &mut bson::Document, key: &str, addr: &net::IpAddr) {
    match addr {
        net::IpAddr::V4(a) => document.insert(key, u32::from(*a)),
        net::IpAddr::V6(a) => document.insert(key, bson::Binary { subtype: bson::spec::BinarySubtype::UserDefined(0), bytes: a.octets().to_vec() }),
    };
}


