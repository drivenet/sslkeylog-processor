use std::{convert::TryFrom, net::IpAddr, str::FromStr};

use anyhow::Context;
use chrono::{DateTime, Utc};
use mongodb::bson::{self, doc};
use regex::Regex;

use crate::to_bson::ToBson;

pub(crate) struct Record {
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

impl From<Record> for bson::Document {
    fn from(record: Record) -> Self {
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
}

impl TryFrom<&str> for Record {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{1,4}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{16,})$";
        lazy_static! {
            static ref FILTER_REGEX: Regex = Regex::new(FILTER_REGEX_PATTERN).unwrap();
        }

        let captures = FILTER_REGEX
            .captures(value)
            .with_context(|| format!("Invalid line {}", value))?;
        let timestamp = &captures[1];
        let timestamp = DateTime::parse_from_rfc3339(timestamp)
            .with_context(|| format!("Invalid timestamp {}", timestamp))?
            .with_timezone(&Utc);
        let client_ip = &captures[2];
        let client_ip = IpAddr::from_str(client_ip)
            .with_context(|| format!("Invalid client IP address {}", client_ip))?;
        let client_port = &captures[3];
        let client_port = u16::from_str(client_port)
            .with_context(|| format!("Invalid client port {}", client_port))?;
        let server_ip = &captures[4];
        let server_ip = IpAddr::from_str(server_ip)
            .with_context(|| format!("Invalid server IP address {}", server_ip))?;
        let server_port = &captures[5];
        let server_port = u16::from_str(server_port)
            .with_context(|| format!("Invalid server port {}", server_port))?;
        let sni = &captures[6];
        let cipher_id = &captures[7];
        let cipher_id = u16::from_str_radix(cipher_id, 16)
            .with_context(|| format!("Invalid cipher id {}", cipher_id))?;
        let server_random = &captures[8];
        let server_random = hex::decode(server_random)
            .with_context(|| format!("Invalid server random {}", server_random))?;
        let client_random = &captures[9];
        let client_random = hex::decode(client_random)
            .with_context(|| format!("Invalid client random {}", client_random))?;
        let premaster = &captures[10];
        let premaster = hex::decode(premaster)
            .with_context(|| format!("Invalid premaster secret {}", premaster))?;

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
}