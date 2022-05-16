use std::{convert::TryFrom, net::IpAddr, str::FromStr, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use mongodb::bson::{self, doc};
use regex::Regex;
use url::{self, Host, Url};

use crate::{logging, to_bson::ToBson};

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

pub(crate) struct EnrichedRecord<'a> {
    pub record: &'a Record,
    pub geoname_id: u32,
}

pub(crate) fn get_index_model() -> Vec<bson::Document> {
    vec![
        doc! {
            "key": doc! { "r" : 1 },
            "name": "random",
        },
        doc! {
            "key": doc! { "t" : 1 },
            "name": "timestamp",
        },
    ]
}

impl From<&Record> for bson::Document {
    fn from(record: &Record) -> Self {
        doc! {
            "_id": record.server_random.to_bson(),
            "c": record.cipher_id as i32,
            "t": record.timestamp,
            "i": record.client_ip.to_bson(),
            "p": record.client_port as i32,
            "r": record.client_random.to_bson(),
            "k": record.premaster.to_bson(),
        }
    }
}

impl<'a> From<&EnrichedRecord<'a>> for bson::Document {
    fn from(record: &EnrichedRecord) -> Self {
        let mut document = Self::from(record.record);
        document.insert("g", record.geoname_id);
        document
    }
}

impl TryFrom<&str> for Record {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{1,4}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{16,})$";
        lazy_static! {
            static ref FILTER_REGEX: Regex = Regex::new(FILTER_REGEX_PATTERN).expect("Failed to parse filter regex");
        }

        let captures = FILTER_REGEX
            .captures(value)
            .with_context(|| format!("Invalid line {}", value))?;
        let timestamp = &captures[1];
        let timestamp = DateTime::parse_from_rfc3339(timestamp)
            .with_context(|| format!("Invalid timestamp {}", timestamp))?
            .with_timezone(&Utc);
        let client_ip = &captures[2];
        let client_ip = IpAddr::from_str(client_ip).with_context(|| format!("Invalid client IP address {}", client_ip))?;
        let client_port = &captures[3];
        let client_port = u16::from_str(client_port).with_context(|| format!("Invalid client port {}", client_port))?;
        let server_ip = &captures[4];
        let server_ip = IpAddr::from_str(server_ip).with_context(|| format!("Invalid server IP address {}", server_ip))?;
        let server_port = &captures[5];
        let server_port = u16::from_str(server_port).with_context(|| format!("Invalid server port {}", server_port))?;
        let sni = &captures[6];
        let cipher_id = &captures[7];
        let cipher_id = u16::from_str_radix(cipher_id, 16).with_context(|| format!("Invalid cipher id {}", cipher_id))?;
        let server_random = &captures[8];
        let server_random = hex::decode(server_random).with_context(|| format!("Invalid server random {}", server_random))?;
        let client_random = &captures[9];
        let client_random = hex::decode(client_random).with_context(|| format!("Invalid client random {}", client_random))?;
        let premaster = &captures[10];
        let premaster = hex::decode(premaster).with_context(|| format!("Invalid premaster secret {}", premaster))?;

        let sni = parse_sni(sni, server_ip, server_port).with_context(|| format!("Invalid SNI {} in line {}", sni, value));
        let sni = match sni {
            Ok(v) => v,
            Err(e) => {
                logging::print_warning(&e);
                String::new()
            }
        };

        Ok(Record {
            timestamp,
            client_ip,
            client_port,
            server_ip,
            server_port,
            sni,
            cipher_id,
            server_random,
            client_random,
            premaster,
        })
    }
}

fn parse_sni(sni: &str, server_ip: IpAddr, server_port: u16) -> Result<String> {
    if sni.is_empty() {
        return Ok(String::new());
    }

    let url = format!("https://{}/", sni);
    let url = Url::parse(&url).context("Invalid SNI format")?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "Unexpected SNI format"
    );

    if let Some(port) = url.port() {
        ensure!(
            port == server_port,
            "Mismatching port, expected {}, got {}",
            server_port,
            port
        );
    }

    Ok(match url.host() {
        Some(Host::Ipv4(a)) => {
            ensure!(a == server_ip, "Mismatching IPv4 address, expected {}, got {}", server_ip, a);
            ""
        }
        Some(Host::Ipv6(a)) => {
            ensure!(a == server_ip, "Mismatching IPv6 address, expected {}, got {}", server_ip, a);
            ""
        }
        Some(Host::Domain(d)) => d.trim_end_matches('.'),
        None => bail!("Missing host"),
    }
    .to_string())
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse_sni_test(sni: &str, server_ip: &str, server_port: u16) -> String {
        parse_sni(sni, IpAddr::from_str(server_ip).unwrap(), server_port).unwrap()
    }

    #[test]
    fn parse_sni_normalizes_domain() {
        assert_eq!(
            "some-sni.host.domain",
            parse_sni_test("some-SNI.HoSt.DoMain.", "127.0.0.1", 443)
        );
    }

    #[test]
    fn parse_sni_normalizes_ips() {
        assert_eq!("", parse_sni_test("192.168.88.17", "192.168.88.17", 443));
        assert_eq!("", parse_sni_test("127.000.0.1:587", "127.0.0.1", 587));
        assert_eq!("", parse_sni_test("8.007.132.66:443", "8.7.132.66", 443));
    }

    #[test]
    #[should_panic]
    fn parse_sni_fails_on_invalid_hosts() {
        parse_sni_test("just-a-host.com/some-url#fragment", "127.0.0.1", 80);
    }

    #[test]
    #[should_panic]
    fn parse_sni_fails_on_invalid_port() {
        parse_sni_test("just-a-host.com:1193", "127.0.0.1", 80);
    }

    #[test]
    fn parse_sni_doesnt_fail_on_invalid_implicit_port() {
        assert_eq!("just-a-host.com", parse_sni_test("just-a-host.com", "127.0.0.1", 80,));
    }
}
