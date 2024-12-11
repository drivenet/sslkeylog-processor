use std::{convert::TryFrom, net::IpAddr, str::FromStr};

use anyhow::{anyhow, bail, ensure, Context, Result};
use mongodb::bson::{self, doc};
use regex::Regex;
use time::{format_description, OffsetDateTime};
use url::{self, Host, Url};

use crate::{logging, to_bson::ToBson};

pub(crate) trait BsonSerializable {
    fn serialize(&self, document: &mut bson::Document);
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum InputFormat {
    SslKeylog,
    DdgSyslog,
}

pub(crate) enum InputLine<'a> {
    SslKeylog(&'a str),
    DdgSyslog(&'a str),
}

pub(crate) trait TlsRecord: BsonSerializable {
    fn get_metadata(&self) -> &RecordMetadata;
}

pub(crate) struct RecordMetadata {
    pub timestamp: OffsetDateTime,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub sni: String,
    pub cipher_id: u16,
    pub server_random: Vec<u8>,
    pub client_random: Vec<u8>,
}

impl BsonSerializable for RecordMetadata {
    fn serialize(&self, document: &mut bson::Document) {
        document.insert("_id", self.server_random.to_bson());
        document.insert("c", self.cipher_id as i32);
        document.insert("t", self.timestamp);
        document.insert("i", self.client_ip.to_bson());
        document.insert("p", self.client_port as i32);
        document.insert("r", self.client_random.to_bson());
    }
}

pub(crate) struct TlsPre13Record {
    pub metadata: RecordMetadata,
    pub premaster: Vec<u8>,
}

impl BsonSerializable for TlsPre13Record {
    fn serialize(&self, document: &mut bson::Document) {
        self.metadata.serialize(document);
        document.insert("k", self.premaster.to_bson());
    }
}

impl TlsRecord for TlsPre13Record {
    fn get_metadata(&self) -> &RecordMetadata {
        &self.metadata
    }
}

impl TryFrom<&InputLine<'_>> for TlsPre13Record {
    type Error = anyhow::Error;

    fn try_from(value: &InputLine<'_>) -> Result<Self, Self::Error> {
        match value {
            InputLine::SslKeylog(s) => tls_pre13_from_sslkeylog(s),
            InputLine::DdgSyslog(s) => tls_pre13_from_ddg_syslog(s),
        }
    }
}

fn tls_pre13_from_sslkeylog(value: &str) -> Result<TlsPre13Record, anyhow::Error> {
    const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{1,4}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{16,})$";
    lazy_static! {
        static ref FILTER_REGEX: Regex =
            Regex::new(FILTER_REGEX_PATTERN).expect("Failed to parse TLS pre-1.3 record sslkeylog filter regex");
    }

    let captures = FILTER_REGEX
        .captures(value)
        .with_context(|| format!("Invalid TLS pre-1.3 sslkeylog line {}", value))?;
    let metadata = RecordMetadata::try_from(&RecordMetadataSource {
        timestamp: &captures[1],
        client_ip: &captures[2],
        client_port: &captures[3],
        server_ip: &captures[4],
        server_port: &captures[5],
        sni: &captures[6],
        cipher_id: &captures[7],
        server_random: &captures[8],
        client_random: &captures[9],
    })?;
    let premaster = tls_secret_try_from(&captures[10], "premaster")?;

    Ok(TlsPre13Record { metadata, premaster })
}

fn tls_pre13_from_ddg_syslog(value: &str) -> Result<TlsPre13Record, anyhow::Error> {
    const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?) (\S*) (\S+?) (\S+?) (\d{1,5}) (\d{1,5}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64}) \- \- \- \- ([0-9a-fA-F]{1,4}) ([0-9a-fA-F]{16,})$";
    lazy_static! {
        static ref FILTER_REGEX: Regex =
            Regex::new(FILTER_REGEX_PATTERN).expect("Failed to parse TLS pre-1.3 record DDG syslog filter regex");
    }

    let captures = FILTER_REGEX
        .captures(value)
        .with_context(|| format!("Invalid TLS pre-1.3 DDG syslog line {}", value))?;
    let metadata = RecordMetadata::try_from(&RecordMetadataSource {
        timestamp: &captures[1],
        sni: &captures[2],
        client_ip: &captures[3],
        server_ip: &captures[4],
        client_port: &captures[5],
        server_port: &captures[6],
        client_random: &captures[7],
        server_random: &captures[8],
        cipher_id: &captures[9],
    })?;
    let premaster = tls_secret_try_from(&captures[10], "premaster")?;

    Ok(TlsPre13Record { metadata, premaster })
}

pub(crate) struct Tls13Record {
    pub metadata: RecordMetadata,
    pub server_handshake: Vec<u8>,
    pub client_handshake: Vec<u8>,
    pub server_0: Vec<u8>,
    pub client_0: Vec<u8>,
}

impl BsonSerializable for Tls13Record {
    fn serialize(&self, document: &mut bson::Document) {
        self.metadata.serialize(document);
        document.insert("h", self.server_handshake.to_bson());
        document.insert("f", self.client_handshake.to_bson());
        document.insert("z", self.server_0.to_bson());
        document.insert("s", self.client_0.to_bson());
    }
}

impl TlsRecord for Tls13Record {
    fn get_metadata(&self) -> &RecordMetadata {
        &self.metadata
    }
}

impl<'a> From<&'a Tls13Record> for &'a RecordMetadata {
    fn from(value: &'a Tls13Record) -> Self {
        &value.metadata
    }
}

impl TryFrom<&InputLine<'_>> for Tls13Record {
    type Error = anyhow::Error;

    fn try_from(value: &InputLine<'_>) -> Result<Self, Self::Error> {
        match value {
            InputLine::SslKeylog(s) => tls13_from_sslkeylog(s),
            InputLine::DdgSyslog(s) => tls13_from_ddg_syslog(s),
        }
    }
}

fn tls13_from_sslkeylog(value: &str) -> Result<Tls13Record, anyhow::Error> {
    const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+?):(\d{1,5}) (\S+?):(\d{1,5}) (\S*) ([0-9a-fA-F]{1,4}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{16,}) ([0-9a-fA-F]{16,}) ([0-9a-fA-F]{16,}) ([0-9a-fA-F]{16,})$";
    lazy_static! {
        static ref FILTER_REGEX: Regex =
            Regex::new(FILTER_REGEX_PATTERN).expect("Failed to parse TLS 1.3 sslkeylog record filter regex");
    }

    let captures = FILTER_REGEX
        .captures(value)
        .with_context(|| format!("Invalid TLS 1.3 sslkeylog line {}", value))?;
    let metadata = RecordMetadata::try_from(&RecordMetadataSource {
        timestamp: &captures[1],
        client_ip: &captures[2],
        client_port: &captures[3],
        server_ip: &captures[4],
        server_port: &captures[5],
        sni: &captures[6],
        cipher_id: &captures[7],
        server_random: &captures[8],
        client_random: &captures[9],
    })?;
    let server_handshake = tls_secret_try_from(&captures[10], "server handshake")?;
    let client_handshake = tls_secret_try_from(&captures[11], "client handshake")?;
    let server_0 = tls_secret_try_from(&captures[12], "server initial")?;
    let client_0 = tls_secret_try_from(&captures[13], "client initial")?;

    Ok(Tls13Record {
        metadata,
        server_handshake,
        client_handshake,
        server_0,
        client_0,
    })
}

fn tls13_from_ddg_syslog(value: &str) -> Result<Tls13Record, anyhow::Error> {
    const FILTER_REGEX_PATTERN: &str = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?) (\S*) (\S+?) (\S+?) (\d{1,5}) (\d{1,5}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{64}) ([0-9a-fA-F]{16,}) ([0-9a-fA-F]{16,}) ([0-9a-fA-F]{16,}) ([0-9a-fA-F]{16,}) ([0-9a-fA-F]{1,4}) -$";
    lazy_static! {
        static ref FILTER_REGEX: Regex =
            Regex::new(FILTER_REGEX_PATTERN).expect("Failed to parse TLS 1.3 DDG syslog record filter regex");
    }

    let captures = FILTER_REGEX
        .captures(value)
        .with_context(|| format!("Invalid TLS 1.3 DDG syslog line {}", value))?;
    let metadata = RecordMetadata::try_from(&RecordMetadataSource {
        timestamp: &captures[1],
        sni: &captures[2],
        client_ip: &captures[3],
        server_ip: &captures[4],
        client_port: &captures[5],
        server_port: &captures[6],
        client_random: &captures[7],
        server_random: &captures[8],
        cipher_id: &captures[13],
    })?;
    let client_handshake = tls_secret_try_from(&captures[9], "client handshake")?;
    let server_handshake = tls_secret_try_from(&captures[10], "server handshake")?;
    let client_0 = tls_secret_try_from(&captures[11], "client initial")?;
    let server_0 = tls_secret_try_from(&captures[12], "server initial")?;

    Ok(Tls13Record {
        metadata,
        server_handshake,
        client_handshake,
        server_0,
        client_0,
    })
}

pub(crate) struct GeoMetadata {
    pub geoname_id: u32,
}

impl BsonSerializable for GeoMetadata {
    fn serialize(&self, document: &mut bson::Document) {
        document.insert("g", self.geoname_id);
    }
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

struct RecordMetadataSource<'a> {
    pub timestamp: &'a str,
    pub client_ip: &'a str,
    pub client_port: &'a str,
    pub server_ip: &'a str,
    pub server_port: &'a str,
    pub sni: &'a str,
    pub cipher_id: &'a str,
    pub server_random: &'a str,
    pub client_random: &'a str,
}

impl TryFrom<&RecordMetadataSource<'_>> for RecordMetadata {
    type Error = anyhow::Error;

    fn try_from(value: &RecordMetadataSource) -> Result<Self, anyhow::Error> {
        let timestamp = OffsetDateTime::parse(value.timestamp, &format_description::well_known::Rfc3339)
            .with_context(|| format!("Invalid timestamp {}", value.timestamp))?;
        let client_ip =
            IpAddr::from_str(value.client_ip).with_context(|| format!("Invalid client IP address {}", value.client_ip))?;
        let client_port = u16::from_str(value.client_port).with_context(|| format!("Invalid client port {}", value.client_port))?;
        let server_ip =
            IpAddr::from_str(value.server_ip).with_context(|| format!("Invalid server IP address {}", value.server_ip))?;
        let server_port = u16::from_str(value.server_port).with_context(|| format!("Invalid server port {}", value.server_port))?;
        let cipher_id =
            u16::from_str_radix(value.cipher_id, 16).with_context(|| format!("Invalid cipher id {}", value.cipher_id))?;
        let server_random =
            hex::decode(value.server_random).with_context(|| format!("Invalid server random {}", value.server_random))?;
        let client_random =
            hex::decode(value.client_random).with_context(|| format!("Invalid client random {}", value.client_random))?;
        let sni = parse_sni(value.sni, server_ip, server_port)
            .with_context(|| format!("Invalid SNI {} (ip {}, port {})", value.sni, server_ip, server_port));
        let sni = match sni {
            Ok(v) => v,
            Err(e) => {
                logging::print_warning(&e);
                String::new()
            }
        };

        Ok(Self {
            timestamp,
            client_ip,
            client_port,
            server_ip,
            server_port,
            sni,
            cipher_id,
            server_random,
            client_random,
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

impl TryFrom<&str> for InputFormat {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "sslkeylog" => Ok(Self::SslKeylog),
            "ddgsyslog" => Ok(Self::DdgSyslog),
            _ => Err(anyhow!("Invalid input format")),
        }
    }
}

fn tls_secret_try_from(value: &str, kind: &str) -> Result<Vec<u8>, anyhow::Error> {
    hex::decode(value).with_context(|| format!("Invalid TLS {} secret {}", kind, value))
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
    fn parse_sni_succeeds_on_invalid_implicit_port() {
        assert_eq!("just-a-host.com", parse_sni_test("just-a-host.com", "127.0.0.1", 80,));
    }
}
