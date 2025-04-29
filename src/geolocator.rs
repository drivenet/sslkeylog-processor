use std::{net::IpAddr, path::Path};

use anyhow::{bail, Result};
use maxminddb::{geoip2, Reader};

pub(crate) struct Geolocator {
    reader: Reader<Vec<u8>>,
}

impl Geolocator {
    pub fn new<P: AsRef<Path>>(database: P) -> Result<Self> {
        Ok(Self {
            reader: Reader::open_readfile(database)?,
        })
    }

    pub fn locate(&self, address: IpAddr) -> Result<Option<u32>> {
        Ok(match self.reader.lookup::<geoip2::City>(address) {
            Ok(Some(result)) => result
                .city
                .as_ref()
                .and_then(|c| c.geoname_id)
                .or_else(|| result.country.and_then(|c| c.geoname_id)),
            Ok(None) => None,
            Err(e) => bail!(e),
        })
    }
}
