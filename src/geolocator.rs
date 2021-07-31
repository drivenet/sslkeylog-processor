use std::{net::IpAddr, path::Path};

use anyhow::Result;
use maxminddb::Reader;

pub(crate) struct Geolocator {
    reader: Reader<Vec<u8>>,
}

impl Geolocator {
    pub fn new<P>(database: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            reader: Reader::open_readfile(database)?,
        })
    }

    pub fn locate(&self, address: IpAddr) -> Result<Option<u32>> {
        use anyhow::bail;
        use maxminddb::{geoip2, MaxMindDBError};

        Ok(match self.reader.lookup::<geoip2::City>(address) {
            Ok(result) => result
                .city
                .as_ref()
                .and_then(|c| c.geoname_id)
                .or_else(|| result.country.and_then(|c| c.geoname_id)),
            Err(MaxMindDBError::AddressNotFoundError(_)) => None,
            Err(e) => bail!(e),
        })
    }
}
