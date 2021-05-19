use std::net::IpAddr;

use mongodb::bson::{self, Bson};

pub(crate) trait ToBson {
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
