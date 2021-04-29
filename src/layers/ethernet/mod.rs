//! Ethernet Layer

use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Mutex;

use lazy_static::lazy_static;

use crate::types::MACAddress;
use crate::Error;
use crate::Layer;

mod types;
use types::ETHERTYPE_IP;

const ETH_HEADER_LEN: usize = 14_usize;

lazy_static! {
    /// A Map maintaining EtherType -> Creator fns for Layer Creators of L3 Layers.
    ///
    /// The creator function simply creates a `default` L3 struct that implements the dissectors
    /// for the Layer.
    static ref ETHERTYPES_MAP: Mutex<HashMap<EtherType, fn() -> Box<dyn Layer>>> =
        Mutex::new(HashMap::new());
}

pub type EtherType = u16;

/// Registers well-known EtherType values
pub fn register_defaults() -> Result<(), Error> {
    use super::ipv4::IPv4;

    register_ethertype(ETHERTYPE_IP, IPv4::creator)
}

/// Register for a given EtherType
///
/// A Layer that would handle subsequent decoding for a given Ethertype, should register itself
/// by calling this function.
///
pub fn register_ethertype(eth_type: EtherType, layer: fn() -> Box<dyn Layer>) -> Result<(), Error> {
    let mut map = ETHERTYPES_MAP.lock().unwrap();
    if map.contains_key(&eth_type) {
        return Err(Error::RegisterError);
    }
    map.insert(eth_type, layer);

    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct Ethernet {
    src_mac: MACAddress,
    dst_mac: MACAddress,
    ethertype: EtherType,
}

impl Ethernet {
    pub fn creator() -> Box<dyn Layer> {
        Box::new(Ethernet::default())
    }
}

impl Layer for Ethernet {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        if bytes.len() < ETH_HEADER_LEN {
            return Err(Error::TooShort);
        }
        self.src_mac = bytes[0..6].try_into()?;
        self.dst_mac = bytes[6..12].try_into()?;
        self.ethertype = (bytes[12] as u16) << 8 | bytes[13] as u16;
        let map = ETHERTYPES_MAP.lock().unwrap();
        let layer = map.get(&self.ethertype);
        if layer.is_none() {
            return Ok((None, ETH_HEADER_LEN));
        } else {
            let l3_creator = layer.unwrap();
            return Ok((Some(l3_creator()), ETH_HEADER_LEN));
        }
    }

    fn name(&self) -> &str {
        "Ethernet"
    }

    fn short_name(&self) -> &str {
        "eth"
    }
}
