//! Ethernet Layer

use core::convert::TryInto;

// FIXME: Should work with no_std
use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::Serialize;

use crate::errors::Error;
use crate::types::{EtherType, LayerCreatorFn, MACAddress};
use crate::{Layer, Packet, ENCAP_TYPE_ETH};

pub const ETH_HEADER_LEN: usize = 14_usize;

lazy_static! {
    /// A Map maintaining EtherType -> Creator fns for Layer Creators of L3 Layers.
    ///
    /// The creator function simply creates a `default` L3 struct that implements the dissector
    /// for the Layer.
    pub(crate) static ref ETHERTYPES_MAP: RwLock<HashMap<EtherType, LayerCreatorFn>> =
        RwLock::new(HashMap::new());

}

// Register our Encap Types with the Packet.
pub(crate) fn register_defaults() -> Result<(), Error> {
    lazy_static::initialize(&ETHERTYPES_MAP);

    Packet::register_encap_type(ENCAP_TYPE_ETH, Ethernet::creator)
}

/// Register for a given EtherType
///
/// A Layer that would handle subsequent decoding for a given Ethertype, should register itself
/// by calling this function. For example [`crate::layers::ipv4`] would call `register_ethertype`
/// with [`EtherType`] value of 0x0800, passing the creator function for that layer.
pub fn register_ethertype(eth_type: EtherType, layer: LayerCreatorFn) -> Result<(), Error> {
    lazy_static::initialize(&ETHERTYPES_MAP);

    let mut map = ETHERTYPES_MAP.write().unwrap();
    if map.contains_key(&eth_type) {
        return Err(Error::RegisterError(format!("ether_type: {}", eth_type)));
    }
    map.insert(eth_type, layer);

    Ok(())
}

/// Structure representing the Ethernet Header of a Packet.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Ethernet {
    src_mac: MACAddress,
    dst_mac: MACAddress,
    #[serde(serialize_with = "crate::types::hex::serialize_upper_hex_u16")]
    ethertype: EtherType,
}

impl Ethernet {
    pub(crate) fn creator() -> Box<dyn Layer + Send> {
        Box::<Ethernet>::default()
    }
}

impl Layer for Ethernet {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < ETH_HEADER_LEN {
            return Err(Error::TooShort {
                required: ETH_HEADER_LEN,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }
        self.src_mac = bytes[0..6].try_into()?;
        self.dst_mac = bytes[6..12].try_into()?;
        self.ethertype = (bytes[12] as u16) << 8 | bytes[13] as u16;

        let map = ETHERTYPES_MAP.read().unwrap();
        let layer = map.get(&self.ethertype);
        match layer {
            None => Ok((None, ETH_HEADER_LEN)),
            Some(l3_creator) => Ok((Some(l3_creator()), ETH_HEADER_LEN)),
        }
    }

    fn name(&self) -> &'static str {
        "Ethernet"
    }

    fn short_name(&self) -> &'static str {
        "eth"
    }
}
