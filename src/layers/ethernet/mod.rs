//! Ethernet Layer

use core::convert::TryInto;

// FIXME: Should work with no_std
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use serde::Serialize;

use crate::errors::Error;
use crate::types::{EtherType, LayerCreatorFn, MACAddress};
use crate::{Layer, Packet, ENCAP_TYPE_ETH};

pub const ETH_HEADER_LENGTH: usize = 14_usize;

pub fn get_ethertypes_map() -> &'static RwLock<HashMap<EtherType, LayerCreatorFn>> {
    /// A Map maintaining EtherType -> Creator fns for Layer Creators of L3 Layers.
    ///
    /// The creator function simply creates a `default` L3 struct that implements the dissector
    /// for the Layer.
    pub(crate) static ETHERTYPES_MAP: OnceLock<RwLock<HashMap<EtherType, LayerCreatorFn>>> =
        OnceLock::new();
    ETHERTYPES_MAP.get_or_init(|| RwLock::new(HashMap::new()))
}

// Register our Encap Types with the Packet.
pub(crate) fn register_defaults() -> Result<(), Error> {
    get_ethertypes_map();

    Packet::register_encap_type(ENCAP_TYPE_ETH, Ethernet::creator)
}

/// Register for a given EtherType
///
/// A Layer that would handle subsequent decoding for a given Ethertype, should register itself
/// by calling this function. For example [`crate::layers::ipv4`] would call `register_ethertype`
/// with [`EtherType`] value of 0x0800, passing the creator function for that layer.
pub fn register_ethertype(eth_type: EtherType, layer: LayerCreatorFn) -> Result<(), Error> {
    let mut map = get_ethertypes_map().write().unwrap();
    if map.contains_key(&eth_type) {
        return Err(Error::RegisterError(format!("ether_type: {}", eth_type)));
    }
    map.insert(eth_type, layer);

    Ok(())
}

/// Structure representing the Ethernet Header of a Packet.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Ethernet {
    dst_mac: MACAddress,
    src_mac: MACAddress,
    #[serde(serialize_with = "crate::types::hex::serialize_upper_hex_u16")]
    ethertype: EtherType,
}

impl Ethernet {
    pub fn new() -> Self {
        Self {
            ethertype: 0xFFFF,
            ..Default::default()
        }
    }

    pub(crate) fn creator() -> Box<dyn Layer + Send> {
        Box::<Ethernet>::default()
    }
}

impl Layer for Ethernet {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < ETH_HEADER_LENGTH {
            return Err(Error::TooShort {
                required: ETH_HEADER_LENGTH,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }
        self.dst_mac = bytes[0..6].try_into()?;
        self.src_mac = bytes[6..12].try_into()?;
        self.ethertype = (bytes[12] as u16) << 8 | bytes[13] as u16;

        let map = get_ethertypes_map().read().unwrap();
        let layer = map.get(&self.ethertype);
        match layer {
            None => Ok((None, ETH_HEADER_LENGTH)),
            Some(l3_creator) => Ok((Some(l3_creator()), ETH_HEADER_LENGTH)),
        }
    }

    #[cfg(feature = "sculpting")]
    fn stack_and_encode(
        &mut self,
        next_layer: Option<&[u8]>,
        info: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut result = Vec::with_capacity(ETH_HEADER_LENGTH);

        result.extend(self.dst_mac.as_slice());
        result.extend(self.src_mac.as_slice());

        let ethertype: u16 = match info {
            "ARP" => crate::types::ETHERTYPE_ARP,
            "IPv4" => crate::types::ETHERTYPE_IP,
            "IPv6" => crate::types::ETHERTYPE_IP6,
            // FIXME: can also be `ETHERTYPE_MPLS_MULTICAST`
            "MPLS" => crate::types::ETHERTYPE_MPLS_UNICAST,
            "raw" => 0xffff,
            // NOTE: should return Err instead
            _ => unimplemented!(),
        };

        result.extend(ethertype.to_be_bytes());
        result.extend(next_layer.unwrap_or_default());

        // TODO: pad to 64 bytes(minimum packet size)

        Ok(result)
    }

    fn name(&self) -> &'static str {
        "Ethernet"
    }

    fn short_name(&self) -> &'static str {
        "eth"
    }
}
