//! IPv4 Layer

use core::convert::TryInto as _;

use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;

use crate::errors::Error;
use crate::layer::Layer;
use crate::types::{IPv4Address, LayerCreatorFn};

pub const IPV4_BASE_HDR_LEN: usize = 20_usize;

lazy_static! {
    static ref PROTOCOLS_MAP: RwLock<HashMap<u8, LayerCreatorFn>> = RwLock::new(HashMap::new());
}

/// Register ourselves to well-known Layer 2
///
/// Right now only Ethernet is Supported
pub fn register_defaults() -> Result<(), Error> {
    use crate::layers::ethernet::register_ethertype;

    register_ethertype(crate::types::ETHERTYPE_IP.clone(), IPv4::creator)?;

    Ok(())
}

/// Register a Protocol for dissection.
///
/// Higher level protocols should call this function to register themselves for decoding with the
/// IPv4 Layer.
pub fn register_protocol(proto: u8, creator: LayerCreatorFn) -> Result<(), Error> {
    let mut map = PROTOCOLS_MAP.write().unwrap();
    if map.contains_key(&proto) {
        return Err(Error::RegisterError);
    }
    map.insert(proto, creator);

    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct IPv4 {
    version: u8,
    hdr_len: u8,
    tos: u8,
    len: u16,
    id: u16,
    flags: u8,
    frag_offset: u16,
    ttl: u8,
    proto: u8,
    checksum: u16,
    src_addr: IPv4Address,
    dst_addr: IPv4Address,
    // FIXME: Add options
}

impl IPv4 {
    pub fn creator() -> Box<dyn Layer> {
        Box::new(IPv4::default())
    }
}

impl Layer for IPv4 {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        self.version = bytes[0] >> 4;
        self.hdr_len = bytes[0] & 0x0f;
        // Length is in 4 octets
        if bytes.len() < (self.hdr_len * 4).into() {
            return Err(Error::ParseError);
        }
        self.tos = bytes[1];
        self.len = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        self.id = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let flags_offset = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        self.flags = (flags_offset >> 13) as u8;
        self.frag_offset = flags_offset & 0xe0;
        self.ttl = bytes[8];
        self.proto = bytes[9];
        self.checksum = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
        self.src_addr = bytes[12..16].try_into().unwrap();
        self.dst_addr = bytes[16..20].try_into().unwrap();

        let map = PROTOCOLS_MAP.read().unwrap();
        let layer = map.get(&self.proto);
        if layer.is_none() {
            Ok((None, IPV4_BASE_HDR_LEN))
        } else {
            let l4_creator = layer.unwrap();
            Ok((Some(l4_creator()), IPV4_BASE_HDR_LEN))
        }
    }

    fn name(&self) -> &str {
        "IPv4"
    }

    fn short_name(&self) -> &str {
        "ip"
    }
}
