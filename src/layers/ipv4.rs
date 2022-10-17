//! IPv4 Layer

use core::convert::TryInto as _;

use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::Serialize;

use crate::errors::Error;
use crate::layer::Layer;
use crate::types::{IPv4Address, LayerCreatorFn};

pub const IPV4_BASE_HDR_LEN: usize = 20_usize;

lazy_static! {
    static ref PROTOCOLS_MAP: RwLock<HashMap<u8, LayerCreatorFn>> = RwLock::new(HashMap::new());
}

// Register ourselves to well-known Layer 2
//
// Right now only Ethernet is Supported
pub(crate) fn register_defaults() -> Result<(), Error> {
    use crate::layers::ethernet::register_ethertype;

    register_ethertype(crate::types::ETHERTYPE_IP, IPv4::creator)?;

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

#[derive(Debug, Default, Serialize)]
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
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::new(IPv4::default())
    }
}

impl Layer for IPv4 {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        self.version = bytes[0] >> 4;
        self.hdr_len = bytes[0] & 0x0f;
        // Length is in 4 octets
        if bytes.len() < (self.hdr_len * 4).into() {
            return Err(Error::ParseError);
        }
        self.tos = bytes[1];
        self.len = (bytes[2] as u16) << 8 | (bytes[3] as u16);
        self.id = (bytes[4] as u16) << 8 | (bytes[5] as u16);
        let flags_offset = (bytes[6] as u16) << 8 | (bytes[7] as u16);
        self.flags = (flags_offset >> 13) as u8;
        self.frag_offset = flags_offset & 0xe0;
        self.ttl = bytes[8];
        self.proto = bytes[9];
        self.checksum = (bytes[10] as u16) << 8 | (bytes[11] as u16);
        self.src_addr = bytes[12..16].try_into().unwrap();
        self.dst_addr = bytes[16..20].try_into().unwrap();

        let map = PROTOCOLS_MAP.read().unwrap();
        let layer = map.get(&self.proto);
        match layer {
            None => Ok((None, IPV4_BASE_HDR_LEN)),
            Some(l4_creator) => Ok((Some(l4_creator()), IPV4_BASE_HDR_LEN)),
        }
    }

    fn name(&self) -> &'static str {
        "IPv4"
    }

    fn short_name(&self) -> &'static str {
        "ip"
    }
}
