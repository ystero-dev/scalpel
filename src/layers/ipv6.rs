//! IPv6 Layer

use core::convert::TryInto;

use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use serde::Serialize;

use crate::errors::Error;
use crate::layer::Layer;
use crate::types::{IPv6Address, LayerCreatorFn};

pub const IPV6_BASE_HDR_LEN: usize = 40_usize;

lazy_static! {
    static ref NEXT_HEADERS_MAP: RwLock<HashMap<u8, LayerCreatorFn>> = RwLock::new(HashMap::new());
}

/// Register ourselves to well-known Layer 2
///
/// Right now only Ethernet is Supported
pub fn register_defaults() -> Result<(), Error> {
    use crate::layers::ethernet::register_ethertype;

    register_ethertype(crate::types::ETHERTYPE_IP6.clone(), IPv6::creator)?;

    Ok(())
}

/// Register Next Header
///
/// All the Protocols use this value, in addition to IPv6 Extension headers.
pub fn register_next_header(header: u8, creator: LayerCreatorFn) -> Result<(), Error> {
    let mut map = NEXT_HEADERS_MAP.write().unwrap();

    if map.contains_key(&header) {
        return Err(Error::RegisterError);
    }

    map.insert(header, creator);

    Ok(())
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct IPv6 {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_len: u16,
    next_hdr: u8,
    hop_limit: u8,
    src_addr: IPv6Address,
    dst_addr: IPv6Address,
}

impl IPv6 {
    pub fn creator() -> Box<dyn Layer> {
        Box::new(IPv6::default())
    }
}

impl Layer for IPv6 {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        if bytes.len() < IPV6_BASE_HDR_LEN {
            return Err(Error::ParseError);
        }

        self.version = bytes[0] >> 4;
        self.traffic_class = ((bytes[0] & 0xF) << 4) | (bytes[1] >> 4);
        self.flow_label = (bytes[1] as u32) << 12 | (bytes[2] as u32) << 8 | (bytes[3] as u32);
        self.payload_len = (bytes[4] as u16) << 8 | (bytes[5] as u16);
        self.next_hdr = bytes[6];
        self.hop_limit = bytes[7];
        self.src_addr = bytes[8..24].try_into().unwrap();
        self.dst_addr = bytes[24..40].try_into().unwrap();

        let map = NEXT_HEADERS_MAP.read().unwrap();
        let layer = map.get(&self.next_hdr);
        if layer.is_none() {
            Ok((None, IPV6_BASE_HDR_LEN))
        } else {
            let next_layer_creator = layer.unwrap();
            Ok((Some(next_layer_creator()), IPV6_BASE_HDR_LEN))
        }
    }

    fn name(&self) -> &str {
        "IPv6"
    }

    fn short_name(&self) -> &str {
        "ip6"
    }
}
