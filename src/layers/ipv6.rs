//! IPv6 Layer

use core::convert::TryInto;

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use serde::Serialize;

use crate::errors::Error;
use crate::types::{IPv6Address, LayerCreatorFn};
use crate::Layer;

/// Basic Length of the IPv6 Header
pub const IPV6_BASE_HEADER_LENGTH: usize = 40_usize;

fn get_next_headers_map() -> &'static RwLock<HashMap<u8, LayerCreatorFn>> {
    static NEXT_HEADERS_MAP: OnceLock<RwLock<HashMap<u8, LayerCreatorFn>>> = OnceLock::new();
    NEXT_HEADERS_MAP.get_or_init(|| RwLock::new(HashMap::new()))
}

// Register ourselves to well-known Layer 2
//
// Right now only Ethernet is Supported
pub(crate) fn register_defaults() -> Result<(), Error> {
    use crate::layers::ethernet::register_ethertype;

    let name = Some(IPv6::default().name());
    register_ethertype(crate::types::ETHERTYPE_IP6, name, IPv6::creator)?;

    Ok(())
}

/// Register Next Header (Usually a Transport Porotocol).
///
/// All the Protocols use this value, in addition to IPv6 Extension headers. For example [TCP
/// Protocol][`crate::layers::tcp`] would call this function with a header value of 6 and creator
/// function for [`TCP`][`crate::layers::tcp::TCP`].
pub fn register_next_header(header: u8, creator: LayerCreatorFn) -> Result<(), Error> {
    let mut map = get_next_headers_map().write().unwrap();

    if map.contains_key(&header) {
        return Err(Error::RegisterError(format!(
            "IPv6 Next Header: {}",
            header
        )));
    }

    map.insert(header, creator);

    Ok(())
}

/// Structure representing IPv6 Protocol Headers.
#[derive(Debug, Default, Serialize)]
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
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::<IPv6>::default()
    }
}

impl Layer for IPv6 {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < IPV6_BASE_HEADER_LENGTH {
            return Err(Error::TooShort {
                required: IPV6_BASE_HEADER_LENGTH,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }

        self.version = bytes[0] >> 4;
        self.traffic_class = ((bytes[0] & 0xF) << 4) | (bytes[1] >> 4);
        self.flow_label = (bytes[1] as u32) << 12 | (bytes[2] as u32) << 8 | (bytes[3] as u32);
        self.payload_len = (bytes[4] as u16) << 8 | (bytes[5] as u16);
        self.next_hdr = bytes[6];
        self.hop_limit = bytes[7];
        self.src_addr = bytes[8..24].try_into().unwrap();
        self.dst_addr = bytes[24..40].try_into().unwrap();

        let map = get_next_headers_map().read().unwrap();
        let layer = map.get(&self.next_hdr);
        match layer {
            None => Ok((None, IPV6_BASE_HEADER_LENGTH)),
            Some(next_layer_creator) => Ok((Some(next_layer_creator()), IPV6_BASE_HEADER_LENGTH)),
        }
    }

    fn name(&self) -> &'static str {
        "IPv6"
    }

    fn short_name(&self) -> &'static str {
        "ip6"
    }
}
