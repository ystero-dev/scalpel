//! IPv6 Layer

use core::convert::TryInto;

use crate::errors::Error;
use crate::layer::Layer;
use crate::types::IPv6Address;

pub const IPV6_BASE_HDR_LEN: usize = 40_usize;

#[derive(Debug, Default, Clone)]
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

        Ok((None, IPV6_BASE_HDR_LEN))
    }

    fn name(&self) -> &str {
        "IPv6"
    }

    fn short_name(&self) -> &str {
        "ip6"
    }
}
