//! Multi Label Protocol Switching

use std::convert::TryInto;

use serde::Serialize;

use crate::errors::Error;
use crate::layers::ethernet;
use crate::types::ETHERTYPE_MPLS_UNICAST;
use crate::Layer;

use super::ipv4::IPv4;

/// Default Header Length for MPLS Packets
pub const MPLS_HDR_LEN: usize = 4_usize;

// Register Ourselves to the Ethernet layer, as this is a 2.5 layer protocol
pub(crate) fn register_defaults() -> Result<(), Error> {
    ethernet::register_ethertype(ETHERTYPE_MPLS_UNICAST, MPLS::creator)
}

#[derive(Debug, Default, Serialize)]
pub struct MPLS{//Make built-in types
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u32")]
    label:u32,//This is only 20 bits
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    exp:u8,//This is only 3 bits
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    bos:u8,//This is only 1 bit
    #[serde(serialize_with = "crate::types::hex::serialize_lower_hex_u8")]
    ttl:u8,//This is 1 byte
}

impl MPLS {
    pub fn creator() -> Box<dyn Layer + Send> {
        Box::<MPLS>::default()
    }
}

impl Layer for MPLS {
    fn decode_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Box<dyn Layer + Send>>, usize), Error> {
        if bytes.len() < MPLS_HDR_LEN {
            return Err(Error::TooShort {
                required: MPLS_HDR_LEN,
                available: bytes.len(),
                data: hex::encode(bytes),
            });
        }
        
        //FIXME:For now the first few bits are not useful in label,exp and bos
        self.label = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as u32 >> 12;
        self.exp = u8::from_be(bytes[2] << 4) >> 5; 
        self.bos = u8::from_be(bytes[2] << 7) >> 7;
        self.ttl = bytes[3];

        Ok((Some(IPv4::creator()), MPLS_HDR_LEN))
    }

    fn name(&self) -> &'static str {
        "MPLS"
    }

    fn short_name(&self) -> &'static str {
        "mpls"
    }
}
